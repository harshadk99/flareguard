/**
 * "Connect with Cloudflare" OAuth routes.
 *
 *   GET /auth/cf/start     → redirect the user to Cloudflare's consent screen
 *   GET /auth/cf/callback  → exchange the code and hand the token to the SPA
 *
 * The CSRF `state` and the PKCE `verifier` are carried across the round-trip in
 * one short-lived, HttpOnly cookie — no server-side storage, so the Worker
 * stays stateless and persists no credentials (CLAUDE.md).
 *
 * The resulting access token is returned to the browser in the URL fragment of
 * the /audit redirect (fragments are never sent to the server or written to
 * access logs). The SPA reads it into the in-memory token field and strips the
 * fragment immediately — the same "token lives only in the browser" model the
 * manual-token path already uses.
 */
import {
  buildAuthorizeUrl,
  exchangeCodeForToken,
  generatePkce,
  randomState,
  allScopes,
} from './cloudflare-oauth.js';

const STATE_COOKIE = 'fg_oauth';
const COOKIE_MAX_AGE = 600; // 10 min — long enough to sign in, short enough to be safe
const COOKIE_PATH = '/auth/cf';

/** OAuth is active only when the deployer has configured a client id. */
export function oauthEnabled(env) {
  return typeof env.CF_OAUTH_CLIENT_ID === 'string' && env.CF_OAUTH_CLIENT_ID.length > 0;
}

function buildCookie(value, { clear } = {}) {
  return [
    `${STATE_COOKIE}=${value}`,
    `Path=${COOKIE_PATH}`,
    'HttpOnly',
    'Secure',
    'SameSite=Lax',
    `Max-Age=${clear ? 0 : COOKIE_MAX_AGE}`,
  ].join('; ');
}

function readCookie(request, name) {
  const header = request.headers.get('Cookie') || '';
  for (const part of header.split(/;\s*/)) {
    const eq = part.indexOf('=');
    if (eq > -1 && part.slice(0, eq) === name) return part.slice(eq + 1);
  }
  return null;
}

function redirect(location, headers = {}) {
  return new Response(null, { status: 302, headers: { Location: location, ...headers } });
}

/** /audit with a URL fragment the SPA can read (token/scope or error). */
function redirectToApp(origin, params) {
  return `${origin}/audit#${new URLSearchParams(params).toString()}`;
}

function callbackUri(request) {
  return new URL(request.url).origin + '/auth/cf/callback';
}

export async function handleOAuthStart(request, env) {
  const origin = new URL(request.url).origin;

  if (!oauthEnabled(env)) {
    return redirect(redirectToApp(origin, {
      cf_error: 'Connect with Cloudflare is not configured on this deployment (set CF_OAUTH_CLIENT_ID).',
    }));
  }

  const { verifier, challenge } = await generatePkce();
  const state = randomState();

  const authUrl = buildAuthorizeUrl({
    clientId: env.CF_OAUTH_CLIENT_ID,
    redirectUri: callbackUri(request),
    scopes: allScopes(),
    state,
    codeChallenge: challenge,
  });

  const payload = btoa(JSON.stringify({ state, verifier }));
  return redirect(authUrl, { 'Set-Cookie': buildCookie(payload) });
}

export async function handleOAuthCallback(request, env) {
  const url = new URL(request.url);
  const origin = url.origin;
  const clearCookie = { 'Set-Cookie': buildCookie('', { clear: true }) };
  const fail = (msg) => redirect(redirectToApp(origin, { cf_error: msg }), clearCookie);

  // Provider-side error (user declined consent, invalid client, etc.)
  const providerError = url.searchParams.get('error');
  if (providerError) {
    return fail(url.searchParams.get('error_description') || providerError);
  }

  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  if (!code || !state) return fail('Missing authorization code or state.');

  // Validate state against the cookie (CSRF protection).
  const raw = readCookie(request, STATE_COOKIE);
  if (!raw) return fail('Sign-in session expired — please try again.');
  let saved;
  try {
    saved = JSON.parse(atob(raw));
  } catch {
    return fail('Invalid sign-in session — please try again.');
  }
  if (!saved.state || saved.state !== state) return fail('State mismatch — please try again.');

  if (!oauthEnabled(env)) return fail('Connect with Cloudflare is not configured on this deployment.');

  let token;
  try {
    token = await exchangeCodeForToken({
      clientId: env.CF_OAUTH_CLIENT_ID,
      redirectUri: callbackUri(request),
      code,
      codeVerifier: saved.verifier,
    });
  } catch (e) {
    return fail('Token exchange failed: ' + e.message);
  }

  if (!token.access_token) return fail('Cloudflare did not return an access token.');

  return redirect(redirectToApp(origin, {
    cf_token: token.access_token,
    cf_scope: token.scope || '',
    cf_expires: String(token.expires_in ?? ''),
  }), clearCookie);
}
