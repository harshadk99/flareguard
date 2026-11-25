/**
 * Cloudflare self-managed OAuth — "Connect with Cloudflare".
 *
 * Lets a user grant FlareGuard READ-ONLY access to their Cloudflare account
 * via the standard OAuth 2.0 Authorization Code + PKCE flow, instead of
 * pasting a long-lived API token.
 *
 * FlareGuard registers as a PUBLIC OAuth client (token_endpoint_auth_method:
 * "none"), so there is NO client secret — PKCE (S256) is what proves the token
 * request came from the same client that started the flow. This means the
 * client id is safe to ship as a plain Worker var.
 *
 * Endpoints are Cloudflare's published OAuth endpoints (the same ones Wrangler
 * uses), verified against:
 *   https://dash.cloudflare.com/.well-known/openid-configuration
 *
 * Privacy (see CLAUDE.md): the access token is handed straight to the browser
 * and used per-request, exactly like a pasted token. The Worker never stores
 * or logs it.
 */

export const CF_OAUTH_ENDPOINTS = {
  authorize: 'https://dash.cloudflare.com/oauth2/auth',
  token: 'https://dash.cloudflare.com/oauth2/token',
  revoke: 'https://dash.cloudflare.com/oauth2/revoke',
};

/**
 * Least-privilege READ scopes, mapped to FlareGuard's evaluators. Scope ids
 * mirror Cloudflare API-token permission names.
 *
 * `required` cover a single-zone audit. `optional` unlock the account-level
 * checks (Zero Trust / Workers / account Logpush); a user can decline them on
 * the consent screen without breaking the zone audit.
 */
export const FLAREGUARD_SCOPES = {
  required: [
    'zone.read',                 // Zone Read — list/resolve the zone
    'zone-settings.read',        // Zone Settings Read — SSL/TLS/HSTS/security level/…
    'dns.read',                  // DNS Read — DNSSEC
    'ssl-and-certificates.read', // SSL and Certificates Read — CT monitoring, certs
    'firewall-services.read',    // Firewall Services Read — WAF, firewall, rate limiting
    'bot-management.read',       // Bot Management Read
    'page-shield.read',          // Page Shield Read
    'logs.read',                 // Logs Read — zone Logpush
  ],
  optional: [
    'account-settings.read',     // Account Settings Read
    'access.read',               // Access: Apps and Policies Read — Zero Trust
    'workers-scripts.read',      // Workers Scripts Read — zombie / secret-env checks
    'workers-routes.read',       // Workers Routes Read
    'account-logs.read',         // Logs Read (account) — account Logpush
  ],
};

export function allScopes() {
  return [...FLAREGUARD_SCOPES.required, ...FLAREGUARD_SCOPES.optional];
}

// ── PKCE (RFC 7636, S256) ───────────────────────────────────────────────────────

function base64url(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function sha256(str) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return new Uint8Array(digest);
}

/**
 * Generate a PKCE { verifier, challenge } pair.
 *
 * Cloudflare's authorization server can mis-parse a code_challenge that begins
 * with a non-alphanumeric character (`-` / `_`), so we regenerate until the
 * challenge starts [A-Za-z0-9].
 */
export async function generatePkce() {
  for (let i = 0; i < 16; i++) {
    const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
    const challenge = base64url(await sha256(verifier));
    if (/^[A-Za-z0-9]/.test(challenge)) return { verifier, challenge };
  }
  throw new Error('Could not generate a valid PKCE challenge');
}

export function randomState() {
  return base64url(crypto.getRandomValues(new Uint8Array(16)));
}

// ── Flow ─────────────────────────────────────────────────────────────────────────

export function buildAuthorizeUrl({ clientId, redirectUri, scopes, state, codeChallenge }) {
  const u = new URL(CF_OAUTH_ENDPOINTS.authorize);
  u.searchParams.set('response_type', 'code');
  u.searchParams.set('client_id', clientId);
  u.searchParams.set('redirect_uri', redirectUri);
  u.searchParams.set('scope', scopes.join(' '));
  u.searchParams.set('state', state);
  u.searchParams.set('code_challenge', codeChallenge);
  u.searchParams.set('code_challenge_method', 'S256');
  return u.toString();
}

/**
 * Exchange an authorization code for an access token (public client + PKCE).
 * Runs server-side in the Worker, so there is no browser CORS constraint.
 *
 * @returns {Promise<{ access_token: string, token_type: string, expires_in?: number, scope?: string, refresh_token?: string }>}
 */
export async function exchangeCodeForToken({ clientId, redirectUri, code, codeVerifier }) {
  const res = await fetch(CF_OAUTH_ENDPOINTS.token, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: clientId,
      redirect_uri: redirectUri,
      code_verifier: codeVerifier,
    }),
  });

  const text = await res.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = { error: 'invalid_response', error_description: text.slice(0, 200) };
  }
  if (!res.ok || data.error) {
    throw new Error(data.error_description || data.error || `Token exchange failed (HTTP ${res.status})`);
  }
  return data;
}
