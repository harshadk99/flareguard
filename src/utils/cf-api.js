/**
 * Thin wrapper around the Cloudflare API.
 * All methods throw CloudflareAPIError on non-2xx / success:false responses.
 */

/** Map API path prefixes to the token permission needed for that call. */
const PATH_PERMISSION_HINTS = [
  [/\/zones\/[^/]+\/settings/, 'Zone Settings Read (or Zone Read)'],
  [/\/zones\/[^/]+\/dnssec/, 'DNS Read'],
  [/\/zones\/[^/]+\/rulesets\/phases\/http_request_firewall_managed/, 'Zone WAF / Firewall Services Read'],
  [/\/zones\/[^/]+\/rulesets\/phases\/http_ratelimit/, 'Zone WAF / Firewall Services Read'],
  [/\/zones\/[^/]+\/rate_limits/, 'Zone WAF / Firewall Services Read'],
  [/\/zones\/[^/]+\/firewall\/waf/, 'Zone WAF / Firewall Services Read'],
  [/\/zones\/[^/]+\/firewall\/rules/, 'Zone WAF / Firewall Services Read'],
  [/\/zones\/[^/]+\/bot_management/, 'Bot Management Read'],
  [/\/zones\/[^/]+\/page_shield/, 'Page Shield: Read'],
  [/\/zones\/[^/]+\/logpush/, 'Logs Read'],
  [/\/zones\/[^/]+\/workers\/routes/, 'Workers Routes Read'],
  [/\/accounts\/[^/]+\/logpush/, 'Logs Read'],
  [/\/accounts\/[^/]+\/access\//, 'Access: Apps and Policies Read'],
  [/\/accounts\/[^/]+\/workers\//, 'Workers Scripts Read'],
  [/\/zones\?/, 'Zone Read'],
  [/\/zones\/[^/]+$/, 'Zone Read'],
];

export function permissionHintForPath(path = '') {
  for (const [re, hint] of PATH_PERMISSION_HINTS) {
    if (re.test(path)) return hint;
  }
  return 'the permission required for this Cloudflare API endpoint';
}

/**
 * Structured Cloudflare API failure so evaluators can distinguish
 * auth vs insufficient-scope vs other errors.
 */
export class CloudflareAPIError extends Error {
  /**
   * @param {{ path: string, status: number, code?: number|null, apiMessage: string, errors?: object[] }} opts
   */
  constructor({ path, status, code = null, apiMessage, errors = [] }) {
    super(`Cloudflare API error on ${path}: ${apiMessage}`);
    this.name = 'CloudflareAPIError';
    this.path = path;
    this.status = status;
    this.code = code;
    this.apiMessage = apiMessage;
    this.errors = errors;
    this.kind = classifyError(status, code, apiMessage);
  }
}

function classifyError(status, code, message) {
  const msg = (message ?? '').toLowerCase();

  if (status === 410) return 'gone';
  if (status === 404) return 'not_found';

  // Invalid / revoked token — authentication failed
  if (status === 401) return 'auth';
  if (code === 10000 && /authentication/.test(msg)) return 'auth';
  if (/authentication error|invalid.*(token|key)|expired.*token|revoked/.test(msg) && !/permission|authorized|scope/.test(msg)) {
    return 'auth';
  }

  // Valid token, missing grant — insufficient scope
  if (status === 403) return 'permission';
  if (/insufficient|not (authorized|permitted)|permission|unauthorized|access denied|missing.+scope|does not have access/.test(msg)) {
    return 'permission';
  }
  // Cloudflare often returns 400/403 with code 9109 for authorization
  if (code === 9109 || code === 9106) return 'permission';

  return 'api';
}

export class CloudflareAPI {
  constructor(apiToken) {
    this.token = apiToken;
    this.base = 'https://api.cloudflare.com/client/v4';
  }

  async #get(path) {
    const res = await fetch(`${this.base}${path}`, {
      headers: {
        Authorization: `Bearer ${this.token}`,
        'Content-Type': 'application/json',
      },
    });

    let data;
    try {
      data = await res.json();
    } catch {
      throw new CloudflareAPIError({
        path,
        status: res.status,
        apiMessage: `HTTP ${res.status} (non-JSON body)`,
      });
    }

    if (!res.ok || data.success === false) {
      const first = data.errors?.[0];
      const apiMessage = first?.message ?? `HTTP ${res.status}`;
      throw new CloudflareAPIError({
        path,
        status: res.status,
        code: first?.code ?? null,
        apiMessage,
        errors: data.errors ?? [],
      });
    }
    return data.result;
  }

  // ── Zone ──────────────────────────────────────────────────────────────────

  getZone(zoneId) {
    return this.#get(`/zones/${zoneId}`);
  }

  getZoneSetting(zoneId, setting) {
    return this.#get(`/zones/${zoneId}/settings/${setting}`);
  }

  getAllZoneSettings(zoneId) {
    return this.#get(`/zones/${zoneId}/settings`);
  }

  getDNSSEC(zoneId) {
    return this.#get(`/zones/${zoneId}/dnssec`);
  }

  /** @deprecated Legacy WAF packages API — prefer getManagedWAFEntrypoint. */
  getWAFPackages(zoneId) {
    return this.#get(`/zones/${zoneId}/firewall/waf/packages`);
  }

  /**
   * Managed WAF phase entrypoint (Cloudflare Managed + OWASP CRS execute rules).
   * GET /zones/{id}/rulesets/phases/http_request_firewall_managed/entrypoint
   */
  getManagedWAFEntrypoint(zoneId) {
    return this.#get(`/zones/${zoneId}/rulesets/phases/http_request_firewall_managed/entrypoint`);
  }

  /**
   * Current rate limiting rules via the http_ratelimit phase entrypoint ruleset.
   * Replaces the retired GET /zones/{id}/rate_limits (HTTP 410).
   */
  getRateLimitEntrypoint(zoneId) {
    return this.#get(`/zones/${zoneId}/rulesets/phases/http_ratelimit/entrypoint`);
  }

  /** @deprecated Retired by Cloudflare — kept only for tests of the error path. */
  getRateLimitRules(zoneId) {
    return this.#get(`/zones/${zoneId}/rate_limits`);
  }

  getBotManagement(zoneId) {
    return this.#get(`/zones/${zoneId}/bot_management`);
  }

  getFirewallRules(zoneId) {
    return this.#get(`/zones/${zoneId}/firewall/rules`);
  }

  // ── Account ───────────────────────────────────────────────────────────────

  listZones(accountId) {
    return this.#get(`/zones?account.id=${accountId}&per_page=50`);
  }

  listWorkers(accountId) {
    return this.#get(`/accounts/${accountId}/workers/scripts`);
  }

  /** Script settings including bindings (plain_text, secret_text, kv, etc.). */
  getWorkerSettings(accountId, scriptName) {
    return this.#get(`/accounts/${accountId}/workers/scripts/${encodeURIComponent(scriptName)}/settings`);
  }

  getWorkerMeta(accountId, scriptName) {
    return this.#get(`/accounts/${accountId}/workers/scripts/${encodeURIComponent(scriptName)}/deployments`);
  }

  /** Zone-level Worker routes (pattern → script). */
  listWorkerRoutes(zoneId) {
    return this.#get(`/zones/${zoneId}/workers/routes`);
  }

  // ── Observability ─────────────────────────────────────────────────────────

  getPageShield(zoneId) {
    return this.#get(`/zones/${zoneId}/page_shield`);
  }

  getLogpushJobs(zoneId) {
    return this.#get(`/zones/${zoneId}/logpush/jobs`);
  }

  getAccountLogpushJobs(accountId) {
    return this.#get(`/accounts/${accountId}/logpush/jobs`);
  }

  // ── Zero Trust / Access ───────────────────────────────────────────────────

  listAccessApps(accountId) {
    return this.#get(`/accounts/${accountId}/access/apps`);
  }

  getAccessAppPolicy(accountId, appId) {
    return this.#get(`/accounts/${accountId}/access/apps/${appId}/policies`);
  }

  listIdentityProviders(accountId) {
    return this.#get(`/accounts/${accountId}/access/identity_providers`);
  }
}
