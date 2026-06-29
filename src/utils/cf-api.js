/**
 * Thin wrapper around the Cloudflare API.
 * All methods throw on non-2xx responses with a structured error.
 */
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
    const data = await res.json();
    if (!res.ok || !data.success) {
      const msg = data.errors?.[0]?.message ?? `HTTP ${res.status}`;
      throw new Error(`Cloudflare API error on ${path}: ${msg}`);
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

  getWAFPackages(zoneId) {
    return this.#get(`/zones/${zoneId}/firewall/waf/packages`);
  }

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

  getWorkerMeta(accountId, scriptName) {
    return this.#get(`/accounts/${accountId}/workers/scripts/${scriptName}/deployments`);
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
