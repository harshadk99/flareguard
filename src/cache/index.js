/**
 * KV-backed cache for Cloudflare API responses.
 * Falls through gracefully when KV is not bound (e.g. during local dev without --local).
 */
export class Cache {
  constructor(kv, ttlSeconds = 300) {
    this.kv = kv;
    this.ttl = ttlSeconds;
  }

  async get(key) {
    if (!this.kv) return null;
    try {
      const raw = await this.kv.get(key, 'json');
      return raw ?? null;
    } catch {
      return null;
    }
  }

  async set(key, value) {
    if (!this.kv) return;
    try {
      await this.kv.put(key, JSON.stringify(value), { expirationTtl: this.ttl });
    } catch {
      // Cache write failures are non-fatal
    }
  }

  async delete(key) {
    if (!this.kv) return;
    try { await this.kv.delete(key); } catch {}
  }

  /** Cache key helpers */
  static zoneKey(zoneId, setting) { return `zone:${zoneId}:${setting}`; }
  static workerListKey(accountId) { return `workers:${accountId}`; }
  static accessAppsKey(accountId) { return `access-apps:${accountId}`; }
}
