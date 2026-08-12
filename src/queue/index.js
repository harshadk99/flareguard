import { runZoneAudit } from '../audit/engine.js';
import { saveAudit, setReportKey, hasDB } from '../db/index.js';
import { ReportStorage } from '../storage/index.js';
import { Cache } from '../cache/index.js';
import { hashId } from '../utils/privacy.js';

/**
 * Enqueue a zone scan job.
 *
 * SECURITY: The API token is deliberately excluded from the queue message.
 * Queue messages are persisted briefly by the Cloudflare runtime and are
 * visible in the Cloudflare dashboard. Tokens must never be stored there.
 *
 * The queue consumer uses CF_API_TOKEN — a Worker secret set via
 * `wrangler secret put CF_API_TOKEN` — to authenticate API calls.
 * Account-wide scans require a pre-configured service token, not user tokens.
 */
export async function enqueueZoneScan(queue, zoneId, accountId) {
  await queue.send({ zoneId, accountId, enqueuedAt: new Date().toISOString() });
}

/**
 * Queue consumer — called by the Workers runtime for each batch.
 * Wrangler wires this up via the `queue` export in src/index.js.
 *
 * Uses CF_API_TOKEN service secret (not user-supplied tokens).
 */
export async function processQueue(batch, env) {
  const serviceToken = env.CF_API_TOKEN;
  if (!serviceToken) {
    console.error('CF_API_TOKEN secret is not set — aborting queue batch. Run: wrangler secret put CF_API_TOKEN');
    for (const msg of batch.messages) msg.ack(); // don't retry a misconfiguration loop
    return;
  }

  const cache = new Cache(env.CACHE, Number(env.CACHE_TTL_SECONDS ?? 300));
  const storage = new ReportStorage(env.REPORTS);

  for (const msg of batch.messages) {
    const { zoneId, accountId } = msg.body;
    const zoneIdHash = await hashId(zoneId).catch(() => '[hash-error]');

    try {
      const report = await runZoneAudit(zoneId, serviceToken, accountId ?? null, env, cache);

      if (hasDB(env)) {
        const auditId = await saveAudit(env, report, 'zone'); // env, not env.DB
        if (env.REPORTS && auditId) {
          const r2Key = await storage.saveReport(auditId, report);
          if (r2Key) await setReportKey(env, auditId, r2Key);
        }
      }

      msg.ack();
    } catch (e) {
      // Log only the hashed zone ID — never the raw ID
      console.error(`Queue job failed for zone [${zoneIdHash}]:`, e.message);
      msg.retry();
    }
  }
}
