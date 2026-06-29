import { runZoneAudit } from '../audit/engine.js';
import { saveAudit, setReportKey } from '../db/index.js';
import { ReportStorage } from '../storage/index.js';
import { Cache } from '../cache/index.js';

/**
 * Enqueue a zone scan job.
 * Called from the API when a user triggers an account-wide scan.
 */
export async function enqueueZoneScan(queue, zoneId, apiToken, accountId) {
  await queue.send({ zoneId, apiToken, accountId, enqueuedAt: new Date().toISOString() });
}

/**
 * Queue consumer — called by the Workers runtime for each batch.
 * Wrangler wires this up via the `queue` export in src/index.js.
 */
export async function processQueue(batch, env) {
  const cache = new Cache(env.CACHE, Number(env.CACHE_TTL_SECONDS ?? 300));
  const storage = new ReportStorage(env.REPORTS);

  for (const msg of batch.messages) {
    const { zoneId, apiToken, accountId } = msg.body;
    try {
      const report = await runZoneAudit(zoneId, apiToken, accountId, env, cache);
      const auditId = await saveAudit(env.DB, report, 'zone');
      const r2Key = await storage.saveReport(auditId, report);
      if (r2Key) await setReportKey(env.DB, auditId, r2Key);
      msg.ack();
    } catch (err) {
      console.error(`Queue job failed for zone ${zoneId}:`, err.message);
      msg.retry();
    }
  }
}
