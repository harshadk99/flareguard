/**
 * Workers evaluator.
 * Uses script list + per-script settings (bindings) + zone routes for real signal.
 */
import { pass, fail, na, error, unevaluable } from '../finding.js';

const ZOMBIE_THRESHOLD_DAYS = 90;
const SECRET_PATTERNS = [
  /password/i, /secret/i, /token/i, /api[_-]?key/i, /credential/i,
  /auth/i, /private[_-]?key/i, /client[_-]?secret/i,
];

export async function evaluateWorkers(check, api, zoneId, accountId) {
  if (!accountId) {
    return na(check, 'Account ID is required for Worker checks. Provide account_id in your request.');
  }

  let workers;
  try {
    workers = await api.listWorkers(accountId);
  } catch (err) {
    return unevaluable(check, err);
  }

  if (!Array.isArray(workers) || workers.length === 0) {
    return na(check, 'No Workers found for this account.');
  }

  if (check.id === 'WRK-001') return checkZombies(check, api, workers, zoneId);
  if (check.id === 'WRK-002') return checkSecrets(check, api, workers, accountId);
  return na(check, `Worker check ${check.id} not implemented.`);
}

async function checkZombies(check, api, workers, zoneId) {
  let routed = new Set();
  let routesAvailable = false;

  if (zoneId) {
    try {
      const routes = await api.listWorkerRoutes(zoneId);
      routesAvailable = true;
      for (const r of routes ?? []) {
        if (r.script) routed.add(r.script);
      }
    } catch (err) {
      // Permission on routes — still evaluate staleness, but note limited visibility
      if (err?.kind === 'permission' || err?.kind === 'auth') {
        return unevaluable(check, err);
      }
    }
  }

  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - ZOMBIE_THRESHOLD_DAYS);

  const zombies = workers.filter(w => {
    const name = w.id ?? w.script ?? w.script_name;
    const lastModified = w.modified_on ? new Date(w.modified_on) : null;
    const isStale = !lastModified || lastModified < cutoff;
    if (!isStale) return false;
    if (routesAvailable) return !routed.has(name);
    // Without route data, only flag scripts with empty/missing handlers and stale mtime
    const handlers = w.handlers ?? w.usage_model;
    return !handlers || (Array.isArray(handlers) && handlers.length === 0);
  });

  if (zombies.length === 0) {
    const routeNote = routesAvailable
      ? ` Cross-checked ${routed.size} route(s) on this zone.`
      : ' (zone routes unavailable — used script metadata only).';
    return pass(check, `No zombie workers among ${workers.length} script(s).${routeNote}`);
  }

  const names = zombies.map(w => w.id ?? w.script_name ?? 'unknown').slice(0, 10).join(', ');
  const extra = zombies.length > 10 ? ` (+${zombies.length - 10} more)` : '';
  return fail(
    check,
    `${zombies.length} zombie worker(s) (stale ≥${ZOMBIE_THRESHOLD_DAYS}d` +
      `${routesAvailable ? ', no routes on this zone' : ''}): ${names}${extra}`
  );
}

async function checkSecrets(check, api, workers, accountId) {
  const flagged = [];
  // Cap concurrent settings fetches to avoid blowing subrequest limits on large accounts
  const batch = workers.slice(0, 40);
  const results = await Promise.allSettled(
    batch.map(w => {
      const name = w.id ?? w.script ?? w.script_name;
      return api.getWorkerSettings(accountId, name).then(settings => ({ name, settings }));
    })
  );

  let fetched = 0;
  let permissionErrors = 0;
  for (const outcome of results) {
    if (outcome.status === 'rejected') {
      permissionErrors += 1;
      continue;
    }
    fetched += 1;
    const { name, settings } = outcome.value;
    const bindings = settings?.bindings ?? [];
    const plain = bindings.filter(b => b.type === 'plain_text' || b.type === 'plain-text');
    const suspicious = plain
      .map(b => b.name)
      .filter(n => n && SECRET_PATTERNS.some(p => p.test(n)));
    if (suspicious.length > 0) {
      flagged.push(`${name}: [${suspicious.join(', ')}]`);
    }
  }

  if (fetched === 0 && permissionErrors > 0) {
    return error(
      check,
      'Token lacks permission for this check. Required: Workers Scripts Read. Could not read Worker settings (bindings).'
    );
  }

  if (fetched === 0) {
    return na(check, 'Could not inspect Worker bindings for any script.');
  }

  if (flagged.length === 0) {
    const truncated = workers.length > batch.length
      ? ` (inspected first ${batch.length} of ${workers.length})`
      : '';
    return pass(check, `No plain-text secret-like bindings across ${fetched} worker(s)${truncated}.`);
  }
  return fail(check, `Potential secrets in plain-text bindings: ${flagged.join(' | ')}`);
}
