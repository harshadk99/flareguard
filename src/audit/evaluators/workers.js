// Days without deployment before a worker is considered a zombie
const ZOMBIE_THRESHOLD_DAYS = 90;
// Env var name patterns that suggest secrets stored in plain text
const SECRET_PATTERNS = [/password/i, /secret/i, /token/i, /key/i, /api_key/i, /credential/i, /auth/i, /private/i];

export async function evaluateWorkers(check, api, _zoneId, accountId) {
  if (!accountId) {
    return na(check, 'Account ID is required for Worker checks. Provide account_id in your request.');
  }

  let workers;
  try {
    workers = await api.listWorkers(accountId);
  } catch (err) {
    return na(check, `Could not list workers: ${err.message}`);
  }

  if (!Array.isArray(workers) || workers.length === 0) {
    return na(check, 'No Workers found for this account.');
  }

  if (check.id === 'WRK-001') return checkZombies(check, workers);
  if (check.id === 'WRK-002') return checkSecrets(check, workers);
  return na(check, `Worker check ${check.id} not implemented.`);
}

function checkZombies(check, workers) {
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - ZOMBIE_THRESHOLD_DAYS);

  const zombies = workers.filter(w => {
    const lastModified = w.modified_on ? new Date(w.modified_on) : null;
    const hasRoutes = Array.isArray(w.routes) && w.routes.length > 0;
    const isStale = !lastModified || lastModified < cutoff;
    // Zombie = stale AND no routes (orphaned script)
    return isStale && !hasRoutes;
  });

  if (zombies.length === 0) {
    return pass_(check, `No zombie workers detected among ${workers.length} script(s). All scripts are either recently updated or have active routes.`);
  }

  const names = zombies.map(w => w.id ?? w.script_name ?? 'unknown').join(', ');
  return fail(check, `${zombies.length} zombie worker(s) detected (no routes, not updated in ${ZOMBIE_THRESHOLD_DAYS}+ days): ${names}`);
}

function checkSecrets(check, workers) {
  const flagged = [];
  for (const w of workers) {
    const envKeys = Object.keys(w.bindings?.filter?.(b => b.type === 'plain_text').reduce((acc, b) => { acc[b.name] = true; return acc; }, {}) ?? {});
    const suspicious = envKeys.filter(k => SECRET_PATTERNS.some(p => p.test(k)));
    if (suspicious.length > 0) {
      flagged.push(`${w.id ?? w.script_name}: [${suspicious.join(', ')}]`);
    }
  }

  if (flagged.length === 0) {
    return pass_(check, `No plain-text environment variables with secret-like names found across ${workers.length} worker(s).`);
  }
  return fail(check, `Potential secrets in plain-text env vars: ${flagged.join(' | ')}`);
}

function pass_(check, message) { return r(check, 'PASS', message); }
function fail(check, message) { return r(check, 'FAIL', message, check.remediation); }
function na(check, message) { return r(check, 'NA', message); }
function r(check, status, message, remediation) {
  return { id: check.id, name: check.name, category: check.category, service: check.service, severity: check.severity, nist_controls: check.nist_controls ?? [], status, message, remediation: status === 'FAIL' ? remediation : null };
}
