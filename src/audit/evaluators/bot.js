export async function evaluateBot(check, api, zoneId) {
  let bot;
  try {
    bot = await api.getBotManagement(zoneId);
  } catch {
    // Bot Management requires Business/Enterprise — fall back to checking fight mode via zone settings
    try {
      const setting = await api.getZoneSetting(zoneId, 'bot_fight_mode');
      const enabled = setting?.value === 'on';
      return enabled
        ? pass_(check, 'Bot Fight Mode is enabled (free tier).')
        : fail(check, 'Neither Bot Fight Mode nor Bot Management is enabled.');
    } catch {
      return na(check, 'Bot management settings are not available for this zone plan.');
    }
  }

  const enabled = bot?.enable_js === true || bot?.fight_mode === true || bot?.sbfm_definitely_automated === 'block';
  if (enabled) return pass_(check, `Bot Management is enabled (mode: ${bot?.optimization_target ?? 'configured'}).`);
  return fail(check, 'Bot Management is configured but not actively blocking bots.');
}

function pass_(check, message) { return r(check, 'PASS', message); }
function fail(check, message) { return r(check, 'FAIL', message, check.remediation); }
function na(check, message) { return r(check, 'NA', message); }
function r(check, status, message, remediation) {
  return { id: check.id, name: check.name, category: check.category, service: check.service, severity: check.severity, nist_controls: check.nist_controls ?? [], status, message, remediation: status === 'FAIL' ? remediation : null };
}
