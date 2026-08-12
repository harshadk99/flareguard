import { pass, fail, unevaluable } from '../finding.js';

export async function evaluateBot(check, api, zoneId) {
  let bot;
  try {
    bot = await api.getBotManagement(zoneId);
  } catch (primaryErr) {
    // Bot Management requires Business/Enterprise — fall back to Bot Fight Mode setting
    try {
      const setting = await api.getZoneSetting(zoneId, 'bot_fight_mode');
      const enabled = setting?.value === 'on';
      return enabled
        ? pass(check, 'Bot Fight Mode is enabled (free tier).')
        : fail(check, 'Neither Bot Fight Mode nor Bot Management is enabled.');
    } catch (fallbackErr) {
      // Prefer the more specific permission/auth signal from whichever call failed that way
      const prefer = [fallbackErr, primaryErr].find(e => e?.kind === 'permission' || e?.kind === 'auth');
      return unevaluable(check, prefer ?? fallbackErr ?? primaryErr);
    }
  }

  const enabled = bot?.enable_js === true || bot?.fight_mode === true || bot?.sbfm_definitely_automated === 'block';
  if (enabled) return pass(check, `Bot Management is enabled (mode: ${bot?.optimization_target ?? 'configured'}).`);
  return fail(check, 'Bot Management is configured but not actively blocking bots.');
}
