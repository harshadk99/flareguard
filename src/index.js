import {
  handleZoneAudit,
  handleAccountAudit,
  handleTestConnection,
  handleHistory,
  handleAuditFindings,
  handleDrift,
  handleReportDownload,
  handleStatus,
} from './api/routes.js';
import { processQueue } from './queue/index.js';
import { generateDashboard } from './ui/dashboard.js';

export default {
  // ── HTTP handler ─────────────────────────────────────────────────────────────
  async fetch(request, env, _ctx) {
    const url = new URL(request.url);
    const { pathname, method } = { pathname: url.pathname, method: request.method };

    // CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
        },
      });
    }

    // ── API Routes ──────────────────────────────────────────────────────────
    if (pathname === '/api/audit/zone'    && method === 'POST') return handleZoneAudit(request, env);
    if (pathname === '/api/audit/account' && method === 'POST') return handleAccountAudit(request, env);
    if (pathname === '/api/test-connection' && method === 'POST') return handleTestConnection(request, env);

    if (pathname === '/api/status' && method === 'GET') return handleStatus(env);

    // GET /api/history/:zoneId
    const historyMatch = pathname.match(/^\/api\/history\/([a-f0-9]{32})$/i);
    if (historyMatch && method === 'GET') return handleHistory(historyMatch[1], env);

    // GET /api/audit/:auditId/findings
    const findingsMatch = pathname.match(/^\/api\/audit\/([^/]+)\/findings$/);
    if (findingsMatch && method === 'GET') return handleAuditFindings(findingsMatch[1], env);

    // GET /api/drift/:zoneId
    const driftMatch = pathname.match(/^\/api\/drift\/([a-f0-9]{32})$/i);
    if (driftMatch && method === 'GET') return handleDrift(driftMatch[1], env);

    // GET /api/report/:key
    const reportMatch = pathname.match(/^\/api\/report\/(.+)$/);
    if (reportMatch && method === 'GET') return handleReportDownload(reportMatch[1], env);

    // ── UI (served by Worker when Pages is not used) ────────────────────────
    if (pathname === '/' || pathname === '/index.html') {
      return new Response(generateDashboard(), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      });
    }

    return new Response(JSON.stringify({ error: 'Not found' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' },
    });
  },

  // ── Queue consumer ───────────────────────────────────────────────────────────
  async queue(batch, env) {
    return processQueue(batch, env);
  },
};
