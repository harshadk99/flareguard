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
import { generateLanding } from './ui/landing.js';

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

    // ── UI ──────────────────────────────────────────────────────────────────
    const HTML_HEADERS = {
      'Content-Type': 'text/html; charset=utf-8',
      // Prevent MIME-type sniffing
      'X-Content-Type-Options': 'nosniff',
      // Block clickjacking
      'X-Frame-Options': 'DENY',
      // Prevent referrer leakage of credentials
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      // Minimal CSP: no external scripts, inline styles only (dashboard uses inline JS)
      'Content-Security-Policy': [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline'",   // inline JS in generated HTML (no CDN)
        "style-src 'self' 'unsafe-inline'",    // inline styles
        "img-src 'self' data: https://img.shields.io",
        "connect-src 'self' https://api.cloudflare.com",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
      ].join('; '),
      // Disable browser features not needed by the tool
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    };

    if (pathname === '/' || pathname === '/index.html') {
      return new Response(generateLanding(), { headers: HTML_HEADERS });
    }
    if (pathname === '/audit') {
      return new Response(generateDashboard(), { headers: HTML_HEADERS });
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
