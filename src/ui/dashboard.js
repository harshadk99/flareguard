export function generateDashboard() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>FlareGuard — Cloudflare Security Posture Management</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --cf-orange: #f38020;
      --cf-yellow: #faad3f;
      --cf-dark:   #1d1d1d;
      --cf-gray:   #404041;
      --bg:        #f6f6f6;
      --card:      #ffffff;
      --pass:      #22c55e;
      --fail:      #ef4444;
      --warn:      #f59e0b;
      --na:        #94a3b8;
      --critical:  #7c3aed;
      --radius:    8px;
    }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: var(--bg); color: var(--cf-dark); line-height: 1.5; }

    /* Header */
    header { background: var(--cf-orange); color: #fff; padding: 1rem 2rem; display: flex; align-items: center; gap: 1rem; }
    header h1 { font-size: 1.4rem; font-weight: 700; letter-spacing: -0.5px; }
    header p  { font-size: 0.85rem; opacity: 0.85; }
    .header-badge { margin-left: auto; background: rgba(255,255,255,0.2); border-radius: 4px; padding: 0.25rem 0.75rem; font-size: 0.75rem; }

    /* Layout */
    .container { max-width: 1100px; margin: 2rem auto; padding: 0 1.5rem; }
    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }
    @media (max-width: 700px) { .grid-2 { grid-template-columns: 1fr; } }

    /* Cards */
    .card { background: var(--card); border-radius: var(--radius); box-shadow: 0 1px 4px rgba(0,0,0,.08); padding: 1.5rem; }
    .card h2 { font-size: 1rem; color: var(--cf-gray); margin-bottom: 1rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }

    /* Form */
    .form-group { margin-bottom: 1rem; }
    label { display: block; font-size: 0.85rem; font-weight: 600; margin-bottom: 0.35rem; color: var(--cf-gray); }
    input[type=text], input[type=password] {
      width: 100%; padding: 0.55rem 0.75rem; border: 1px solid #ddd; border-radius: 6px;
      font-size: 0.9rem; outline: none; transition: border-color 0.2s;
    }
    input:focus { border-color: var(--cf-orange); }
    .hint { font-size: 0.75rem; color: #888; margin-top: 0.25rem; }
    .btn-row { display: flex; gap: 0.75rem; margin-top: 1.25rem; flex-wrap: wrap; }
    .btn { padding: 0.55rem 1.25rem; border: none; border-radius: 6px; cursor: pointer; font-size: 0.9rem; font-weight: 600; transition: opacity 0.2s; }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .btn-primary { background: var(--cf-orange); color: #fff; }
    .btn-secondary { background: var(--cf-dark); color: #fff; }
    .btn-outline { background: transparent; border: 1.5px solid var(--cf-orange); color: var(--cf-orange); }
    .btn:not(:disabled):hover { opacity: 0.85; }

    /* Tabs */
    .tabs { display: flex; gap: 0; border-bottom: 2px solid #e5e7eb; margin-bottom: 1.5rem; }
    .tab { padding: 0.6rem 1.25rem; cursor: pointer; font-size: 0.9rem; font-weight: 600; color: #888; border-bottom: 2.5px solid transparent; margin-bottom: -2px; background: none; border-left: none; border-right: none; border-top: none; }
    .tab.active { color: var(--cf-orange); border-bottom-color: var(--cf-orange); }
    .tab-panel { display: none; }
    .tab-panel.active { display: block; }

    /* Score circle */
    .score-ring { width: 110px; height: 110px; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 1rem; font-size: 1.8rem; font-weight: 800; color: #fff; }

    /* Stat grid */
    .stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.75rem; margin-bottom: 1.5rem; }
    @media (max-width: 600px) { .stat-grid { grid-template-columns: repeat(2, 1fr); } }
    .stat { background: var(--bg); border-radius: 6px; padding: 0.75rem; text-align: center; }
    .stat-val { font-size: 1.6rem; font-weight: 800; }
    .stat-lbl { font-size: 0.7rem; color: #888; text-transform: uppercase; letter-spacing: 0.5px; }
    .c-pass { color: var(--pass); }
    .c-fail { color: var(--fail); }
    .c-warn { color: var(--warn); }
    .c-na   { color: var(--na); }

    /* Finding cards */
    .finding { border-left: 4px solid #ddd; padding: 0.9rem 1rem; margin-bottom: 0.75rem; background: var(--bg); border-radius: 0 6px 6px 0; }
    .finding.PASS    { border-left-color: var(--pass); }
    .finding.FAIL    { border-left-color: var(--fail); }
    .finding.WARNING { border-left-color: var(--warn); }
    .finding.NA      { border-left-color: var(--na); }
    .finding-header { display: flex; justify-content: space-between; align-items: flex-start; gap: 0.5rem; margin-bottom: 0.3rem; }
    .finding-title { font-size: 0.9rem; font-weight: 600; }
    .badges { display: flex; gap: 0.4rem; flex-wrap: wrap; }
    .badge { font-size: 0.65rem; font-weight: 700; padding: 0.15rem 0.5rem; border-radius: 4px; text-transform: uppercase; color: #fff; }
    .badge-CRITICAL { background: var(--critical); }
    .badge-HIGH     { background: var(--fail); }
    .badge-MEDIUM   { background: var(--warn); }
    .badge-LOW      { background: #3b82f6; }
    .badge-PASS     { background: var(--pass); }
    .badge-FAIL     { background: var(--fail); }
    .badge-WARNING  { background: var(--warn); }
    .badge-NA       { background: var(--na); }
    .finding-msg { font-size: 0.82rem; color: #555; margin-bottom: 0.25rem; }
    .finding-remediation { font-size: 0.8rem; color: var(--fail); background: #fff5f5; padding: 0.35rem 0.6rem; border-radius: 4px; margin-top: 0.35rem; }
    .finding-nist { font-size: 0.7rem; color: #888; margin-top: 0.25rem; }

    /* Filters */
    .filters { display: flex; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 1rem; }
    .filter-btn { padding: 0.3rem 0.8rem; border-radius: 20px; border: 1.5px solid #ddd; background: none; cursor: pointer; font-size: 0.8rem; font-weight: 600; }
    .filter-btn.active { background: var(--cf-dark); color: #fff; border-color: var(--cf-dark); }

    /* History table */
    table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
    th { text-align: left; padding: 0.5rem 0.75rem; background: var(--bg); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.4px; color: #888; }
    td { padding: 0.5rem 0.75rem; border-bottom: 1px solid #f0f0f0; }
    tr:hover td { background: #fafafa; }
    .score-pill { display: inline-block; padding: 0.15rem 0.6rem; border-radius: 12px; font-weight: 700; font-size: 0.8rem; color: #fff; }

    /* Alert */
    .alert { padding: 0.75rem 1rem; border-radius: 6px; margin-bottom: 1rem; font-size: 0.875rem; }
    .alert-success { background: #f0fdf4; border-left: 4px solid var(--pass); color: #166534; }
    .alert-error   { background: #fef2f2; border-left: 4px solid var(--fail); color: #991b1b; }
    .alert-info    { background: #eff6ff; border-left: 4px solid #3b82f6; color: #1e40af; }

    /* Spinner */
    .spinner { display: none; margin: 2rem auto; width: 40px; height: 40px; border: 4px solid #eee; border-top-color: var(--cf-orange); border-radius: 50%; animation: spin 0.8s linear infinite; }
    @keyframes spin { to { transform: rotate(360deg); } }

    /* Drift */
    .drift-change { display: flex; align-items: center; gap: 0.75rem; padding: 0.6rem; background: var(--bg); border-radius: 6px; margin-bottom: 0.5rem; font-size: 0.85rem; }
    .arrow { font-weight: 700; }

    footer { text-align: center; padding: 2rem; color: #aaa; font-size: 0.78rem; margin-top: 3rem; border-top: 1px solid #e5e7eb; }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>FlareGuard</h1>
      <p>Cloudflare Security Posture Management</p>
    </div>
    <span class="header-badge">v2.0 — Full Stack</span>
  </header>

  <div class="container">
    <!-- Tabs -->
    <div class="tabs">
      <button class="tab active" data-tab="scan">Zone Scan</button>
      <button class="tab" data-tab="account">Account Scan</button>
      <button class="tab" data-tab="history">Audit History</button>
      <button class="tab" data-tab="drift">Drift Detection</button>
    </div>

    <!-- ── Tab: Zone Scan ─────────────────────────────────────────────────── -->
    <div class="tab-panel active" id="tab-scan">
      <div class="grid-2">
        <div class="card">
          <h2>Zone Audit</h2>
          <div id="scan-alert" class="alert" style="display:none"></div>
          <div class="form-group">
            <label>Cloudflare Zone ID</label>
            <input type="text" id="zone-id" placeholder="e.g. abc123…" maxlength="32" />
          </div>
          <div class="form-group">
            <label>API Token</label>
            <input type="password" id="api-token" placeholder="Your Cloudflare API Token" />
            <p class="hint">Needs: Zone Read, SSL Read, WAF Read, DNS Read</p>
          </div>
          <div class="form-group">
            <label>Account ID <span style="font-weight:400;color:#aaa">(optional — enables Zero Trust & Worker checks)</span></label>
            <input type="text" id="account-id" placeholder="e.g. abc123…" maxlength="32" />
          </div>
          <div class="btn-row">
            <button class="btn btn-secondary" id="btn-test">Test Connection</button>
            <button class="btn btn-primary" id="btn-audit">Run Audit</button>
          </div>
          <div class="spinner" id="scan-spinner"></div>
        </div>

        <div class="card" id="score-card" style="display:none">
          <h2>Security Score</h2>
          <div class="score-ring" id="score-ring">—</div>
          <div class="stat-grid" id="stat-grid"></div>
          <button class="btn btn-outline" id="btn-download" style="width:100%">Download JSON Report</button>
        </div>
      </div>

      <!-- Findings -->
      <div class="card" id="findings-card" style="display:none; margin-top:1.5rem">
        <h2>Findings</h2>
        <div class="filters">
          <button class="filter-btn active" data-filter="ALL">All</button>
          <button class="filter-btn" data-filter="FAIL">Failures</button>
          <button class="filter-btn" data-filter="WARNING">Warnings</button>
          <button class="filter-btn" data-filter="PASS">Passed</button>
          <button class="filter-btn" data-filter="NA">N/A</button>
        </div>
        <div id="findings-list"></div>
      </div>
    </div>

    <!-- ── Tab: Account Scan ──────────────────────────────────────────────── -->
    <div class="tab-panel" id="tab-account">
      <div class="card">
        <h2>Account-Wide Scan</h2>
        <p style="font-size:0.875rem;color:#555;margin-bottom:1rem">Scans all zones in your account. Jobs are enqueued asynchronously — results appear in Audit History.</p>
        <div id="account-alert" class="alert" style="display:none"></div>
        <div class="form-group">
          <label>Account ID</label>
          <input type="text" id="acc-account-id" placeholder="Your Cloudflare Account ID" maxlength="32" />
        </div>
        <div class="form-group">
          <label>API Token</label>
          <input type="password" id="acc-api-token" placeholder="Your Cloudflare API Token" />
          <p class="hint">Needs: Zone Read (all zones), Account Read</p>
        </div>
        <div class="btn-row">
          <button class="btn btn-primary" id="btn-account-scan">Scan All Zones</button>
        </div>
        <div class="spinner" id="account-spinner"></div>
      </div>
    </div>

    <!-- ── Tab: History ───────────────────────────────────────────────────── -->
    <div class="tab-panel" id="tab-history">
      <div class="card">
        <h2>Audit History</h2>
        <div class="form-group" style="display:flex;gap:0.75rem;align-items:flex-end">
          <div style="flex:1">
            <label>Zone ID</label>
            <input type="text" id="hist-zone-id" placeholder="Zone ID to look up" maxlength="32" />
          </div>
          <button class="btn btn-primary" id="btn-history" style="margin-bottom:0">Load</button>
        </div>
        <div id="history-content" style="margin-top:1rem">
          <p style="color:#aaa;font-size:0.875rem">Enter a Zone ID and click Load to view scan history.</p>
        </div>
      </div>
    </div>

    <!-- ── Tab: Drift ─────────────────────────────────────────────────────── -->
    <div class="tab-panel" id="tab-drift">
      <div class="card">
        <h2>Drift Detection</h2>
        <p style="font-size:0.875rem;color:#555;margin-bottom:1rem">Compare the two most recent audits for a zone to see what changed.</p>
        <div class="form-group" style="display:flex;gap:0.75rem;align-items:flex-end">
          <div style="flex:1">
            <label>Zone ID</label>
            <input type="text" id="drift-zone-id" placeholder="Zone ID" maxlength="32" />
          </div>
          <button class="btn btn-primary" id="btn-drift" style="margin-bottom:0">Check Drift</button>
        </div>
        <div id="drift-content" style="margin-top:1rem">
          <p style="color:#aaa;font-size:0.875rem">Enter a Zone ID and click Check Drift.</p>
        </div>
      </div>
    </div>
  </div>

  <footer>
    FlareGuard is an independent open-source project. Not affiliated with or endorsed by Cloudflare, Inc.<br/>
    <a href="https://github.com/harshadk99/flareguard" style="color:var(--cf-orange)">GitHub</a>
  </footer>

<script>
// ── Tabs ─────────────────────────────────────────────────────────────────────
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
  });
});

// ── Helpers ──────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
function showAlert(elId, msg, type) {
  const el = $(elId);
  el.className = 'alert alert-' + type;
  el.textContent = msg;
  el.style.display = 'block';
}
function hideAlert(elId) { $(elId).style.display = 'none'; }
function scoreColor(s) { return s >= 90 ? 'var(--pass)' : s >= 70 ? 'var(--warn)' : 'var(--fail)'; }
function scoreRingStyle(s) { return 'background:' + scoreColor(s); }

// ── Test Connection ───────────────────────────────────────────────────────────
$('btn-test').addEventListener('click', async () => {
  hideAlert('scan-alert');
  const body = { zone_id: $('zone-id').value.trim(), api_token: $('api-token').value.trim() };
  if ($('account-id').value.trim()) body.account_id = $('account-id').value.trim();
  try {
    const res = await fetch('/api/test-connection', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) });
    const data = await res.json();
    showAlert('scan-alert', data.success ? '✓ ' + data.message : '✗ ' + (data.error ?? 'Connection failed'), data.success ? 'success' : 'error');
  } catch(e) { showAlert('scan-alert', '✗ ' + e.message, 'error'); }
});

// ── Zone Audit ───────────────────────────────────────────────────────────────
let _lastReport = null;
$('btn-audit').addEventListener('click', async () => {
  hideAlert('scan-alert');
  $('scan-spinner').style.display = 'block';
  $('score-card').style.display = 'none';
  $('findings-card').style.display = 'none';
  $('btn-audit').disabled = true;

  const body = { zone_id: $('zone-id').value.trim(), api_token: $('api-token').value.trim() };
  if ($('account-id').value.trim()) body.account_id = $('account-id').value.trim();

  try {
    const res = await fetch('/api/audit/zone', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) });
    const data = await res.json();
    if (data.error) { showAlert('scan-alert', '✗ ' + data.error, 'error'); return; }
    _lastReport = data;
    renderResults(data);
    $('score-card').style.display = 'block';
    $('findings-card').style.display = 'block';
  } catch(e) {
    showAlert('scan-alert', '✗ ' + e.message, 'error');
  } finally {
    $('scan-spinner').style.display = 'none';
    $('btn-audit').disabled = false;
  }
});

function renderResults(data) {
  const s = data.summary;
  const ring = $('score-ring');
  ring.textContent = s.score + '%';
  ring.style = scoreRingStyle(s.score);

  $('stat-grid').innerHTML = [
    ['Total',    s.total_checks, ''],
    ['Passed',   s.passed,  'c-pass'],
    ['Failed',   s.failed,  'c-fail'],
    ['Warnings', s.warnings,'c-warn'],
  ].map(([l,v,c]) => \`<div class="stat"><div class="stat-val \${c}">\${v}</div><div class="stat-lbl">\${l}</div></div>\`).join('');

  renderFindings(data.findings, 'ALL');
}

function renderFindings(findings, filter) {
  const shown = filter === 'ALL' ? findings : findings.filter(f => f.status === filter);
  $('findings-list').innerHTML = shown.map(f => \`
    <div class="finding \${f.status}">
      <div class="finding-header">
        <span class="finding-title">\${f.id}: \${f.name}</span>
        <div class="badges">
          <span class="badge badge-\${f.severity}">\${f.severity}</span>
          <span class="badge badge-\${f.status}">\${f.status}</span>
        </div>
      </div>
      <div class="finding-msg">\${f.message ?? ''}</div>
      \${f.remediation ? \`<div class="finding-remediation">⚠ \${f.remediation}</div>\` : ''}
      \${f.nist_controls?.length ? \`<div class="finding-nist">NIST: \${f.nist_controls.join(', ')}</div>\` : ''}
    </div>
  \`).join('') || '<p style="color:#aaa">No findings match this filter.</p>';
}

// Filters
document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    if (_lastReport) renderFindings(_lastReport.findings, btn.dataset.filter);
  });
});

// Download
$('btn-download').addEventListener('click', () => {
  if (!_lastReport) return;
  const blob = new Blob([JSON.stringify(_lastReport, null, 2)], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'flareguard-' + (_lastReport.zone_id ?? 'report') + '.json';
  a.click();
});

// ── Account Scan ─────────────────────────────────────────────────────────────
$('btn-account-scan').addEventListener('click', async () => {
  hideAlert('account-alert');
  $('account-spinner').style.display = 'block';
  $('btn-account-scan').disabled = true;
  const body = { account_id: $('acc-account-id').value.trim(), api_token: $('acc-api-token').value.trim() };
  try {
    const res = await fetch('/api/audit/account', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) });
    const data = await res.json();
    if (data.error) { showAlert('account-alert', '✗ ' + data.error, 'error'); return; }
    const msg = data.queued
      ? \`✓ \${data.zone_count} zone(s) queued for scanning. Check Audit History for results.\`
      : \`✓ Account scan complete. \${data.zones?.length ?? 0} zone(s) scanned.\`;
    showAlert('account-alert', msg, 'success');
  } catch(e) {
    showAlert('account-alert', '✗ ' + e.message, 'error');
  } finally {
    $('account-spinner').style.display = 'none';
    $('btn-account-scan').disabled = false;
  }
});

// ── History ───────────────────────────────────────────────────────────────────
$('btn-history').addEventListener('click', async () => {
  const zoneId = $('hist-zone-id').value.trim();
  if (!zoneId) return;
  $('history-content').innerHTML = '<div class="spinner" style="display:block"></div>';
  try {
    const res = await fetch('/api/history/' + zoneId);
    const data = await res.json();
    if (data.error) { $('history-content').innerHTML = '<p style="color:var(--fail)">' + data.error + '</p>'; return; }
    if (!data.history?.length) { $('history-content').innerHTML = '<p style="color:#aaa">No audit history found for this zone.</p>'; return; }
    $('history-content').innerHTML = \`
      <table>
        <thead><tr><th>Date</th><th>Score</th><th>Passed</th><th>Failed</th><th>Warnings</th><th>Type</th></tr></thead>
        <tbody>\${data.history.map(h => \`
          <tr>
            <td>\${new Date(h.created_at).toLocaleString()}</td>
            <td><span class="score-pill" style="background:\${scoreColor(h.score)}">\${h.score}%</span></td>
            <td class="c-pass">\${h.passed}</td>
            <td class="c-fail">\${h.failed}</td>
            <td class="c-warn">\${h.warnings}</td>
            <td>\${h.scan_type}</td>
          </tr>
        \`).join('')}</tbody>
      </table>\`;
  } catch(e) { $('history-content').innerHTML = '<p style="color:var(--fail)">' + e.message + '</p>'; }
});

// ── Drift ─────────────────────────────────────────────────────────────────────
$('btn-drift').addEventListener('click', async () => {
  const zoneId = $('drift-zone-id').value.trim();
  if (!zoneId) return;
  $('drift-content').innerHTML = '<div class="spinner" style="display:block"></div>';
  try {
    const res = await fetch('/api/drift/' + zoneId);
    const data = await res.json();
    if (data.error) { $('drift-content').innerHTML = '<p style="color:var(--fail)">' + data.error + '</p>'; return; }
    if (!data.changes?.length) {
      $('drift-content').innerHTML = \`<div class="alert alert-success">No drift detected between the two most recent audits. \${data.message ?? ''}</div>\`;
      return;
    }
    const statusColor = { PASS: 'var(--pass)', FAIL: 'var(--fail)', WARNING: 'var(--warn)', NA: 'var(--na)' };
    $('drift-content').innerHTML = \`
      <div class="alert alert-info">\${data.changes.length} change(s) detected between the two most recent audits.</div>
      \${data.changes.map(c => \`
        <div class="drift-change">
          <strong>\${c.check_id}</strong>
          <span>\${c.check_name}</span>
          <span class="arrow">
            <span style="color:\${statusColor[c.from]}">\${c.from}</span>
            →
            <span style="color:\${statusColor[c.to]}">\${c.to}</span>
          </span>
        </div>
      \`).join('')}\`;
  } catch(e) { $('drift-content').innerHTML = '<p style="color:var(--fail)">' + e.message + '</p>'; }
});
</script>
</body>
</html>`;
}
