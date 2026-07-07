export function generateDashboard() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>FlareGuard — Zone Audit</title>
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    :root{
      --orange:#f38020;--dark:#1d1d1d;--gray:#404041;
      --bg:#f6f6f6;--card:#ffffff;--border:#e5e7eb;
      --pass:#22c55e;--fail:#ef4444;--warn:#f59e0b;--na:#94a3b8;--critical:#7c3aed;
    }
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--dark);line-height:1.5}

    /* NAV */
    nav{background:var(--orange);color:#fff;padding:.75rem 2rem;display:flex;align-items:center;gap:1rem}
    nav a.logo{font-size:1.1rem;font-weight:800;color:#fff;text-decoration:none;letter-spacing:-.5px}
    nav a.back{margin-left:auto;color:rgba(255,255,255,.8);text-decoration:none;font-size:.85rem;display:flex;align-items:center;gap:.35rem}
    nav a.back:hover{color:#fff}
    nav .nav-sub{font-size:.8rem;opacity:.75}

    /* LAYOUT */
    .container{max-width:1100px;margin:2rem auto;padding:0 1.5rem}
    .grid-2{display:grid;grid-template-columns:1fr 1fr;gap:1.5rem}
    @media(max-width:700px){.grid-2{grid-template-columns:1fr}}

    /* CARDS */
    .card{background:var(--card);border-radius:10px;box-shadow:0 1px 4px rgba(0,0,0,.07);padding:1.5rem}
    .card-title{font-size:.75rem;color:#888;font-weight:700;text-transform:uppercase;letter-spacing:.06em;margin-bottom:1rem}

    /* FORM */
    .form-group{margin-bottom:1rem}
    label{display:block;font-size:.85rem;font-weight:600;margin-bottom:.35rem;color:var(--gray)}
    input[type=text],input[type=password]{width:100%;padding:.55rem .75rem;border:1.5px solid var(--border);border-radius:6px;font-size:.9rem;outline:none;transition:border-color .2s;background:#fff}
    input:focus{border-color:var(--orange)}
    .hint{font-size:.72rem;color:#aaa;margin-top:.25rem}
    .btn-row{display:flex;gap:.75rem;margin-top:1.25rem;flex-wrap:wrap}
    .btn{padding:.5rem 1.1rem;border:none;border-radius:6px;cursor:pointer;font-size:.875rem;font-weight:600;transition:opacity .2s}
    .btn:disabled{opacity:.45;cursor:not-allowed}
    .btn-primary{background:var(--orange);color:#fff}
    .btn-secondary{background:var(--dark);color:#fff}
    .btn-outline{background:transparent;border:1.5px solid var(--orange);color:var(--orange)}
    .btn:not(:disabled):hover{opacity:.85}

    /* TABS */
    .tabs{display:flex;gap:0;border-bottom:2px solid var(--border);margin-bottom:1.5rem}
    .tab{padding:.6rem 1.25rem;cursor:pointer;font-size:.875rem;font-weight:600;color:#888;border-bottom:2.5px solid transparent;margin-bottom:-2px;background:none;border-left:none;border-right:none;border-top:none}
    .tab.active{color:var(--orange);border-bottom-color:var(--orange)}
    .tab-panel{display:none}.tab-panel.active{display:block}

    /* SCORE */
    .score-ring{width:100px;height:100px;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto .75rem;font-size:1.7rem;font-weight:800;color:#fff}
    .zone-name{text-align:center;font-size:1rem;font-weight:700;margin-bottom:.25rem}
    .framework-ver{text-align:center;font-size:.68rem;color:#aaa;margin-bottom:1rem}
    .stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:.6rem;margin-bottom:1rem}
    @media(max-width:500px){.stat-grid{grid-template-columns:repeat(2,1fr)}}
    .stat{background:var(--bg);border-radius:6px;padding:.65rem .5rem;text-align:center}
    .stat-val{font-size:1.4rem;font-weight:800}
    .stat-lbl{font-size:.65rem;color:#888;text-transform:uppercase;letter-spacing:.04em}
    .c-pass{color:var(--pass)}.c-fail{color:var(--fail)}.c-warn{color:var(--warn)}.c-na{color:var(--na)}

    /* FILTERS */
    .filter-row{display:flex;gap:.4rem;flex-wrap:wrap;margin-bottom:1rem;align-items:center}
    .filter-group-label{font-size:.65rem;text-transform:uppercase;letter-spacing:.06em;color:#aaa;margin-right:.25rem;white-space:nowrap}
    .filter-btn{padding:.25rem .7rem;border-radius:20px;border:1.5px solid var(--border);background:none;cursor:pointer;font-size:.75rem;font-weight:600;color:#666;transition:all .15s;white-space:nowrap}
    .filter-btn.active{background:var(--dark);color:#fff;border-color:var(--dark)}
    .filter-btn.active.f-fail{background:var(--fail);border-color:var(--fail)}
    .filter-btn.active.f-pass{background:var(--pass);border-color:var(--pass)}
    .filter-btn.active.f-warn{background:var(--warn);border-color:var(--warn)}
    .filter-btn.active.f-cis{background:#3b82f6;border-color:#3b82f6}
    .filter-divider{width:1px;height:20px;background:var(--border);margin:0 .25rem}

    /* FINDINGS */
    .finding{border-left:4px solid #ddd;margin-bottom:.6rem;background:#fff;border-radius:0 8px 8px 0;box-shadow:0 1px 3px rgba(0,0,0,.05);overflow:hidden;transition:box-shadow .15s}
    .finding:hover{box-shadow:0 2px 8px rgba(0,0,0,.1)}
    .finding.PASS{border-left-color:var(--pass)}
    .finding.FAIL{border-left-color:var(--fail)}
    .finding.WARNING{border-left-color:var(--warn)}
    .finding.NA{border-left-color:var(--na)}
    .finding-main{padding:.8rem 1rem;cursor:pointer;display:flex;align-items:flex-start;gap:.75rem}
    .finding-badges{display:flex;flex-direction:column;gap:.3rem;align-items:center;min-width:52px;flex-shrink:0}
    .badge{font-size:.6rem;font-weight:700;padding:.15rem .45rem;border-radius:4px;text-transform:uppercase;color:#fff;text-align:center;width:100%}
    .badge-CRITICAL{background:var(--critical)}.badge-HIGH{background:var(--fail)}
    .badge-MEDIUM{background:var(--warn)}.badge-LOW{background:#3b82f6}
    .badge-PASS{background:var(--pass)}.badge-FAIL{background:var(--fail)}
    .badge-WARNING{background:var(--warn)}.badge-NA{background:var(--na)}
    .finding-body{flex:1;min-width:0}
    .finding-title{font-size:.875rem;font-weight:700;margin-bottom:.2rem;line-height:1.3}
    .finding-msg{font-size:.78rem;color:#555;margin-bottom:.3rem}
    .finding-tags{display:flex;gap:.35rem;flex-wrap:wrap}
    .tag{font-size:.65rem;color:#888;background:var(--bg);border:1px solid var(--border);padding:.1rem .4rem;border-radius:3px}
    .tag.tag-cis{color:#1d4ed8;background:#eff6ff;border-color:#bfdbfe}
    .finding-expand-icon{color:#aaa;font-size:.75rem;margin-left:auto;flex-shrink:0;padding-top:.1rem;transition:transform .2s}
    .finding.expanded .finding-expand-icon{transform:rotate(180deg)}

    /* EXPANDED CONTROLS */
    .finding-detail{display:none;padding:0 1rem .9rem 1rem;border-top:1px solid var(--border)}
    .finding.expanded .finding-detail{display:block}
    .detail-remediation{font-size:.78rem;color:var(--fail);background:#fff5f5;padding:.5rem .75rem;border-radius:6px;margin:.75rem 0;border-left:3px solid var(--fail)}
    .controls-section-title{font-size:.65rem;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:#aaa;margin:.75rem 0 .5rem}
    .controls-grid{display:grid;grid-template-columns:1fr 1fr;gap:.6rem}
    @media(max-width:600px){.controls-grid{grid-template-columns:1fr}}
    .control-card{background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:.75rem}
    .control-card.nist{border-left:3px solid #f38020}
    .control-card.cis{border-left:3px solid #3b82f6}
    .control-id{font-size:.7rem;font-weight:800;color:#888;margin-bottom:.2rem}
    .control-card.nist .control-id{color:var(--orange)}
    .control-card.cis .control-id{color:#3b82f6}
    .control-title{font-size:.8rem;font-weight:700;margin-bottom:.2rem;line-height:1.3}
    .control-family{font-size:.7rem;color:#888;margin-bottom:.4rem}
    .control-igs{display:flex;gap:.25rem;flex-wrap:wrap;margin-bottom:.4rem}
    .ig{font-size:.6rem;font-weight:700;padding:.1rem .35rem;border-radius:3px;background:#dbeafe;color:#1e40af}
    .control-link{font-size:.72rem;color:var(--orange);text-decoration:none}
    .control-link:hover{text-decoration:underline}

    /* ALERT */
    .alert{padding:.75rem 1rem;border-radius:6px;margin-bottom:1rem;font-size:.875rem}
    .alert-success{background:#f0fdf4;border-left:4px solid var(--pass);color:#166534}
    .alert-error{background:#fef2f2;border-left:4px solid var(--fail);color:#991b1b}
    .alert-info{background:#eff6ff;border-left:4px solid #3b82f6;color:#1e40af}

    /* SPINNER */
    .spinner{display:none;margin:2rem auto;width:36px;height:36px;border:3px solid #eee;border-top-color:var(--orange);border-radius:50%;animation:spin .7s linear infinite}
    @keyframes spin{to{transform:rotate(360deg)}}

    /* DRIFT */
    .drift-row{display:flex;align-items:center;gap:.75rem;padding:.6rem .75rem;background:var(--bg);border-radius:6px;margin-bottom:.5rem;font-size:.85rem}
    .drift-arrow{font-weight:800}

    /* HISTORY TABLE */
    table{width:100%;border-collapse:collapse;font-size:.85rem}
    th{text-align:left;padding:.5rem .75rem;background:var(--bg);font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;color:#888}
    td{padding:.5rem .75rem;border-bottom:1px solid #f0f0f0}
    tr:hover td{background:#fafafa}
    .score-pill{display:inline-block;padding:.15rem .6rem;border-radius:12px;font-weight:700;font-size:.8rem;color:#fff}

    footer{text-align:center;padding:2rem;color:#aaa;font-size:.75rem;margin-top:3rem;border-top:1px solid var(--border)}
    footer a{color:var(--orange);text-decoration:none}
  </style>
</head>
<body>
<nav>
  <div>
    <a class="logo" href="/">FlareGuard</a>
    <div class="nav-sub">Cloudflare Security Posture Management</div>
  </div>
  <a class="back" href="/">← Back to overview</a>
</nav>

<div class="container">
  <div class="tabs">
    <button class="tab active" data-tab="scan">Zone Audit</button>
    <button class="tab" data-tab="account">Account Scan</button>
    <button class="tab" data-tab="history">Audit History</button>
    <button class="tab" data-tab="drift">Drift Detection</button>
  </div>

  <!-- ── Zone Scan ─────────────────────────────────────────────────────────── -->
  <div class="tab-panel active" id="tab-scan">
    <div class="grid-2">
      <div class="card">
        <div class="card-title">Zone credentials</div>
        <div id="scan-alert" class="alert" style="display:none"></div>
        <div class="form-group">
          <label>Zone ID</label>
          <input type="text" id="zone-id" placeholder="32-character zone ID" maxlength="32"/>
        </div>
        <div class="form-group">
          <label>API Token</label>
          <input type="password" id="api-token" placeholder="Cloudflare API token"/>
          <p class="hint">Needs: Zone Read · SSL Read · WAF Read · DNS Read · Logs Read · Page Shield Read</p>
        </div>
        <div class="form-group">
          <label>Account ID <span style="font-weight:400;color:#bbb">(optional — enables Zero Trust, Workers, Logpush)</span></label>
          <input type="text" id="account-id" placeholder="32-character account ID" maxlength="32"/>
        </div>
        <div class="btn-row">
          <button class="btn btn-secondary" id="btn-test">Test Connection</button>
          <button class="btn btn-primary" id="btn-audit">Run Audit →</button>
        </div>
        <div class="spinner" id="scan-spinner"></div>
      </div>

      <div class="card" id="score-card" style="display:none">
        <div class="card-title">Security score</div>
        <div class="score-ring" id="score-ring">—</div>
        <div class="zone-name" id="zone-name"></div>
        <div class="framework-ver" id="framework-ver"></div>
        <div class="stat-grid" id="stat-grid"></div>
        <button class="btn btn-outline" id="btn-download" style="width:100%;margin-top:.25rem">Download JSON report</button>
      </div>
    </div>

    <!-- Findings -->
    <div class="card" id="findings-card" style="display:none;margin-top:1.5rem">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem;flex-wrap:wrap;gap:.5rem">
        <div class="card-title" style="margin-bottom:0">Findings <span id="findings-count" style="font-weight:400;color:#aaa"></span></div>
      </div>
      <div class="filter-row" id="status-filters">
        <span class="filter-group-label">Status</span>
        <button class="filter-btn active" data-filter="status" data-val="ALL">All</button>
        <button class="filter-btn f-fail" data-filter="status" data-val="FAIL">Fail</button>
        <button class="filter-btn f-warn" data-filter="status" data-val="WARNING">Warning</button>
        <button class="filter-btn f-pass" data-filter="status" data-val="PASS">Pass</button>
        <button class="filter-btn" data-filter="status" data-val="NA">N/A</button>
        <div class="filter-divider"></div>
        <span class="filter-group-label">CIS</span>
        <button class="filter-btn f-cis" data-filter="cis" data-val="CIS">CIS mapped</button>
      </div>
      <div class="filter-row" id="category-filters" style="margin-bottom:.75rem">
        <span class="filter-group-label">Category</span>
      </div>
      <div id="findings-list"></div>
    </div>
  </div>

  <!-- ── Account Scan ───────────────────────────────────────────────────────── -->
  <div class="tab-panel" id="tab-account">
    <div class="card">
      <div class="card-title">Account-wide scan</div>
      <p style="font-size:.875rem;color:#666;margin-bottom:1.25rem">Scans all zones in your account and returns a ranked risk summary — worst zones first.</p>
      <div id="account-alert" class="alert" style="display:none"></div>
      <div class="form-group">
        <label>Account ID</label>
        <input type="text" id="acc-account-id" placeholder="32-character account ID" maxlength="32"/>
      </div>
      <div class="form-group">
        <label>API Token</label>
        <input type="password" id="acc-api-token" placeholder="Cloudflare API token"/>
        <p class="hint">Needs: Zone Read (all zones) · Account Read</p>
      </div>
      <div class="btn-row">
        <button class="btn btn-primary" id="btn-account-scan">Scan All Zones →</button>
      </div>
      <div class="spinner" id="account-spinner"></div>
      <div id="account-results" style="margin-top:1.25rem"></div>
    </div>
  </div>

  <!-- ── History ────────────────────────────────────────────────────────────── -->
  <div class="tab-panel" id="tab-history">
    <div class="card">
      <div class="card-title">Audit history</div>
      <p style="font-size:.875rem;color:#666;margin-bottom:1rem">Score trend and persistent failures for a zone. Requires D1 persistent storage enabled on the worker.</p>
      <div class="form-group" style="display:flex;gap:.75rem;align-items:flex-end">
        <div style="flex:1"><label>Zone ID</label><input type="text" id="hist-zone-id" placeholder="32-character zone ID" maxlength="32"/></div>
        <button class="btn btn-primary" id="btn-history" style="margin-bottom:0">Load</button>
      </div>
      <div id="history-content" style="margin-top:1rem"><p style="color:#aaa;font-size:.875rem">Enter a Zone ID and click Load.</p></div>
    </div>
  </div>

  <!-- ── Drift ──────────────────────────────────────────────────────────────── -->
  <div class="tab-panel" id="tab-drift">
    <div class="card">
      <div class="card-title">Drift detection</div>
      <p style="font-size:.875rem;color:#666;margin-bottom:1rem">Compare the two most recent audits for a zone. Highlights every check that changed status. Requires D1 storage enabled.</p>
      <div class="form-group" style="display:flex;gap:.75rem;align-items:flex-end">
        <div style="flex:1"><label>Zone ID</label><input type="text" id="drift-zone-id" placeholder="32-character zone ID" maxlength="32"/></div>
        <button class="btn btn-primary" id="btn-drift" style="margin-bottom:0">Check Drift</button>
      </div>
      <div id="drift-content" style="margin-top:1rem"><p style="color:#aaa;font-size:.875rem">Enter a Zone ID and click Check Drift.</p></div>
    </div>
  </div>
</div>

<footer>
  <a href="/">FlareGuard</a> — Independent open-source project · Not affiliated with Cloudflare, Inc. ·
  <a href="https://github.com/harshadk99/flareguard" target="_blank">GitHub</a>
</footer>

<script>
// ── Helpers ───────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const scoreColor = s => s >= 90 ? 'var(--pass)' : s >= 70 ? 'var(--warn)' : 'var(--fail)';

function showAlert(id, msg, type) {
  const el = $(id); el.className = 'alert alert-' + type;
  el.textContent = msg; el.style.display = 'block';
}
function hideAlert(id) { $(id).style.display = 'none'; }

// ── Tabs ──────────────────────────────────────────────────────────────────────
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    $('tab-' + tab.dataset.tab).classList.add('active');
  });
});

// ── Test Connection ───────────────────────────────────────────────────────────
$('btn-test').addEventListener('click', async () => {
  hideAlert('scan-alert');
  const body = { zone_id: $('zone-id').value.trim(), api_token: $('api-token').value.trim() };
  if ($('account-id').value.trim()) body.account_id = $('account-id').value.trim();
  try {
    const res = await fetch('/api/test-connection', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body) });
    const data = await res.json();
    showAlert('scan-alert', data.success ? '✓ ' + data.message : '✗ ' + (data.error ?? 'Connection failed'), data.success ? 'success' : 'error');
  } catch(e) { showAlert('scan-alert', '✗ ' + e.message, 'error'); }
});

// ── Zone Audit ────────────────────────────────────────────────────────────────
let _report = null;
let _activeFilters = { status: 'ALL', cis: false, category: 'ALL' };

$('btn-audit').addEventListener('click', async () => {
  hideAlert('scan-alert');
  $('scan-spinner').style.display = 'block';
  $('score-card').style.display = 'none';
  $('findings-card').style.display = 'none';
  $('btn-audit').disabled = true;
  const body = { zone_id: $('zone-id').value.trim(), api_token: $('api-token').value.trim() };
  if ($('account-id').value.trim()) body.account_id = $('account-id').value.trim();
  try {
    const res = await fetch('/api/audit/zone', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body) });
    const data = await res.json();
    if (data.error) { showAlert('scan-alert', '✗ ' + data.error, 'error'); return; }
    _report = data;
    _activeFilters = { status:'ALL', cis:false, category:'ALL' };
    renderReport(data);
    $('score-card').style.display = 'block';
    $('findings-card').style.display = 'block';
  } catch(e) {
    showAlert('scan-alert', '✗ ' + e.message, 'error');
  } finally {
    $('scan-spinner').style.display = 'none';
    $('btn-audit').disabled = false;
  }
});

function renderReport(data) {
  const s = data.summary;
  const ring = $('score-ring');
  ring.textContent = s.score + '%';
  ring.style.background = scoreColor(s.score);
  $('zone-name').textContent = data.zone_name ?? data.zone_id;
  const fv = data.framework_versions;
  $('framework-ver').textContent = fv ? (fv.nist_800_53 + ' · ' + fv.cis_controls) : '';
  $('stat-grid').innerHTML = [
    ['Total', s.total_checks, ''],
    ['Pass',  s.passed,       'c-pass'],
    ['Fail',  s.failed,       'c-fail'],
    ['Warn',  s.warnings,     'c-warn'],
  ].map(([l,v,c]) => \`<div class="stat"><div class="stat-val \${c}">\${v}</div><div class="stat-lbl">\${l}</div></div>\`).join('');

  buildCategoryFilters(data.findings);
  applyFilters();
}

function buildCategoryFilters(findings) {
  const cats = ['ALL', ...new Set(findings.map(f => f.category).filter(Boolean))];
  const row = $('category-filters');
  // keep the label, remove old buttons
  const label = row.querySelector('.filter-group-label');
  row.innerHTML = '';
  row.appendChild(label);
  cats.forEach(cat => {
    const btn = document.createElement('button');
    btn.className = 'filter-btn' + (cat === 'ALL' ? ' active' : '');
    btn.dataset.filter = 'category';
    btn.dataset.val = cat;
    btn.textContent = cat === 'ALL' ? 'All categories' : cat;
    btn.addEventListener('click', () => {
      row.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      _activeFilters.category = cat;
      applyFilters();
    });
    row.appendChild(btn);
  });
}

// Status + CIS filter wiring
document.querySelectorAll('[data-filter="status"]').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('[data-filter="status"]').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    _activeFilters.status = btn.dataset.val;
    applyFilters();
  });
});
document.querySelector('[data-filter="cis"]').addEventListener('click', function() {
  _activeFilters.cis = !_activeFilters.cis;
  this.classList.toggle('active', _activeFilters.cis);
  applyFilters();
});

function applyFilters() {
  if (!_report) return;
  let findings = _report.findings;
  if (_activeFilters.status !== 'ALL') findings = findings.filter(f => f.status === _activeFilters.status);
  if (_activeFilters.category !== 'ALL') findings = findings.filter(f => f.category === _activeFilters.category);
  if (_activeFilters.cis) findings = findings.filter(f => f.cis_controls?.length > 0);
  // Sort: FAIL → WARNING → PASS → NA
  const order = {FAIL:0,WARNING:1,PASS:2,NA:3};
  findings = [...findings].sort((a,b) => (order[a.status]??9) - (order[b.status]??9));
  $('findings-count').textContent = '(' + findings.length + ')';
  renderFindings(findings);
}

function renderFindings(findings) {
  if (!findings.length) {
    $('findings-list').innerHTML = '<p style="color:#aaa;padding:.5rem 0">No findings match the current filters.</p>';
    return;
  }
  $('findings-list').innerHTML = findings.map(f => {
    const nist = f.nist_controls ?? [];
    const cis  = f.cis_controls  ?? [];
    const rc   = f.resolved_controls;
    const nistCards = (rc?.nist ?? []).map(c => \`
      <div class="control-card nist">
        <div class="control-id">NIST \${c.id}</div>
        <div class="control-title">\${c.title ?? c.id}</div>
        \${c.family ? \`<div class="control-family">\${c.family} · NIST SP 800-53 Rev 5</div>\` : ''}
        \${c.url ? \`<a class="control-link" href="\${c.url}" target="_blank" rel="noopener">Reference →</a>\` : ''}
      </div>
    \`).join('');
    const cisCards = (rc?.cis ?? []).map(c => \`
      <div class="control-card cis">
        <div class="control-id">CIS \${c.id}</div>
        <div class="control-title">\${c.title ?? c.id}</div>
        \${c.group ? \`<div class="control-family">\${c.group} · CIS Controls v8</div>\` : ''}
        \${c.implementation_groups?.length ? \`<div class="control-igs">\${c.implementation_groups.map(g=>\`<span class="ig">\${g}</span>\`).join('')}</div>\` : ''}
      </div>
    \`).join('');
    const hasDetail = f.remediation || nistCards || cisCards;
    return \`
      <div class="finding \${f.status}" onclick="toggleFinding(this)">
        <div class="finding-main">
          <div class="finding-badges">
            <span class="badge badge-\${f.severity}">\${f.severity}</span>
            <span class="badge badge-\${f.status}">\${f.status}</span>
          </div>
          <div class="finding-body">
            <div class="finding-title">\${f.id}: \${f.name}</div>
            \${f.message ? \`<div class="finding-msg">\${f.message}</div>\` : ''}
            <div class="finding-tags">
              \${nist.map(n=>\`<span class="tag">NIST \${n}</span>\`).join('')}
              \${cis.map(c=>\`<span class="tag tag-cis">CIS \${c}</span>\`).join('')}
            </div>
          </div>
          \${hasDetail ? '<span class="finding-expand-icon">▼</span>' : ''}
        </div>
        \${hasDetail ? \`
        <div class="finding-detail">
          \${f.remediation ? \`<div class="detail-remediation">⚠ \${f.remediation}</div>\` : ''}
          \${(nistCards || cisCards) ? \`
            <div class="controls-section-title">Framework controls</div>
            <div class="controls-grid">\${nistCards}\${cisCards}</div>
          \` : ''}
        </div>\` : ''}
      </div>
    \`;
  }).join('');
}

function toggleFinding(el) {
  el.classList.toggle('expanded');
}

// Download
$('btn-download').addEventListener('click', () => {
  if (!_report) return;
  const blob = new Blob([JSON.stringify(_report, null, 2)], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'flareguard-' + (_report.zone_name ?? _report.zone_id ?? 'report') + '.json';
  a.click();
});

// ── Account Scan ──────────────────────────────────────────────────────────────
$('btn-account-scan').addEventListener('click', async () => {
  hideAlert('account-alert');
  $('account-spinner').style.display = 'block';
  $('btn-account-scan').disabled = true;
  $('account-results').innerHTML = '';
  const body = { account_id: $('acc-account-id').value.trim(), api_token: $('acc-api-token').value.trim() };
  try {
    const res = await fetch('/api/audit/account', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body) });
    const data = await res.json();
    if (data.error) { showAlert('account-alert', '✗ ' + data.error, 'error'); return; }
    if (data.queued) {
      showAlert('account-alert', \`✓ \${data.zone_count} zone(s) queued. Check Audit History once complete.\`, 'info');
    } else if (data.zones?.length) {
      renderAccountResults(data.zones);
    }
  } catch(e) {
    showAlert('account-alert', '✗ ' + e.message, 'error');
  } finally {
    $('account-spinner').style.display = 'none';
    $('btn-account-scan').disabled = false;
  }
});

function renderAccountResults(zones) {
  const sorted = [...zones].sort((a,b) => (a.summary?.score ?? 999) - (b.summary?.score ?? 999));
  const avgScore = Math.round(zones.reduce((s,z) => s + (z.summary?.score ?? 0), 0) / zones.length);
  const atRisk = zones.filter(z => (z.summary?.score ?? 100) < 70).length;
  $('account-results').innerHTML = \`
    <div style="display:flex;gap:1rem;margin-bottom:1rem;flex-wrap:wrap">
      <div class="stat" style="flex:1"><div class="stat-val">\${zones.length}</div><div class="stat-lbl">Zones scanned</div></div>
      <div class="stat" style="flex:1"><div class="stat-val" style="color:\${scoreColor(avgScore)}">\${avgScore}%</div><div class="stat-lbl">Avg score</div></div>
      <div class="stat" style="flex:1"><div class="stat-val \${atRisk > 0 ? 'c-fail' : 'c-pass'}">\${atRisk}</div><div class="stat-lbl">Zones below 70%</div></div>
    </div>
    <table>
      <thead><tr><th>Zone</th><th>Score</th><th>Pass</th><th>Fail</th><th>Warn</th></tr></thead>
      <tbody>\${sorted.map(z => z.error ? \`
        <tr><td colspan="5" style="color:var(--fail)">\${z.zone_name ?? z.zone_id}: \${z.error}</td></tr>
      \` : \`
        <tr>
          <td style="font-weight:600">\${z.zone_name ?? z.zone_id}</td>
          <td><span class="score-pill" style="background:\${scoreColor(z.summary.score)}">\${z.summary.score}%</span></td>
          <td class="c-pass">\${z.summary.passed}</td>
          <td class="c-fail">\${z.summary.failed}</td>
          <td class="c-warn">\${z.summary.warnings}</td>
        </tr>
      \`).join('')}</tbody>
    </table>
  \`;
}

// ── History ───────────────────────────────────────────────────────────────────
$('btn-history').addEventListener('click', async () => {
  const zoneId = $('hist-zone-id').value.trim();
  if (!zoneId) return;
  $('history-content').innerHTML = '<div class="spinner" style="display:block"></div>';
  try {
    const res = await fetch('/api/history/' + zoneId);
    const data = await res.json();
    if (data.error) { $('history-content').innerHTML = '<p style="color:var(--fail)">' + data.error + '</p>'; return; }
    if (!data.history?.length) { $('history-content').innerHTML = '<p style="color:#aaa">No audit history found. Run a zone audit first — history requires D1 storage enabled.</p>'; return; }
    $('history-content').innerHTML = \`
      <table>
        <thead><tr><th>Date</th><th>Score</th><th>Pass</th><th>Fail</th><th>Warn</th><th>Type</th></tr></thead>
        <tbody>\${data.history.map(h => \`
          <tr>
            <td>\${new Date(h.created_at).toLocaleString()}</td>
            <td><span class="score-pill" style="background:\${scoreColor(h.score)}">\${h.score}%</span></td>
            <td class="c-pass">\${h.passed}</td><td class="c-fail">\${h.failed}</td><td class="c-warn">\${h.warnings}</td>
            <td style="color:#aaa">\${h.scan_type}</td>
          </tr>
        \`).join('')}</tbody>
      </table>
    \`;
  } catch(e) { $('history-content').innerHTML = '<p style="color:var(--fail)">' + e.message + '</p>'; }
});

// ── Drift ──────────────────────────────────────────────────────────────────────
$('btn-drift').addEventListener('click', async () => {
  const zoneId = $('drift-zone-id').value.trim();
  if (!zoneId) return;
  $('drift-content').innerHTML = '<div class="spinner" style="display:block"></div>';
  try {
    const res = await fetch('/api/drift/' + zoneId);
    const data = await res.json();
    if (data.error) { $('drift-content').innerHTML = '<p style="color:var(--fail)">' + data.error + '</p>'; return; }
    if (!data.changes?.length) {
      $('drift-content').innerHTML = \`<div class="alert alert-success">✓ No drift — configuration is unchanged between the two most recent audits. \${data.message ?? ''}</div>\`;
      return;
    }
    const statusColor = {PASS:'var(--pass)',FAIL:'var(--fail)',WARNING:'var(--warn)',NA:'var(--na)'};
    const dangerous = data.changes.filter(c => c.to === 'FAIL');
    $('drift-content').innerHTML = \`
      \${dangerous.length ? \`<div class="alert alert-error">⚠ \${dangerous.length} check(s) regressed to FAIL since last audit.</div>\` : ''}
      <div class="alert alert-info">\${data.changes.length} change(s) detected between the two most recent audits.</div>
      \${data.changes.map(c => \`
        <div class="drift-row" style="border-left:3px solid \${statusColor[c.to] ?? '#ddd'}">
          <strong style="font-size:.8rem;min-width:110px">\${c.check_id}</strong>
          <span style="flex:1;font-size:.82rem;color:#555">\${c.check_name}</span>
          <span class="drift-arrow">
            <span style="color:\${statusColor[c.from]}">\${c.from}</span>
            →
            <span style="color:\${statusColor[c.to]};font-weight:700">\${c.to}</span>
          </span>
        </div>
      \`).join('')}
    \`;
  } catch(e) { $('drift-content').innerHTML = '<p style="color:var(--fail)">' + e.message + '</p>'; }
});
</script>
</body>
</html>`;
}
