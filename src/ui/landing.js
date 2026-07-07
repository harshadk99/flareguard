export function generateLanding() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>FlareGuard — Cloudflare Security Posture Management</title>
<meta name="description" content="The first open-source CSPM built for the Cloudflare developer ecosystem. 29 checks mapped to NIST SP 800-53 and CIS Controls v8. Zero infrastructure required."/>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --orange:#f38020;--orange-light:#ffa040;--orange-dim:#f3802020;
  --dark:#0f0f0f;--surface:#1a1a1a;--surface2:#242424;--border:#2e2e2e;
  --text:#f0f0f0;--muted:#888;--pass:#22c55e;--fail:#ef4444;--warn:#f59e0b;--critical:#7c3aed;
}
html{scroll-behavior:smooth}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--dark);color:var(--text);line-height:1.6}

/* NAV */
nav{position:sticky;top:0;z-index:100;background:rgba(15,15,15,.9);backdrop-filter:blur(12px);border-bottom:1px solid var(--border);padding:.75rem 2rem;display:flex;align-items:center;gap:1rem}
.nav-logo{font-size:1.1rem;font-weight:800;color:var(--orange);letter-spacing:-.5px;text-decoration:none}
.nav-links{margin-left:auto;display:flex;gap:1.5rem;align-items:center}
.nav-links a{color:var(--muted);text-decoration:none;font-size:.875rem;transition:color .15s}
.nav-links a:hover{color:var(--text)}
.btn-nav{background:var(--orange);color:#fff;padding:.4rem 1.1rem;border-radius:6px;font-weight:600;font-size:.875rem;text-decoration:none;transition:opacity .15s}
.btn-nav:hover{opacity:.85;color:#fff}

/* HERO */
.hero{max-width:860px;margin:0 auto;padding:5rem 2rem 4rem;text-align:center}
.hero-eyebrow{display:inline-block;background:var(--orange-dim);border:1px solid var(--orange);color:var(--orange);font-size:.75rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;padding:.3rem .9rem;border-radius:99px;margin-bottom:1.5rem}
.hero h1{font-size:clamp(2rem,5vw,3.25rem);font-weight:800;line-height:1.15;letter-spacing:-.02em;margin-bottom:1.25rem}
.hero h1 span{color:var(--orange)}
.hero p{font-size:1.1rem;color:var(--muted);max-width:600px;margin:0 auto 2.5rem}
.btn-cta{display:inline-block;background:var(--orange);color:#fff;padding:.8rem 2rem;border-radius:8px;font-weight:700;font-size:1rem;text-decoration:none;transition:opacity .15s;margin-right:.75rem}
.btn-cta:hover{opacity:.88;color:#fff}
.btn-ghost{display:inline-block;border:1.5px solid var(--border);color:var(--muted);padding:.8rem 2rem;border-radius:8px;font-weight:600;font-size:1rem;text-decoration:none;transition:all .15s}
.btn-ghost:hover{border-color:var(--orange);color:var(--orange)}

/* STATS BAR */
.stats-bar{display:flex;justify-content:center;gap:0;margin:3rem auto 0;max-width:700px;border:1px solid var(--border);border-radius:10px;overflow:hidden}
.stat-item{flex:1;padding:1.25rem 1rem;text-align:center;border-right:1px solid var(--border)}
.stat-item:last-child{border-right:none}
.stat-num{font-size:1.75rem;font-weight:800;color:var(--orange)}
.stat-label{font-size:.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-top:.15rem}

/* SECTION */
section{max-width:1060px;margin:0 auto;padding:4rem 2rem}
.section-label{font-size:.75rem;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:var(--orange);margin-bottom:.75rem}
.section-title{font-size:clamp(1.5rem,3vw,2rem);font-weight:800;letter-spacing:-.02em;margin-bottom:1rem}
.section-sub{color:var(--muted);font-size:1rem;max-width:560px}
hr.divider{border:none;border-top:1px solid var(--border);margin:0}

/* THE GAP */
.gap-grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-top:2rem}
@media(max-width:640px){.gap-grid{grid-template-columns:1fr}}
.gap-card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:1.25rem}
.gap-card .tool{font-size:.8rem;font-weight:700;color:var(--muted);margin-bottom:.3rem}
.gap-card .coverage{font-size:.9rem;color:var(--text);margin-bottom:.5rem}
.gap-card .blind{font-size:.8rem;color:var(--fail);background:rgba(239,68,68,.08);padding:.3rem .6rem;border-radius:4px;display:inline-block}
.gap-card.highlight{border-color:var(--orange);background:rgba(243,128,32,.05)}
.gap-card.highlight .tool{color:var(--orange)}
.gap-card.highlight .blind{color:var(--pass);background:rgba(34,197,94,.08)}

/* CHECKS TABLE */
.checks-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:1rem;margin-top:2rem}
.check-category{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:1.25rem}
.check-category h4{font-size:.85rem;font-weight:700;color:var(--text);margin-bottom:.75rem;display:flex;align-items:center;gap:.5rem}
.cat-count{background:var(--orange);color:#fff;font-size:.65rem;font-weight:800;padding:.1rem .45rem;border-radius:99px}
.check-list{list-style:none;display:flex;flex-direction:column;gap:.4rem}
.check-list li{font-size:.78rem;color:var(--muted);display:flex;align-items:flex-start;gap:.5rem}
.check-list li::before{content:'—';color:var(--border);flex-shrink:0}
.sev{font-size:.6rem;font-weight:700;padding:.1rem .35rem;border-radius:3px;flex-shrink:0;margin-top:.1rem}
.sev-CRITICAL{background:rgba(124,58,237,.2);color:#a78bfa}
.sev-HIGH{background:rgba(239,68,68,.15);color:#fca5a5}
.sev-MEDIUM{background:rgba(245,158,11,.15);color:#fcd34d}
.sev-LOW{background:rgba(59,130,246,.15);color:#93c5fd}

/* DEMO FINDING */
.demo-section{background:var(--surface);border:1px solid var(--border);border-radius:12px;overflow:hidden;margin-top:2rem}
.demo-header{padding:1rem 1.5rem;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.demo-score{display:flex;align-items:center;gap:1.5rem}
.score-circle{width:64px;height:64px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:1.1rem;font-weight:800;color:#fff;background:var(--warn);flex-shrink:0}
.demo-stats{display:flex;gap:1.25rem}
.demo-stat{text-align:center}
.demo-stat .v{font-size:1.3rem;font-weight:800}
.demo-stat .l{font-size:.65rem;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.demo-findings{padding:1rem 1.5rem;display:flex;flex-direction:column;gap:.6rem}
.demo-finding{border-left:3px solid var(--border);padding:.7rem 1rem;border-radius:0 6px 6px 0;background:var(--surface2);display:flex;align-items:flex-start;gap:.75rem}
.demo-finding.FAIL{border-left-color:var(--fail)}
.demo-finding.PASS{border-left-color:var(--pass)}
.demo-finding.WARN{border-left-color:var(--warn)}
.df-badges{display:flex;flex-direction:column;gap:.3rem;align-items:center;flex-shrink:0;min-width:54px}
.df-sev,.df-status{font-size:.6rem;font-weight:800;padding:.15rem .4rem;border-radius:3px;text-align:center;width:100%}
.df-status-FAIL{background:rgba(239,68,68,.2);color:#fca5a5}
.df-status-PASS{background:rgba(34,197,94,.2);color:#86efac}
.df-status-WARN{background:rgba(245,158,11,.2);color:#fcd34d}
.df-info{flex:1;min-width:0}
.df-name{font-size:.85rem;font-weight:600;color:var(--text);margin-bottom:.2rem}
.df-msg{font-size:.75rem;color:var(--muted)}
.df-controls{display:flex;gap:.4rem;margin-top:.35rem;flex-wrap:wrap}
.df-ctrl{font-size:.65rem;color:var(--muted);background:var(--surface);border:1px solid var(--border);padding:.1rem .4rem;border-radius:3px}

/* PILLARS */
.pillars{display:grid;grid-template-columns:repeat(3,1fr);gap:1.25rem;margin-top:2rem}
@media(max-width:700px){.pillars{grid-template-columns:1fr}}
.pillar{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:1.5rem}
.pillar-icon{font-size:1.75rem;margin-bottom:.75rem}
.pillar h3{font-size:.95rem;font-weight:700;margin-bottom:.5rem}
.pillar p{font-size:.82rem;color:var(--muted);line-height:1.6}

/* HOW IT WORKS */
.steps{display:flex;flex-direction:column;gap:1rem;margin-top:2rem;max-width:600px}
.step{display:flex;gap:1rem;align-items:flex-start}
.step-num{width:28px;height:28px;border-radius:50%;background:var(--orange);color:#fff;font-weight:800;font-size:.8rem;display:flex;align-items:center;justify-content:center;flex-shrink:0;margin-top:.1rem}
.step-body h4{font-size:.9rem;font-weight:700;margin-bottom:.2rem}
.step-body p{font-size:.82rem;color:var(--muted)}
code{background:var(--surface2);border:1px solid var(--border);padding:.1rem .4rem;border-radius:4px;font-size:.8rem;font-family:'SF Mono',Monaco,monospace;color:var(--orange)}

/* YAML BLOCK */
.yaml-block{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:1.5rem;margin-top:2rem;font-family:'SF Mono',Monaco,monospace;font-size:.8rem;line-height:1.8;overflow-x:auto}
.y-comment{color:#555}.y-key{color:#7dd3fc}.y-val{color:#86efac}.y-str{color:#fcd34d}

/* CTA SECTION */
.cta-section{text-align:center;padding:5rem 2rem;background:linear-gradient(to bottom,transparent,rgba(243,128,32,.05))}
.cta-section h2{font-size:clamp(1.5rem,3vw,2rem);font-weight:800;margin-bottom:1rem}
.cta-section p{color:var(--muted);margin-bottom:2rem}

/* FOOTER */
footer{border-top:1px solid var(--border);padding:2rem;text-align:center;color:var(--muted);font-size:.8rem}
footer a{color:var(--orange);text-decoration:none}
</style>
</head>
<body>

<nav>
  <a class="nav-logo" href="/">FlareGuard</a>
  <div class="nav-links">
    <a href="#checks">Checks</a>
    <a href="#how">How it works</a>
    <a href="https://github.com/harshadk99/flareguard" target="_blank">GitHub</a>
    <a class="btn-nav" href="/audit">Audit your zone →</a>
  </div>
</nav>

<!-- HERO -->
<div class="hero">
  <div class="hero-eyebrow">Open Source · MIT License</div>
  <h1>Security posture for<br/><span>the Cloudflare stack</span></h1>
  <p>Wiz covers AWS. Orca covers GCP. Prisma covers Azure.<br/>Nobody audits your Cloudflare configuration — until now.</p>
  <a class="btn-cta" href="/audit">Audit your zone →</a>
  <a class="btn-ghost" href="https://github.com/harshadk99/flareguard" target="_blank">View on GitHub</a>

  <div class="stats-bar">
    <div class="stat-item"><div class="stat-num">29</div><div class="stat-label">Security checks</div></div>
    <div class="stat-item"><div class="stat-num">9</div><div class="stat-label">Categories</div></div>
    <div class="stat-item"><div class="stat-num">NIST</div><div class="stat-label">SP 800-53 Rev 5</div></div>
    <div class="stat-item"><div class="stat-num">CIS</div><div class="stat-label">Controls v8</div></div>
    <div class="stat-item"><div class="stat-num">0</div><div class="stat-label">Infrastructure needed</div></div>
  </div>
</div>

<hr class="divider"/>

<!-- THE GAP -->
<section>
  <div class="section-label">The problem</div>
  <div class="section-title">Every CSPM tool has a Cloudflare blind spot</div>
  <div class="section-sub">Mainstream tools are built for cloud infrastructure — S3 buckets, VMs, IAM policies. Cloudflare's control plane is invisible to all of them.</div>
  <div class="gap-grid">
    <div class="gap-card">
      <div class="tool">Wiz / Orca / Prisma Cloud</div>
      <div class="coverage">AWS · GCP · Azure infrastructure</div>
      <div class="blind">Blind to Cloudflare WAF, Zero Trust, Workers</div>
    </div>
    <div class="gap-card">
      <div class="tool">FireMon / SolarWinds NCM</div>
      <div class="coverage">On-prem firewall policy management</div>
      <div class="blind">Blind to Cloudflare SASE and edge runtime</div>
    </div>
    <div class="gap-card">
      <div class="tool">Cloudflare Dashboard</div>
      <div class="coverage">Configuration UI per-zone</div>
      <div class="blind">No posture scoring, no cross-zone comparison, no compliance evidence</div>
    </div>
    <div class="gap-card highlight">
      <div class="tool">FlareGuard</div>
      <div class="coverage">Cloudflare Workers · WAF · DNS · Zero Trust · Page Shield · Logpush</div>
      <div class="blind">✓ Built specifically for the Cloudflare control plane</div>
    </div>
  </div>
</section>

<hr class="divider"/>

<!-- SAMPLE RESULT -->
<section>
  <div class="section-label">See it in action</div>
  <div class="section-title">A real audit, in under 3 seconds</div>
  <div class="section-sub">FlareGuard calls the Cloudflare API, evaluates your configuration against the baseline, and returns a structured report with remediation guidance and framework mappings.</div>
  <div class="demo-section">
    <div class="demo-header">
      <div class="demo-score">
        <div class="score-circle">68%</div>
        <div>
          <div style="font-weight:700;font-size:.95rem">example.com</div>
          <div style="font-size:.75rem;color:var(--muted);margin-top:.1rem">Zone audit · 29 checks · NIST SP 800-53 Rev 5 · CIS Controls v8</div>
        </div>
      </div>
      <div class="demo-stats">
        <div class="demo-stat"><div class="v" style="color:var(--pass)">16</div><div class="l">Pass</div></div>
        <div class="demo-stat"><div class="v" style="color:var(--fail)">8</div><div class="l">Fail</div></div>
        <div class="demo-stat"><div class="v" style="color:var(--warn)">3</div><div class="l">Warn</div></div>
        <div class="demo-stat"><div class="v" style="color:#555">2</div><div class="l">N/A</div></div>
      </div>
    </div>
    <div class="demo-findings">
      <div class="demo-finding FAIL">
        <div class="df-badges">
          <div class="df-sev sev-CRITICAL">CRIT</div>
          <div class="df-status df-status-FAIL">FAIL</div>
        </div>
        <div class="df-info">
          <div class="df-name">CF-WAF-001 · OWASP Core Rule Set is enabled</div>
          <div class="df-msg">WAF package not found or not enabled — OWASP CRS protection is inactive</div>
          <div class="df-controls">
            <span class="df-ctrl">NIST SI-3</span>
            <span class="df-ctrl">NIST SC-7</span>
          </div>
        </div>
      </div>
      <div class="demo-finding FAIL">
        <div class="df-badges">
          <div class="df-sev sev-HIGH">HIGH</div>
          <div class="df-status df-status-FAIL">FAIL</div>
        </div>
        <div class="df-info">
          <div class="df-name">CF-HSTS-001 · HTTP Strict Transport Security is enabled</div>
          <div class="df-msg">security_header.strict_transport_security.enabled is false — browsers can be downgraded to HTTP</div>
          <div class="df-controls">
            <span class="df-ctrl">NIST SC-8(1)</span>
            <span class="df-ctrl">CIS 3.10 · IG1</span>
          </div>
        </div>
      </div>
      <div class="demo-finding FAIL">
        <div class="df-badges">
          <div class="df-sev sev-HIGH">HIGH</div>
          <div class="df-status df-status-FAIL">FAIL</div>
        </div>
        <div class="df-info">
          <div class="df-name">CF-LOG-001 · Active Logpush job is configured</div>
          <div class="df-msg">No Logpush jobs configured — HTTP traffic logs are not being exported to a SIEM</div>
          <div class="df-controls">
            <span class="df-ctrl">NIST AU-2</span>
            <span class="df-ctrl">CIS 6.1</span>
            <span class="df-ctrl">CIS 8.2 · IG1</span>
          </div>
        </div>
      </div>
      <div class="demo-finding PASS">
        <div class="df-badges">
          <div class="df-sev sev-HIGH">HIGH</div>
          <div class="df-status df-status-PASS">PASS</div>
        </div>
        <div class="df-info">
          <div class="df-name">CF-DNS-001 · DNSSEC is enabled and active</div>
          <div class="df-msg">DNSSEC status is active with algorithm 13 (ECDSA P-256 SHA-256)</div>
          <div class="df-controls">
            <span class="df-ctrl">NIST SC-20</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</section>

<hr class="divider"/>

<!-- CHECKS -->
<section id="checks">
  <div class="section-label">Security baseline</div>
  <div class="section-title">29 checks across 9 categories</div>
  <div class="section-sub">Every check maps to NIST SP 800-53 Rev 5 and/or CIS Controls v8. The baseline is a YAML file — adding a check requires no code.</div>
  <div class="checks-grid">
    <div class="check-category">
      <h4>SSL / TLS <span class="cat-count">5</span></h4>
      <ul class="check-list">
        <li><span class="sev sev-HIGH">HIGH</span>Full (Strict) mode enforced</li>
        <li><span class="sev sev-HIGH">HIGH</span>Minimum TLS 1.2 or higher</li>
        <li><span class="sev sev-MEDIUM">MED</span>TLS 1.3 enabled</li>
        <li><span class="sev sev-MEDIUM">MED</span>Always Use HTTPS</li>
        <li><span class="sev sev-LOW">LOW</span>Opportunistic Encryption</li>
      </ul>
    </div>
    <div class="check-category">
      <h4>Transport Security <span class="cat-count">6</span></h4>
      <ul class="check-list">
        <li><span class="sev sev-HIGH">HIGH</span>HSTS enabled (CIS 3.10)</li>
        <li><span class="sev sev-MEDIUM">MED</span>HSTS max-age ≥ 6 months</li>
        <li><span class="sev sev-MEDIUM">MED</span>Automatic HTTPS Rewrites</li>
        <li><span class="sev sev-HIGH">HIGH</span>Authenticated Origin Pulls (mTLS)</li>
        <li><span class="sev sev-MEDIUM">MED</span>Certificate Transparency Monitoring</li>
      </ul>
    </div>
    <div class="check-category">
      <h4>WAF <span class="cat-count">2</span></h4>
      <ul class="check-list">
        <li><span class="sev sev-CRITICAL">CRIT</span>OWASP Core Rule Set enabled</li>
        <li><span class="sev sev-HIGH">HIGH</span>WAF in block mode, not detect-only</li>
      </ul>
    </div>
    <div class="check-category">
      <h4>Zero Trust <span class="cat-count">2</span></h4>
      <ul class="check-list">
        <li><span class="sev sev-HIGH">HIGH</span>MFA enforced on all Access apps</li>
        <li><span class="sev sev-HIGH">HIGH</span>Identity provider configured</li>
      </ul>
    </div>
    <div class="check-category">
      <h4>Observability <span class="cat-count">3</span></h4>
      <ul class="check-list">
        <li><span class="sev sev-HIGH">HIGH</span>Active Logpush job (CIS 6.1, 8.2)</li>
        <li><span class="sev sev-HIGH">HIGH</span>Page Shield enabled (CIS 8.2)</li>
        <li><span class="sev sev-MEDIUM">MED</span>Page Shield enforcement mode</li>
      </ul>
    </div>
    <div class="check-category">
      <h4>Workers <span class="cat-count">2</span></h4>
      <ul class="check-list">
        <li><span class="sev sev-HIGH">HIGH</span>No zombie workers (stale + unrouted)</li>
        <li><span class="sev sev-CRITICAL">CRIT</span>No plain-text secret env vars</li>
      </ul>
    </div>
    <div class="check-category">
      <h4>DNS <span class="cat-count">1</span></h4>
      <ul class="check-list">
        <li><span class="sev sev-HIGH">HIGH</span>DNSSEC active</li>
      </ul>
    </div>
    <div class="check-category">
      <h4>Protocol Hygiene <span class="cat-count">3</span></h4>
      <ul class="check-list">
        <li><span class="sev sev-LOW">LOW</span>HTTP/2 enabled (CIS 12.6)</li>
        <li><span class="sev sev-LOW">LOW</span>HTTP/3 / QUIC enabled</li>
        <li><span class="sev sev-LOW">LOW</span>IPv6 compatibility</li>
      </ul>
    </div>
    <div class="check-category">
      <h4>Security / Content <span class="cat-count">5</span></h4>
      <ul class="check-list">
        <li><span class="sev sev-HIGH">HIGH</span>Bot Fight Mode / Bot Management</li>
        <li><span class="sev sev-MEDIUM">MED</span>Rate limiting rules configured</li>
        <li><span class="sev sev-MEDIUM">MED</span>Browser Integrity Check</li>
        <li><span class="sev sev-MEDIUM">MED</span>Security Level ≥ Medium</li>
        <li><span class="sev sev-LOW">LOW</span>Hotlink Protection (CIS 9.3)</li>
      </ul>
    </div>
  </div>
</section>

<hr class="divider"/>

<!-- PILLARS -->
<section>
  <div class="section-label">Design principles</div>
  <div class="section-title">Built different from day one</div>
  <div class="pillars">
    <div class="pillar">
      <div class="pillar-icon">🔒</div>
      <h3>Privacy-first, stateless</h3>
      <p>API tokens exist in memory only for the duration of the request. Zone IDs are SHA-256 hashed before any storage write. Nothing is logged, nothing is retained.</p>
    </div>
    <div class="pillar">
      <div class="pillar-icon">📋</div>
      <h3>Compliance-grade mappings</h3>
      <p>Every finding resolves to full NIST SP 800-53 Rev 5 and CIS Controls v8 metadata — title, description, reference URL, implementation groups. Ready for GRC evidence packages.</p>
    </div>
    <div class="pillar">
      <div class="pillar-icon">⚡</div>
      <h3>Zero infrastructure</h3>
      <p>Runs as a Cloudflare Worker — the same runtime it audits. Deploy in 60 seconds with <code>wrangler deploy</code>. No database, no agents, no credentials stored server-side.</p>
    </div>
  </div>
</section>

<hr class="divider"/>

<!-- HOW IT WORKS -->
<section id="how">
  <div class="section-label">How it works</div>
  <div class="section-title">Three steps, under 5 seconds</div>
  <div class="steps">
    <div class="step">
      <div class="step-num">1</div>
      <div class="step-body">
        <h4>Provide credentials</h4>
        <p>Enter your Zone ID and a read-only Cloudflare API token. Optionally add an Account ID to enable Zero Trust, Workers, and Logpush checks.</p>
      </div>
    </div>
    <div class="step">
      <div class="step-num">2</div>
      <div class="step-body">
        <h4>Engine evaluates 29 checks in parallel</h4>
        <p>The audit engine dispatches checks to typed evaluators — each making real Cloudflare API calls. Results are scored and enriched with NIST and CIS metadata in a single pass.</p>
      </div>
    </div>
    <div class="step">
      <div class="step-num">3</div>
      <div class="step-body">
        <h4>Get a structured, compliance-ready report</h4>
        <p>Score, per-finding remediation, and resolved control references with full titles, descriptions, and URLs. Download as JSON or connect D1 to track drift over time.</p>
      </div>
    </div>
  </div>

  <div class="yaml-block" style="margin-top:2.5rem">
    <div class="y-comment"># Adding a check requires only YAML — no code</div>
    <br/>
    <span class="y-key">- id:</span> <span class="y-str">CF-NEW-001</span><br/>
    &nbsp;&nbsp;<span class="y-key">name:</span> <span class="y-str">My new security check</span><br/>
    &nbsp;&nbsp;<span class="y-key">service:</span> <span class="y-val">zone-setting</span><br/>
    &nbsp;&nbsp;<span class="y-key">setting:</span> <span class="y-val">some_cloudflare_setting</span><br/>
    &nbsp;&nbsp;<span class="y-key">expect:</span> <span class="y-str">"on"</span><br/>
    &nbsp;&nbsp;<span class="y-key">severity:</span> <span class="y-val">MEDIUM</span><br/>
    &nbsp;&nbsp;<span class="y-key">nist_controls:</span> <span class="y-val">[SC-8]</span><br/>
    &nbsp;&nbsp;<span class="y-key">cis_controls:</span> <span class="y-val">["3.10"]</span><br/>
    &nbsp;&nbsp;<span class="y-key">remediation:</span> <span class="y-str">Enable this in the Cloudflare dashboard.</span>
  </div>
</section>

<!-- CTA -->
<div class="cta-section">
  <h2>Your Cloudflare zone has blind spots.<br/>Find them in 3 seconds.</h2>
  <p>Free, open-source, stateless. No account required.</p>
  <a class="btn-cta" href="/audit">Audit your zone now →</a>
  <a class="btn-ghost" href="https://github.com/harshadk99/flareguard" target="_blank" style="margin-left:.75rem">Star on GitHub</a>
</div>

<footer>
  FlareGuard is an independent open-source project · Not affiliated with Cloudflare, Inc.<br/>
  <a href="https://github.com/harshadk99/flareguard">GitHub</a> ·
  <a href="/audit">Launch audit tool</a> ·
  Built by <a href="https://harshadsadashivkadam.com">Harshad Sadashiv Kadam</a>
</footer>

</body>
</html>`;
}
