import http from "http";
import fs from "fs/promises";
import fsSync from "fs";
import path from "path";
import { fileURLToPath } from "url";
import {
    domainSecurityAudit,
    sslTlsInspector,
    subdomainOsintRecon,
    webMetadataAndRobotsAnalyzer,
    tcpPortScanner,
    jsBundleReverser,
    cookieCorsAuditor,
    codeStructureAnalyzer,
    alternativeBlueprintGenerator,
    vulnerabilityAndHeaderRemediator,
    generateSecurityReport,
} from "./index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);
const PORT       = process.env.PORT || 3000;
const reportsDir = path.join(__dirname, "reports");

// Ensure reports directory exists
await fs.mkdir(reportsDir, { recursive: true });

// Live In-Memory Stats
const stats = {
    auditsRun: 0,
    blueprintsGenerated: 0,
    startTime: new Date().toISOString(),
};

/** Helper to sanitize domain string */
function cleanDomain(raw) {
    return (raw || "").replace(/^https?:\/\//, "").split("/")[0].trim().toLowerCase();
}

/** Helper to parse JSON body from incoming HTTP request safely */
function parseJsonBody(req) {
    return new Promise((resolve) => {
        let body = "";
        req.on("data", chunk => {
            body += chunk;
            if (body.length > 5 * 1024 * 1024) {
                req.destroy();
                resolve({});
            }
        });
        req.on("end", () => {
            if (!body || !body.trim()) return resolve({});
            try {
                return resolve(JSON.parse(body));
            } catch {
                try {
                    const params = new URLSearchParams(body);
                    return resolve(Object.fromEntries(params.entries()));
                } catch {
                    return resolve({});
                }
            }
        });
        req.on("error", () => resolve({}));
    });
}

/** Helper to send JSON response with universal CORS headers */
function sendJson(res, statusCode, data) {
    if (res.writableEnded) return;
    const payload = JSON.stringify(data);
    res.writeHead(statusCode, {
        "Content-Type": "application/json; charset=utf-8",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
        "Content-Length": Buffer.byteLength(payload),
    });
    res.end(payload);
}

// ─── HTML Web UI Dashboard ───────────────────────────────────
const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Omni-Arch Pro v3.0 — Cyber Defense &amp; Architecture Reconnaissance Suite</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #070a12;
      --bg-panel: #0d1322;
      --bg-card: rgba(18, 25, 43, 0.7);
      --bg-code: #090e1a;
      --border: rgba(30, 45, 75, 0.8);
      --border-accent: rgba(0, 212, 255, 0.35);
      --primary: #00d4ff;
      --primary-dim: rgba(0, 212, 255, 0.12);
      --secondary: #7b61ff;
      --green: #00ff88;
      --yellow: #f5a623;
      --red: #ff3b3b;
      --text: #cbd5e1;
      --text-bright: #ffffff;
      --text-dim: #64748b;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: 'Inter', sans-serif;
      font-size: 14px;
      line-height: 1.5;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }
    a { color: var(--primary); text-decoration: none; }
    a:hover { text-decoration: underline; }

    /* ── Header ── */
    header {
      background: var(--bg-panel);
      border-bottom: 1px solid var(--border);
      padding: 14px 28px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 100;
      backdrop-filter: blur(10px);
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .logo-badge {
      width: 36px;
      height: 36px;
      background: linear-gradient(135deg, var(--primary), var(--secondary));
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 18px;
      font-weight: 800;
      color: #fff;
      box-shadow: 0 0 15px rgba(0, 212, 255, 0.35);
    }
    .brand-title {
      font-size: 16px;
      font-weight: 800;
      color: var(--text-bright);
      letter-spacing: -0.3px;
    }
    .brand-title span {
      background: linear-gradient(90deg, var(--primary), var(--secondary));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .brand-subtitle {
      font-size: 11px;
      color: var(--text-dim);
    }
    .status-pill {
      display: flex;
      align-items: center;
      gap: 8px;
      background: rgba(0, 255, 136, 0.08);
      border: 1px solid rgba(0, 255, 136, 0.25);
      border-radius: 20px;
      padding: 4px 12px;
      font-size: 12px;
      font-weight: 600;
      color: var(--green);
    }
    .status-dot {
      width: 8px;
      height: 8px;
      background: var(--green);
      border-radius: 50%;
      box-shadow: 0 0 8px var(--green);
      animation: pulse 2s infinite;
    }
    @keyframes pulse {
      0% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.4; transform: scale(0.85); }
      100% { opacity: 1; transform: scale(1); }
    }

    /* ── Main Container ── */
    main {
      flex: 1;
      max-width: 1300px;
      margin: 0 auto;
      width: 100%;
      padding: 24px;
    }

    /* ── Command / Search Console ── */
    .console-hero {
      background: linear-gradient(135deg, #0d1424 0%, #0e1832 50%, #0a1122 100%);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 28px 32px;
      margin-bottom: 24px;
      position: relative;
      overflow: hidden;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);
    }
    .console-hero::before {
      content: '';
      position: absolute;
      top: -100px;
      right: -100px;
      width: 300px;
      height: 300px;
      background: radial-gradient(circle, rgba(0, 212, 255, 0.12), transparent 70%);
      pointer-events: none;
    }
    .hero-h1 {
      font-size: 22px;
      font-weight: 800;
      color: var(--text-bright);
      margin-bottom: 6px;
    }
    .hero-desc {
      color: var(--text-dim);
      font-size: 13px;
      margin-bottom: 20px;
      max-width: 800px;
    }
    .input-row {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
    }
    .input-box {
      flex: 1;
      min-width: 280px;
      position: relative;
      display: flex;
      align-items: center;
    }
    .input-icon {
      position: absolute;
      left: 14px;
      color: var(--text-dim);
      font-size: 15px;
    }
    .input-box input {
      width: 100%;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 12px 14px 12px 42px;
      color: var(--text-bright);
      font-size: 14px;
      font-family: 'Inter', sans-serif;
      transition: all 0.2s;
    }
    .input-box input:focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 12px rgba(0, 212, 255, 0.25);
    }
    .profile-select {
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 12px 16px;
      color: var(--text-bright);
      font-size: 13px;
      font-family: 'Inter', sans-serif;
      cursor: pointer;
    }
    .profile-select:focus {
      outline: none;
      border-color: var(--primary);
    }
    .btn-launch {
      background: linear-gradient(135deg, var(--primary), var(--secondary));
      color: #fff;
      border: none;
      border-radius: 8px;
      padding: 12px 24px;
      font-weight: 700;
      font-size: 14px;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 8px;
      box-shadow: 0 4px 16px rgba(0, 212, 255, 0.35);
      transition: all 0.2s;
    }
    .btn-launch:hover {
      transform: translateY(-2px);
      box-shadow: 0 6px 22px rgba(0, 212, 255, 0.5);
    }
    .btn-launch:disabled {
      opacity: 0.6;
      cursor: not-allowed;
      transform: none;
    }

    /* Progress bar */
    #progress-bar {
      display: none;
      margin-top: 14px;
      height: 4px;
      background: rgba(255, 255, 255, 0.08);
      border-radius: 4px;
      overflow: hidden;
      position: relative;
    }
    #progress-fill {
      height: 100%;
      background: linear-gradient(90deg, var(--primary), var(--secondary), var(--green));
      width: 0%;
      animation: progress-anim 1.5s infinite ease-in-out;
    }
    @keyframes progress-anim {
      0% { width: 0%; transform: translateX(0); }
      50% { width: 60%; transform: translateX(30%); }
      100% { width: 100%; transform: translateX(100%); }
    }

    /* ── Tabs Navigation ── */
    .tabs-nav {
      display: flex;
      gap: 6px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 22px;
      overflow-x: auto;
    }
    .tab-btn {
      background: transparent;
      border: none;
      border-bottom: 2px solid transparent;
      padding: 10px 18px;
      color: var(--text-dim);
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
      white-space: nowrap;
    }
    .tab-btn:hover {
      color: var(--text);
    }
    .tab-btn.active {
      color: var(--primary);
      border-bottom-color: var(--primary);
    }
    .tab-content {
      display: none;
    }
    .tab-content.active {
      display: block;
    }

    /* ── Metrics Grid ── */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 14px;
      margin-bottom: 22px;
    }
    .stat-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 16px;
      position: relative;
      overflow: hidden;
    }
    .stat-card::before {
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 2px;
      background: linear-gradient(90deg, var(--primary), transparent);
    }
    .stat-label {
      font-size: 11px;
      font-weight: 600;
      color: var(--text-dim);
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 6px;
    }
    .stat-val {
      font-size: 24px;
      font-weight: 800;
      line-height: 1.1;
      margin-bottom: 4px;
    }
    .stat-sub {
      font-size: 11px;
      color: var(--text-dim);
    }

    /* ── Panel Cards ── */
    .panel {
      background: var(--bg-panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      margin-bottom: 18px;
      overflow: hidden;
    }
    .panel-hdr {
      background: rgba(255, 255, 255, 0.02);
      border-bottom: 1px solid var(--border);
      padding: 14px 18px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .panel-hdr h3 {
      font-size: 14px;
      font-weight: 700;
      color: var(--text-bright);
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .panel-body {
      padding: 18px;
    }

    /* ── Code Box & Copy Button ── */
    .code-container {
      position: relative;
      margin-bottom: 16px;
    }
    pre {
      background: var(--bg-code);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px 16px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      line-height: 1.6;
      color: #93c5fd;
      overflow-x: auto;
    }
    .btn-copy {
      position: absolute;
      top: 10px;
      right: 10px;
      background: rgba(255, 255, 255, 0.08);
      border: 1px solid var(--border);
      color: var(--text);
      font-size: 11px;
      font-weight: 600;
      padding: 4px 10px;
      border-radius: 6px;
      cursor: pointer;
      transition: all 0.2s;
    }
    .btn-copy:hover {
      background: var(--primary);
      color: #000;
    }

    /* ── Table Styling ── */
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    th {
      text-align: left;
      padding: 10px 14px;
      border-bottom: 1px solid var(--border);
      color: var(--text-dim);
      font-weight: 600;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    td {
      padding: 10px 14px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.03);
      vertical-align: middle;
    }
    tr:hover td {
      background: rgba(255, 255, 255, 0.02);
    }
    .badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 12px;
      font-size: 11px;
      font-weight: 700;
    }
    .badge-cyan { background: rgba(0, 212, 255, 0.15); color: var(--primary); }
    .badge-green { background: rgba(0, 255, 136, 0.15); color: var(--green); }
    .badge-yellow { background: rgba(245, 166, 35, 0.15); color: var(--yellow); }
    .badge-red { background: rgba(255, 59, 59, 0.15); color: var(--red); }

    .btn-action {
      background: rgba(255, 255, 255, 0.06);
      border: 1px solid var(--border);
      color: var(--text);
      border-radius: 6px;
      padding: 4px 10px;
      font-size: 12px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      margin-right: 6px;
      transition: all 0.2s;
    }
    .btn-action:hover {
      background: var(--primary);
      color: #000;
      border-color: var(--primary);
    }

    /* ── Modal ── */
    .modal-overlay {
      position: fixed;
      inset: 0;
      background: rgba(0,0,0,0.8);
      backdrop-filter: blur(6px);
      display: none;
      align-items: center;
      justify-content: center;
      z-index: 1000;
      padding: 20px;
    }
    .modal-overlay.open {
      display: flex;
    }
    .modal-box {
      background: var(--bg-panel);
      border: 1px solid var(--border);
      border-radius: 12px;
      width: 100%;
      max-width: 1100px;
      height: 85vh;
      display: flex;
      flex-direction: column;
      overflow: hidden;
      box-shadow: 0 20px 50px rgba(0,0,0,0.8);
    }
    .modal-hdr {
      background: var(--bg);
      border-bottom: 1px solid var(--border);
      padding: 12px 18px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .modal-iframe {
      flex: 1;
      width: 100%;
      border: none;
      background: #0a0e1a;
    }

    /* Toast */
    #toast {
      position: fixed;
      bottom: 24px;
      right: 24px;
      background: var(--primary);
      color: #000;
      font-weight: 700;
      font-size: 13px;
      padding: 10px 18px;
      border-radius: 8px;
      box-shadow: 0 8px 24px rgba(0,0,0,0.6);
      display: none;
      z-index: 2000;
    }
  </style>
</head>
<body>

<header>
  <div class="brand">
    <div class="logo-badge">🛡️</div>
    <div>
      <div class="brand-title">Omni-Arch <span>Pro v3.0</span></div>
      <div class="brand-subtitle">Defensive Cyber Audit &amp; Architecture Suite</div>
    </div>
  </div>
  <div class="status-pill">
    <span class="status-dot"></span>
    SERVER ACTIVE · PORT 3000
  </div>
</header>

<main>
  <!-- Console / Search Bar -->
  <div class="console-hero">
    <div class="hero-h1">Interactive Recon &amp; Architecture Console</div>
    <div class="hero-desc">Enter any public domain to run full OSINT reconnaissance, security audit, reverse-engineering, and generate copy-pasteable remediation patches.</div>
    <div class="input-row">
      <div class="input-box">
        <span class="input-icon">🌐</span>
        <input type="text" id="domain-input" placeholder="e.g. hackertarget.com or stripe.com" value="hackertarget.com" autofocus>
      </div>
      <select class="profile-select" id="scan-profile">
        <option value="full">⚡ Full Security &amp; Remediation Audit</option>
        <option value="arch">🏗️ Architecture &amp; Clean Blueprint</option>
        <option value="ports">🔌 Fast TCP Port Scanner (12 Ports)</option>
        <option value="cookies">🍪 Cookie &amp; CORS Inspection</option>
      </select>
      <button class="btn-launch" id="btn-run" onclick="runAudit()">
        <span>Launch Audit</span> 🚀
      </button>
    </div>
    <div id="progress-bar"><div id="progress-fill"></div></div>
  </div>

  <!-- Navigation Tabs -->
  <div class="tabs-nav">
    <button class="tab-btn active" onclick="switchTab('tab-overview', this)">📊 Security Overview</button>
    <button class="tab-btn" onclick="switchTab('tab-remediation', this)">🛠️ Auto-Fix Patches</button>
    <button class="tab-btn" onclick="switchTab('tab-blueprint', this)">🏗️ Architecture &amp; Blueprint</button>
    <button class="tab-btn" onclick="switchTab('tab-reports', this)">🗂️ Report Center (<span id="report-count">0</span>)</button>
  </div>

  <!-- TAB 1: Security Overview -->
  <div id="tab-overview" class="tab-content active">
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-label">Risk Score</div>
        <div class="stat-val" id="metric-risk" style="color:var(--green)">--/100</div>
        <div class="stat-sub" id="metric-risk-label">Awaiting Scan</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Header Grade</div>
        <div class="stat-val" id="metric-grade" style="color:var(--primary)">--</div>
        <div class="stat-sub" id="metric-grade-score">0/6 score</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">SSL Validity</div>
        <div class="stat-val" id="metric-ssl" style="color:var(--green)">--</div>
        <div class="stat-sub" id="metric-ssl-status">Valid TLS</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Open Ports</div>
        <div class="stat-val" id="metric-ports" style="color:var(--text-bright)">--</div>
        <div class="stat-sub" id="metric-ports-risky">0 critical</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Subdomains</div>
        <div class="stat-val" id="metric-subs" style="color:var(--primary)">--</div>
        <div class="stat-sub">Multi-Source OSINT</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Cookie / CORS</div>
        <div class="stat-val" id="metric-cookies" style="color:var(--green)">--</div>
        <div class="stat-sub">OWASP Hardening</div>
      </div>
    </div>

    <!-- Live Details Section -->
    <div class="panel">
      <div class="panel-hdr">
        <h3><span>🏆</span> Security Headers &amp; RFC Compliance</h3>
      </div>
      <div class="panel-body" id="headers-container">
        <p style="color:var(--text-dim)">Click "Launch Audit" above to run an active assessment on the target domain.</p>
      </div>
    </div>

    <div class="panel">
      <div class="panel-hdr">
        <h3><span>🔌</span> Open Ports &amp; Service Mapping</h3>
      </div>
      <div class="panel-body" id="ports-container">
        <p style="color:var(--text-dim)">No active port scan performed yet.</p>
      </div>
    </div>

    <div class="panel">
      <div class="panel-hdr">
        <h3><span>🗺</span> Subdomain Infrastructure Map</h3>
      </div>
      <div class="panel-body" id="subdomains-container">
        <p style="color:var(--text-dim)">No subdomains discovered yet.</p>
      </div>
    </div>
  </div>

  <!-- TAB 2: Auto-Fix Patches -->
  <div id="tab-remediation" class="tab-content">
    <div class="panel">
      <div class="panel-hdr">
        <h3><span>🛠</span> 1-Click Defensive Hardening Configurations</h3>
      </div>
      <div class="panel-body">
        <p style="color:var(--text-dim);margin-bottom:18px">Copy these production-ready configuration snippets directly into your reverse proxy, DNS manager, or cloud edge to immediately remediate missing security headers and harden email delivery.</p>

        <div style="font-weight:700;color:var(--primary);margin-bottom:6px">1. Nginx Hardening (nginx.conf)</div>
        <div class="code-container">
          <button class="btn-copy" onclick="copySnippet('code-nginx')">Copy Nginx</button>
          <pre id="code-nginx"># Run an audit to generate tailored Nginx snippets...</pre>
        </div>

        <div style="font-weight:700;color:var(--primary);margin-bottom:6px">2. Vercel Edge Headers (vercel.json)</div>
        <div class="code-container">
          <button class="btn-copy" onclick="copySnippet('code-vercel')">Copy Vercel</button>
          <pre id="code-vercel">// Run an audit to generate tailored Vercel snippets...</pre>
        </div>

        <div style="font-weight:700;color:var(--primary);margin-bottom:6px">3. Next.js Headers (next.config.js)</div>
        <div class="code-container">
          <button class="btn-copy" onclick="copySnippet('code-next')">Copy Next.js</button>
          <pre id="code-next">// Run an audit to generate tailored Next.js snippets...</pre>
        </div>

        <div style="font-weight:700;color:var(--primary);margin-bottom:6px">4. Recommended DMARC DNS TXT Record</div>
        <div class="code-container">
          <button class="btn-copy" onclick="copySnippet('code-dmarc')">Copy DMARC</button>
          <pre id="code-dmarc">v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc-reports@example.com;</pre>
        </div>
      </div>
    </div>
  </div>

  <!-- TAB 3: Architecture & Blueprint -->
  <div id="tab-blueprint" class="tab-content">
    <div class="panel">
      <div class="panel-hdr">
        <h3><span>🏗</span> Analyzed Architecture &amp; Re-Engineered Alternative</h3>
      </div>
      <div class="panel-body">
        <div id="arch-overview" style="margin-bottom:20px;color:var(--text-dim)">
          Launch an Architecture scan to dissect frontend frameworks, component flows, and generate clean alternative code blueprints.
        </div>

        <div style="font-weight:700;color:var(--primary);margin-bottom:6px">Modern Alternative HTML5 SPA Blueprint</div>
        <div class="code-container">
          <button class="btn-copy" onclick="copySnippet('code-spa')">Copy HTML5 SPA</button>
          <pre id="code-spa">&lt;!-- Clean alternative SPA code will appear here --&gt;</pre>
        </div>

        <div style="font-weight:700;color:var(--primary);margin-bottom:6px">Hardened Node.js Microservice Architecture</div>
        <div class="code-container">
          <button class="btn-copy" onclick="copySnippet('code-microservice')">Copy Backend</button>
          <pre id="code-microservice">// Hardened backend microservice will appear here</pre>
        </div>
      </div>
    </div>
  </div>

  <!-- TAB 4: Report Center -->
  <div id="tab-reports" class="tab-content">
    <div class="panel">
      <div class="panel-hdr">
        <h3><span>🗂</span> Saved Executive Reports (HTML &amp; Markdown)</h3>
        <button class="btn-action" onclick="fetchReports()">🔄 Refresh List</button>
      </div>
      <div class="panel-body">
        <table>
          <thead>
            <tr>
              <th>File Name</th>
              <th>Target Domain</th>
              <th>Type</th>
              <th>Size</th>
              <th>Generated Date</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="reports-table-body">
            <tr><td colspan="6" style="color:var(--text-dim);text-align:center">Loading reports...</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</main>

<!-- Modal for Previewing Reports -->
<div class="modal-overlay" id="preview-modal">
  <div class="modal-box">
    <div class="modal-hdr">
      <h3 id="modal-title" style="color:var(--primary);font-size:14px;display:flex;align-items:center;gap:8px">📄 Report Preview</h3>
      <button class="btn-action" style="margin:0" onclick="closeModal()">✕ Close</button>
    </div>
    <iframe class="modal-iframe" id="modal-frame"></iframe>
  </div>
</div>

<div id="toast">Copied to clipboard!</div>

<script>
  function switchTab(tabId, el) {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    if (el) el.classList.add('active');
    const targetTab = document.getElementById(tabId);
    if (targetTab) targetTab.classList.add('active');
    if (tabId === 'tab-reports') fetchReports();
  }

  function showToast(msg = 'Copied to clipboard!') {
    const t = document.getElementById('toast');
    if (!t) return;
    t.innerText = msg;
    t.style.display = 'block';
    setTimeout(() => { t.style.display = 'none'; }, 2500);
  }

  function copySnippet(id) {
    const el = document.getElementById(id);
    if (!el) return;
    navigator.clipboard.writeText(el.innerText);
    showToast('Snippet copied to clipboard!');
  }

  function openPreview(url, title) {
    document.getElementById('modal-title').innerText = '📄 ' + title;
    document.getElementById('modal-frame').src = url;
    document.getElementById('preview-modal').classList.add('open');
  }

  function closeModal() {
    document.getElementById('preview-modal').classList.remove('open');
    document.getElementById('modal-frame').src = '';
  }

  async function fetchReports() {
    try {
      const res = await fetch('/api/reports');
      const data = await res.json();
      const countEl = document.getElementById('report-count');
      if (countEl) countEl.innerText = data.length;
      const tbody = document.getElementById('reports-table-body');
      if (!tbody) return;
      if (!data.length) {
        tbody.innerHTML = '<tr><td colspan="6" style="color:var(--text-dim);text-align:center">No reports saved yet. Run an audit to generate reports!</td></tr>';
        return;
      }
      tbody.innerHTML = data.map(r => \`
        <tr>
          <td><b>\${r.filename}</b></td>
          <td><code>\${r.target}</code></td>
          <td><span class="badge \${r.type === 'html' ? 'badge-cyan' : 'badge-yellow'}">\${r.type.toUpperCase()}</span></td>
          <td>\${(r.size / 1024).toFixed(1)} KB</td>
          <td>\${new Date(r.mtime).toLocaleString()}</td>
          <td>
            \${r.type === 'html' ? \`<button class="btn-action" onclick="openPreview('/reports/\${r.filename}', '\${r.filename}')">👁 Preview</button>\` : ''}
            <a class="btn-action" href="/reports/\${r.filename}" target="_blank">↗ Open</a>
          </td>
        </tr>
      \`).join('');
    } catch (e) {
      console.error(e);
    }
  }

  async function runAudit() {
    const inputEl = document.getElementById('domain-input');
    const domain = (inputEl ? inputEl.value : '').trim();
    if (!domain) {
      showToast('Please enter a target domain name');
      return;
    }
    const profile = (document.getElementById('scan-profile')?.value || 'full').toLowerCase();

    const btn = document.getElementById('btn-run');
    const prog = document.getElementById('progress-bar');
    if (btn) {
      btn.disabled = true;
      btn.innerHTML = '<span>Scanning...</span> ⌛';
    }
    if (prog) prog.style.display = 'block';

    try {
      const res = await fetch('/api/audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain, profile })
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.error || \`HTTP error \${res.status}\`);
      }

      const data = await res.json();

      if (profile === 'arch' && data.blueprint) {
        renderArch(data);
        const blueprintBtn = document.querySelectorAll('.tab-btn')[2];
        if (blueprintBtn) switchTab('tab-blueprint', blueprintBtn);
      } else {
        renderAudit(data);
      }
      fetchReports();
    } catch (err) {
      console.error('Audit failed:', err);
      showToast('Notice: ' + err.message);
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = '<span>Launch Audit</span> 🚀';
      }
      if (prog) prog.style.display = 'none';
    }
  }

  function renderAudit(data) {
    const s = data.summary || {};
    const rScore = typeof s.risk_score === 'number' ? s.risk_score : '--';
    const rColor = rScore >= 70 ? 'var(--red)' : rScore >= 45 ? 'var(--yellow)' : 'var(--green)';
    
    const metricRisk = document.getElementById('metric-risk');
    if (metricRisk) {
      metricRisk.innerText = rScore + (typeof rScore === 'number' ? '/100' : '');
      metricRisk.style.color = rColor;
    }
    const metricRiskLabel = document.getElementById('metric-risk-label');
    if (metricRiskLabel) metricRiskLabel.innerText = s.risk_level || 'Evaluated';

    const metricGrade = document.getElementById('metric-grade');
    if (metricGrade) metricGrade.innerText = (String(s.header_grade || 'N/A')).split(' ')[0];
    const metricGradeScore = document.getElementById('metric-grade-score');
    if (metricGradeScore) metricGradeScore.innerText = s.header_score || '';

    const metricSsl = document.getElementById('metric-ssl');
    if (metricSsl) {
      const days = s.ssl_days_remaining;
      metricSsl.innerText = typeof days === 'number' ? days + 'd' : (days || '--');
    }
    const metricSslStatus = document.getElementById('metric-ssl-status');
    if (metricSslStatus) metricSslStatus.innerText = s.ssl_status || 'TLS active';

    const metricPorts = document.getElementById('metric-ports');
    if (metricPorts) metricPorts.innerText = (s.open_ports ?? 0) + ' open';
    const metricPortsRisky = document.getElementById('metric-ports-risky');
    if (metricPortsRisky) metricPortsRisky.innerText = (s.risky_ports ?? 0) + ' risky';

    const metricSubs = document.getElementById('metric-subs');
    if (metricSubs) metricSubs.innerText = s.subdomains_found ?? 0;
    const metricCookies = document.getElementById('metric-cookies');
    if (metricCookies) metricCookies.innerText = s.cookie_cors_risk || 'Optimal';

    // Populate Remediation Tab
    if (s.remediation_snippets) {
      const elNginx = document.getElementById('code-nginx');
      if (elNginx) elNginx.innerText = s.remediation_snippets.nginx || '';
      const elVercel = document.getElementById('code-vercel');
      if (elVercel) elVercel.innerText = s.remediation_snippets.vercel_json || '';
      const elNext = document.getElementById('code-next');
      if (elNext) elNext.innerText = s.remediation_snippets.next_config_js || '';
      const elDmarc = document.getElementById('code-dmarc');
      if (elDmarc && s.remediation_snippets.dmarc_dns_record) {
        elDmarc.innerText =
          'Record: ' + s.remediation_snippets.dmarc_dns_record.name + '\\nType: TXT\\nValue: ' + s.remediation_snippets.dmarc_dns_record.value;
      }
    }

    // Populate Headers container
    const headersBox = document.getElementById('headers-container');
    if (headersBox) {
      if (data.cookies) {
        const findingsList = (data.cookies.findings || []).map(f => \`<li style="color:var(--yellow);margin-bottom:4px">\${f}</li>\`).join('') || '<li>No cookie/CORS vulnerabilities detected.</li>';
        headersBox.innerHTML = \`
          <div style="margin-bottom:10px;font-size:13px;color:var(--text-bright)">Cookie &amp; CORS Posture: <b style="color:\${s.cookie_cors_risk === 'CRITICAL' ? 'var(--red)' : 'var(--green)'}">\${s.cookie_cors_risk || 'Optimal'}</b></div>
          <ul style="margin-left:18px;color:var(--text)">\${findingsList}</ul>
        \`;
      } else {
        headersBox.innerHTML = \`
          <div style="margin-bottom:12px;font-size:13px;color:var(--text-bright)">Grade: <b style="color:\${rColor}">\${s.header_grade || 'N/A'}</b> (\${s.header_score || ''})</div>
          <div style="color:var(--text-dim);font-size:12px">Full dark-mode HTML &amp; Markdown reports generated in reports/ folder. Switch to "Auto-Fix Patches" to copy configurations!</div>
        \`;
      }
    }

    // Populate Ports container
    const portsBox = document.getElementById('ports-container');
    if (portsBox) {
      if (data.ports && data.ports.open_ports) {
        const badges = data.ports.open_ports.map(p => \`<span class="badge \${p.risk === 'HIGH' ? 'badge-red' : 'badge-cyan'}" style="margin:2px 4px">\${p.port}/\${p.service} (\${p.risk})</span>\`).join('') || '<span style="color:var(--green)">No exposed services detected.</span>';
        portsBox.innerHTML = \`
          <div style="margin-bottom:8px;font-size:13px;color:var(--text-bright)">Detected <b>\${s.open_ports ?? 0}</b> open ports (\${s.risky_ports ?? 0} flagged risky):</div>
          <div>\${badges}</div>
        \`;
      } else {
        portsBox.innerHTML = \`
          <div style="font-size:13px;color:var(--text-bright)">Detected <b>\${s.open_ports ?? 0}</b> open ports (\${s.risky_ports ?? 0} flagged risky). View full breakdown in HTML Report.</div>
        \`;
      }
    }

    // Populate Subdomains container
    const subsBox = document.getElementById('subdomains-container');
    if (subsBox) {
      subsBox.innerHTML = \`
        <div style="font-size:13px;color:var(--text-bright)">Discovered <b>\${s.subdomains_found ?? 0}</b> subdomains via certificate transparency and passive OSINT fallback.</div>
      \`;
    }

    showToast('Scan complete! Reports saved.');
  }

  function renderArch(data) {
    const arch = data.blueprint || {};
    const archOverview = document.getElementById('arch-overview');
    if (archOverview) {
      archOverview.innerHTML = \`
        <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px">
          <span class="badge badge-cyan">Frameworks: \${(arch.analyzed_frameworks||[]).join(', ') || 'Modern Vanilla'}</span>
          <span class="badge badge-green">Styling: \${(arch.analyzed_styling||[]).join(', ') || 'Custom CSS'}</span>
        </div>
        <div style="color:var(--text);font-size:13px;margin-bottom:8px">\${arch.remediation_summary || ''}</div>
      \`;
    }
    if (arch.blueprints) {
      const elSpa = document.getElementById('code-spa');
      if (elSpa) elSpa.innerText = arch.blueprints.frontend_html5_spa || '';
      const elNode = document.getElementById('code-microservice');
      if (elNode) elNode.innerText = arch.blueprints.backend_microservice_node || '';
    }
    showToast('Architecture blueprints generated!');
  }

  // Initial load and event wiring
  window.addEventListener('DOMContentLoaded', () => {
    fetchReports();

    const domainInput = document.getElementById('domain-input');
    if (domainInput) {
      domainInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          runAudit();
        }
      });
    }

    const btnRun = document.getElementById('btn-run');
    if (btnRun) {
      btnRun.addEventListener('click', (e) => {
        e.preventDefault();
        runAudit();
      });
    }
  });
</script>
</body>
</html>`;

// ─── HTTP Server Router ──────────────────────────────────────
const server = http.createServer(async (req, res) => {
    const parsedUrl = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    const pathname  = parsedUrl.pathname;

    // CORS preflight
    if (req.method === "OPTIONS") {
        res.writeHead(204, {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
            "Access-Control-Max-Age": "86400",
        });
        return res.end();
    }

    try {
        // 1. Dashboard UI Root
        if (req.method === "GET" && pathname === "/") {
            res.writeHead(200, {
                "Content-Type": "text/html; charset=utf-8",
                "Access-Control-Allow-Origin": "*",
            });
            return res.end(DASHBOARD_HTML);
        }

        // 2. API: Run Audit (Handles all scan modes: full, arch, ports, cookies)
        if (req.method === "POST" && pathname === "/api/audit") {
            const body = await parseJsonBody(req);
            const rawDomain = body.domain || body.target || body.host || "";
            const domain = cleanDomain(rawDomain);
            if (!domain) return sendJson(res, 400, { success: false, error: "Domain parameter required" });

            const profile = (body.profile || body.mode || "full").toLowerCase();
            stats.auditsRun++;

            try {
                if (profile === "ports") {
                    const portsResult = await tcpPortScanner(domain);
                    const riskScore = Math.min((portsResult.total_risky || 0) * 25 + (portsResult.total_open || 0) * 5, 100);
                    return sendJson(res, 200, {
                        success: true,
                        tool: "tcp_port_scanner",
                        domain,
                        target: domain,
                        profile: "ports",
                        mode: "ports",
                        ports: portsResult,
                        summary: {
                            risk_score: riskScore,
                            risk_level: riskScore >= 50 ? "HIGH" : riskScore >= 20 ? "MEDIUM" : "LOW",
                            header_grade: "N/A",
                            header_score: "Port Mode",
                            ssl_days_remaining: "--",
                            ssl_status: "Skipped in Port Mode",
                            tls_protocol: "N/A",
                            subdomains_found: 0,
                            open_ports: portsResult.total_open ?? 0,
                            risky_ports: portsResult.total_risky ?? 0,
                            cookie_cors_risk: "Optimal",
                        },
                        message: `Port scan completed: ${portsResult.total_open ?? 0} open ports detected.`
                    });
                }

                if (profile === "cookies") {
                    const cookieCorsResult = await cookieCorsAuditor(domain);
                    const riskScore = cookieCorsResult.risk_level === "CRITICAL" ? 75 : cookieCorsResult.risk_level === "HIGH" ? 50 : cookieCorsResult.risk_level === "MEDIUM" ? 25 : 10;
                    return sendJson(res, 200, {
                        success: true,
                        tool: "cookie_cors_auditor",
                        domain,
                        target: domain,
                        profile: "cookies",
                        mode: "cookies",
                        cookies: cookieCorsResult,
                        summary: {
                            risk_score: riskScore,
                            risk_level: cookieCorsResult.risk_level || "LOW",
                            header_grade: "N/A",
                            header_score: "Cookie & CORS Mode",
                            ssl_days_remaining: "--",
                            ssl_status: "Skipped in Cookie Mode",
                            tls_protocol: "N/A",
                            subdomains_found: 0,
                            open_ports: 0,
                            risky_ports: 0,
                            cookie_cors_risk: cookieCorsResult.risk_level || "Optimal",
                            remediation_snippets: {
                                nginx: `# Cookie & CORS Hardening Configuration\nadd_header Set-Cookie "Path=/; Secure; HttpOnly; SameSite=Strict";\nadd_header Access-Control-Allow-Origin "https://${domain}";`
                            }
                        },
                        message: `Cookie & CORS inspection completed: ${cookieCorsResult.findings?.length || 0} findings.`
                    });
                }

                if (profile === "arch") {
                    stats.blueprintsGenerated++;
                    const blueprint = await alternativeBlueprintGenerator(domain, body.specification || "");
                    return sendJson(res, 200, {
                        success: true,
                        tool: "alternative_blueprint_generator",
                        domain,
                        target: domain,
                        profile: "arch",
                        mode: "arch",
                        blueprint,
                        summary: {
                            risk_score: 10,
                            risk_level: "Optimal",
                            header_grade: "A+",
                            header_score: "Blueprint Ready",
                            ssl_days_remaining: "--",
                            ssl_status: "Clean Architecture",
                            tls_protocol: "TLS 1.3",
                            subdomains_found: 0,
                            open_ports: 0,
                            risky_ports: 0,
                            cookie_cors_risk: "Optimal",
                        },
                        message: `Architecture blueprints generated for ${domain}.`
                    });
                }

                // Default: Full Security & Remediation Report
                const report = await generateSecurityReport(domain);
                return sendJson(res, 200, { success: true, domain, target: domain, profile: "full", mode: "full", ...report });
            } catch (scanErr) {
                console.error(`Audit error for ${domain} [${profile}]:`, scanErr);
                return sendJson(res, 200, {
                    success: false,
                    error: scanErr.message,
                    domain,
                    target: domain,
                    profile,
                    mode: profile,
                    summary: {
                        risk_score: 0,
                        risk_level: "Audit Warning",
                        header_grade: "N/A",
                        header_score: scanErr.message.slice(0, 30),
                        ssl_days_remaining: "--",
                        ssl_status: "Incomplete",
                        tls_protocol: "N/A",
                        subdomains_found: 0,
                        open_ports: 0,
                        risky_ports: 0,
                        cookie_cors_risk: "N/A",
                    },
                    message: `Audit completed with notice: ${scanErr.message}`
                });
            }
        }

        // 3. API: Analyze Architecture & Generate Blueprints
        if (req.method === "POST" && pathname === "/api/analyze-architecture") {
            const body = await parseJsonBody(req);
            const rawDomain = body.domain || body.target || "";
            const domain = cleanDomain(rawDomain);
            if (!domain) return sendJson(res, 400, { success: false, error: "Domain parameter required" });

            stats.blueprintsGenerated++;
            try {
                const blueprint = await alternativeBlueprintGenerator(domain, body.specification || "");
                return sendJson(res, 200, { success: true, domain, target: domain, blueprint });
            } catch (archErr) {
                console.error("Architecture analysis error:", archErr);
                return sendJson(res, 200, { success: false, error: archErr.message, blueprint: {} });
            }
        }

        // 4. API: List Reports
        if (req.method === "GET" && pathname === "/api/reports") {
            try {
                const files = await fs.readdir(reportsDir);
                const reports = [];
                for (const f of files) {
                    if (!f.endsWith(".html") && !f.endsWith(".md")) continue;
                    const stat = await fs.stat(path.join(reportsDir, f));
                    const target = f.replace(/-audit\.(html|md)$/, "").replace(/-/g, ".");
                    reports.push({
                        filename: f,
                        target,
                        type: f.endsWith(".html") ? "html" : "md",
                        size: stat.size,
                        mtime: stat.mtime
                    });
                }
                reports.sort((a, b) => new Date(b.mtime) - new Date(a.mtime));
                return sendJson(res, 200, reports);
            } catch {
                return sendJson(res, 200, []);
            }
        }

        // 5. Serve Report Files
        if (req.method === "GET" && pathname.startsWith("/reports/")) {
            const filename = path.basename(pathname);
            const filePath = path.join(reportsDir, filename);

            if (!fsSync.existsSync(filePath)) {
                return sendJson(res, 404, { success: false, error: "Report file not found" });
            }

            const contentType = filename.endsWith(".html") ? "text/html; charset=utf-8" : "text/markdown; charset=utf-8";
            const content = await fs.readFile(filePath, "utf8");
            res.writeHead(200, {
                "Content-Type": contentType,
                "Access-Control-Allow-Origin": "*",
            });
            return res.end(content);
        }

        // 6. API: Live Stats
        if (req.method === "GET" && pathname === "/api/stats") {
            try {
                const files = await fs.readdir(reportsDir);
                return sendJson(res, 200, {
                    ...stats,
                    totalReports: files.length,
                    uptime: process.uptime(),
                });
            } catch {
                return sendJson(res, 200, { ...stats, totalReports: 0, uptime: process.uptime() });
            }
        }

        // 404 Fallback
        return sendJson(res, 404, { success: false, error: `Endpoint not found: ${pathname}` });
    } catch (err) {
        console.error("Server error:", err);
        return sendJson(res, 500, { success: false, error: err.message || "Internal server error" });
    }
});

// Configure server timeouts to prevent premature client disconnections
server.timeout = 180000;
server.keepAliveTimeout = 65000;
server.headersTimeout = 66000;

server.on("clientError", (err, socket) => {
    if (err.code === "ECONNRESET" || !socket.writable) return;
    socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
});

process.on("uncaughtException", (err) => {
    console.error("Uncaught exception in server-ui:", err);
});

process.on("unhandledRejection", (reason) => {
    console.error("Unhandled rejection in server-ui:", reason);
});

server.listen(PORT, () => {
    console.log(`\n============================================================`);
    console.log(`  🛡️  Omni-Arch Pro v3.0 Web UI Dashboard is LIVE!`);
    console.log(`  🌐  URL: http://localhost:${PORT}`);
    console.log(`  📊  Report Center: Active (${reportsDir})`);
    console.log(`============================================================\n`);
});
