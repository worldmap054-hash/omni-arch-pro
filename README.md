# 🛡️ Omni-Arch Pro v3.0 // Matrix Core
### 🚀 Autonomous Cyber Intelligence, Reverse-Engineering & Clean-Room Architecture Suite

![Matrix HUD](https://img.shields.io/badge/Matrix-HUD%20Online-00ff66?style=for-the-badge&logo=matrix&logoColor=black)
![NodeJS](https://img.shields.io/badge/Backend-Node.js-339933?style=for-the-badge&logo=node.js&logoColor=white)
![Security](https://img.shields.io/badge/Security-Enterprise%20Grade-red?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)

---

## 🌟 Introduction & What it Does
**Omni-Arch Pro v3.0 // Matrix Core** is an elite, multi-threaded autonomous cyber intelligence and reverse-engineering platform wrapped in a sleek Web UI Dashboard and Model Context Protocol (MCP) server.

It goes far beyond traditional vulnerability scanners by performing deep heuristic OSINT infrastructure mapping, client-side JavaScript bundle reverse-engineering, clean-room API mock synthesis, and automated zero-trust remediation—all in real-time!

---

## 🚀 The 10 Elite Backend Superpowers

1. 🔍 **Smart Redirect & Multi-Chunk DNS Resolver:** Automatically follows HTTP 301/302 redirect chains up to 5 hops to audit final destination headers, and deep-parses multi-chunk TXT records for 100% accurate SPF and DMARC (`p=reject`) validation.
2. 🕵️‍♂️ **Exposed Source-Map & Git/Env Leak Detector:** Passive scanner for hidden `/.git/HEAD`, `/.env`, and `.js.map` files, reconstructing original un-minified component trees when source maps are exposed.
3. 🧪 **Clean-Room API Mock Synthesizer (REA++):** Parses discovered JS endpoints and client routes to automatically generate a fully running **Node.js/Express Mock Microservice** (`mock_express_microservice.js`) and OpenAPI 3.0.3 specification model (`openapi.json`).
4. 🛡️ **Deep Tech-Stack & WAF Fingerprinter:** Passive signature matching across 50+ WAFs (Cloudflare, AWS WAF, Akamai, Imperva, Fastly) and modern web frameworks (Next.js App Router, Nuxt, SvelteKit, Laravel).
5. 🚩 **Subdomain Takeover & Dangling CNAME Auditor:** Resolves CNAME records for discovered subdomains against fingerprint rules for inactive AWS S3, Vercel, and GitHub Pages instances.
6. 🔑 **Inline + External JS AST & Secret Extractor:** Scans both external bundles and inline `<script>` tags (`window.__NEXT_DATA__`, `window.__INITIAL_STATE__`) for 20+ secret patterns (AWS keys, Google/Firebase keys, JWTs, Stripe) and outdated vulnerable libraries.
7. 🖼️ **Steganography & Image Asset Metadata Inspector:** Downloads branding assets as binary buffers, validates magic bytes, parses EXIF data, and detects trailing payload bytes past EOF boundaries with Shannon entropy checks.
8. 📊 **Mermaid.js Architecture & Attack Topology:** Dynamically synthesizes valid Mermaid.js flowchart syntax mapping ingress traffic flow, WAF barriers, and open ports into executive reports.
9. 📋 **3-Column Structured Audit Matrix:** Every report compiles a clear 3-column tactical decision matrix detailing Component Status, Technical Flaws, Business Impact, and 1-Click Remediation Patches.
10. 🖨️ **Zero-Dependency Print Dossier:** Generates clean HTML reports featuring high-end `@media print` CSS rules for professional 1-click executive PDF exports.

---

## 🛠️ Quick Start & Installation

### 1. Prerequisites
- **Node.js** v18.0.0 or higher
- **npm** v9.0.0 or higher

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/omni-arch-pro.git
cd omni-arch-pro

# Install dependencies
npm install
```

---

## 💻 Usage Modes

### Mode 1: Launch the Local Web UI Dashboard
```bash
npm run ui
# 🌐 Command Center live at: http://localhost:3000
```
- Real-time audit triggers across **Full Audit**, **Architecture Blueprint**, **TCP Ports**, and **Cookies/CORS**.
- Built-in **Report Vault** for previewing and downloading HTML/Markdown dossiers.

### Mode 2: High-Speed CLI Runner
```bash
# Full security audit + HTML/MD report export
npm run audit -- example.com --export

# Fast TCP Port Scanner (12 high-value ports)
npm run audit -- example.com --tool=ports

# Web & JS Bundle Reverse-Engineering
npm run audit -- example.com --tool=js

# Cookie & CORS Security Auditor
npm run audit -- example.com --tool=cookies

# Architecture & Code Structure Analyzer
npm run audit -- example.com --tool=arch

# Local Repository Hardcoded Secret Scanner
npm run audit -- --path=./my-project
```

### Mode 3: Model Context Protocol (MCP) Server
Integrate Omni-Arch Pro directly into **Claude Desktop**, **Cursor**, or any MCP-compatible agent:

Add to your `claude_desktop_config.json` or Cursor `mcp.json`:
```json
{
  "mcpServers": {
    "omni-arch-matrix": {
      "command": "node",
      "args": ["<PATH_TO_OMNI_ARCH_PRO>/index.js"]
    }
  }
}
```

---

## 📚 Complete MCP Tool Registry (15 Tools)

| Tool | Parameters | Description |
|---|---|---|
| `domain_security_audit` | `{ domain }` | DNS records + smart redirect inspection + RFC 7208 multi-chunk SPF & DMARC policies. |
| `ssl_tls_inspector` | `{ domain }` | TLS cipher suites, certificate validity, SANs, days remaining. |
| `subdomain_osint_recon` | `{ domain }` | Multi-source OSINT (crt.sh, HackerTarget, AlienVault) + active DNS wordlist fallback. |
| `sourcemap_and_git_leak_detector` | `{ domain }` | Detects exposed `/.git/HEAD`, `/.env`, and `.js.map` un-minified component trees. |
| `web_metadata_and_robots_analyzer` | `{ domain }` | Audits `robots.txt`, `security.txt`, `sitemap.xml`, and HTML metadata. |
| `local_code_secret_auditor` | `{ path }` | Scans directories for AWS keys, JWTs, Stripe tokens, and database URIs. |
| `js_bundle_reverser` | `{ domain }` | Extracts API paths, cloud endpoints, secrets, and outdated frontend dependencies. |
| `tcp_port_scanner` | `{ domain }` | High-speed TCP socket scanner across 12 high-value administrative/database ports. |
| `cookie_cors_auditor` | `{ domain }` | Inspects `Set-Cookie` flags (`Secure`, `HttpOnly`, `SameSite`) and CORS origin reflection. |
| `steganography_and_image_inspector` | `{ domain }` | Checks branding assets for EXIF GPS tags and hidden appended payloads past EOF boundaries. |
| `vulnerability_and_header_remediator` | `{ domain }` | Generates 1-click configs for Nginx, Vercel, Next.js, Cloudflare, Apache, and DMARC. |
| `code_structure_analyzer` | `{ domain }` | Analyzes public frontend frameworks, styling engines, and component hierarchy. |
| `alternative_blueprint_generator` | `{ domain }` | Synthesizes modern alternative HTML5 SPA and hardened Express microservices. |
| `strategic_swot_analyzer` | `{ domain }` | Computes an automated heuristic SWOT analysis and security ROI metrics. |
| `generate_security_report` | `{ domain }` | Runs all 10 superpower engines in parallel and exports printable executive dossiers. |

---

## 📁 Project Architecture

```
omni-arch-pro/
├── index.js              # Core Autonomous Engine (10 Superpowers & 15 MCP Tools)
├── server-ui.js          # Web UI Dashboard & Real-Time HTTP API Server
├── cli-test.js           # CLI Terminal Runner with ANSI styling & Spinners
├── package.json          # Manifest, Dependencies & npm run scripts
├── .gitignore            # Git exclusion rules (node_modules, reports, logs)
└── README.md             # Project Documentation
```

---

## 🔒 Security & Defensive Ethics
This suite is designed strictly for **defensive security auditing, blue-team infrastructure hardening, and reverse-engineering research**. Always ensure you have appropriate authorization before auditing third-party systems.

---

## 📄 License
Released under the [MIT License](LICENSE).
