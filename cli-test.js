#!/usr/bin/env node
// ============================================================
//  Omni-Recon Pro v3.0 — Hybrid OSINT & Web Reverse Engineering CLI
//  Usage:
//    node cli-test.js example.com              → full scan (6 tools)
//    node cli-test.js example.com --export     → full scan + HTML/MD report
//    node cli-test.js example.com --tool=ports → TCP port scan only
//    node cli-test.js example.com --tool=js    → JS bundle reverser only
//    node cli-test.js --path=./myproject       → local secret scanner
// ============================================================

import {
    domainSecurityAudit,
    sslTlsInspector,
    subdomainOsintRecon,
    webMetadataAndRobotsAnalyzer,
    localCodeSecretAuditor,
    tcpPortScanner,
    jsBundleReverser,
    cookieCorsAuditor,
    codeStructureAnalyzer,
    alternativeBlueprintGenerator,
    vulnerabilityAndHeaderRemediator,
    generateSecurityReport,
} from "./index.js";

// ─── ANSI Color Palette ──────────────────────────────────────
const C = {
    reset:   "\x1b[0m",
    bold:    "\x1b[1m",
    dim:     "\x1b[2m",
    red:     "\x1b[38;5;203m",
    green:   "\x1b[38;5;120m",
    yellow:  "\x1b[38;5;220m",
    cyan:    "\x1b[38;5;87m",
    blue:    "\x1b[38;5;75m",
    magenta: "\x1b[38;5;213m",
    orange:  "\x1b[38;5;215m",
    white:   "\x1b[97m",
    bgDark:  "\x1b[48;5;235m",
    gray:    "\x1b[38;5;245m",
};

const clr  = (color, text) => `${C[color]}${text}${C.reset}`;
const bold  = (text)        => `${C.bold}${text}${C.reset}`;
const dim   = (text)        => `${C.dim}${text}${C.reset}`;

// ─── Banner ──────────────────────────────────────────────────
function printBanner() {
    const line = "═".repeat(62);
    console.log(`\n${clr("cyan", bold(line))}`);
    console.log(clr("cyan", bold("  ██████╗ ███╗   ███╗███╗   ██╗██╗    ██████╗ ███████╗ ██████╗ ")));
    console.log(clr("cyan", bold("  ██╔═══██╗████╗ ████║████╗  ██║██║    ██╔══██╗██╔════╝██╔════╝ ")));
    console.log(clr("cyan", bold("  ██║   ██║██╔████╔██║██╔██╗ ██║██║    ██████╔╝█████╗  ██║  ███╗")));
    console.log(clr("cyan", bold("  ██║   ██║██║╚██╔╝██║██║╚██╗██║██║    ██╔══██╗██╔══╝  ██║   ██║")));
    console.log(clr("cyan", bold("  ╚██████╔╝██║ ╚═╝ ██║██║ ╚████║██║    ██║  ██║███████╗╚██████╔╝")));
    console.log(clr("cyan", bold("   ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═══╝╚═╝    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ")));
    console.log(`\n  ${clr("magenta", bold("Omni-Recon Pro v3.0"))}  ${dim("— Hybrid OSINT & Web Reverse Engineering")}`);
    console.log(`  ${dim("Powered by Multi-Source OSINT, TCP Port Discovery & JS Reverse Engineering")}`);
    console.log(`${clr("cyan", bold(line))}\n`);
}

// ─── Section Header ──────────────────────────────────────────
function section(title, icon = "◆") {
    const bar = "─".repeat(58);
    console.log(`\n${clr("magenta", bold(`  ${icon} ${title}`))}`);
    console.log(clr("gray", `  ${bar}`));
}

// ─── KV Printer ──────────────────────────────────────────────
function kv(label, value, indent = 4) {
    const pad = " ".repeat(indent);
    const lbl = clr("cyan", `${pad}${label}:`);
    const val = value == null || value === "" ? clr("gray", "N/A")
              : typeof value === "boolean"    ? (value ? clr("green", "✔ yes") : clr("red", "✘ no"))
              : String(value);
    console.log(`${lbl} ${val}`);
}

function bullet(text, color = "white", indent = 6) {
    console.log(`${" ".repeat(indent)}${clr(color, `• ${text}`)}`);
}

// ─── Renderers ───────────────────────────────────────────────

function renderDomainAudit(r) {
    section("DOMAIN SECURITY AUDIT", "🔍");

    kv("Domain",    r.domain);
    kv("Timestamp", r.timestamp);

    section("DNS Records", "🌐");
    kv("IPv4", (r.dns_records.ipv4 || []).join(", ") || "none");
    kv("IPv6", (r.dns_records.ipv6 || []).join(", ") || "none");
    kv("NS",   (r.dns_records.ns   || []).join(", ") || "none");

    const mxList = (r.dns_records.mx || []).map(m => `${m.exchange} (priority ${m.priority})`);
    kv("MX", mxList.join(", ") || "none");

    kv("SPF",   (r.dns_records.spf  || []).join("; ") || clr("yellow", "⚠ Not configured"));
    kv("DMARC", (r.dns_records.dmarc || []).join("; ") || clr("yellow", "⚠ Not configured"));

    section("Server Info", "🖥");
    kv("Status Code",  r.server_info?.status_code);
    kv("Server",       r.server_info?.server);
    kv("X-Powered-By", r.server_info?.x_powered_by);
    kv("Content-Type", r.server_info?.content_type);
    if (r.server_info?.error) kv("Error", clr("red", r.server_info.error));

    section("Security Header Grade", "🏆");
    const grade = r.header_grade || "N/A";
    const gradeColor = grade.startsWith("A") ? "green" : grade.startsWith("B") ? "cyan" : grade.startsWith("C") ? "yellow" : "red";
    kv("Score", r.header_score);
    kv("Grade", clr(gradeColor, bold(grade)));

    if (Object.keys(r.security_headers || {}).length > 0) {
        console.log(`\n    ${clr("green", bold("✔ Present Headers:"))}`);
        for (const [k, v] of Object.entries(r.security_headers)) {
            bullet(`${k}: ${dim(v.slice(0, 80))}`, "green");
        }
    }

    if ((r.missing_headers || []).length > 0) {
        console.log(`\n    ${clr("red", bold("✘ Missing Headers:"))}`);
        for (const h of r.missing_headers) bullet(h, "red");
    }

    if ((r.remediation || []).length > 0) {
        console.log(`\n    ${clr("yellow", bold("💡 Remediation Advice:"))}`);
        for (const tip of r.remediation) bullet(tip, "yellow");
    }
}

function renderSSL(r) {
    section("SSL / TLS CERTIFICATE INSPECTION", "🔐");
    kv("Domain",    r.domain);
    kv("Timestamp", r.timestamp);

    if (r.error) { kv("Error", clr("red", r.error)); return; }

    const c = r.certificate || {};
    const t = r.tls_connection || {};

    section("Certificate Details", "📜");
    kv("Subject CN",       c.subject?.CN || "N/A");
    kv("Issuer Org",       c.issuer?.O || c.issuer?.CN || "N/A");
    kv("Valid From",       c.valid_from);
    kv("Valid To",         c.valid_to);

    const statusColor = (c.expiry_status || "").startsWith("VALID") ? "green"
                      : (c.expiry_status || "").startsWith("WARNING") ? "yellow" : "red";
    kv("Days Remaining",   clr(statusColor, bold(String(c.days_remaining ?? "N/A"))));
    kv("Expiry Status",    clr(statusColor, bold(c.expiry_status || "N/A")));
    kv("Serial Number",    c.serial_number);
    kv("Fingerprint",      c.fingerprint);

    section("TLS Connection", "🔒");
    kv("Protocol",         t.protocol);
    kv("Cipher Suite",     t.cipher_suite);
    kv("Cipher Version",   t.cipher_bits);

    if ((c.subject_alt_names || []).length > 0) {
        section("Subject Alternative Names (SANs)", "🌍");
        c.subject_alt_names.slice(0, 20).forEach(s => bullet(s, "cyan"));
        if (c.subject_alt_names.length > 20)
            console.log(clr("gray", `      ... and ${c.subject_alt_names.length - 20} more`));
    }
}

function renderSubdomain(r) {
    section("SUBDOMAIN OSINT RECONNAISSANCE", "🗺");
    kv("Domain",      r.domain);
    kv("Total Found", r.total_found ?? r.subdomains?.length ?? 0);
    kv("Timestamp",   r.timestamp);

    // Multi-source status
    if ((r.sources_succeeded || []).length > 0) {
        console.log(`\n    ${clr("green", bold("✔ Sources Succeeded:"))}`);
        for (const s of r.sources_succeeded) bullet(s, "green");
    }
    if ((r.sources_failed || []).length > 0) {
        console.log(`\n    ${clr("yellow", bold("⚠ Sources Failed (fallback active):"))}`);
        for (const s of r.sources_failed) bullet(s, "yellow");
    }
    // Legacy single-source field
    if (r.source && !r.sources_queried) kv("Source", r.source);
    if (r.error) { kv("Error", clr("red", r.error)); return; }

    section("Infrastructure Map", "🏗");
    const map = r.infrastructure_map || [];
    if (map.length === 0) { console.log(clr("gray", "    No subdomains resolved.")); return; }

    const maxSub = Math.max(...map.map(e => e.subdomain.length));
    for (const entry of map) {
        const ip = entry.ip === "unresolvable"
            ? clr("gray", entry.ip.padStart(15))
            : clr("green", entry.ip.padStart(15));
        console.log(`      ${clr("cyan", entry.subdomain.padEnd(maxSub + 2))} ${ip}`);
    }
}

function renderMetadata(r) {
    section("WEB METADATA & ROBOTS ANALYZER", "🤖");
    kv("Domain",    r.domain);
    kv("Timestamp", r.timestamp);

    section("robots.txt", "🚦");
    const rob = r.robots_txt || {};
    if (rob.status) { kv("Status", clr("yellow", rob.status)); }
    else {
        kv("Disallowed Paths", (rob.disallowed_paths || []).length + " entries");
        (rob.disallowed_paths || []).slice(0, 10).forEach(p => bullet(p, "orange"));
        kv("Sitemap Refs", (rob.sitemap_references || []).join(", ") || "none");
    }

    section("security.txt", "🔑");
    const sec = r.security_txt || {};
    kv("Found",    sec.found);
    if (sec.found) {
        (sec.contacts || []).forEach(c => kv("Contact", c));
        kv("Expires", sec.expires);
    } else {
        console.log(clr("yellow", `    ⚠  ${sec.note}`));
    }

    section("sitemap.xml", "🗂");
    const sm = r.sitemap_xml || {};
    kv("Found",     sm.found);
    if (sm.found) {
        kv("URL Count", sm.url_count);
        console.log(`    ${dim("Sample URLs:")}`);
        (sm.sample_urls || []).slice(0, 5).forEach(u => bullet(u, "blue"));
    }

    section("HTML Metadata", "🏷");
    const meta = r.html_metadata || {};
    const tags = meta.meta_tags || {};
    for (const [k, v] of Object.entries(tags)) {
        kv(k, v.slice(0, 100));
    }
    if ((meta.public_emails || []).length > 0) {
        console.log(`\n    ${clr("orange", bold("📧 Exposed Emails:"))}`);
        meta.public_emails.forEach(e => bullet(e, "orange"));
    }
    if ((meta.script_sources || []).length > 0) {
        section("External Script Sources", "📦");
        meta.script_sources.slice(0, 10).forEach(s => bullet(s, "blue"));
    }
}

function renderSecretAudit(r) {
    section("LOCAL CODE SECRET AUDITOR", "🔎");
    kv("Scan Path",     r.scan_path);
    kv("Files Scanned", r.files_scanned);
    kv("Total Issues",  r.total_issues);
    kv("Timestamp",     r.timestamp);

    if (r.error) { kv("Error", clr("red", r.error)); return; }

    if (r.total_issues === 0) {
        console.log(`\n    ${clr("green", bold("✅ " + r.risk_summary))}`);
        return;
    }

    console.log(`\n    ${clr("red", bold("🚨 " + r.risk_summary))}\n`);

    for (const f of r.findings) {
        const bar = "─".repeat(54);
        console.log(clr("red", `    ┌${bar}┐`));
        kv("Type",    clr("red", bold(f.type)), 6);
        kv("File",    f.file, 6);
        kv("Line",    f.line, 6);
        kv("Match",   clr("yellow", f.match), 6);
        kv("Snippet", dim(f.snippet), 6);
        console.log(clr("red", `    └${bar}┘`));
    }
}

function renderPortScan(r) {
    section("TCP PORT & SERVICE SCANNER", "🔌");
    kv("Target Domain", r.domain);
    kv("Resolved IP",   r.target_ip || "Failed to resolve");
    kv("Timestamp",     r.timestamp);
    if (r.error) { kv("Error", clr("red", r.error)); return; }

    kv("Open Ports",      clr(r.total_risky > 0 ? "red" : "green", bold(`${r.total_open ?? 0} open`)));
    kv("Risky Exposures", clr(r.total_risky > 0 ? "red" : "green", bold(`${r.total_risky ?? 0} risky`)));

    if ((r.open_ports || []).length > 0) {
        console.log(`\n    ${clr("cyan", bold("Discovered Open Ports & Services:"))}`);
        for (const p of r.open_ports) {
            const riskColor = p.risk === "CRITICAL" ? "red"
                            : p.risk === "HIGH" ? "orange"
                            : p.risk === "MEDIUM" ? "yellow"
                            : p.risk === "LOW" ? "green" : "gray";
            const badge = clr(riskColor, bold(`[${p.risk}]`));
            console.log(`      • ${clr("white", bold(String(p.port).padEnd(6)))} ${clr("cyan", p.service.padEnd(12))} ${badge.padEnd(14)} ${dim(p.note)}`);
        }
    } else {
        console.log(`\n    ${clr("gray", "No open ports found on monitored targets.")}`);
    }
}

function renderJSReverser(r) {
    section("WEB & JS REVERSE ENGINEERING", "⚡");
    kv("Domain",           r.domain);
    kv("Bundles Analyzed", r.total_bundles ?? 0);
    kv("API Endpoints",    clr("cyan", bold(String(r.total_endpoints ?? 0))));
    kv("Cloud References", clr("magenta", bold(String(r.total_cloud_refs ?? 0))));
    kv("Exposed Secrets",  clr((r.total_secrets || 0) > 0 ? "red" : "green", bold(String(r.total_secrets ?? 0))));
    kv("Env Variables",    clr("yellow", bold(String((r.env_variables || []).length))));

    if (r.error) { kv("Error", clr("red", r.error)); return; }

    if ((r.secrets || []).length > 0) {
        console.log(`\n    ${clr("red", bold("🚨 Potential Exposed Secrets / Tokens:"))}`);
        for (const s of r.secrets) {
            bullet(`${clr("red", bold(s.type))}: ${clr("yellow", s.match.slice(0, 80))}`, "red");
        }
    }

    if ((r.env_variables || []).length > 0) {
        console.log(`\n    ${clr("yellow", bold("⚠ Client Environment Variables:"))}`);
        for (const env of r.env_variables) {
            bullet(env, "yellow");
        }
    }

    if ((r.api_endpoints || []).length > 0) {
        console.log(`\n    ${clr("cyan", bold("🌐 Discovered API Routes & Endpoints:"))}`);
        for (const ep of r.api_endpoints.slice(0, 25)) {
            bullet(ep, "cyan");
        }
        if (r.api_endpoints.length > 25) {
            console.log(clr("gray", `      ... and ${r.api_endpoints.length - 25} more`));
        }
    }

    if ((r.cloud_urls || []).length > 0) {
        console.log(`\n    ${clr("magenta", bold("☁ Cloud & Third-Party Integrations:"))}`);
        for (const c of r.cloud_urls.slice(0, 15)) {
            bullet(c, "magenta");
        }
        if (r.cloud_urls.length > 15) {
            console.log(clr("gray", `      ... and ${r.cloud_urls.length - 15} more`));
        }
    }
}

function renderCookiesAndCors(r) {
    section("COOKIE & CORS SECURITY AUDITOR", "🍪");
    kv("Target Domain", r.domain);
    kv("Risk Level",    clr(r.risk_level === "CRITICAL" ? "red" : r.risk_level === "HIGH" ? "orange" : "green", bold(r.risk_level)));
    kv("CORS Origin",   r.cors?.allow_origin);
    kv("Credentials",   r.cors?.allow_credentials);
    kv("Cookies Found", r.cookies?.length ?? 0);
    if ((r.findings || []).length > 0) {
        console.log(`\n    ${clr("yellow", bold("⚠ Findings:"))}`);
        for (const f of r.findings) bullet(f, "yellow");
    }
    if ((r.cookies || []).length > 0) {
        console.log(`\n    ${clr("cyan", bold("Cookie Attributes:"))}`);
        for (const c of r.cookies) {
            bullet(`${clr("white", bold(c.name))}: Secure=${c.secure ? clr("green","✔") : clr("red","✘")}, HttpOnly=${c.httpOnly ? clr("green","✔") : clr("red","✘")}, SameSite=${c.sameSite}`, "white");
        }
    }
}

function renderArchitecture(r) {
    section("ETHICAL CODE STRUCTURE & ARCHITECTURE", "🏗️");
    kv("Target Domain", r.domain);
    kv("Frameworks",    (r.frameworks || []).join(", ") || "Modern Vanilla");
    kv("Styling Engine", (r.styling_engine || []).join(", ") || "Custom CSS");
    if ((r.layout_components || []).length > 0) {
        console.log(`\n    ${clr("cyan", bold("Layout Components Detected:"))}`);
        for (const comp of r.layout_components) bullet(comp, "cyan");
    }
    if ((r.features_detected || []).length > 0) {
        console.log(`\n    ${clr("magenta", bold("Features & Business Logic:"))}`);
        for (const feat of r.features_detected) bullet(feat, "magenta");
    }
}

function renderReportResult(r) {
    section("SECURITY REPORT GENERATED", "📄");
    kv("Domain",    r.domain);
    kv("Timestamp", r.timestamp);
    if (r.error) { kv("Error", clr("red", r.error)); return; }

    console.log(`\n    ${clr("green", bold("✔ Report files saved:"))}`);
    bullet(clr("cyan", r.html_report     || "N/A"), "white");
    bullet(clr("cyan", r.markdown_report || "N/A"), "white");

    const s = r.summary || {};
    section("Report Summary", "📊");
    const riskClr = (s.risk_score || 0) >= 70 ? "red" : (s.risk_score || 0) >= 45 ? "orange" : (s.risk_score || 0) >= 25 ? "yellow" : "green";
    kv("Risk Score",     clr(riskClr, bold(`${s.risk_score ?? "N/A"}/100 (${s.risk_level || "N/A"})`)));
    kv("Header Grade",   s.header_grade);
    kv("Header Score",   s.header_score);
    kv("SSL Days Left",  s.ssl_days_remaining);
    kv("SSL Status",     s.ssl_status);
    kv("TLS Protocol",   s.tls_protocol);
    kv("Subdomains",     s.subdomains_found);
    kv("Open Ports",     `${s.open_ports ?? 0} open (${s.risky_ports ?? 0} risky)`);
    kv("JS Endpoints",   `${s.js_endpoints ?? 0} endpoints (${s.js_secrets ?? 0} secrets)`);
    kv("security.txt",   s.security_txt ? clr("green", "✔ Present") : clr("red", "✘ Missing"));
}

// ─── CLI Entry Point ─────────────────────────────────────────

async function main() {
    const args = process.argv.slice(2);

    // Parse flags
    const flags = {};
    const positional = [];
    for (const arg of args) {
        if (arg.startsWith("--")) {
            const [k, ...rest] = arg.slice(2).split("=");
            flags[k] = rest.join("=") || true;
        } else {
            positional.push(arg);
        }
    }

    const domain    = positional[0] || flags.domain || null;
    const localPath = flags.path    || null;
    const toolFilter = flags.tool   || null;
    const doExport   = flags.export === true || flags.export === "true" || flags.export === "";

    printBanner();

    // ── Help ────────────────────────────────────────────────
    if (!domain && !localPath) {
        console.log(`  ${clr("yellow", bold("Usage:"))}`);
        console.log(`    ${clr("cyan", "node cli-test.js <domain>")}\n`);
        console.log(`    ${dim("Full scan (DNS + TLS + Subdomains + Meta + Ports + JS):")}`);
        console.log(`    ${clr("cyan", "node cli-test.js example.com")}\n`);
        console.log(`    ${dim("Full scan + export HTML/MD report (with Risk Score 0-100):")}`);
        console.log(`    ${clr("cyan", "node cli-test.js example.com --export")}\n`);
        console.log(`    ${dim("Single tool (dns | ssl | subdomain | meta | ports | js | secret):")}`);
        console.log(`    ${clr("cyan", "node cli-test.js example.com --tool=ports")}`);
        console.log(`    ${clr("cyan", "node cli-test.js example.com --tool=js")}\n`);
        console.log(`    ${dim("Local secret scanner:")}`);
        console.log(`    ${clr("cyan", "node cli-test.js --path=./myproject")}\n`);
        process.exit(0);
    }

    const tasks = [];

    if (localPath) {
        tasks.push({ name: "secret", label: "Secret Auditor" });
    } else {
        const all = ["dns", "ssl", "subdomain", "meta", "ports", "js", "secret"];
        const selected = toolFilter ? [toolFilter] : all.filter(t => t !== "secret");
        tasks.push(...selected.map(t => ({ name: t, label: t })));
    }

    const spinner = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"];
    let si = 0;

    const spin = (label) => {
        process.stdout.write(`\r  ${clr("cyan", spinner[si++ % spinner.length])} ${label}...   `);
    };

    const clearSpin = () => process.stdout.write("\r" + " ".repeat(60) + "\r");

    // Collect results for --export
    const collected = {};

    for (const task of tasks) {
        let interval;
        try {
            interval = setInterval(() => spin(`Running ${task.label}`), 80);

            let result;
            switch (task.name) {
                case "dns":
                case "domain":
                    result = await domainSecurityAudit(domain);
                    clearInterval(interval); clearSpin();
                    collected.dns = result;
                    renderDomainAudit(result);
                    break;
                case "ssl":
                case "tls":
                    result = await sslTlsInspector(domain);
                    clearInterval(interval); clearSpin();
                    collected.ssl = result;
                    renderSSL(result);
                    break;
                case "subdomain":
                case "subdomains":
                    result = await subdomainOsintRecon(domain);
                    clearInterval(interval); clearSpin();
                    collected.subdomain = result;
                    renderSubdomain(result);
                    break;
                case "meta":
                    result = await webMetadataAndRobotsAnalyzer(domain);
                    clearInterval(interval); clearSpin();
                    collected.meta = result;
                    renderMetadata(result);
                    break;
                case "ports":
                case "port":
                    result = await tcpPortScanner(domain);
                    clearInterval(interval); clearSpin();
                    collected.ports = result;
                    renderPortScan(result);
                    break;
                case "js":
                case "reverser":
                case "bundle":
                    result = await jsBundleReverser(domain);
                    clearInterval(interval); clearSpin();
                    collected.js = result;
                    renderJSReverser(result);
                    break;
                case "cookies":
                case "cookie":
                case "cors":
                    result = await cookieCorsAuditor(domain);
                    clearInterval(interval); clearSpin();
                    collected.cookies = result;
                    renderCookiesAndCors(result);
                    break;
                case "arch":
                case "architecture":
                case "structure":
                    result = await codeStructureAnalyzer(domain);
                    clearInterval(interval); clearSpin();
                    collected.arch = result;
                    renderArchitecture(result);
                    break;
                case "secret":
                    result = await localCodeSecretAuditor(localPath || domain);
                    clearInterval(interval); clearSpin();
                    collected.secret = result;
                    renderSecretAudit(result);
                    break;
                default:
                    clearInterval(interval); clearSpin();
                    console.log(clr("red", `Unknown tool: ${task.name}. Use: dns, ssl, subdomain, meta, ports, js, cookies, arch, secret`));
            }
        } catch (err) {
            clearInterval(interval); clearSpin();
            console.log(clr("red", `\n  ✘ ${task.label} failed: ${err.message}`));
        }
    }

    // ── Export report if --export flag is set ───────────────
    if (doExport && domain) {
        let interval;
        try {
            interval = setInterval(() => spin("Generating security report"), 80);
            const reportResult = await generateSecurityReport(domain);
            clearInterval(interval); clearSpin();
            renderReportResult(reportResult);
        } catch (err) {
            clearInterval(interval); clearSpin();
            console.log(clr("red", `\n  ✘ Report generation failed: ${err.message}`));
        }
    }

    const footer = "═".repeat(62);
    console.log(`\n${clr("cyan", bold(footer))}`);
    console.log(`  ${clr("green", bold("✔ Omni-Recon Pro v2.1 — Scan Complete!"))}  ${dim(new Date().toLocaleString())}`);
    if (doExport && domain) {
        const slug = domain.replace(/^https?:\/\//, "").split("/")[0].replace(/\./g, "-");
        const reportPath = `reports/${slug}-audit.html`;
        console.log(`  ${clr("cyan", bold("📄 Report:"))} ${dim(reportPath)}`);
    }
    console.log(`${clr("cyan", bold(footer))}\n`);
}

main().catch((err) => {
    console.error(clr("red", `\nFatal error: ${err.message}`));
    process.exit(1);
});

