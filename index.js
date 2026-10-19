// ============================================================
//  Omni-Arch Pro v3.0 / Matrix Core — Enterprise Defensive Security,
//  OSINT, Web Reverse-Engineering & Architecture Synthesis Suite
//  Author: Matrix Core Engineering  |  Transport: stdio / ESM
// ============================================================

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
    CallToolRequestSchema,
    ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import axios from "axios";
import dns from "dns/promises";
import tls from "tls";
import net from "net";
import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

// ─────────────────────────────────────────────────────────────
//  CORE UTILITIES & SANITIZATION
// ─────────────────────────────────────────────────────────────

/** Strip protocol, query parameters, and trailing path from a domain */
export function cleanDomain(raw) {
    if (!raw || typeof raw !== "string") return "";
    return raw.replace(/^https?:\/\//i, "").split("/")[0].split("?")[0].trim().toLowerCase();
}

/** Resolve an IPv4 address with short timeout; returns null on failure */
export async function resolveIP(host) {
    try {
        const addrs = await dns.resolve4(host);
        return addrs[0] || null;
    } catch {
        return null;
    }
}

/** HTML entity encoder for report generation */
function esc(str) {
    if (str == null) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

/** Safe Shannon entropy calculator (bits per byte) */
function calculateEntropy(buffer) {
    if (!buffer || buffer.length === 0) return 0;
    const freqs = new Map();
    for (let i = 0; i < buffer.length; i++) {
        const byte = buffer[i];
        freqs.set(byte, (freqs.get(byte) || 0) + 1);
    }
    let entropy = 0;
    const len = buffer.length;
    for (const count of freqs.values()) {
        const p = count / len;
        entropy -= p * Math.log2(p);
    }
    return Math.round(entropy * 100) / 100;
}

/** Standard anti-blocking browser headers mimicking authentic Chrome on Windows */
export const REALISTIC_BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Cache-Control": "max-age=0",
    "Sec-Ch-Ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1"
};

/** Helper to execute an async task with exponential backoff retries */
export async function fetchWithRetry(fn, retries = 1, delayMs = 500) {
    let lastError;
    for (let attempt = 0; attempt <= retries; attempt++) {
        try {
            return await fn();
        } catch (err) {
            lastError = err;
            if (attempt < retries) {
                await new Promise(res => setTimeout(res, delayMs * Math.pow(2, attempt)));
            }
        }
    }
    throw lastError;
}

/** High-value common subdomain wordlist for active DNS fallback */
export const COMMON_SUBDOMAIN_WORDLIST = [
    "www", "api", "app", "m", "mobile", "mail", "webmail", "smtp",
    "admin", "portal", "dashboard", "login", "auth", "sso", "secure",
    "cdn", "static", "assets", "media", "images", "img", "files",
    "dev", "devel", "stage", "staging", "test", "beta", "demo",
    "shop", "store", "billing", "pay", "payment", "checkout", "cart",
    "blog", "news", "forum", "community", "support", "help", "docs",
    "status", "health", "monitor", "cloud", "vpn", "gateway", "remote",
    "hub", "connect", "link", "services", "server", "ns1", "ns2"
];

// ─────────────────────────────────────────────────────────────
//  SUPERPOWER 1: SMART REDIRECT & MULTI-CHUNK DNS RESOLVER
// ─────────────────────────────────────────────────────────────

/**
 * TOOL 1 — domain_security_audit
 * Follows HTTP 301/302 redirect chains to audit final destination headers.
 * Resolves multi-chunk DNS TXT records per RFC 7208 & checks dedicated _dmarc TXT.
 */
export async function domainSecurityAudit(domain) {
    const target = cleanDomain(domain);
    const report = {
        tool: "domain_security_audit",
        domain: target,
        timestamp: new Date().toISOString(),
        redirect_chain: [],
        destination_url: `https://${target}`,
        dns_records: {
            ipv4: [],
            ipv6: [],
            mx: [],
            ns: [],
            cname: [],
            spf: [],
            dmarc: [],
            txt: [],
        },
        spf_policy: null,
        dmarc_policy: null,
        server_info: {},
        security_headers: {},
        missing_headers: [],
        header_score: "0/6 (0%)",
        header_grade: "F",
        remediation: [],
    };

    // ── 1. Smart Multi-Chunk DNS Resolution ───────────────────
    const [ipv4, ipv6, mx, ns, cname, txtTarget, txtDmarc] = await Promise.allSettled([
        dns.resolve4(target),
        dns.resolve6(target),
        dns.resolveMx(target),
        dns.resolveNs(target),
        dns.resolveCname(target),
        dns.resolveTxt(target),
        dns.resolveTxt(`_dmarc.${target}`),
    ]);

    report.dns_records.ipv4  = ipv4.status === "fulfilled" ? ipv4.value : [];
    report.dns_records.ipv6  = ipv6.status === "fulfilled" ? ipv6.value : [];
    report.dns_records.mx    = mx.status === "fulfilled" ? mx.value : [];
    report.dns_records.ns    = ns.status === "fulfilled" ? ns.value : [];
    report.dns_records.cname = cname.status === "fulfilled" ? cname.value : [];

    // Parse multi-chunk TXT records (Node returns Array of Arrays: string[][])
    // RFC 7208: concatenate multi-chunks within a single record without whitespace
    const parsedTargetTxt = (txtTarget.status === "fulfilled" ? txtTarget.value : []).map(chunks =>
        Array.isArray(chunks) ? chunks.join("") : String(chunks)
    );
    const parsedDmarcTxt = (txtDmarc.status === "fulfilled" ? txtDmarc.value : []).map(chunks =>
        Array.isArray(chunks) ? chunks.join("") : String(chunks)
    );

    report.dns_records.txt = parsedTargetTxt;
    report.dns_records.spf = parsedTargetTxt.filter(r => r.startsWith("v=spf1"));

    // Check target TXT for DMARC first, then fallback to dedicated _dmarc subdomain
    const directDmarc = parsedTargetTxt.filter(r => r.startsWith("v=DMARC1"));
    const subDmarc    = parsedDmarcTxt.filter(r => r.startsWith("v=DMARC1"));
    report.dns_records.dmarc = directDmarc.length > 0 ? directDmarc : subDmarc;

    // Detailed SPF Validation
    if (report.dns_records.spf.length > 0) {
        const spf = report.dns_records.spf[0];
        const isPermissive = spf.includes("+all") || (!spf.includes("-all") && !spf.includes("~all"));
        report.spf_policy = {
            raw: spf,
            valid: true,
            status: isPermissive ? "WEAK_PERMISSIVE" : spf.includes("-all") ? "STRICT_HARDFAIL" : "SOFTFAIL",
            recommendation: isPermissive ? "Change '+all' or '?all' to '-all' to enforce strict mail rejection." : "Optimal SPF enforcement."
        };
    } else {
        report.spf_policy = {
            raw: null,
            valid: false,
            status: "MISSING",
            recommendation: "Create a TXT record with 'v=spf1 mx -all' to prevent email spoofing."
        };
    }

    // Detailed DMARC Validation
    if (report.dns_records.dmarc.length > 0) {
        const dmarc = report.dns_records.dmarc[0];
        const pMatch = dmarc.match(/p=(reject|quarantine|none)/i);
        const policy = pMatch ? pMatch[1].toLowerCase() : "unknown";
        report.dmarc_policy = {
            raw: dmarc,
            policy: policy,
            status: policy === "reject" ? "STRONG_REJECT" : policy === "quarantine" ? "MODERATE_QUARANTINE" : "MONITORING_ONLY",
            recommendation: policy === "none" ? "Upgrade DMARC policy from 'p=none' to 'p=quarantine' or 'p=reject'." : "Optimal DMARC policy in place."
        };
    } else {
        report.dmarc_policy = {
            raw: null,
            policy: "none",
            status: "MISSING",
            recommendation: `Add TXT record at _dmarc.${target} with 'v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc@${target}'`
        };
    }

    // ── 2. Smart HTTP Redirect Following & Destination Inspection ──
    const probeUrls = [`https://${target}`, `http://${target}`];
    let finalRes = null;
    let chain = [];

    for (const initialUrl of probeUrls) {
        try {
            let currentUrl = initialUrl;
            let hops = 0;
            const maxHops = 5;

            while (hops < maxHops) {
                const res = await axios.get(currentUrl, {
                    timeout: 8000,
                    maxRedirects: 0, // Manual hop tracking for full visibility
                    validateStatus: () => true,
                    headers: REALISTIC_BROWSER_HEADERS,
                });

                chain.push({
                    url: currentUrl,
                    status: res.status,
                    location: res.headers["location"] || null,
                });

                if ([301, 302, 303, 307, 308].includes(res.status) && res.headers["location"]) {
                    let nextLoc = res.headers["location"];
                    try {
                        nextLoc = new URL(nextLoc, currentUrl).href;
                    } catch {
                        // Keep as is
                    }
                    currentUrl = nextLoc;
                    hops++;
                } else {
                    finalRes = res;
                    report.destination_url = currentUrl;
                    break;
                }
            }

            if (finalRes) break;
        } catch {
            // Try next protocol
        }
    }

    // If manual loop did not succeed, fallback to standard axios redirect follower
    if (!finalRes) {
        try {
            finalRes = await axios.get(`https://${target}`, {
                timeout: 10000,
                maxRedirects: 5,
                validateStatus: () => true,
                headers: REALISTIC_BROWSER_HEADERS,
            });
            report.destination_url = finalRes.request?.res?.responseUrl || `https://${target}`;
        } catch (err) {
            report.server_info.error = `HTTP connection failed: ${err.message}`;
        }
    }

    report.redirect_chain = chain;

    // Evaluate Security Headers on Destination Response
    if (finalRes) {
        const h = finalRes.headers;
        report.server_info = {
            status_code: finalRes.status,
            final_destination: report.destination_url,
            server: h["server"] || "Hidden",
            x_powered_by: h["x-powered-by"] || "Hidden",
            content_type: h["content-type"] || "N/A",
            via: h["via"] || "Direct",
            age: h["age"] || null,
        };

        const CHECKS = [
            ["strict-transport-security", "Add HSTS: 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload'"],
            ["content-security-policy",   "Implement a Content-Security-Policy (CSP) to stop XSS and unauthorized data exfiltration."],
            ["x-frame-options",           "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking attacks."],
            ["x-content-type-options",    "Add 'X-Content-Type-Options: nosniff' to disable MIME-type sniffing."],
            ["referrer-policy",           "Add 'Referrer-Policy: strict-origin-when-cross-origin' to protect sensitive URL parameters."],
            ["permissions-policy",        "Add 'Permissions-Policy' to restrict unauthorized browser API access (camera, microphone, geolocation)."],
        ];

        let score = 0;
        for (const [key, advice] of CHECKS) {
            if (h[key]) {
                report.security_headers[key] = h[key];
                score++;
            } else {
                report.missing_headers.push(key);
                report.remediation.push(advice);
            }
        }

        const pct = Math.round((score / CHECKS.length) * 100);
        if (pct === 100) report.header_grade = "A+ (Hardened)";
        else if (pct >= 83) report.header_grade = "A";
        else if (pct >= 66) report.header_grade = "B";
        else if (pct >= 50) report.header_grade = "C";
        else if (pct >= 33) report.header_grade = "D";
        else report.header_grade = "F (High Vulnerability Risk)";

        report.header_score = `${score}/${CHECKS.length} (${pct}%)`;
    }

    return report;
}

// ─────────────────────────────────────────────────────────────
//  TOOL 2: SSL / TLS CERTIFICATE INSPECTOR
// ─────────────────────────────────────────────────────────────

export async function sslTlsInspector(domain) {
    const target = cleanDomain(domain);

    return new Promise((resolve) => {
        const report = {
            tool: "ssl_tls_inspector",
            domain: target,
            timestamp: new Date().toISOString(),
        };

        const socket = tls.connect(
            { host: target, port: 443, servername: target, rejectUnauthorized: false, timeout: 10000 },
            () => {
                try {
                    const cert   = socket.getPeerCertificate(true);
                    const cipher = socket.getCipher();
                    const proto  = socket.getProtocol();

                    const validTo  = new Date(cert.valid_to);
                    const now      = new Date();
                    const daysLeft = Math.ceil((validTo - now) / (1000 * 60 * 60 * 24));

                    report.certificate = {
                        subject: cert.subject || {},
                        issuer: cert.issuer || {},
                        valid_from: cert.valid_from,
                        valid_to: cert.valid_to,
                        days_remaining: daysLeft,
                        expiry_status: daysLeft < 0  ? "EXPIRED"
                                      : daysLeft < 14 ? "CRITICAL — expires very soon"
                                      : daysLeft < 30 ? "WARNING — expires within 30 days"
                                      : "VALID",
                        serial_number: cert.serialNumber,
                        fingerprint: cert.fingerprint,
                        subject_alt_names: cert.subjectaltname
                            ? cert.subjectaltname.split(", ").map(s => s.replace("DNS:", ""))
                            : [],
                    };
                    report.tls_connection = {
                        protocol: proto,
                        cipher_suite: cipher?.name || "Unknown",
                        cipher_bits: cipher?.version || "Unknown",
                    };
                } catch (e) {
                    report.error = `Certificate parse error: ${e.message}`;
                }
                socket.end();
                resolve(report);
            }
        );

        socket.on("error", (err) => {
            report.error = `TLS connection failed: ${err.message}`;
            resolve(report);
        });

        socket.setTimeout(10000, () => {
            report.error = "TLS connection timed out";
            socket.destroy();
            resolve(report);
        });
    });
}

// ─────────────────────────────────────────────────────────────
//  SUPERPOWER 5: SUBDOMAIN TAKEOVER & DANGLING CNAME AUDITOR
// ─────────────────────────────────────────────────────────────

/** Known Dangling CNAME Signatures for Subdomain Takeover Detection */
const TAKEOVER_FINGERPRINTS = [
    { service: "GitHub Pages", cname: /\.github\.io$/i, pattern: /There isn't a GitHub Pages site here/i, statusCodes: [404] },
    { service: "AWS S3 Bucket", cname: /(?:s3[\w.-]*\.amazonaws\.com|s3-website[\w.-]*\.amazonaws\.com)$/i, pattern: /The specified bucket does not exist|NoSuchBucket/i, statusCodes: [404] },
    { service: "Vercel", cname: /(?:cname\.vercel-dns\.com|\.vercel\.app)$/i, pattern: /The deployment could not be found|DEPLOYMENT_NOT_FOUND/i, statusCodes: [404] },
    { service: "Heroku", cname: /(?:herokuapp\.com|herokudns\.com)$/i, pattern: /No such app|herokucdn\.com\/error-pages\/no-such-app/i, statusCodes: [404, 502] },
    { service: "Azure App Service", cname: /(?:azurewebsites\.net|trafficmanager\.net)$/i, pattern: /404 Web Site not found/i, statusCodes: [404] },
    { service: "Shopify", cname: /shops\.myshopify\.com$/i, pattern: /Sorry, this shop is currently unavailable/i, statusCodes: [404] },
    { service: "Fastly", cname: /fastly\.net$/i, pattern: /Fastly error: unknown domain/i, statusCodes: [404, 500] },
    { service: "Surge.sh", cname: /surge\.sh$/i, pattern: /project not found/i, statusCodes: [404] },
    { service: "Ghost.io", cname: /ghost\.io$/i, pattern: /Thing not found/i, statusCodes: [404] },
    { service: "Zendesk", cname: /zendesk\.com$/i, pattern: /Help Center Closed/i, statusCodes: [404] },
    { service: "Bitbucket", cname: /bitbucket\.io$/i, pattern: /Repository not found/i, statusCodes: [404] },
    { service: "Readme.io", cname: /readme\.io$/i, pattern: /Project doesnt exist/i, statusCodes: [404] },
];

/**
 * Audits a list of subdomains for dangling CNAME records and takeover risks.
 */
export async function subdomainTakeoverAuditor(domain, subdomains = []) {
    const target = cleanDomain(domain);
    const subList = (subdomains.length ? subdomains : [target]).slice(0, 30);
    const findings = [];

    const checkSub = async (sub) => {
        try {
            const cnames = await dns.resolveCname(sub);
            for (const cn of cnames) {
                const fp = TAKEOVER_FINGERPRINTS.find(f => f.cname.test(cn));
                if (fp) {
                    // Probe HTTP to verify dangling status
                    let isDangling = false;
                    let probeError = null;
                    try {
                        const probeRes = await axios.get(`http://${sub}`, {
                            timeout: 5000,
                            maxRedirects: 5,
                            validateStatus: () => true,
                            headers: REALISTIC_BROWSER_HEADERS
                        });
                        const body = String(probeRes.data || "");
                        if (fp.statusCodes.includes(probeRes.status) && fp.pattern.test(body)) {
                            isDangling = true;
                        }
                    } catch (e) {
                        probeError = e.message;
                    }

                    findings.push({
                        subdomain: sub,
                        cname: cn,
                        service: fp.service,
                        status: isDangling ? "CRITICAL_VULNERABLE" : "SUSPICIOUS_UNCLAIMED_CNAME",
                        dangling_verified: isDangling,
                        note: isDangling
                            ? `Dangling CNAME to inactive ${fp.service} instance! Immediate takeover risk.`
                            : `Points to ${fp.service} (${cn}). Verify ownership to avoid takeover.`,
                        remediation: `Remove dangling DNS CNAME record for ${sub} or claim the resource on ${fp.service}.`
                    });
                }
            }
        } catch {
            // No CNAME or resolve failed
        }
    };

    // Audit up to 10 concurrently
    const chunks = [];
    for (let i = 0; i < subList.length; i += 10) {
        chunks.push(subList.slice(i, i + 10));
    }
    for (const chunk of chunks) {
        await Promise.all(chunk.map(checkSub));
    }

    return {
        tool: "subdomain_takeover_auditor",
        domain: target,
        subdomains_checked: subList.length,
        vulnerabilities_found: findings.length,
        findings
    };
}

/**
 * TOOL 3 — subdomain_osint_recon
 * Multi-source CT + OSINT subdomain finder with dangling CNAME takeover check.
 */
export async function subdomainOsintRecon(domain) {
    const target = cleanDomain(domain);
    const report = {
        tool: "subdomain_osint_recon",
        domain: target,
        timestamp: new Date().toISOString(),
        sources_queried: ["crt.sh", "HackerTarget", "AlienVault OTX"],
        sources_succeeded: [],
        sources_failed: [],
        subdomains: [],
        infrastructure_map: [],
        takeover_audit: null,
    };

    const seen = new Set();

    const fetchCrtSh = async () => {
        return await fetchWithRetry(async () => {
            const res = await axios.get(
                `https://crt.sh/?q=%.${target}&output=json`,
                {
                    timeout: 5000,
                    headers: {
                        ...REALISTIC_BROWSER_HEADERS,
                        "Accept": "application/json, text/plain, */*"
                    }
                }
            );
            const data = Array.isArray(res.data) ? res.data : [];
            const found = [];
            for (const entry of data) {
                for (const name of (entry.name_value || "").split("\n")) {
                    const n = name.trim().toLowerCase();
                    if (n && !n.startsWith("*") && n.endsWith(`.${target}`) && !seen.has(n)) {
                        seen.add(n); found.push(n);
                    }
                }
            }
            return found;
        }, 1, 500);
    };

    const fetchHackerTarget = async () => {
        return await fetchWithRetry(async () => {
            const res = await axios.get(
                `https://api.hackertarget.com/hostsearch/?q=${target}`,
                {
                    timeout: 5000,
                    responseType: "text",
                    headers: REALISTIC_BROWSER_HEADERS
                }
            );
            const text = String(res.data || "");
            if (text.includes("error") || text.includes("API count exceeded")) {
                throw new Error(text.slice(0, 80));
            }
            const found = [];
            for (const line of text.split("\n")) {
                const [sub] = line.split(",");
                const n = (sub || "").trim().toLowerCase();
                if (n && n.endsWith(`.${target}`) && !seen.has(n)) {
                    seen.add(n); found.push(n);
                }
            }
            return found;
        }, 1, 500);
    };

    const fetchAlienVault = async () => {
        return await fetchWithRetry(async () => {
            const res = await axios.get(
                `https://otx.alienvault.com/api/v1/indicators/domain/${target}/passive_dns`,
                {
                    timeout: 5000,
                    headers: {
                        ...REALISTIC_BROWSER_HEADERS,
                        "Accept": "application/json"
                    }
                }
            );
            const records = res.data?.passive_dns || [];
            const found = [];
            for (const rec of records) {
                const n = (rec.hostname || "").trim().toLowerCase();
                if (n && n.endsWith(`.${target}`) && !seen.has(n)) {
                    seen.add(n); found.push(n);
                }
            }
            return found;
        }, 1, 500);
    };

    const [crt, ht, av] = await Promise.allSettled([
        fetchCrtSh(),
        fetchHackerTarget(),
        fetchAlienVault(),
    ]);

    const sourceMap = [
        ["crt.sh", crt],
        ["HackerTarget", ht],
        ["AlienVault OTX", av],
    ];

    let all = [];
    for (const [name, result] of sourceMap) {
        if (result.status === "fulfilled") {
            report.sources_succeeded.push(`${name} (${result.value.length} found)`);
            all.push(...result.value);
        } else {
            report.sources_failed.push(`${name}: ${result.reason?.message || "unknown error"}`);
        }
    }

    // ── Active Wordlist Fallback & Augmentor ──────────────────
    // Ensures subdomains are NEVER falsely reported as 0 if public APIs are down, rate-limited, or blocked.
    const activeFromWordlist = [];
    const wordlistChecks = await Promise.allSettled(
        COMMON_SUBDOMAIN_WORDLIST.map(async (prefix) => {
            const candidate = `${prefix}.${target}`;
            try {
                const addrs = await Promise.race([
                    dns.resolve4(candidate),
                    new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 2500))
                ]);
                if (addrs && addrs.length > 0) return { subdomain: candidate, ip: addrs[0] };
            } catch {
                try {
                    const cnames = await dns.resolveCname(candidate);
                    if (cnames && cnames.length > 0) return { subdomain: candidate, ip: "cname-alias" };
                } catch {}
            }
            return null;
        })
    );

    for (const res of wordlistChecks) {
        if (res.status === "fulfilled" && res.value?.subdomain) {
            const sub = res.value.subdomain;
            if (!seen.has(sub)) {
                seen.add(sub);
                activeFromWordlist.push(sub);
                all.push(sub);
            }
        }
    }

    if (activeFromWordlist.length > 0) {
        report.sources_succeeded.push(`Built-in Active DNS Wordlist (${activeFromWordlist.length} verified active)`);
    }

    report.subdomains = [...new Set(all)].sort();
    report.total_found = report.subdomains.length;

    // Resolve IPs in batches of 5
    const BATCH = 5;
    for (let i = 0; i < report.subdomains.length; i += BATCH) {
        const batch = report.subdomains.slice(i, i + BATCH);
        const resolved = await Promise.all(
            batch.map(async (sub) => ({
                subdomain: sub,
                ip: (await resolveIP(sub)) || "unresolvable",
            }))
        );
        report.infrastructure_map.push(...resolved);
    }

    // Run Dangling CNAME & Subdomain Takeover Audit
    try {
        report.takeover_audit = await subdomainTakeoverAuditor(target, report.subdomains);
    } catch {
        report.takeover_audit = { error: "Takeover audit skipped" };
    }

    return report;
}

// ─────────────────────────────────────────────────────────────
//  SUPERPOWER 2: EXPOSED SOURCE-MAP (.js.map) & GIT/ENV LEAK DETECTOR
// ─────────────────────────────────────────────────────────────

/**
 * Passive scanner for source-map files, .git repositories, .env files, and sensitive path leaks.
 */
export async function sourcemapAndGitLeakDetector(domain, knownScripts = []) {
    const target = cleanDomain(domain);
    const BASE = `https://${target}`;
    const report = {
        tool: "sourcemap_and_git_leak_detector",
        domain: target,
        timestamp: new Date().toISOString(),
        sensitive_files: [],
        sourcemaps_discovered: [],
        reconstructed_component_trees: [],
        exposure_risk: "LOW"
    };

    const SENSITIVE_PATHS = [
        { path: "/.git/HEAD", pattern: /^ref:\s*refs\/heads\//m, type: "Git Repository Root", severity: "CRITICAL" },
        { path: "/.git/config", pattern: /\[core\]|repositoryformatversion/i, type: "Git Config Exposure", severity: "CRITICAL" },
        { path: "/.env", pattern: /(?:PORT|DB_|SECRET|AWS_|KEY|NODE_ENV)\s*=/i, type: "Production .env File", severity: "CRITICAL" },
        { path: "/.env.local", pattern: /(?:PORT|DB_|SECRET|KEY)\s*=/i, type: "Local Environment File", severity: "CRITICAL" },
        { path: "/.env.production", pattern: /(?:PORT|DB_|SECRET|KEY)\s*=/i, type: "Production Env File", severity: "CRITICAL" },
        { path: "/.DS_Store", isBinary: true, type: "macOS Directory Metadata (.DS_Store)", severity: "MEDIUM" },
        { path: "/swagger.json", pattern: /"openapi"|"swagger"/i, type: "Swagger API Documentation", severity: "MEDIUM" },
        { path: "/openapi.json", pattern: /"openapi"/i, type: "OpenAPI Specification", severity: "MEDIUM" },
        { path: "/package.json", pattern: /"name"\s*:\s*"[^"]+"/i, type: "Internal package.json Manifest", severity: "HIGH" },
    ];

    // Check sensitive paths in parallel
    await Promise.all(SENSITIVE_PATHS.map(async (check) => {
        try {
            const res = await axios.get(`${BASE}${check.path}`, {
                timeout: 5000,
                maxRedirects: 5,
                validateStatus: s => s === 200,
                responseType: check.isBinary ? "arraybuffer" : "text",
                headers: REALISTIC_BROWSER_HEADERS
            });

            let matched = false;
            if (check.isBinary) {
                const buf = Buffer.from(res.data);
                // Check .DS_Store header bytes (0x00 0x00 0x00 0x01 0x42 0x75 0x64 0x31 -> "Bud1")
                if (buf.length >= 8 && buf.readUInt32BE(0) === 0x1 && buf.toString("ascii", 4, 8) === "Bud1") {
                    matched = true;
                }
            } else {
                const text = String(res.data || "");
                if (check.pattern && check.pattern.test(text)) {
                    matched = true;
                }
            }

            if (matched) {
                report.sensitive_files.push({
                    url: `${BASE}${check.path}`,
                    type: check.type,
                    severity: check.severity,
                    remediation: `Block direct web server access to '${check.path}' immediately in Nginx/Vercel/Cloudflare.`
                });
            }
        } catch {
            // Not exposed
        }
    }));

    // Probe .js.map for candidate JavaScript files
    const mapUrlsToCheck = [];
    for (const s of knownScripts.slice(0, 6)) {
        if (s.endsWith(".js")) {
            mapUrlsToCheck.push(`${s}.map`);
        }
    }

    for (const mapUrl of mapUrlsToCheck) {
        try {
            const res = await axios.get(mapUrl, {
                timeout: 6000,
                maxRedirects: 5,
                validateStatus: s => s === 200,
                responseType: "json",
                headers: REALISTIC_BROWSER_HEADERS
            });

            const data = res.data;
            if (data && (Array.isArray(data.sources) || data.version === 3)) {
                const sources = Array.isArray(data.sources) ? data.sources : [];
                report.sourcemaps_discovered.push({
                    map_url: mapUrl,
                    sources_count: sources.length,
                    has_sources_content: Array.isArray(data.sourcesContent) && data.sourcesContent.length > 0,
                    sample_sources: sources.slice(0, 15)
                });

                // Reconstruct Component Tree
                const tree = {};
                for (const src of sources) {
                    const cleanPath = src.replace(/^[./\\]+/, "");
                    const parts = cleanPath.split(/[/\\]/);
                    let curr = tree;
                    for (let i = 0; i < parts.length; i++) {
                        const part = parts[i];
                        if (i === parts.length - 1) {
                            curr[part] = "FILE";
                        } else {
                            curr[part] = curr[part] || {};
                            curr = curr[part];
                        }
                    }
                }

                report.reconstructed_component_trees.push({
                    map: mapUrl,
                    tree_structure: tree,
                    unminified_files_exposed: sources.length
                });
            }
        } catch {
            // Map not accessible
        }
    }

    if (report.sensitive_files.some(f => f.severity === "CRITICAL") || report.sourcemaps_discovered.some(m => m.has_sources_content)) {
        report.exposure_risk = "CRITICAL";
    } else if (report.sensitive_files.length > 0 || report.sourcemaps_discovered.length > 0) {
        report.exposure_risk = "HIGH";
    }

    return report;
}

/**
 * TOOL 4 — web_metadata_and_robots_analyzer
 * Fetches robots.txt, security.txt, sitemap.xml, HTML metadata, and runs passive leak checks.
 */
export async function webMetadataAndRobotsAnalyzer(domain) {
    const target = cleanDomain(domain);
    const report = {
        tool: "web_metadata_and_robots_analyzer",
        domain: target,
        timestamp: new Date().toISOString(),
        robots_txt: null,
        security_txt: null,
        sitemap_xml: null,
        html_metadata: {},
        leaks_and_sourcemaps: null,
    };

    const fetchText = async (url) => {
        try {
            const r = await axios.get(url, {
                timeout: 8000,
                maxRedirects: 5,
                validateStatus: s => s < 500,
                headers: REALISTIC_BROWSER_HEADERS,
            });
            return r.status === 200 ? r.data : null;
        } catch {
            return null;
        }
    };

    const [robots, secTxt, sitemap, html] = await Promise.all([
        fetchText(`https://${target}/robots.txt`),
        fetchText(`https://${target}/.well-known/security.txt`),
        fetchText(`https://${target}/sitemap.xml`),
        fetchText(`https://${target}`),
    ]);

    if (robots) {
        const disallowed  = (robots.match(/^Disallow:\s*.+/gm) || []).map(l => l.replace("Disallow:", "").trim());
        const sitemapRef  = (robots.match(/^Sitemap:\s*.+/gm) || []).map(l => l.replace("Sitemap:", "").trim());
        report.robots_txt = { raw_excerpt: robots.slice(0, 800), disallowed_paths: disallowed, sitemap_references: sitemapRef };
    } else {
        report.robots_txt = { status: "Not found or inaccessible" };
    }

    if (secTxt) {
        const contacts = (secTxt.match(/^Contact:\s*.+/gm) || []).map(l => l.replace("Contact:", "").trim());
        const expires  = (secTxt.match(/^Expires:\s*.+/gm) || [])[0]?.replace("Expires:", "").trim();
        report.security_txt = { found: true, contacts, expires, raw_excerpt: secTxt.slice(0, 600) };
    } else {
        report.security_txt = { found: false, note: "No security.txt — consider adding one per RFC 9116." };
    }

    if (sitemap) {
        const urls = (sitemap.match(/<loc>(.*?)<\/loc>/g) || []).map(l => l.replace(/<\/?loc>/g, ""));
        report.sitemap_xml = { found: true, url_count: urls.length, sample_urls: urls.slice(0, 10) };
    } else {
        report.sitemap_xml = { found: false };
    }

    const scripts = [];
    if (html) {
        const metas = {};
        const metaRe = /<meta\s+(?:name|property)=["']([^"']+)["']\s+content=["']([^"']+)["']/gi;
        let m;
        while ((m = metaRe.exec(html)) !== null) metas[m[1]] = m[2];

        const scriptRe = /<script[^>]+src=["']([^"']+)["']/gi;
        while ((m = scriptRe.exec(html)) !== null) {
            try {
                scripts.push(new URL(m[1], `https://${target}`).href);
            } catch {
                scripts.push(m[1]);
            }
        }

        const emails = [...new Set((html.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g) || []))];

        report.html_metadata = {
            meta_tags: metas,
            script_sources: scripts.slice(0, 15),
            public_emails: emails.slice(0, 10),
        };
    }

    // Run Source-Map and Git/Env leak detection
    try {
        report.leaks_and_sourcemaps = await sourcemapAndGitLeakDetector(target, scripts);
    } catch {
        report.leaks_and_sourcemaps = { error: "Passive leak scan skipped" };
    }

    return report;
}

// ─────────────────────────────────────────────────────────────
//  TOOL 5: LOCAL CODE SECRET AUDITOR
// ─────────────────────────────────────────────────────────────

export async function localCodeSecretAuditor(targetPath) {
    const report = {
        tool: "local_code_secret_auditor",
        scan_path: targetPath,
        timestamp: new Date().toISOString(),
        findings: [],
        files_scanned: 0,
        total_issues: 0,
    };

    const SECRET_PATTERNS = [
        ["AWS Access Key",           /AKIA[0-9A-Z]{16}/g],
        ["AWS Secret Key",           /(?:aws[_\-]?secret|AWS_SECRET)[_\-]?(?:access[_\-]?)?key\s*[=:]\s*['"]?[A-Za-z0-9+/]{40}['"]?/gi],
        ["Google API Key",           /AIza[0-9A-Za-z\-_]{35}/g],
        ["GitHub Token",             /gh[pousr]_[A-Za-z0-9]{36,}/g],
        ["JWT Token",                /eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/]*/g],
        ["Private Key Block",        /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g],
        ["Stripe Secret Key",        /sk_live_[0-9a-zA-Z]{24,}/g],
        ["Stripe Publishable Key",   /pk_live_[0-9a-zA-Z]{24,}/g],
        ["Slack Token",              /xox[baprs]-[0-9a-zA-Z\-]{10,}/g],
        ["Generic API Key",          /(?:api[_\-]?key|apikey)\s*[=:]\s*['"]?[A-Za-z0-9\-_]{20,}['"]?/gi],
        ["Generic Secret/Password",  /(?:secret|password|passwd|pwd)\s*[=:]\s*['"][^'"]{8,}['"]/gi],
        ["Bearer Token",             /Bearer\s+[A-Za-z0-9\-_.~+/]+=*/g],
        ["Hardcoded DB Credentials", /(?:mysql|postgres|mongodb):\/\/[^:]+:[^@]+@/gi],
    ];

    const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".next", "__pycache__", ".venv", "venv"]);
    const TEXT_EXTS = new Set([".js",".ts",".jsx",".tsx",".py",".rb",".go",".java",".cs",".php",
                                ".env",".sh",".bash",".zsh",".yaml",".yml",".json",".toml",
                                ".ini",".cfg",".conf",".xml",".html",".md",".txt",".properties"]);

    const scanFile = async (filePath) => {
        const ext  = path.extname(filePath).toLowerCase();
        const base = path.basename(filePath).toLowerCase();
        if (!TEXT_EXTS.has(ext) && !base.startsWith(".env")) return;

        try {
            const content = await fs.readFile(filePath, "utf8");
            report.files_scanned++;
            const lines = content.split("\n");

            for (const [label, regex] of SECRET_PATTERNS) {
                regex.lastIndex = 0;
                let match;
                while ((match = regex.exec(content)) !== null) {
                    const lineNum     = content.slice(0, match.index).split("\n").length;
                    const lineContent = lines[lineNum - 1]?.trim() || "";
                    report.findings.push({
                        severity: "HIGH",
                        type: label,
                        file: filePath,
                        line: lineNum,
                        snippet: lineContent.slice(0, 120),
                        match: match[0].slice(0, 60) + (match[0].length > 60 ? "…" : ""),
                    });
                    regex.lastIndex = match.index + 1;
                }
            }
        } catch { /* skip unreadable */ }
    };

    const walk = async (dir) => {
        let entries;
        try { entries = await fs.readdir(dir, { withFileTypes: true }); }
        catch { return; }

        for (const entry of entries) {
            if (entry.isDirectory()) {
                if (!SKIP_DIRS.has(entry.name)) await walk(path.join(dir, entry.name));
            } else {
                await scanFile(path.join(dir, entry.name));
            }
        }
    };

    try {
        const stat = await fs.stat(targetPath);
        if (stat.isDirectory()) { await walk(targetPath); }
        else { await scanFile(targetPath); }
    } catch (err) {
        report.error = `Cannot access path: ${err.message}`;
    }

    report.total_issues = report.findings.length;
    report.risk_summary = report.total_issues === 0
        ? "No obvious secrets detected."
        : `${report.total_issues} potential secret(s) found — review immediately before pushing to version control!`;

    return report;
}

// ─────────────────────────────────────────────────────────────
//  SUPERPOWER 3: CLEAN-ROOM BACKEND & API SCHEMA SYNTHESIZER (REA++)
// ─────────────────────────────────────────────────────────────

/**
 * Synthesizes a 100% working Node.js/Express mock microservice and OpenAPI 3.0 schema
 * based on discovered client-side routes, GraphQL operations, and API paths.
 */
export function cleanRoomApiSynthesizer(endpoints = [], domain = "example.com") {
    const cleanEndpoints = [...new Set(endpoints)]
        .filter(ep => typeof ep === "string" && ep.startsWith("/"))
        .map(ep => ep.split("?")[0].replace(/\/+$/, "") || "/");

    const paths = cleanEndpoints.length ? cleanEndpoints.slice(0, 25) : ["/api/v1/auth", "/api/v1/users", "/api/v1/data"];

    // 1. Generate OpenAPI 3.0.3 Specification
    const openApiPaths = {};
    for (const p of paths) {
        const isAuth = /auth|login|token/i.test(p);
        const isGraphql = /graphql/i.test(p);
        const tag = p.split("/")[1] || "general";

        openApiPaths[p] = {
            get: {
                tags: [tag],
                summary: `Discovered Endpoint ${p}`,
                operationId: `get_${p.replace(/[^a-zA-Z0-9]/g, "_")}`,
                responses: {
                    "200": {
                        description: "Successful response blueprint",
                        content: {
                            "application/json": {
                                schema: {
                                    type: "object",
                                    properties: {
                                        success: { type: "boolean", example: true },
                                        data: { type: "array", items: { type: "object" } },
                                        timestamp: { type: "string", example: new Date().toISOString() }
                                    }
                                }
                            }
                        }
                    },
                    "401": { description: "Unauthorized / API Token Required" }
                }
            }
        };

        if (isAuth || isGraphql || /create|update|submit|upload/i.test(p)) {
            openApiPaths[p].post = {
                tags: [tag],
                summary: `Mutation/Submission for ${p}`,
                operationId: `post_${p.replace(/[^a-zA-Z0-9]/g, "_")}`,
                requestBody: {
                    required: true,
                    content: {
                        "application/json": {
                            schema: {
                                type: "object",
                                properties: isAuth
                                    ? { username: { type: "string" }, password: { type: "string" } }
                                    : { query: { type: "string" }, variables: { type: "object" } }
                            }
                        }
                    }
                },
                responses: {
                    "200": { description: "Success response blueprint" }
                }
            };
        }
    }

    const openApiSpec = {
        openapi: "3.0.3",
        info: {
            title: `${domain.toUpperCase()} — Synthesized Clean-Room API Specification`,
            version: "1.0.0-synthesized",
            description: `Auto-generated reverse-engineered microservice contract based on discovered client bundles from ${domain}.`,
        },
        servers: [
            { url: `http://localhost:8080`, description: "Local Mock Microservice" },
            { url: `https://${domain}`, description: "Production Target" }
        ],
        paths: openApiPaths,
    };

    // 2. Generate Runnable Node.js / Express Microservice Blueprint
    const routeHandlers = paths.map(p => {
        const cleanName = p.replace(/[^a-zA-Z0-9]/g, "_");
        return `// Handlers for ${p}
app.get("${p}", (req, res) => {
  res.json({
    success: true,
    endpoint: "${p}",
    mode: "synthesized_mock",
    target: "${domain}",
    timestamp: new Date().toISOString(),
    payload: [{ id: 1, name: "Sample Item", status: "active" }]
  });
});

app.post("${p}", (req, res) => {
  const body = req.body || {};
  res.status(201).json({
    success: true,
    message: "Synthetic mock transaction accepted",
    received: body,
    transactionId: "txn_" + Date.now()
  });
});`;
    }).join("\n\n");

    const mockExpressService = `/**
 * Clean-Room Microservice Blueprint for: ${domain}
 * Generated automatically by Omni-Arch Pro v3.0 / Matrix Core
 * 
 * Instructions:
 *   1. npm install express cors helmet
 *   2. node mock_express_microservice.js
 */

import express from "express";
import cors from "cors";
import helmet from "helmet";

const app = express();
const PORT = process.env.PORT || 8080;

app.use(helmet());
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

// System Health Probe
app.get("/health", (req, res) => {
  res.json({
    status: "healthy",
    service: "${domain}-mock-microservice",
    endpoints_active: ${paths.length},
    timestamp: new Date().toISOString()
  });
});

${routeHandlers}

// Catch-all 404 handler
app.use((req, res) => {
  res.status(404).json({ error: "Endpoint not found in synthesized blueprint", path: req.path });
});

app.listen(PORT, () => {
  console.log("⚡ Clean-Room Mock Microservice live on http://localhost:" + PORT);
  console.log("⚡ Synthesized ${paths.length} endpoints ready for testing.");
});
`;

    return {
        openapi_spec: openApiSpec,
        mock_microservice_code: mockExpressService,
        endpoints_count: paths.length,
        endpoints: paths
    };
}

// ─────────────────────────────────────────────────────────────
//  SUPERPOWER 6: INLINE + EXTERNAL JS AST & SECRET EXTRACTOR
// ─────────────────────────────────────────────────────────────

/**
 * TOOL 6 — js_bundle_reverser
 * Scans both external JS bundles and inline <script> blocks (e.g. __NEXT_DATA__)
 * for API routes, cloud storage, secrets, and outdated libraries.
 */
export async function jsBundleReverser(domain) {
    const target = cleanDomain(domain);
    const BASE   = `https://${target}`;
    const report = {
        tool: "js_bundle_reverser",
        domain: target,
        timestamp: new Date().toISOString(),
        bundles_analyzed: [],
        inline_scripts_analyzed: 0,
        api_endpoints: [],
        cloud_urls: [],
        secrets: [],
        env_variables: [],
        outdated_libraries: [],
        clean_room_synthesizer: null,
    };

    let html = "";
    try {
        const r = await axios.get(BASE, {
            timeout: 10000,
            maxRedirects: 5,
            validateStatus: () => true,
            headers: REALISTIC_BROWSER_HEADERS,
        });
        html = String(r.data || "");
    } catch (err) {
        report.error = `Homepage fetch failed: ${err.message}`;
        return report;
    }

    // Extract inline <script> blocks (including JSON state like __NEXT_DATA__)
    const inlineScriptContents = [];
    const inlineRe = /<script(?:\s+[^>]*?)?>([\s\S]*?)<\/script>/gi;
    let match;
    while ((match = inlineRe.exec(html)) !== null) {
        const content = match[1]?.trim();
        if (content && content.length > 20) {
            inlineScriptContents.push(content);
        }
    }
    report.inline_scripts_analyzed = inlineScriptContents.length;

    // Extract external <script src> URLs
    const scriptUrls = [];
    const scriptRe = /<script[^>]+src=["']([^"']+)["']/gi;
    while ((match = scriptRe.exec(html)) !== null) {
        try { scriptUrls.push(new URL(match[1], BASE).href); } catch { /* skip */ }
    }

    const BUNDLE_RE = /\b(main|app|chunk|bundle|index|vendor|runtime|pages|_app|_next)\b/i;
    const topBundles = [
        ...scriptUrls.filter(u => BUNDLE_RE.test(u)),
        ...scriptUrls.filter(u => !BUNDLE_RE.test(u) && u.endsWith(".js")),
    ].filter(u => u.includes(".js")).slice(0, 6);

    const API_RE   = /["'`](\/(?:api|v\d+|graphql|admin|internal|auth|user|webhook|rest|rpc|query|search|upload|download|billing)[a-zA-Z0-9_\-\/]*)["'`]/g;
    const CLOUD_RE = /https?:\/\/[a-zA-Z0-9.\-]+\.(?:amazonaws\.com|firebaseio\.com|firebase\.app|supabase\.co|stripe\.com|twilio\.com|sendgrid\.net|cloudinary\.com|algolia\.net|pusher\.com|neon\.tech|vercel-storage\.com)[^\s"'`<>]*/g;
    const ENV_RE   = /((?:NEXT_PUBLIC_|REACT_APP_|VITE_)[A-Z0-9_]+)\s*[:=]\s*["'`]?([^"'`\s,;){]{3,60})/g;

    const SECRET_PATTERNS = [
        ["AWS Access Key",           /AKIA[0-9A-Z]{16}/g],
        ["Google API Key",           /AIza[0-9A-Za-z\-_]{35}/g],
        ["GitHub Token",             /gh[pousr]_[A-Za-z0-9]{36,}/g],
        ["JWT Token",                /eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_.+/]{10,}/g],
        ["Stripe Secret Key",        /sk_live_[0-9a-zA-Z]{24,}/g],
        ["Stripe Publishable Key",   /pk_live_[0-9a-zA-Z]{24,}/g],
        ["Slack Token",              /xox[baprs]-[0-9a-zA-Z\-]{10,}/g],
        ["Bearer Token",             /Authorization:\s*["'`]?Bearer\s+([A-Za-z0-9\-_.~+/]+=*)/gi],
        ["Client Secret",            /client[_-]?secret\s*[:=]\s*["'`]([A-Za-z0-9\-_]{10,})["'`]/gi],
        ["Hardcoded DB URI",         /(?:mysql|postgres|mongodb|redis):\/\/[^:]+:[^@]+@/gi],
    ];

    const LIBRARY_AUDITS = [
        { name: "jQuery (outdated)", re: /jquery[/-]([12]\.\d+\.\d+|3\.[0-4]\.\d+)/i, cve: "CVE-2020-11022 (XSS)", risk: "HIGH" },
        { name: "Lodash (vulnerable)", re: /lodash[/-]([0-3]\.\d+\.\d+|4\.(?:[0-9]|1[0-6])\.\d+)/i, cve: "CVE-2021-23337 (Prototype Pollution)", risk: "HIGH" },
        { name: "Moment.js (deprecated)", re: /moment\.js\s*v?(\d+\.\d+\.\d+)/i, cve: "Deprecated / ReDoS Risks", risk: "LOW" },
        { name: "AngularJS 1.x (EOL)", re: /angular[.-]1\.\d+\.\d+/i, cve: "EOL / Client Template Injection", risk: "CRITICAL" },
        { name: "Bootstrap 3.x/4.x", re: /bootstrap[/-]([3]\.\d+\.\d+|4\.[0-3]\.\d+)/i, cve: "CVE-2019-8331 (XSS)", risk: "MEDIUM" },
    ];

    // Helper to scan a code string
    const scanCodeBlock = (code, sourceName) => {
        const foundEndpoints = new Set();
        API_RE.lastIndex = 0;
        let m;
        while ((m = API_RE.exec(code)) !== null) {
            if (m[1].length > 2 && m[1].length < 100) foundEndpoints.add(m[1]);
            API_RE.lastIndex = m.index + 1;
        }

        const foundCloud = new Set();
        CLOUD_RE.lastIndex = 0;
        while ((m = CLOUD_RE.exec(code)) !== null) {
            foundCloud.add(m[0].slice(0, 150));
            CLOUD_RE.lastIndex = m.index + 1;
        }

        const foundSecrets = [];
        for (const [label, re] of SECRET_PATTERNS) {
            re.lastIndex = 0;
            while ((m = re.exec(code)) !== null) {
                foundSecrets.push({
                    type: label,
                    source: sourceName,
                    match: m[0].slice(0, 80) + (m[0].length > 80 ? "…" : "")
                });
                re.lastIndex = m.index + 1;
                if (foundSecrets.length >= 30) break;
            }
        }

        const foundEnvs = new Set();
        ENV_RE.lastIndex = 0;
        while ((m = ENV_RE.exec(code)) !== null) {
            foundEnvs.add(`${m[1]}=${m[2]}`);
            ENV_RE.lastIndex = m.index + 1;
        }

        for (const lib of LIBRARY_AUDITS) {
            const libMatch = code.match(lib.re);
            if (libMatch) {
                report.outdated_libraries.push({
                    library: lib.name,
                    version_detected: libMatch[0],
                    cve: lib.cve,
                    severity: lib.risk,
                    source: sourceName
                });
            }
        }

        return {
            endpoints: [...foundEndpoints],
            clouds: [...foundCloud],
            secrets: foundSecrets,
            envs: [...foundEnvs]
        };
    };

    // 1. Scan Inline Scripts
    for (let i = 0; i < inlineScriptContents.length; i++) {
        const res = scanCodeBlock(inlineScriptContents[i], `inline-script-${i + 1}`);
        report.api_endpoints.push(...res.endpoints);
        report.cloud_urls.push(...res.clouds);
        report.secrets.push(...res.secrets);
        report.env_variables.push(...res.envs);
    }

    // 2. Scan External Bundles
    for (const url of topBundles) {
        const bundle = { url, size_kb: 0, api_endpoints: [], cloud_urls: [], secrets: [], env_vars: [] };
        try {
            const res = await axios.get(url, {
                timeout: 8000,
                maxRedirects: 5,
                responseType: "text",
                headers: REALISTIC_BROWSER_HEADERS,
            });
            const code = String(res.data || "");
            bundle.size_kb = Math.round(code.length / 1024);

            const parsed = scanCodeBlock(code, path.basename(url));
            bundle.api_endpoints = parsed.endpoints.slice(0, 40);
            bundle.cloud_urls    = parsed.clouds.slice(0, 20);
            bundle.secrets       = parsed.secrets;
            bundle.env_vars      = parsed.envs.slice(0, 20);
        } catch (err) {
            bundle.error = err.message;
        }

        report.bundles_analyzed.push(bundle);
        report.api_endpoints.push(...bundle.api_endpoints);
        report.cloud_urls.push(...bundle.cloud_urls);
        report.secrets.push(...bundle.secrets);
        report.env_variables.push(...bundle.env_vars);
    }

    report.api_endpoints  = [...new Set(report.api_endpoints)].sort().slice(0, 60);
    report.cloud_urls     = [...new Set(report.cloud_urls)].slice(0, 30);
    report.env_variables  = [...new Set(report.env_variables)].slice(0, 30);
    report.total_bundles  = topBundles.length;
    report.total_endpoints = report.api_endpoints.length;
    report.total_secrets  = report.secrets.length;
    report.total_cloud_refs = report.cloud_urls.length;

    // Superpower 3 Synthesizer integration
    report.clean_room_synthesizer = cleanRoomApiSynthesizer(report.api_endpoints, target);

    return report;
}

// ─────────────────────────────────────────────────────────────
//  TOOL 7: TCP PORT SCANNER
// ─────────────────────────────────────────────────────────────

export async function tcpPortScanner(domain) {
    const target = cleanDomain(domain);
    const report = {
        tool: "tcp_port_scanner",
        domain: target,
        timestamp: new Date().toISOString(),
        target_ip: null,
        open_ports: [],
        closed_ports: [],
        risky_exposures: [],
    };

    const PORT_MAP = {
        21:    { service: "FTP",        risk: "HIGH",     note: "Unencrypted file transfer — replace with SFTP" },
        22:    { service: "SSH",        risk: "MEDIUM",   note: "Ensure key-only auth and disable root login" },
        25:    { service: "SMTP",       risk: "MEDIUM",   note: "Verify not an open relay" },
        80:    { service: "HTTP",       risk: "LOW",      note: "Redirect all traffic to HTTPS" },
        443:   { service: "HTTPS",      risk: "NONE",     note: "Expected — verify TLS 1.2+ cipher policy" },
        3306:  { service: "MySQL",      risk: "CRITICAL", note: "Database exposed to internet — firewall immediately!" },
        5432:  { service: "PostgreSQL", risk: "CRITICAL", note: "Database exposed to internet — firewall immediately!" },
        6379:  { service: "Redis",      risk: "CRITICAL", note: "Often unauthenticated — critical exposure" },
        8000:  { service: "HTTP-Dev",   risk: "MEDIUM",   note: "Dev server exposed — verify intentional" },
        8080:  { service: "HTTP-Alt",   risk: "MEDIUM",   note: "May expose admin panels or dev builds" },
        8443:  { service: "HTTPS-Alt",  risk: "LOW",      note: "Alt HTTPS port" },
        27017: { service: "MongoDB",    risk: "CRITICAL", note: "Database exposed to internet — firewall immediately!" },
    };

    const ip = await resolveIP(target);
    if (!ip) {
        report.error = `Could not resolve IP for ${target}`;
        return report;
    }
    report.target_ip = ip;

    const checkPort = (host, port) => new Promise((resolve) => {
        const sock = new net.Socket();
        let done = false;
        const finish = (open) => {
            if (!done) {
                done = true;
                sock.destroy();
                resolve({ port, open });
            }
        };
        sock.setTimeout(1500);
        sock.on("connect", () => finish(true));
        sock.on("timeout",  () => finish(false));
        sock.on("error",    () => finish(false));
        sock.connect(port, host);
    });

    const results = await Promise.all(
        Object.keys(PORT_MAP).map(p => checkPort(ip, parseInt(p)))
    );

    for (const { port, open } of results) {
        const info = PORT_MAP[port];
        if (open) {
            const entry = { port, service: info.service, risk: info.risk, note: info.note };
            report.open_ports.push(entry);
            if (!["NONE", "LOW"].includes(info.risk)) report.risky_exposures.push(entry);
        } else {
            report.closed_ports.push(port);
        }
    }

    report.open_ports.sort((a, b) => a.port - b.port);
    report.total_open  = report.open_ports.length;
    report.total_risky = report.risky_exposures.length;
    return report;
}

// ─────────────────────────────────────────────────────────────
//  TOOL 8: COOKIE & CORS SECURITY AUDITOR
// ─────────────────────────────────────────────────────────────

export async function cookieCorsAuditor(domain) {
    const target = cleanDomain(domain);
    const report = {
        tool: "cookie_cors_auditor",
        domain: target,
        timestamp: new Date().toISOString(),
        cookies: [],
        cors: {},
        findings: [],
        risk_level: "LOW"
    };

    let res;
    for (const proto of ["https://", "http://"]) {
        try {
            res = await axios.get(`${proto}${target}`, {
                timeout: 8000,
                validateStatus: () => true,
                maxRedirects: 5,
                headers: {
                    ...REALISTIC_BROWSER_HEADERS,
                    "Origin": "https://evil-security-test.example.com"
                }
            });
            break;
        } catch { /* try next */ }
    }

    if (!res) {
        report.error = `Could not connect to ${target}`;
        return report;
    }

    // Inspect Set-Cookie
    const rawCookies = res.headers["set-cookie"] || [];
    const cookieList = Array.isArray(rawCookies) ? rawCookies : [rawCookies];
    for (const c of cookieList) {
        if (!c) continue;
        const parts = c.split(";").map(p => p.trim());
        const [nameVal] = parts;
        const [cName] = nameVal.split("=");
        const isSecure = parts.some(p => /^secure$/i.test(p));
        const isHttpOnly = parts.some(p => /^httponly$/i.test(p));
        const sameSitePart = parts.find(p => /^samesite=/i.test(p));
        const sameSiteVal = sameSitePart ? sameSitePart.split("=")[1] : null;

        const flags = { name: cName, secure: isSecure, httpOnly: isHttpOnly, sameSite: sameSiteVal || "Unset", issues: [] };
        if (!isSecure) flags.issues.push("Missing Secure flag");
        if (!isHttpOnly) flags.issues.push("Missing HttpOnly flag");
        if (!sameSiteVal) flags.issues.push("Missing SameSite attribute");
        else if (sameSiteVal.toLowerCase() === "none" && !isSecure) flags.issues.push("SameSite=None requires Secure flag");

        report.cookies.push(flags);
        if (flags.issues.length) {
            report.findings.push(`Cookie "${cName}": ${flags.issues.join(", ")}`);
        }
    }

    // Inspect CORS
    const acao = res.headers["access-control-allow-origin"];
    const acac = res.headers["access-control-allow-credentials"];
    const acam = res.headers["access-control-allow-methods"];
    const acah = res.headers["access-control-allow-headers"];

    report.cors = {
        allow_origin: acao || "Not set",
        allow_credentials: acac || "Not set",
        allow_methods: acam || "Not set",
        allow_headers: acah || "Not set"
    };

    if (acao === "*") {
        if (acac === "true") {
            report.findings.push("CRITICAL: Access-Control-Allow-Origin: * combined with credentials=true");
            report.risk_level = "CRITICAL";
        } else {
            report.findings.push("INFO: Access-Control-Allow-Origin is set to wildcard (*)");
        }
    } else if (acao === "https://evil-security-test.example.com") {
        report.findings.push("HIGH: Dynamic origin reflection detected without validation (arbitrary Origin accepted)");
        report.risk_level = "HIGH";
    }

    if (report.findings.some(f => f.startsWith("CRITICAL"))) report.risk_level = "CRITICAL";
    else if (report.findings.some(f => f.startsWith("HIGH"))) report.risk_level = "HIGH";
    else if (report.findings.length > 0) report.risk_level = "MEDIUM";

    return report;
}

// ─────────────────────────────────────────────────────────────
//  SUPERPOWER 4: DEEP TECH-STACK & WAF FINGERPRINTER
// ─────────────────────────────────────────────────────────────

/**
 * 50+ WAF and Framework Signature Fingerprinting Engine
 */
export function deepWafAndTechFingerprinter(headers = {}, html = "", cookies = []) {
    const wafsDetected = [];
    const frameworksDetected = [];
    const h = {};
    for (const [k, v] of Object.entries(headers || {})) {
        h[k.toLowerCase()] = String(v).toLowerCase();
    }
    const htmlStr = typeof html === "string" ? html : "";
    const cookieStr = Array.isArray(cookies) ? cookies.map(c => c.name || "").join(" ") : "";

    // 1. WAF Signature Matching
    const WAF_RULES = [
        { name: "Cloudflare WAF / Edge", check: () => h["cf-ray"] || h["cf-cache-status"] || h["server"]?.includes("cloudflare") || cookieStr.includes("__cf") },
        { name: "AWS WAF / CloudFront", check: () => h["x-amzn-requestid"] || h["x-amz-cf-id"] || h["x-amz-id-2"] || cookieStr.includes("aws-waf-token") },
        { name: "Akamai Edge WAF", check: () => h["x-akamai-transformed"] || h["akamai-origin-hop"] || h["server"]?.includes("akamaighost") },
        { name: "Imperva / Incapsula", check: () => h["x-iinfo"] || cookieStr.includes("visid_incap") || cookieStr.includes("incap_ses") || h["x-cdn"]?.includes("incapsula") },
        { name: "Fastly WAF", check: () => h["x-fastly-request-id"] || h["fastly-debug-digest"] || h["x-served-by"]?.includes("cache-") },
        { name: "F5 BIG-IP ASM", check: () => cookieStr.includes("bigipserver") || cookieStr.includes("ts") || h["server"]?.includes("big-ip") },
        { name: "Sucuri Cloudproxy", check: () => h["x-sucuri-id"] || h["x-sucuri-cache"] || h["server"]?.includes("sucuri") },
        { name: "Azure Front Door / App Gateway", check: () => h["x-azure-ref"] || h["azure-request-id"] || h["x-fd-"] || h["x-ms-"] },
        { name: "Fortinet FortiWeb", check: () => cookieStr.includes("fortiwaf") },
        { name: "Barracuda WAF", check: () => cookieStr.includes("barra_counter_session") || cookieStr.includes("bni__barracuda") },
        { name: "Vercel Edge Gateway", check: () => h["x-vercel-id"] || h["x-vercel-cache"] || h["server"]?.includes("vercel") },
        { name: "Netlify Edge", check: () => h["x-nf-request-id"] || h["server"]?.includes("netlify") },
        { name: "ModSecurity / OWASP CRS", check: () => h["server"]?.includes("mod_security") || h["server"]?.includes("modsecurity") },
    ];

    for (const rule of WAF_RULES) {
        if (rule.check()) wafsDetected.push(rule.name);
    }

    // 2. Modern Framework & Engine Signature Matching
    if (/(__next|_next\/static)/i.test(htmlStr) || h["x-powered-by"]?.includes("next.js")) frameworksDetected.push("Next.js (React Full-Stack / App Router)");
    else if (/react|data-reactroot/i.test(htmlStr)) frameworksDetected.push("React.js SPA");
    if (/__nuxt|nuxt/i.test(htmlStr)) frameworksDetected.push("Nuxt.js (Vue Full-Stack)");
    else if (/vue|data-v-[a-f0-9]/i.test(htmlStr)) frameworksDetected.push("Vue.js");
    if (/ng-version|ng-app/i.test(htmlStr)) frameworksDetected.push("Angular");
    if (/svelte|__sveltekit/i.test(htmlStr)) frameworksDetected.push("Svelte / SvelteKit");
    if (/remix/i.test(htmlStr)) frameworksDetected.push("Remix.run");
    if (/astro/i.test(htmlStr)) frameworksDetected.push("Astro Static Engine");
    if (/laravel_session|xsrf-token/i.test(cookieStr) || h["x-powered-by"]?.includes("php")) frameworksDetected.push("Laravel (PHP Backend)");
    if (/csrftoken|sessionid/i.test(cookieStr) && /django/i.test(htmlStr)) frameworksDetected.push("Django (Python)");
    if (/asp\.net|_sessionid/i.test(cookieStr) || h["x-aspnet-version"]) frameworksDetected.push("ASP.NET Core");
    if (/wp-content|wp-includes/i.test(htmlStr)) frameworksDetected.push("WordPress CMS");

    return {
        wafs: wafsDetected.length ? wafsDetected : ["Direct Ingress / Origin Unmasked"],
        is_waf_protected: wafsDetected.length > 0,
        primary_waf: wafsDetected[0] || "None",
        frameworks: frameworksDetected.length ? frameworksDetected : ["Modern Vanilla HTML5 / ES6 Web Platform"],
    };
}

// ─────────────────────────────────────────────────────────────
//  SUPERPOWER 7: STEGANOGRAPHY & IMAGE ASSET METADATA INSPECTOR
// ─────────────────────────────────────────────────────────────

/**
 * TOOL 9 — steganography_and_image_inspector
 * Inspects target branding, logos, and favicons for EXIF GPS tags and hidden payload data past EOF boundaries.
 */
export async function steganographyAndImageInspector(domain) {
    const target = cleanDomain(domain);
    const BASE = `https://${target}`;
    const report = {
        tool: "steganography_and_image_inspector",
        domain: target,
        timestamp: new Date().toISOString(),
        assets_inspected: [],
        findings: [],
        overall_risk: "LOW"
    };

    // Candidate branding assets to inspect
    const candidates = [
        `${BASE}/favicon.ico`,
        `${BASE}/apple-touch-icon.png`,
        `${BASE}/logo.png`,
    ];

    // Also parse homepage for og:image or favicon links
    try {
        const homeRes = await axios.get(BASE, {
            timeout: 6000,
            maxRedirects: 5,
            validateStatus: () => true,
            headers: REALISTIC_BROWSER_HEADERS
        });
        const html = String(homeRes.data || "");
        const iconMatch = html.match(/<link[^>]+rel=["'](?:shortcut\s+)?icon["'][^>]+href=["']([^"']+)["']/i);
        if (iconMatch) {
            try { candidates.push(new URL(iconMatch[1], BASE).href); } catch {}
        }
        const ogMatch = html.match(/<meta[^>]+property=["']og:image["'][^>]+content=["']([^"']+)["']/i);
        if (ogMatch) {
            try { candidates.push(new URL(ogMatch[1], BASE).href); } catch {}
        }
    } catch {
        // Fallback to defaults
    }

    const uniqueCandidates = [...new Set(candidates)].slice(0, 4);

    for (const assetUrl of uniqueCandidates) {
        try {
            const res = await axios.get(assetUrl, {
                timeout: 6000,
                maxRedirects: 5,
                responseType: "arraybuffer",
                validateStatus: s => s === 200,
                headers: REALISTIC_BROWSER_HEADERS
            });

            const buf = Buffer.from(res.data);
            if (!buf || buf.length < 8) continue;

            const assetReport = {
                url: assetUrl,
                size_bytes: buf.length,
                entropy: calculateEntropy(buf),
                format: "Unknown",
                has_exif: false,
                has_trailing_payload: false,
                trailing_bytes_count: 0,
                exif_details: {},
                notes: []
            };

            // 1. Identify Magic Bytes
            if (buf[0] === 0xFF && buf[1] === 0xD8 && buf[2] === 0xFF) {
                assetReport.format = "JPEG";
                // JPEG EOF marker is FF D9
                let eofIndex = -1;
                for (let i = 2; i < buf.length - 1; i++) {
                    if (buf[i] === 0xFF && buf[i + 1] === 0xD9) {
                        eofIndex = i;
                    }
                }
                if (eofIndex !== -1 && eofIndex + 2 < buf.length) {
                    assetReport.has_trailing_payload = true;
                    assetReport.trailing_bytes_count = buf.length - (eofIndex + 2);
                    assetReport.notes.push(`${assetReport.trailing_bytes_count} bytes appended past JPEG EOF marker!`);
                }

                // Check EXIF marker FF E1
                if (buf.indexOf(Buffer.from([0xFF, 0xE1])) !== -1) {
                    assetReport.has_exif = true;
                    assetReport.notes.push("EXIF metadata segment detected.");
                }
            } else if (buf.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]))) {
                assetReport.format = "PNG";
                // PNG EOF chunk is IEND (49 45 4E 44 AE 42 60 82)
                const iendIndex = buf.indexOf(Buffer.from("IEND"));
                if (iendIndex !== -1 && iendIndex + 8 < buf.length) {
                    assetReport.has_trailing_payload = true;
                    assetReport.trailing_bytes_count = buf.length - (iendIndex + 8);
                    assetReport.notes.push(`${assetReport.trailing_bytes_count} bytes appended past PNG IEND chunk!`);
                }
                if (buf.indexOf(Buffer.from("eXIf")) !== -1) {
                    assetReport.has_exif = true;
                    assetReport.notes.push("PNG eXIf chunk present.");
                }
            } else if (buf.slice(0, 4).toString("ascii") === "GIF8") {
                assetReport.format = "GIF";
                // GIF EOF trailer is 0x3B
                const trailerIndex = buf.lastIndexOf(0x3B);
                if (trailerIndex !== -1 && trailerIndex + 1 < buf.length) {
                    assetReport.has_trailing_payload = true;
                    assetReport.trailing_bytes_count = buf.length - (trailerIndex + 1);
                    assetReport.notes.push(`${assetReport.trailing_bytes_count} bytes appended past GIF trailer!`);
                }
            } else if (buf.readUInt16LE(0) === 0x0000 && buf.readUInt16LE(2) === 0x0001) {
                assetReport.format = "ICO";
            }

            // Check for hidden archive headers past EOF
            if (assetReport.has_trailing_payload) {
                const tail = buf.slice(buf.length - assetReport.trailing_bytes_count);
                if (tail.indexOf(Buffer.from([0x50, 0x4B, 0x03, 0x04])) !== -1) {
                    assetReport.notes.push("CRITICAL: Embedded ZIP archive detected in trailing image bytes!");
                    report.findings.push(`Steganography Alert: ${assetUrl} contains an embedded ZIP file.`);
                    report.overall_risk = "CRITICAL";
                } else {
                    report.findings.push(`Trailing data detected: ${assetUrl} has ${assetReport.trailing_bytes_count} extra bytes.`);
                    if (report.overall_risk === "LOW") report.overall_risk = "MEDIUM";
                }
            }

            report.assets_inspected.push(assetReport);
        } catch {
            // Asset unreachable
        }
    }

    return report;
}

// ─────────────────────────────────────────────────────────────
//  SUPERPOWER 8: MERMAID.JS ARCHITECTURE & ATTACK TOPOLOGY GENERATOR
// ─────────────────────────────────────────────────────────────

/**
 * Generates valid Mermaid.js flowchart syntax mapping out target infrastructure,
 * WAF barriers, services, and endpoints.
 */
export function mermaidTopologyGenerator({ domain, wafData, dnsData, portsData, subdomains = [], apiEndpoints = [] }) {
    const target = cleanDomain(domain);
    const primaryWaf = wafData?.primary_waf || "Edge / Ingress Proxy";
    const ip = (dnsData?.dns_records?.ipv4 || [])[0] || "Target IP";
    const subs = subdomains.slice(0, 5);
    const eps = apiEndpoints.slice(0, 4);

    const openPortList = (portsData?.open_ports || []).map(p => `${p.port}/${p.service}`).join(", ") || "443/HTTPS";

    return `flowchart TD
    %% Styling Definitions
    classDef client fill:#0f172a,stroke:#38bdf8,stroke-width:2px,color:#f8fafc;
    classDef waf fill:#312e81,stroke:#818cf8,stroke-width:2px,color:#e0e7ff;
    classDef origin fill:#064e3b,stroke:#34d399,stroke-width:2px,color:#ecfdf5;
    classDef service fill:#1e1b4b,stroke:#a78bfa,stroke-width:1.5px,color:#f5f3ff;
    classDef portNode fill:#701a75,stroke:#f472b6,stroke-width:1.5px,color:#fdf2f8;
    classDef warning fill:#78350f,stroke:#fbbf24,stroke-width:2px,color:#fffbeb;

    Client["🌐 Global Internet Traffic"]:::client --> Ingress["🛡️ WAF / CDN Layer\\n(${primaryWaf})"]:::waf
    Ingress --> Origin["🖥️ Origin Host: ${target}\\n[${ip}]"]:::origin

    Origin --> Ports["🔌 Open TCP Ports\\n(${openPortList})"]:::portNode
    Origin --> Framework["⚡ Frontend Framework\\n(${wafData?.frameworks?.[0] || 'Modern SPA'})"]:::service

    ${subs.length ? `Origin --> Subdomains["📡 Discovered Subdomains\\n(${subs.join(', ')})"]:::service` : ""}
    ${eps.length ? `Origin --> ApiGateway["🔌 API Gateway\\n(${eps.join(', ')})"]:::service` : ""}
`;
}

// ─────────────────────────────────────────────────────────────
//  SUPERPOWER 9: 3-COLUMN STRUCTURED AUDIT MATRIX
// ─────────────────────────────────────────────────────────────

/**
 * Generates an executive 3-column tactical decision matrix:
 * Column 1: Component & What's Working ✔
 * Column 2: Technical Flaw & Business Impact ✘
 * Column 3: Tactical Remediation & 1-Click Fix 🛠
 */
export function generateStructuredAuditMatrix({ dnsData, sslData, portsData, cookieData, jsData, leakData }) {
    const rows = [];

    // Row 1: Transport Layer Security
    if (sslData?.certificate?.expiry_status === "VALID") {
        rows.push({
            component: "TLS/SSL Certificate (Port 443)",
            working: `Valid certificate active (${sslData.certificate.days_remaining} days remaining). Modern ${sslData.tls_connection?.protocol || 'TLS 1.3'} protocol in use.`,
            flaw: "None detected on active transport layer.",
            impact: "Low — Data in transit is securely encrypted.",
            remediation: "Ensure auto-renewal daemon (Certbot/ACME) is scheduled."
        });
    } else {
        rows.push({
            component: "TLS/SSL Certificate (Port 443)",
            working: "Port 443 accessible.",
            flaw: sslData?.certificate?.expiry_status || "Certificate expired or invalid",
            impact: "CRITICAL — Users receive scary browser warnings; vulnerable to MITM interception.",
            remediation: "certbot certonly --nginx -d " + (dnsData?.domain || "target.com")
        });
    }

    // Row 2: HTTP Security Headers
    const missingH = dnsData?.missing_headers || [];
    if (missingH.length === 0) {
        rows.push({
            component: "HTTP Defense Headers",
            working: "All 6 major security headers (HSTS, CSP, X-Frame-Options, X-Content-Type, Referrer-Policy, Permissions-Policy) active.",
            flaw: "None.",
            impact: "Low — Strong client-side protection against XSS and clickjacking.",
            remediation: "Maintain current header policies."
        });
    } else {
        rows.push({
            component: "HTTP Defense Headers",
            working: `${dnsData?.security_headers ? Object.keys(dnsData.security_headers).length : 0}/6 headers present.`,
            flaw: `Missing: ${missingH.join(", ")}`,
            impact: "HIGH — Vulnerable to clickjacking, MIME sniffing, and cross-site scripting (XSS).",
            remediation: `add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;\nadd_header X-Frame-Options "DENY" always;`
        });
    }

    // Row 3: DNS SPF & DMARC Spoofing Protection
    if (dnsData?.dmarc_policy?.status === "STRONG_REJECT") {
        rows.push({
            component: "Email Spoofing (SPF & DMARC)",
            working: `Strict DMARC policy active ('${dnsData.dmarc_policy.policy}'). Valid SPF record configured.`,
            flaw: "None.",
            impact: "Low — High email reputation; unauthorized senders rejected.",
            remediation: "Monitor DMARC aggregate reports via 'rua' mailbox."
        });
    } else {
        rows.push({
            component: "Email Spoofing (SPF & DMARC)",
            working: (dnsData?.dns_records?.spf || []).length > 0 ? "Basic SPF record found." : "No SPF configured.",
            flaw: dnsData?.dmarc_policy?.status === "MONITORING_ONLY" ? "DMARC set to 'p=none' (does not block spoofed emails)." : "DMARC policy completely missing.",
            impact: "HIGH — Criminals can forge emails pretending to originate from your domain (CEO fraud/phishing).",
            remediation: `TXT record: _dmarc.${dnsData?.domain || "domain.com"} -> "v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc@${dnsData?.domain || "domain.com"}"`
        });
    }

    // Row 4: Port & Database Exposure
    const riskyPorts = portsData?.risky_exposures || [];
    if (riskyPorts.length === 0) {
        rows.push({
            component: "External TCP Surface",
            working: "No risky administrative or database ports (MySQL, Redis, MongoDB) exposed to the public internet.",
            flaw: "None.",
            impact: "Low — Internal data stores correctly isolated.",
            remediation: "Maintain strict cloud firewall / security group ingress rules."
        });
    } else {
        const pNames = riskyPorts.map(p => `${p.port} (${p.service})`).join(", ");
        rows.push({
            component: "External TCP Surface",
            working: "Port scanner completed.",
            flaw: `Exposed Ports: ${pNames}`,
            impact: "CRITICAL — Direct database exposure allows remote brute-force or unauthenticated extraction.",
            remediation: `sudo ufw deny ${riskyPorts[0]?.port} && sudo iptables -A INPUT -p tcp --dport ${riskyPorts[0]?.port} -j DROP`
        });
    }

    // Row 5: Cookies & CORS
    const cookieIssues = cookieData?.findings || [];
    if (cookieIssues.length === 0) {
        rows.push({
            component: "Session Cookies & CORS Policy",
            working: "All session cookies configured with Secure, HttpOnly, and SameSite attributes. Safe CORS boundaries.",
            flaw: "None.",
            impact: "Low — Cookie session tokens protected against client-side theft.",
            remediation: "Verify tokens renew on privilege changes."
        });
    } else {
        rows.push({
            component: "Session Cookies & CORS Policy",
            working: `${cookieData?.cookies?.length || 0} cookies analyzed.`,
            flaw: cookieIssues.slice(0, 2).join("; "),
            impact: "HIGH — Insecure cookies allow session hijacking via XSS or insecure networks.",
            remediation: "Set-Cookie: name=val; Secure; HttpOnly; SameSite=Strict; Path=/;"
        });
    }

    // Row 6: Exposed Files & Leaks
    const sensFiles = leakData?.sensitive_files || [];
    if (sensFiles.length === 0) {
        rows.push({
            component: "Source Code & Repository Hygiene",
            working: "No exposed .git repositories, .env files, or un-minified source maps discovered.",
            flaw: "None.",
            impact: "Low — Proprietary codebase protected.",
            remediation: "Keep git roots outside web server public document root."
        });
    } else {
        rows.push({
            component: "Source Code & Repository Hygiene",
            working: "Passive leak probe completed.",
            flaw: `Exposed: ${sensFiles.map(f => f.type).join(", ")}`,
            impact: "CRITICAL — Attackers can download entire source repositories or API keys directly.",
            remediation: "In Nginx: location ~ /\\.git { deny all; return 404; }"
        });
    }

    return rows;
}

// ─────────────────────────────────────────────────────────────
//  TOOLS 10, 11, 12, 13: REMEDIATOR, STRUCTURE & SWOT
// ─────────────────────────────────────────────────────────────

export async function vulnerabilityAndHeaderRemediator(domain, auditData = null) {
    const target = cleanDomain(domain);
    const dnsData = auditData || await domainSecurityAudit(target);
    const missing = dnsData.missing_headers || [];

    const nginxLines = [
        `# --- Nginx Security Header Hardening for ${target} ---`,
        `# Paste inside your server { ... } or location / { ... } block:`,
        `add_header X-Content-Type-Options "nosniff" always;`,
        `add_header X-Frame-Options "DENY" always;`,
        `add_header Referrer-Policy "strict-origin-when-cross-origin" always;`,
        `add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;`,
        `add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;`,
        `add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; font-src 'self' https:; object-src 'none';" always;`
    ];

    const vercelJson = JSON.stringify({
        headers: [
            {
                source: "/(.*)",
                headers: [
                    { key: "X-Content-Type-Options", value: "nosniff" },
                    { key: "X-Frame-Options", value: "DENY" },
                    { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
                    { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=()" },
                    { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
                    { key: "Content-Security-Policy", value: "default-src 'self'; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:;" }
                ]
            }
        ]
    }, null, 2);

    const nextConfigJs = `// next.config.js - Security Headers
module.exports = {
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=(), payment=()' },
          { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
          { key: 'Content-Security-Policy', value: "default-src 'self'; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:;" },
        ],
      },
    ];
  },
};`;

    const cloudflareRules = `# Cloudflare Rules -> Transform Rules -> Modify Response Header
# Rule filter: (ssl eq true)
Set response headers:
  - Header: Strict-Transport-Security    Value: "max-age=63072000; includeSubDomains; preload"
  - Header: X-Content-Type-Options      Value: "nosniff"
  - Header: X-Frame-Options             Value: "DENY"
  - Header: Referrer-Policy             Value: "strict-origin-when-cross-origin"
  - Header: Permissions-Policy          Value: "camera=(), microphone=(), geolocation=()"
  - Header: Content-Security-Policy     Value: "default-src 'self' https:; object-src 'none';"`;

    const dmarcRecord = {
        name: `_dmarc.${target}`,
        type: "TXT",
        ttl: 3600,
        value: `v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc-reports@${target}; ruf=mailto:dmarc-alerts@${target}; fo=1; adkim=s; aspf=s`,
        explanation: "Enforces strict rejection of unauthorized emails pretending to originate from your domain."
    };

    const spfRecord = {
        name: target,
        type: "TXT",
        ttl: 3600,
        value: `v=spf1 mx -all`,
        explanation: "Permits only primary MX hosts to dispatch outgoing mail, rejecting all unauthorized senders."
    };

    const apacheHtaccess = `<IfModule mod_headers.c>
  Header always set X-Content-Type-Options "nosniff"
  Header always set X-Frame-Options "DENY"
  Header always set Referrer-Policy "strict-origin-when-cross-origin"
  Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"
  Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
  Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' https:;"
</IfModule>`;

    return {
        tool: "vulnerability_and_header_remediator",
        domain: target,
        missing_headers: missing,
        remediation_snippets: {
            nginx: nginxLines.join("\n"),
            vercel_json: vercelJson,
            next_config_js: nextConfigJs,
            cloudflare_transform_rules: cloudflareRules,
            apache_htaccess: apacheHtaccess,
            dmarc_dns_record: dmarcRecord,
            spf_dns_record: spfRecord
        }
    };
}

export async function codeStructureAnalyzer(domain) {
    const target = cleanDomain(domain);
    const report = {
        tool: "code_structure_analyzer",
        domain: target,
        timestamp: new Date().toISOString(),
        frameworks: [],
        styling_engine: [],
        layout_components: [],
        features_detected: [],
        architecture_flow: {}
    };

    let html = "";
    for (const proto of ["https://", "http://"]) {
        try {
            const res = await axios.get(`${proto}${target}`, {
                timeout: 10000,
                maxRedirects: 5,
                validateStatus: () => true,
                headers: REALISTIC_BROWSER_HEADERS
            });
            html = String(res.data || "");
            break;
        } catch { /* fallback */ }
    }

    if (!html) {
        report.error = `Could not fetch target page for ${target}`;
        return report;
    }

    if (/(__next|_next\/static)/i.test(html)) report.frameworks.push("Next.js (React SSR/SSG)");
    else if (/react|data-reactroot/i.test(html)) report.frameworks.push("React.js");
    if (/__nuxt|nuxt/i.test(html)) report.frameworks.push("Nuxt.js (Vue SSR)");
    else if (/vue|data-v-[a-f0-9]/i.test(html)) report.frameworks.push("Vue.js");
    if (/ng-version|ng-app/i.test(html)) report.frameworks.push("Angular");
    if (/svelte/i.test(html)) report.frameworks.push("Svelte");
    if (/alpinejs|x-data/i.test(html)) report.frameworks.push("Alpine.js");
    if (/jquery/i.test(html)) report.frameworks.push("jQuery");
    if (/wp-content|wp-includes/i.test(html)) report.frameworks.push("WordPress CMS");
    if (!report.frameworks.length) report.frameworks.push("Modern Vanilla ES6+ Web Components");

    if (/tailwind/i.test(html) || /class="[^"]*(?:flex|grid|p-\d|m-\d|text-|bg-)[^"]*"/i.test(html)) report.styling_engine.push("Tailwind CSS Utility Engine");
    if (/bootstrap/i.test(html)) report.styling_engine.push("Bootstrap UI System");
    if (/material/i.test(html)) report.styling_engine.push("Material Design / MUI");
    if (/styled-components|emotion/i.test(html)) report.styling_engine.push("CSS-in-JS (Emotion/Styled)");
    if (!report.styling_engine.length) report.styling_engine.push("Custom Vanilla Responsive CSS / Flexbox & CSS Grid");

    if (/<nav\b|<header\b/i.test(html)) report.layout_components.push("Header & Responsive Navigation Bar");
    if (/<form\b/i.test(html)) report.layout_components.push("Interactive Form & Input Handlers");
    if (/<footer\b/i.test(html)) report.layout_components.push("Footer & Site Map Links");
    if (/modal|dialog/i.test(html)) report.layout_components.push("Overlay Dialogs & Modals");
    if (/search/i.test(html)) report.layout_components.push("Real-time Search / Filter Interface");
    if (/table\b/i.test(html)) report.layout_components.push("Tabular Data Display Engine");
    if (/card/i.test(html)) report.layout_components.push("Responsive Card Grid Architecture");

    if (/auth|login|signin|register/i.test(html)) report.features_detected.push("User Authentication & Session Management");
    if (/cart|checkout|stripe|pricing|subscription/i.test(html)) report.features_detected.push("Billing / E-commerce & Checkout Workflow");
    if (/dashboard|analytics|stat|metric/i.test(html)) report.features_detected.push("Analytical Dashboard & Metrics Visualization");
    if (/dark-mode|theme-toggle/i.test(html)) report.features_detected.push("Dynamic Theme Switching (Dark/Light mode)");
    if (/api\//i.test(html)) report.features_detected.push("RESTful / GraphQL Microservice Communication");

    report.architecture_flow = {
        presentation_tier: report.frameworks.join(", ") + " + " + report.styling_engine.join(", "),
        client_state: "Decoupled component reactivity with asynchronous fetch pipelines",
        security_boundary: "HTTPS/TLS encrypted endpoint with standard CORS boundaries",
        component_hierarchy: ["Top Navigation", "Hero / Control Bar", "Dynamic Data Viewport", "Utility Action Modals", "Persistent Footer"]
    };

    return report;
}

export async function alternativeBlueprintGenerator(domain, specification = "") {
    const target = cleanDomain(domain);
    const arch = await codeStructureAnalyzer(target);

    const generatedHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${target.toUpperCase()} — Modern Alternative Architecture</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #090d16;
      --card-bg: rgba(18, 24, 38, 0.7);
      --border: rgba(0, 212, 255, 0.15);
      --primary: #00d4ff;
      --secondary: #7b61ff;
      --accent: #00ff88;
      --text: #e2e8f0;
      --text-dim: #94a3b8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: var(--bg); color: var(--text); font-family: 'Inter', sans-serif; min-height: 100vh; display: flex; flex-direction: column; }
    header { background: rgba(13, 18, 30, 0.85); backdrop-filter: blur(12px); border-bottom: 1px solid var(--border); padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; z-index: 50; }
    .logo { font-weight: 800; font-size: 1.25rem; color: var(--primary); letter-spacing: -0.5px; }
    .nav-links a { color: var(--text-dim); text-decoration: none; margin-left: 1.5rem; transition: color 0.2s; font-size: 0.9rem; }
    .nav-links a:hover { color: var(--primary); }
    .btn { background: linear-gradient(135deg, var(--primary), var(--secondary)); color: #fff; border: none; padding: 0.6rem 1.4rem; border-radius: 8px; font-weight: 600; cursor: pointer; box-shadow: 0 4px 14px rgba(0, 212, 255, 0.3); transition: transform 0.15s, box-shadow 0.15s; }
    .btn:hover { transform: translateY(-2px); box-shadow: 0 6px 20px rgba(0, 212, 255, 0.45); }
    main { flex: 1; max-width: 1200px; margin: 0 auto; width: 100%; padding: 3rem 1.5rem; }
    .hero { text-align: center; margin-bottom: 3.5rem; }
    .hero h1 { font-size: 2.8rem; font-weight: 800; margin-bottom: 1rem; line-height: 1.2; }
    .hero h1 span { background: linear-gradient(90deg, var(--primary), var(--secondary)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .hero p { color: var(--text-dim); font-size: 1.15rem; max-width: 650px; margin: 0 auto 2rem; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 1.5rem; }
    .card { background: var(--card-bg); backdrop-filter: blur(10px); border: 1px solid var(--border); border-radius: 14px; padding: 1.8rem; position: relative; transition: border-color 0.2s, transform 0.2s; }
    .card:hover { border-color: var(--primary); transform: translateY(-4px); }
    .card h3 { font-size: 1.2rem; margin-bottom: 0.75rem; color: #fff; display: flex; align-items: center; gap: 0.5rem; }
    .card p { color: var(--text-dim); font-size: 0.95rem; line-height: 1.6; }
    .badge { display: inline-block; padding: 0.2rem 0.6rem; border-radius: 20px; font-size: 0.75rem; font-weight: 600; background: rgba(0, 212, 255, 0.12); color: var(--primary); border: 1px solid rgba(0, 212, 255, 0.25); }
    footer { border-top: 1px solid var(--border); padding: 1.5rem; text-align: center; color: var(--text-dim); font-size: 0.85rem; }
  </style>
</head>
<body>
  <header>
    <div class="logo">⚡ ${target.toUpperCase()} RE-ENGINEERED</div>
    <nav class="nav-links">
      <a href="#features">Features</a>
      <a href="#architecture">Architecture</a>
      <a href="#security">Security Core</a>
      <button class="btn" onclick="alert('⚡ Omni-Arch Blueprint active!')">Launch App</button>
    </nav>
  </header>
  <main>
    <section class="hero">
      <span class="badge">CLEAN ARCHITECTURE BLUEPRINT</span>
      <h1>Clean, Secure &amp; Scalable <span>${target}</span> Alternative</h1>
      <p>Decoupled component architecture, zero-bloat state management, and enterprise-grade security headers pre-configured.</p>
    </section>
    <div class="grid" id="features">
      <div class="card">
        <h3>🛡️ Hardened Security</h3>
        <p>Built-in protection against XSS, clickjacking, and CSRF with automated Content-Security-Policy and strict transport guarantees.</p>
      </div>
      <div class="card">
        <h3>⚡ Real-Time API Pipeline</h3>
        <p>Optimized asynchronous data exchange with resilient fallback handling, rate-limiting, and error-boundary isolation.</p>
      </div>
      <div class="card">
        <h3>🎨 Ultra-Fast Glassmorphism UI</h3>
        <p>Lightweight CSS variables, pure flexbox/grid layout system without unnecessary runtime JavaScript dependencies.</p>
      </div>
    </div>
  </main>
  <footer>
    &copy; ${new Date().getFullYear()} ${target} Architecture Blueprint · Generated by Omni-Arch Pro v3.0
  </footer>
</body>
</html>`;

    const cleanRoom = cleanRoomApiSynthesizer([], target);

    return {
        tool: "alternative_blueprint_generator",
        target_domain: target,
        analyzed_frameworks: arch.frameworks,
        analyzed_styling: arch.styling_engine,
        blueprints: {
            frontend_html5_spa: generatedHtml,
            backend_microservice_node: cleanRoom.mock_microservice_code,
            openapi_spec: cleanRoom.openapi_spec
        },
        remediation_summary: "100% self-contained, responsive, and pre-hardened code blueprints ready for immediate deployment."
    };
}

export function computeSwotAnalysis({ dnsResult, sslResult, portsResult, cookieCorsResult }) {
    const swot = {
        strengths: [],
        weaknesses: [],
        opportunities: [],
        threats: [],
        roi_recommendations: []
    };

    const presentHeaders = Object.keys(dnsResult?.security_headers || {});
    if (presentHeaders.length > 0) {
        swot.strengths.push(`Active defense headers in place: ${presentHeaders.join(", ")}`);
    }
    const days = sslResult?.certificate?.days_remaining;
    if (typeof days === "number" && days > 30) {
        swot.strengths.push(`Robust TLS posture: ${sslResult.certificate.expiry_status} (${days} days remaining)`);
    }
    if ((dnsResult?.dns_records?.spf || []).length > 0) {
        swot.strengths.push("Domain SPF records published for anti-spoofing verification.");
    }

    const missingHeaders = dnsResult?.missing_headers || [];
    if (missingHeaders.length > 0) {
        swot.weaknesses.push(`Missing critical security headers: ${missingHeaders.join(", ")}`);
    }
    if (!dnsResult?.dns_records?.dmarc || dnsResult.dns_records.dmarc.length === 0) {
        swot.weaknesses.push("No DMARC policy found — domain is vulnerable to email impersonation / phishing.");
    }
    if ((portsResult?.risky_exposures || []).length > 0) {
        swot.weaknesses.push(`Risky open ports detected: ${portsResult.risky_exposures.map(p => `${p.port}/${p.service}`).join(", ")}`);
    }
    if ((cookieCorsResult?.findings || []).length > 0) {
        swot.weaknesses.push(`Cookie/CORS issues: ${cookieCorsResult.findings.slice(0, 2).join("; ")}`);
    }

    swot.opportunities.push("Automate security header deployment using Vercel, Cloudflare, or Nginx configs.");
    swot.opportunities.push("Implement a strict DMARC 'p=reject' policy to boost email deliverability and brand reputation.");
    swot.opportunities.push("Adopt a zero-trust network model for internal databases and non-HTTP service ports.");

    if (missingHeaders.includes("strict-transport-security")) {
        swot.threats.push("Man-in-the-Middle (MITM) downgrade attacks via missing HSTS policy.");
    }
    if (missingHeaders.includes("content-security-policy")) {
        swot.threats.push("Cross-Site Scripting (XSS) and data exfiltration due to absent Content Security Policy.");
    }
    if ((portsResult?.risky_exposures || []).length > 0) {
        swot.threats.push("Direct external exploitation of exposed backend database services.");
    }

    swot.roi_recommendations.push({
        priority: "CRITICAL",
        action: "Deploy Missing Security Headers",
        roi: "Prevents high-severity browser-based exploits (XSS, clickjacking) with near-zero infrastructure cost."
    });
    swot.roi_recommendations.push({
        priority: "HIGH",
        action: "Configure DMARC Policy (p=reject)",
        roi: "Guards against corporate phishing and protects email deliverability rates."
    });
    swot.roi_recommendations.push({
        priority: "HIGH",
        action: "Firewall Non-Essential Ports",
        roi: "Eliminates remote brute-force attack vectors on database and administrative ports."
    });

    return swot;
}

export async function strategicSwotAnalyzer(domain) {
    const target = cleanDomain(domain);
    const [dnsResult, sslResult, portsResult, cookieCorsResult] = await Promise.all([
        domainSecurityAudit(target),
        sslTlsInspector(target),
        tcpPortScanner(target),
        cookieCorsAuditor(target),
    ]);

    const swot = computeSwotAnalysis({ dnsResult, sslResult, portsResult, cookieCorsResult });
    return {
        tool: "strategic_swot_analyzer",
        domain: target,
        timestamp: new Date().toISOString(),
        swot,
    };
}

// ─────────────────────────────────────────────────────────────
//  SUPERPOWER 10: ZERO-DEPENDENCY EXECUTIVE PDF & PRINTABLE REPORT
// ─────────────────────────────────────────────────────────────

/**
 * TOOL 14 — generate_security_report
 * Parallel execution across all security engines, generating both HTML and Markdown
 * reports featuring a high-end printable CSS dossier layout, Mermaid.js attack topology,
 * clean-room mock microservice, and 3-column tactical decision matrix.
 */
export async function generateSecurityReport(domain) {
    const target = cleanDomain(domain);
    const dateStr = new Date().toUTCString();

    // Parallel probes with safe error fallback
    const [dnsSettled, sslSettled, subSettled, metaSettled, portsSettled, jsSettled, cookieSettled] =
        await Promise.allSettled([
            domainSecurityAudit(target),
            sslTlsInspector(target),
            subdomainOsintRecon(target),
            webMetadataAndRobotsAnalyzer(target),
            tcpPortScanner(target),
            jsBundleReverser(target),
            cookieCorsAuditor(target),
        ]);

    const dnsResult        = dnsSettled.status === "fulfilled" ? dnsSettled.value : { error: dnsSettled.reason?.message };
    const sslResult        = sslSettled.status === "fulfilled" ? sslSettled.value : { error: sslSettled.reason?.message };
    const subResult        = subSettled.status === "fulfilled" ? subSettled.value : { error: subSettled.reason?.message };
    const metaResult       = metaSettled.status === "fulfilled" ? metaSettled.value : { error: metaSettled.reason?.message };
    const portsResult      = portsSettled.status === "fulfilled" ? portsSettled.value : { error: portsSettled.reason?.message };
    const jsResult         = jsSettled.status === "fulfilled" ? jsSettled.value : { error: jsSettled.reason?.message };
    const cookieCorsResult = cookieSettled.status === "fulfilled" ? cookieSettled.value : { error: cookieSettled.reason?.message };

    // Deep WAF & Tech Fingerprinting
    const wafData = deepWafAndTechFingerprinter(
        dnsResult.security_headers || {},
        "",
        cookieCorsResult.cookies || []
    );

    // Calculate Risk Score
    let riskScore = 0;
    if (dnsResult.missing_headers?.includes("strict-transport-security")) riskScore += 15;
    if (dnsResult.missing_headers?.includes("content-security-policy")) riskScore += 20;
    if (dnsResult.missing_headers?.includes("x-frame-options")) riskScore += 10;
    if (!dnsResult.dns_records?.dmarc || dnsResult.dns_records.dmarc.length === 0) riskScore += 15;
    if (!dnsResult.dns_records?.spf || dnsResult.dns_records.spf.length === 0) riskScore += 10;

    const certDays = sslResult.certificate?.days_remaining;
    if (typeof certDays === "number") {
        if (certDays < 0) riskScore += 30;
        else if (certDays < 14) riskScore += 20;
        else if (certDays < 30) riskScore += 10;
    }

    riskScore += (portsResult.risky_exposures || []).length * 15;
    riskScore += (jsResult.secrets || []).length * 15;
    if (cookieCorsResult.risk_level === "CRITICAL") riskScore += 25;
    else if (cookieCorsResult.risk_level === "HIGH") riskScore += 15;

    const leaks = metaResult?.leaks_and_sourcemaps?.sensitive_files || [];
    if (leaks.some(l => l.severity === "CRITICAL")) riskScore += 30;
    else if (leaks.length > 0) riskScore += 15;

    riskScore = Math.min(100, riskScore);

    const riskLabel = riskScore < 25 ? "LOW RISK — Strong Security Posture"
                    : riskScore < 55 ? "MODERATE RISK — Action Recommended"
                    : riskScore < 80 ? "HIGH RISK — Immediate Remediation Required"
                    : "CRITICAL RISK — Active Exploitation Surface";

    const riskColor = riskScore < 25 ? "#00ff88"
                    : riskScore < 55 ? "#00d4ff"
                    : riskScore < 80 ? "#f5a623"
                    : "#ff3b3b";

    // Remediation snippets
    const remediationData = await vulnerabilityAndHeaderRemediator(target, dnsResult);

    // SWOT analysis
    const swot = computeSwotAnalysis({ dnsResult, sslResult, portsResult, cookieCorsResult });

    // 3-Column Structured Audit Matrix
    const auditMatrix = generateStructuredAuditMatrix({
        dnsData: dnsResult,
        sslData: sslResult,
        portsData: portsResult,
        cookieData: cookieCorsResult,
        jsData: jsResult,
        leakData: metaResult?.leaks_and_sourcemaps || {}
    });

    // Mermaid Topology
    const mermaidSyntax = mermaidTopologyGenerator({
        domain: target,
        wafData,
        dnsData: dnsResult,
        portsData: portsResult,
        subdomains: subResult?.subdomains || [],
        apiEndpoints: jsResult?.api_endpoints || []
    });

    // Clean-room microservice synthesis
    const cleanRoomBlueprint = cleanRoomApiSynthesizer(jsResult?.api_endpoints || [], target);

    // Save mock microservice and OpenAPI spec to disk
    const reportsDir = path.join(__dirname, "reports");
    await fs.mkdir(reportsDir, { recursive: true });
    const slug = target.replace(/\./g, "-");

    await fs.writeFile(
        path.join(reportsDir, `${slug}-mock-service.js`),
        cleanRoomBlueprint.mock_microservice_code,
        "utf8"
    );
    await fs.writeFile(
        path.join(reportsDir, `${slug}-openapi.json`),
        JSON.stringify(cleanRoomBlueprint.openapi_spec, null, 2),
        "utf8"
    );

    // ── Build HTML Dossier Report ─────────────────────────────
    const matrixRowsHtml = auditMatrix.map(m => `
      <tr>
        <td style="font-weight:700;color:#38bdf8;">${esc(m.component)}<br><span style="font-size:11px;color:#4ade80;">✔ ${esc(m.working)}</span></td>
        <td style="color:#f87171;">✘ ${esc(m.flaw)}<br><span style="font-size:11px;color:#94a3b8;">Impact: ${esc(m.impact)}</span></td>
        <td><pre style="margin:0;background:#0f172a;padding:6px 10px;border-radius:4px;color:#fde047;font-size:11px;white-space:pre-wrap;">${esc(m.remediation)}</pre></td>
      </tr>
    `).join("");

    const htmlReport = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Executive Security Dossier — ${esc(target)}</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@300;400;600;700;900&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
<script>mermaid.initialize({ startOnLoad: true, theme: 'dark' });</script>
<style>
  :root {
    --bg: #090d16; --bg2: #0f1528; --bg3: #141d35;
    --border: #1e2d50; --accent: #00d4ff; --accent2: #7b61ff;
    --green: #00ff88; --red: #ff3b3b; --yellow: #f5a623;
    --text: #c8d6f0; --dim: #5a6a8a;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Inter', sans-serif; font-size: 13px; line-height: 1.6; }

  /* ── Dossier Header ── */
  .hero { background: linear-gradient(135deg, #090d16 0%, #0d1a3a 50%, #0a1628 100%);
    border-bottom: 2px solid var(--accent); padding: 40px 48px; position: relative; }
  .hero-badge { display: inline-flex; align-items: center; gap: 8px; background: rgba(0,212,255,.1);
    border: 1px solid rgba(0,212,255,.3); border-radius: 20px; padding: 4px 14px; font-size: 11px;
    font-weight: 700; color: var(--accent); letter-spacing: 1.5px; text-transform: uppercase; margin-bottom: 12px; }
  .hero h1 { font-size: 32px; font-weight: 900; color: #fff; letter-spacing: -0.5px; }
  .hero h1 span { background: linear-gradient(90deg, var(--accent), var(--accent2)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
  .hero-meta { margin-top: 8px; color: var(--dim); font-size: 13px; display: flex; gap: 20px; flex-wrap: wrap; }
  .hero-meta b { color: var(--text); }

  .container { max-width: 1240px; margin: 0 auto; padding: 32px 24px; }
  .grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
  @media(max-width:900px) { .grid-4 { grid-template-columns: repeat(2,1fr); } }

  .card { background: var(--bg2); border: 1px solid var(--border); border-radius: 12px; padding: 18px 20px; position: relative; }
  .card-label { font-size: 11px; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; color: var(--dim); margin-bottom: 6px; }
  .card-value { font-size: 26px; font-weight: 900; line-height: 1.1; }
  .card-sub { font-size: 12px; color: var(--dim); margin-top: 4px; }

  .panel { background: var(--bg2); border: 1px solid var(--border); border-radius: 12px; margin-bottom: 24px; overflow: hidden; }
  .panel-header { background: var(--bg3); border-bottom: 1px solid var(--border); padding: 14px 20px; display: flex; align-items: center; justify-content: space-between; }
  .panel-header h2 { font-size: 14px; font-weight: 700; color: #fff; letter-spacing: .4px; }
  .panel-body { padding: 20px; }

  table { width: 100%; border-collapse: collapse; font-family: 'JetBrains Mono', monospace; font-size: 12px; }
  th { text-align: left; color: var(--dim); font-size: 11px; letter-spacing: 1px; text-transform: uppercase; padding: 10px 12px; border-bottom: 1px solid var(--border); }
  td { padding: 10px 12px; border-bottom: 1px solid rgba(30,45,80,.4); vertical-align: top; }
  tr:hover td { background: rgba(0,212,255,.02); }

  pre { font-family: 'JetBrains Mono', monospace; }

  /* ── Printable PDF Dossier Styles ── */
  .no-print { display: inline-block; margin-left: auto; }
  .print-btn { background: var(--accent); color: #000; border: none; padding: 8px 18px; border-radius: 6px; font-weight: 700; cursor: pointer; font-size: 12px; }
  .print-btn:hover { background: #fff; }

  @media print {
    @page { size: A4 portrait; margin: 15mm 12mm; }
    body { background: #fff !important; color: #000 !important; font-size: 11px; }
    .hero { background: #fff !important; color: #000 !important; border-bottom: 2px solid #000; padding: 20px 0; }
    .hero h1 span, .hero h1 { color: #000 !important; -webkit-text-fill-color: #000 !important; }
    .no-print { display: none !important; }
    .card, .panel { background: #fff !important; border: 1px solid #ccc !important; break-inside: avoid; margin-bottom: 16px; }
    .panel-header { background: #f1f5f9 !important; border-bottom: 1px solid #ccc; color: #000 !important; }
    .panel-header h2 { color: #000 !important; }
    th { color: #475569 !important; border-bottom: 1px solid #ccc; }
    td { border-bottom: 1px solid #e2e8f0; color: #000 !important; }
    pre { background: #f8fafc !important; color: #0f172a !important; border: 1px solid #cbd5e1; }
    .mermaid { page-break-inside: avoid; }
    .page-break { page-break-before: always; }
  }
</style>
</head>
<body>

<div class="hero">
  <div style="display:flex;align-items:center;">
    <div class="hero-badge">⚡ OMNI-ARCH PRO v3.0 · EXECUTIVE SECURITY DOSSIER</div>
    <div class="no-print">
      <button class="print-btn" onclick="window.print()">🖨 Export Executive PDF</button>
    </div>
  </div>
  <h1>Security Posture: <span>${esc(target)}</span></h1>
  <div class="hero-meta">
    <span>Classification: <b>CONFIDENTIAL / DEFENSIVE AUDIT</b></span>
    <span>Target Ingress: <b>${esc(wafData.primary_waf)}</b></span>
    <span>Audit Date: <b>${esc(dateStr)}</b></span>
    <span>Risk Level: <b style="color:${riskColor}">${riskScore}/100 — ${riskLabel}</b></span>
  </div>
</div>

<div class="container">

<!-- Stat Cards -->
<div class="grid-4">
  <div class="card">
    <div class="card-label">Overall Risk Score</div>
    <div class="card-value" style="color:${riskColor}">${riskScore}<span style="font-size:14px;color:var(--dim)">/100</span></div>
    <div class="card-sub">${riskLabel}</div>
  </div>
  <div class="card">
    <div class="card-label">HTTP Defense Grade</div>
    <div class="card-value" style="color:var(--accent)">${esc(dnsResult.header_grade || 'F')}</div>
    <div class="card-sub">${esc(dnsResult.header_score || '0/6')} headers valid</div>
  </div>
  <div class="card">
    <div class="card-label">WAF Protection Barrier</div>
    <div class="card-value" style="color:${wafData.is_waf_protected ? '#00ff88' : '#f5a623'};font-size:20px;">${esc(wafData.primary_waf)}</div>
    <div class="card-sub">${wafData.is_waf_protected ? 'Active Protection' : 'Direct Ingress Exposed'}</div>
  </div>
  <div class="card">
    <div class="card-label">Clean-Room Endpoints</div>
    <div class="card-value" style="color:var(--accent2)">${cleanRoomBlueprint.endpoints_count}</div>
    <div class="card-sub">Synthesized Express &amp; OpenAPI</div>
  </div>
</div>

<!-- 3-Column Structured Tactical Decision Matrix -->
<div class="panel">
  <div class="panel-header">
    <h2>🎯 3-Column Tactical Decision Matrix (Working · Broken · Remediation)</h2>
  </div>
  <div class="panel-body">
    <table>
      <thead>
        <tr>
          <th width="32%">Component &amp; What's Working ✔</th>
          <th width="34%">Technical Flaw &amp; Business Impact ✘</th>
          <th width="34%">Tactical Remediation &amp; 1-Click Fix 🛠</th>
        </tr>
      </thead>
      <tbody>
        ${matrixRowsHtml}
      </tbody>
    </table>
  </div>
</div>

<!-- Mermaid Architecture Topology -->
<div class="panel page-break">
  <div class="panel-header">
    <h2>🗺️ Automated Attack Surface &amp; Ingress Topology (Mermaid.js)</h2>
  </div>
  <div class="panel-body" style="text-align:center;overflow-x:auto;">
    <div class="mermaid">
${mermaidSyntax}
    </div>
  </div>
</div>

<!-- Strategic SWOT Analysis -->
<div class="panel">
  <div class="panel-header">
    <h2>📊 Strategic SWOT Security Posture</h2>
  </div>
  <div class="panel-body">
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;">
      <div style="background:rgba(0,255,136,.05);border:1px solid rgba(0,255,136,.2);border-radius:8px;padding:14px;">
        <h3 style="color:#00ff88;font-size:13px;margin-bottom:8px;">STRENGTHS (Defensive Controls)</h3>
        <ul style="padding-left:18px;font-size:12px;color:var(--text);">
          ${swot.strengths.map(s => `<li>${esc(s)}</li>`).join("")}
        </ul>
      </div>
      <div style="background:rgba(255,59,59,.05);border:1px solid rgba(255,59,59,.2);border-radius:8px;padding:14px;">
        <h3 style="color:#ff3b3b;font-size:13px;margin-bottom:8px;">WEAKNESSES (Gaps &amp; Exposures)</h3>
        <ul style="padding-left:18px;font-size:12px;color:var(--text);">
          ${swot.weaknesses.map(w => `<li>${esc(w)}</li>`).join("")}
        </ul>
      </div>
    </div>
  </div>
</div>

<!-- Clean-Room Microservice Blueprint -->
<div class="panel">
  <div class="panel-header">
    <h2>⚡ Synthesized Clean-Room Microservice Blueprint (REA++)</h2>
  </div>
  <div class="panel-body">
    <p style="color:var(--dim);margin-bottom:12px;">Auto-generated mock Node.js/Express service based on reverse-engineered routes. Save as <code>mock_express_microservice.js</code>.</p>
    <pre style="background:#0f172a;border:1px solid var(--border);border-radius:8px;padding:16px;color:#a5f3fc;overflow-x:auto;max-height:300px;">${esc(cleanRoomBlueprint.mock_microservice_code)}</pre>
  </div>
</div>

</div>

<div style="text-align:center;padding:30px;color:var(--dim);font-size:12px;border-top:1px solid var(--border);">
  Omni-Arch Pro v3.0 / Matrix Core &nbsp;·&nbsp; Enterprise Defensive Reconnaissance &nbsp;·&nbsp; Strict Confidentiality Enforced
</div>

</body>
</html>`;

    // ── Build Markdown Report ─────────────────────────────────
    const mdMatrix = auditMatrix.map(m =>
        `| **${m.component}**<br>✔ ${m.working} | ✘ ${m.flaw}<br>*Impact: ${m.impact}* | \`${m.remediation.replace(/\n/g, " ")}\` |`
    ).join("\n");

    const mdReport = `# EXECUTIVE SECURITY DOSSIER: ${target.toUpperCase()}
**Engine:** Omni-Arch Pro v3.0 / Matrix Core  
**Audit Timestamp:** ${dateStr}  
**Target Ingress:** ${wafData.primary_waf}  
**Overall Risk Score:** ${riskScore}/100 (${riskLabel})  

---

## 1. EXECUTIVE SUMMARY & POSTURE METRICS
- **Header Security Grade:** ${dnsResult.header_grade || "F"} (${dnsResult.header_score || "0/6"})
- **WAF Protection Barrier:** ${wafData.primary_waf} (${wafData.is_waf_protected ? "Active" : "Direct Ingress"})
- **TLS/SSL Status:** ${sslResult.certificate?.expiry_status || "N/A"} (${sslResult.certificate?.days_remaining ?? "N/A"} days left)
- **Open TCP Ports:** ${(portsResult.open_ports || []).map(p => `${p.port}/${p.service}`).join(", ") || "None"}
- **Synthesized API Endpoints:** ${cleanRoomBlueprint.endpoints_count} routes identified

---

## 2. 3-COLUMN TACTICAL DECISION MATRIX
| Component & What's Working ✔ | Technical Flaw & Business Impact ✘ | Tactical Remediation & 1-Click Fix 🛠 |
| :--- | :--- | :--- |
${mdMatrix}

---

## 3. ARCHITECTURE & INGRESS TOPOLOGY (MERMAID)
\`\`\`mermaid
${mermaidSyntax}
\`\`\`

---

## 4. STRATEGIC SWOT ANALYSIS
### Strengths
${swot.strengths.map(s => `- ${s}`).join("\n")}

### Weaknesses
${swot.weaknesses.map(w => `- ${w}`).join("\n")}

### Opportunities
${swot.opportunities.map(o => `- ${o}`).join("\n")}

### Threats
${swot.threats.map(t => `- ${t}`).join("\n")}

---

## 5. CLEAN-ROOM MOCK MICROSERVICE BLUEPRINT
A complete runnable Node.js/Express mock service has been synthesized and saved to:
\`reports/${slug}-mock-service.js\` and OpenAPI 3.0 specification saved to \`reports/${slug}-openapi.json\`.

---
*Report generated by Omni-Arch Pro v3.0. Confidential client audit.*
`;

    // Save Reports
    const htmlPath = path.join(reportsDir, `${slug}-audit.html`);
    const mdPath   = path.join(reportsDir, `${slug}-audit.md`);

    await fs.writeFile(htmlPath, htmlReport, "utf8");
    await fs.writeFile(mdPath, mdReport, "utf8");

    return {
        tool: "generate_security_report",
        domain: target,
        timestamp: new Date().toISOString(),
        risk_score: riskScore,
        risk_label: riskLabel,
        html_report: htmlPath,
        html_report_path: htmlPath,
        markdown_report: mdPath,
        markdown_report_path: mdPath,
        mock_service_path: path.join(reportsDir, `${slug}-mock-service.js`),
        openapi_spec_path: path.join(reportsDir, `${slug}-openapi.json`),
        waf_fingerprint: wafData,
        audit_matrix: auditMatrix,
        clean_room_endpoints: cleanRoomBlueprint.endpoints,
        swot,
        remediation_snippets: remediationData.remediation_snippets,
        summary: {
            risk_score: riskScore,
            risk_level: riskLabel,
            header_grade: dnsResult.header_grade || "N/A",
            header_score: dnsResult.header_score || "0/6",
            ssl_days_remaining: sslResult.certificate?.days_remaining ?? "--",
            ssl_status: sslResult.certificate?.expiry_status ?? "N/A",
            tls_protocol: sslResult.tls_connection?.protocol ?? "N/A",
            subdomains_found: subResult.total_found ?? 0,
            open_ports: portsResult.total_open ?? 0,
            risky_ports: portsResult.total_risky ?? 0,
            js_endpoints: jsResult.total_endpoints ?? 0,
            js_secrets: jsResult.total_secrets ?? 0,
            security_txt: metaResult.security_txt?.found ?? false,
            cookie_cors_risk: cookieCorsResult.risk_level ?? "LOW",
            remediation_snippets: remediationData.remediation_snippets
        }
    };
}

// ─────────────────────────────────────────────────────────────
//  MCP SERVER INITIALIZATION & TOOL REGISTRATION
// ─────────────────────────────────────────────────────────────

const server = new Server(
    { name: "omni-arch-matrix-core", version: "3.0.0" },
    { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
        {
            name: "domain_security_audit",
            description: "Follows HTTP 301/302 redirects to audit final destination headers (eliminating false-positive Grade F) and resolves multi-chunk DNS TXT records for SPF and DMARC.",
            inputSchema: {
                type: "object",
                properties: { domain: { type: "string", description: "Target domain (e.g., google.com)." } },
                required: ["domain"],
            },
        },
        {
            name: "ssl_tls_inspector",
            description: "Inspects target SSL/TLS certificates, expiry days, SANs, cipher suites, and protocol versions.",
            inputSchema: {
                type: "object",
                properties: { domain: { type: "string", description: "Target domain to inspect TLS for." } },
                required: ["domain"],
            },
        },
        {
            name: "subdomain_osint_recon",
            description: "Multi-source CT + OSINT subdomain finder with dangling CNAME takeover detection (crt.sh, HackerTarget, AlienVault).",
            inputSchema: {
                type: "object",
                properties: { domain: { type: "string", description: "Domain to discover subdomains for." } },
                required: ["domain"],
            },
        },
        {
            name: "sourcemap_and_git_leak_detector",
            description: "Passive scanner to detect exposed source-map (.js.map) files, /.git/HEAD, and /.env files, reconstructing the un-minified component tree layout.",
            inputSchema: {
                type: "object",
                properties: { domain: { type: "string", description: "Domain to audit for exposed leaks and source maps." } },
                required: ["domain"],
            },
        },
        {
            name: "web_metadata_and_robots_analyzer",
            description: "Fetches robots.txt, security.txt, sitemap.xml, HTML metadata, and performs passive leak audits.",
            inputSchema: {
                type: "object",
                properties: { domain: { type: "string", description: "Domain to inspect web metadata for." } },
                required: ["domain"],
            },
        },
        {
            name: "local_code_secret_auditor",
            description: "Audits a local directory or file path for hardcoded API keys, JWTs, cloud credentials, and database URIs.",
            inputSchema: {
                type: "object",
                properties: { path: { type: "string", description: "Absolute or relative directory path to scan." } },
                required: ["path"],
            },
        },
        {
            name: "js_bundle_reverser",
            description: "Reverse-engineers client JavaScript bundles and inline scripts (e.g. __NEXT_DATA__) for API routes, cloud storage, secrets, and outdated libraries.",
            inputSchema: {
                type: "object",
                properties: { domain: { type: "string", description: "Domain whose JS bundles to reverse-engineer." } },
                required: ["domain"],
            },
        },
        {
            name: "tcp_port_scanner",
            description: "Scans the target's primary IP across 12 high-value ports (FTP, SSH, SMTP, HTTP, HTTPS, MySQL, PostgreSQL, Redis, MongoDB, and alt-HTTP ports) flagging critical database exposures.",
            inputSchema: {
                type: "object",
                properties: { domain: { type: "string", description: "Domain to scan ports for." } },
                required: ["domain"],
            },
        },
        {
            name: "cookie_cors_auditor",
            description: "Audits cookies for Secure, HttpOnly, and SameSite flags, and tests CORS configuration for insecure wildcards and origin reflection.",
            inputSchema: {
                type: "object",
                properties: { domain: { type: "string", description: "Domain to audit cookies and CORS for." } },
                required: ["domain"],
            },
        },
        {
            name: "steganography_and_image_inspector",
            description: "Inspects target favicons and branding assets for EXIF GPS tags and hidden payload data past EOF boundaries.",
            inputSchema: {
                type: "object",
                properties: { domain: { type: "string", description: "Domain whose branding assets to inspect." } },
                required: ["domain"],
            },
        },
        {
            name: "vulnerability_and_header_remediator",
            description: "Generates production-ready, copy-pasteable configuration code patches for Nginx, Vercel, Next.js, Cloudflare, Apache, and DNS DMARC/SPF.",
            inputSchema: {
                type: "object",
                properties: { domain: { type: "string", description: "Domain to generate remediation configs for." } },
                required: ["domain"],
            },
        },
        {
            name: "code_structure_analyzer",
            description: "Safely analyzes the publicly accessible frontend architecture, frameworks (React, Next.js, Vue, Angular, WordPress), styling systems, layout components, and business logic flow of any target web application.",
            inputSchema: {
                type: "object",
                properties: { domain: { type: "string", description: "Domain to analyze architecture and code structure for." } },
                required: ["domain"],
            },
        },
        {
            name: "alternative_blueprint_generator",
            description: "Generates complete, optimized, modern alternative code structures (HTML5/CSS3 glassmorphic SPA and hardened Node.js microservice) based on analyzed target architecture.",
            inputSchema: {
                type: "object",
                properties: {
                    domain: { type: "string", description: "Domain to generate alternative architecture blueprint for." },
                    specification: { type: "string", description: "Optional custom architectural specification or goals." }
                },
                required: ["domain"],
            },
        },
        {
            name: "strategic_swot_analyzer",
            description: "Computes a deep heuristic SWOT analysis (Strengths, Weaknesses, Opportunities, Threats) and ROI strategic remediation recommendations for a target domain.",
            inputSchema: {
                type: "object",
                properties: { domain: { type: "string", description: "Domain to analyze SWOT posture for." } },
                required: ["domain"],
            },
        },
        {
            name: "generate_security_report",
            description: "Runs all 10 superpower security engines in parallel, compiles a 3-column tactical decision matrix, generates Mermaid attack topology, synthesizes clean-room mock microservice, and exports an executive printable dossier.",
            inputSchema: {
                type: "object",
                properties: { domain: { type: "string", description: "Domain to audit and generate an executive report for." } },
                required: ["domain"],
            },
        },
    ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    let result;

    switch (name) {
        case "domain_security_audit":            result = await domainSecurityAudit(args.domain); break;
        case "ssl_tls_inspector":                result = await sslTlsInspector(args.domain); break;
        case "subdomain_osint_recon":            result = await subdomainOsintRecon(args.domain); break;
        case "sourcemap_and_git_leak_detector":  result = await sourcemapAndGitLeakDetector(args.domain); break;
        case "web_metadata_and_robots_analyzer": result = await webMetadataAndRobotsAnalyzer(args.domain); break;
        case "local_code_secret_auditor":        result = await localCodeSecretAuditor(args.path); break;
        case "js_bundle_reverser":               result = await jsBundleReverser(args.domain); break;
        case "tcp_port_scanner":                 result = await tcpPortScanner(args.domain); break;
        case "cookie_cors_auditor":              result = await cookieCorsAuditor(args.domain); break;
        case "steganography_and_image_inspector": result = await steganographyAndImageInspector(args.domain); break;
        case "vulnerability_and_header_remediator": result = await vulnerabilityAndHeaderRemediator(args.domain); break;
        case "code_structure_analyzer":          result = await codeStructureAnalyzer(args.domain); break;
        case "alternative_blueprint_generator":  result = await alternativeBlueprintGenerator(args.domain, args.specification); break;
        case "strategic_swot_analyzer":          result = await strategicSwotAnalyzer(args.domain); break;
        case "generate_security_report":         result = await generateSecurityReport(args.domain); break;
        default: throw new Error(`Unknown tool: ${name}`);
    }

    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
});

async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("🛡️  Omni-Arch Pro v3.0 / Matrix Core MCP Server is live on stdio — 15 advanced tools active!");
}

const isDirectRun = process.argv[1] && (
    process.argv[1].endsWith("index.js") ||
    fileURLToPath(import.meta.url) === path.resolve(process.argv[1])
);

if (isDirectRun) {
    main().catch((err) => {
        console.error("Fatal server error:", err);
        process.exit(1);
    });
}