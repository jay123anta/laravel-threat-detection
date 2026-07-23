# Comprehensive Security Standards Gap Analysis
## jayanta/laravel-threat-detection v1.2.0

**Date:** 2026-03-22
**Purpose:** Map industry security standards, IDS/WAF detection capabilities, and known attack patterns against the current package to identify coverage gaps and improvement opportunities.

---

## Table of Contents
1. [OWASP Top 10 (2025)](#1-owasp-top-10-2025)
2. [OWASP ModSecurity Core Rule Set (CRS)](#2-owasp-modsecurity-core-rule-set-crs)
3. [CWE Top 25 (2025)](#3-cwe-top-25-2025)
4. [MITRE ATT&CK Web Techniques](#4-mitre-attck-web-techniques)
5. [Snort/Suricata IDS Signatures](#5-snortsuricata-ids-signatures)
6. [Known CVE Exploit Patterns](#6-known-cve-exploit-patterns)
7. [OWASP API Security Top 10](#7-owasp-api-security-top-10)
8. [Bot & Scanner Detection](#8-bot--scanner-detection)
9. [Commercial WAF Categories](#9-commercial-waf-categories-cloudflare-aws-waf-sucuri)
10. [Paranoia Levels & False Positive Management](#10-paranoia-levels--false-positive-management)
11. [ReDoS Prevention & Pattern Efficiency](#11-redos-prevention--pattern-efficiency)
12. [Current Package Coverage Summary](#12-current-package-coverage-summary)
13. [Gap Analysis: What We Are Missing](#13-gap-analysis-what-we-are-missing)
14. [Recommended Additions by Priority](#14-recommended-additions-by-priority)

---

## 1. OWASP Top 10 (2025)

The 2025 revision reorganizes several categories from 2021.

| Rank | Category | What to Detect | Current Coverage | Gap |
|------|----------|---------------|-----------------|-----|
| A01 | **Broken Access Control** | IDOR patterns, forced browsing, privilege escalation, CORS misconfig, SSRF (merged in) | Partial: IDOR user deletion, admin enumeration, SSRF localhost/metadata | Missing: path manipulation for authz bypass, CORS header abuse, JWT claim tampering |
| A02 | **Security Misconfiguration** | Debug endpoints, default creds, directory listing, stack traces, unnecessary features | Partial: debug/test/console endpoint probes, .env/.git access | Missing: stack trace detection in responses (IDS, not applicable), verbose error header detection |
| A03 | **Software Supply Chain Failures** | Dependency confusion, typosquatting, compromised packages | None (not regex-detectable at request level) | N/A for request-level IDS |
| A04 | **Cryptographic Failures** | Sensitive data in URLs, weak TLS, cleartext credentials | Partial: password exposure, token leaks, PII detection | Missing: credit card number patterns (Luhn), SSN patterns (non-IN regions) |
| A05 | **Injection** | SQLi, XSS, NoSQLi, LDAP injection, OS command injection, SSTI, Expression Language, CRLF | Good: SQLi, XSS, command injection, NoSQLi, EL injection, SSTI (blade/JSP) | Missing: LDAP injection, CRLF injection, XPath injection, header injection |
| A06 | **Insecure Design** | Business logic abuse, rate limiting bypass | Partial: DDoS detection, API rate probes | Mostly design-level, not regex-detectable |
| A07 | **Identification & Auth Failures** | Credential stuffing patterns, brute force, session fixation | Partial: session fixation (CRS 943), auth path awareness | Missing: credential stuffing velocity detection, session fixation via URL |
| A08 | **Software & Data Integrity** | Deserialization attacks, unsigned update channels | Partial: PHP object deserialization | Missing: Java deserialization (ysoserial gadget chains), .NET deserialization |
| A09 | **Security Logging & Monitoring** | Log injection, log forging | Good: Log output sanitization implemented | N/A (meta-category about having IDS) |
| A10 | **Mishandling Exceptional Conditions** | Error-based info disclosure, fail-open conditions | None at request level | Not regex-detectable at request level |

### Key Takeaway
The package covers A01, A02, A04, A05, A07, A08 partially. The biggest regex-detectable gaps are in **injection variants** (LDAP, CRLF, XPath) and **broader PII detection** (credit cards, SSN).

---

## 2. OWASP ModSecurity Core Rule Set (CRS)

The CRS is the industry-standard open-source WAF ruleset. It uses a **numbered rule category system** and **anomaly scoring** (not immediate blocking).

### CRS Rule Categories vs. Package Coverage

| CRS ID Range | Category | Description | Package Coverage |
|-------------|----------|-------------|-----------------|
| 910 | **IP Reputation** | Known malicious IPs, Tor exit nodes, proxy lists | None |
| 911 | **Method Enforcement** | Block unusual HTTP methods (TRACE, CONNECT, etc.) | None |
| 912 | **DoS Protection** | Request rate thresholds | Yes (DDoS detection) |
| 913 | **Scanner Detection** | Known scanner user-agents and fingerprints | Yes (15 scanners + 8 bots) |
| 920 | **Protocol Enforcement** | HTTP protocol violations, request line validation, encoding validation, multipart validation | None |
| 921 | **Protocol Attack** | HTTP request smuggling, response splitting, header injection | None |
| 922 | **Multipart Attack** | Multipart form abuse | None |
| 930 | **Local File Inclusion (LFI)** | Path traversal, sensitive file access | Yes (directory traversal, /etc/passwd, .env, .git) |
| 931 | **Remote File Inclusion (RFI)** | URL-based includes, protocol wrappers | Yes (LFI protocol usage: file://, php://, data://) |
| 932 | **Remote Code Execution** | OS command injection, shell commands | Yes (shell functions, command chains) |
| 933 | **PHP Attack** | PHP-specific injection patterns | Partial (<?php, base64_decode, eval) |
| 934 | **Node.js Attack** | Node-specific patterns | Minimal (--inspect flag only) |
| 941 | **XSS** | Cross-site scripting patterns, hundreds of signatures | Partial (script tags, event handlers, JS URIs, DOM access) |
| 942 | **SQL Injection** | SQL injection patterns across multiple DB engines | Partial (UNION, SELECT, boolean, CHAR, time-based) |
| 943 | **Session Fixation** | Session manipulation | Minimal (session ID exposure) |
| 944 | **Java Attack** | Java-specific patterns (Log4j, OGNL, EL) | Partial (Log4Shell/JNDI only) |

### CRS Anomaly Scoring Model
CRS does NOT block on single pattern matches. Each match adds points:
- **Critical** (severity 2): +5 points
- **Error** (severity 3): +4 points
- **Warning** (severity 4): +3 points
- **Notice** (severity 5): +2 points

Blocking threshold is typically **5 points** (one critical match) or **configurable higher**.

**Comparison to package:** The package uses confidence scoring (0-100) with base score + bonuses, which is conceptually similar but less granular than CRS anomaly scoring.

### Key CRS Patterns the Package Lacks

**Protocol Enforcement (920):**
- Invalid HTTP method detection
- Request line encoding validation
- Multipart boundary validation
- Content-Type vs body mismatch
- Request body size limits
- Multiple/conflicting Content-Length headers

**Protocol Attacks (921):**
- HTTP Request Smuggling (CL.TE, TE.CL conflicts)
- HTTP Response Splitting (CRLF in headers)
- HTTP Header Injection

**XSS (941) -- missing variants:**
```
/<svg[^>]*\bonload\s*=/i                     — SVG onload
/<math[^>]*>.*?<\/math>/is                   — MathML namespace abuse
/<details[^>]*\bontoggle\s*=/i               — ontoggle event
/<video[^>]*\bonerror\s*=/i                  — media error events
/<body[^>]*\bonload\s*=/i                    — body onload
/style\s*=\s*[^>]*expression\s*\(/i          — CSS expression()
/style\s*=\s*[^>]*url\s*\(/i                — CSS url() injection
/@import\s+['"]/i                            — CSS import injection
/\bsetTimeout\s*\(/i                         — setTimeout execution
/\bsetInterval\s*\(/i                        — setInterval execution
/\bFunction\s*\(/i                           — Function constructor
```

**SQL Injection (942) -- missing variants:**
```
/\bGROUP\s+BY\b/i                           — GROUP BY enumeration
/\bHAVING\b\s+\d/i                          — HAVING clause injection
/\bORDER\s+BY\s+\d+/i                       — ORDER BY column enumeration
/\bINTO\s+(OUT|DUMP)FILE\b/i                — File write via SQL
/\bLOAD_FILE\s*\(/i                         — File read via SQL
/\b(ALTER|CREATE|DROP|TRUNCATE)\s+(TABLE|DATABASE)/i — DDL injection
/\b(INSERT|UPDATE|DELETE)\s+INTO?\s+\w/i    — DML injection
/0x[0-9a-fA-F]{8,}/i                        — Hex-encoded SQL strings
/\bUNHEX\s*\(/i                             — UNHEX function
```

**Java/Application Attacks (944):**
```
/\$\{[^}]*\$\{/                             — Nested expression (Log4j obfuscation)
/\bRuntime\b.*\bgetRuntime\b/i              — Java runtime exec
/\bProcessBuilder\b/i                        — Java process builder
/\bScriptEngine\b/i                          — Java scripting engine
```

---

## 3. CWE Top 25 (2025)

The 2025 list, based on 39,080 CVEs:

| Rank | CWE | Weakness | Regex-Detectable? | Package Coverage |
|------|-----|----------|-------------------|-----------------|
| 1 | CWE-79 | **Cross-Site Scripting (XSS)** | Yes | Good |
| 2 | CWE-89 | **SQL Injection** | Yes | Good |
| 3 | CWE-352 | **Cross-Site Request Forgery (CSRF)** | Partial (token detection) | Minimal (CSRF token reference only) |
| 4 | CWE-862 | **Missing Authorization** | No (logic flaw) | N/A |
| 5 | CWE-787 | **Out-of-Bounds Write** | No (memory safety) | N/A |
| 6 | CWE-22 | **Path Traversal** | Yes | Yes |
| 7 | CWE-416 | **Use-After-Free** | No (memory safety) | N/A |
| 8 | CWE-125 | **Out-of-Bounds Read** | No (memory safety) | N/A |
| 9 | CWE-78 | **OS Command Injection** | Yes | Yes |
| 10 | CWE-94 | **Code Injection** | Yes | Partial |
| 11 | CWE-20 | **Improper Input Validation** | Partial | Partial |
| 12 | CWE-434 | **Unrestricted File Upload** | No (server-side) | N/A |
| 13 | CWE-863 | **Incorrect Authorization** | No (logic flaw) | N/A |
| 14 | CWE-476 | **NULL Pointer Dereference** | No (memory safety) | N/A |
| 15 | CWE-259 | **Hard-Coded Password** | No (code-level) | N/A |
| 16 | CWE-918 | **Server-Side Request Forgery (SSRF)** | Yes | Partial |
| 17 | CWE-306 | **Missing Authentication** | No (logic flaw) | N/A |
| 18 | CWE-190 | **Integer Overflow** | No (memory safety) | N/A |
| 19 | CWE-502 | **Deserialization of Untrusted Data** | Yes | Partial (PHP only) |
| 20 | CWE-77 | **Command Injection** | Yes | Yes |
| 21 | CWE-119 | **Buffer Overflow** | No (memory safety) | N/A |
| 22 | CWE-121 | **Stack Buffer Overflow** | No (memory safety) | N/A |
| 23 | CWE-122 | **Heap Buffer Overflow** | No (memory safety) | N/A |
| 24 | CWE-284 | **Improper Access Control** | No (logic flaw) | N/A |
| 25 | CWE-770 | **Resource Allocation Without Limits** | Partial | DDoS detection |

**Key Takeaway:** Of the 25, roughly 10 are regex-detectable at the request level. The package covers CWE-79, CWE-89, CWE-22, CWE-78, CWE-94 (partial), CWE-918 (partial), CWE-502 (PHP), CWE-77, CWE-770 (DDoS). Memory-safety CWEs and logic-flaw CWEs are not applicable to a request-inspection IDS.

---

## 4. MITRE ATT&CK Web Techniques

Key techniques relevant to web application detection:

| Technique | ID | Detection Approach | Package Coverage |
|-----------|----|--------------------|-----------------|
| Exploit Public-Facing App | T1190 | Signature-based pattern matching on injection payloads | Yes (core function) |
| Content Injection | T1659 | XSS, HTML injection, template injection | Yes |
| Drive-by Compromise | T1189 | Malicious script/iframe injection | Partial (iframe/embed) |
| Brute Force | T1110 | Rate-based detection on auth endpoints | Partial (DDoS, but no auth-specific rate limiting) |
| Valid Accounts (Default) | T1078.001 | Default credential probing | None |
| Phishing Links | T1566.002 | URL in input fields pointing to known-bad domains | None |
| Application Layer Protocol | T1071.001 | Unusual HTTP patterns, C2 beaconing | None |
| Data Exfiltration via Web | T1567 | Large response sizes, unusual data patterns | None (response inspection not in scope) |

---

## 5. Snort/Suricata IDS Signatures

Network IDS tools like Snort and Suricata detect web attacks at the packet level with HTTP-aware inspection. Key categories relevant to web app security:

### What They Detect That the Package Could Benefit From

**HTTP Protocol Anomalies:**
- Invalid HTTP version strings
- Unusual HTTP methods (TRACE, CONNECT, OPTIONS with suspicious payload)
- Missing Host header
- Content-Length / Transfer-Encoding conflicts (request smuggling)
- Abnormally long URIs or headers
- Null bytes in URI or headers

**Detection patterns the package could add:**
```
/\x00/                                      — Null byte injection
/\r\n\r\n.*\r\n/s                          — HTTP response splitting
/Transfer-Encoding\s*:\s*chunked/i          — TE header (for smuggling awareness)
/%00/                                        — URL-encoded null byte
/%0d%0a/i                                   — CRLF injection
```

**Shellcode/Binary in HTTP:**
- Non-printable characters in unexpected fields
- Executable content in text fields

---

## 6. Known CVE Exploit Patterns

### Currently Detected
| CVE | Name | Pattern | Covered? |
|-----|------|---------|----------|
| CVE-2021-44228 | **Log4Shell** | `${jndi:ldap://` | Yes |
| CVE-2014-6271 | **Shellshock** | `() {` in headers | **No** |
| CVE-2017-5638 | **Apache Struts** | `%{...}` OGNL | Partial (EL injection) |

### Missing High-Value CVE Patterns

```regex
# Shellshock (CVE-2014-6271) — still actively scanned
/\(\)\s*\{/                                  — Bash function definition in input

# Spring4Shell (CVE-2022-22965)
/class\.module\.classLoader/i                — Spring classloader manipulation

# Apache Struts OGNL (CVE-2017-5638, CVE-2018-11776)
/%\{[^}]+\}/                                 — OGNL expression injection
/\$\{[^}]*getRuntime[^}]*\}/i              — Runtime exec in expression

# Heartbleed probe (CVE-2014-0160) — network level, not HTTP regex
# Not applicable for HTTP request inspection

# ThinkPHP RCE (common in automated scanners)
/invokefunction/i                            — ThinkPHP method invocation
/think\\\\app/i                              — ThinkPHP namespace probe

# PHPUnit RCE (CVE-2017-9841)
/vendor\/phpunit\/phpunit/i                  — PHPUnit eval endpoint probe

# WordPress xmlrpc abuse
/xmlrpc\.php/i                               — XML-RPC endpoint probe

# Drupalgeddon (CVE-2018-7600)
/\#post_render|#lazy_builder|#pre_render/i   — Drupal render array injection

# React2Shell (CVE-2025-55182) — newest
# Needs specific payload pattern research

# GitLab/Jenkins/CI deserialization patterns
/ysoserial|CommonsCollections|Jdk7u21/i      — Java deserialization gadget chains
```

---

## 7. OWASP API Security Top 10

| Rank | Risk | Detection Approach | Package Coverage |
|------|------|--------------------|-----------------|
| API1 | **Broken Object Level Authorization (BOLA)** | Sequential ID access patterns, ID enumeration | Partial (IDOR patterns) |
| API2 | **Broken Authentication** | Brute force, credential stuffing, weak tokens | Partial (auth path awareness) |
| API3 | **Broken Object Property Level Authorization** | Mass assignment, property enumeration | None |
| API4 | **Unrestricted Resource Consumption** | Large limit params, deep pagination, oversized payloads | Partial (API high limit request) |
| API5 | **Broken Function Level Authorization** | Admin endpoint access, HTTP method swapping | Partial (admin path probe) |
| API6 | **Unrestricted Access to Sensitive Business Flows** | Automated flow abuse, bot behavior | Partial (bot detection) |
| API7 | **Server Side Request Forgery (SSRF)** | Internal IP/metadata URL in parameters | Yes |
| API8 | **Security Misconfiguration** | Debug headers, verbose errors, CORS | Partial |
| API9 | **Improper Inventory Management** | Old API version probing, undocumented endpoint access | None |
| API10 | **Unsafe Consumption of APIs** | Redirect following, SSRF via webhooks | None |

### Missing API-Specific Patterns
```regex
# Mass assignment / unexpected fields (hard to detect generically)
# Deep object nesting in JSON (potential DoS)
/\{[^{}]*\{[^{}]*\{[^{}]*\{[^{}]*\{/       — Deeply nested JSON (5+ levels)

# GraphQL introspection abuse
/__schema|__type/i                            — GraphQL introspection query

# GraphQL batching attacks
/\[\s*\{.*"query"/s                          — Batched GraphQL queries

# Old API version probing
/\/(v[0-9]+)\//                              — API version enumeration (context needed)
```

---

## 8. Bot & Scanner Detection

### Currently Detected (Package)
**Security Scanners (15):** sqlmap, nikto, nmap, acunetix, wpscan, nessus, openvas, nuclei, burp, zap, metasploit, w3af, havij, dirbuster, gobuster

**Suspicious Bots (8):** masscan, zgrab, shodan, censys, python-requests, curl, wget, go-http-client

### Missing Bot Signatures

```
# Additional security scanners
'arachni'        => 'Arachni Scanner'
'netsparker'     => 'Netsparker Scanner'
'qualys'         => 'Qualys Scanner'
'skipfish'       => 'Skipfish Scanner'
'vega'           => 'Vega Scanner'
'wapiti'         => 'Wapiti Scanner'
'joomscan'       => 'JoomScan Scanner'
'droopescan'     => 'DroopeScan Scanner'
'commix'         => 'Commix Tool'
'xsstrike'       => 'XSStrike Tool'
'dalfox'         => 'Dalfox XSS Scanner'
'feroxbuster'    => 'FeroxBuster'
'ffuf'           => 'FFUF Fuzzer'
'httpx'          => 'HTTPX Scanner'
'subfinder'      => 'Subfinder Tool'
'katana'         => 'Katana Crawler'

# Malicious bots and crawlers
'ahrefsbot'      => 'Ahrefs Bot' (often abusive)
'semrushbot'     => 'SEMRush Bot' (sometimes spoofed)
'mj12bot'        => 'Majestic Bot'
'dotbot'         => 'DotBot'
'petalbot'       => 'PetalBot'

# AI scrapers (growing concern in 2025-2026)
'claudebot'      => 'Claude AI Bot'
'gptbot'         => 'GPT Bot'
'chatgpt-user'   => 'ChatGPT User'
'bytespider'     => 'ByteSpider'
'anthropic-ai'   => 'Anthropic AI'
'cohere-ai'      => 'Cohere AI'
'ccbot'          => 'Common Crawl Bot'

# Headless browsers / automation
'headlesschrome' => 'Headless Chrome'
'phantomjs'      => 'PhantomJS'
'selenium'       => 'Selenium WebDriver'
'puppeteer'      => 'Puppeteer'
'playwright'     => 'Playwright'
```

### Behavioral Bot Indicators (Beyond User-Agent)
- Empty or missing Accept header
- Missing Accept-Language header
- Non-standard header ordering
- Excessive request rate from single IP
- Sequential URL path crawling

---

## 9. Commercial WAF Categories (Cloudflare, AWS WAF, Sucuri)

### Cloudflare WAF

**Managed Rulesets:**
1. **Cloudflare Managed Ruleset** — CVE-specific signatures, low false positive focus
2. **Cloudflare OWASP Core Ruleset** — CRS v3.3.0 implementation with paranoia levels
3. **Cloudflare Leaked Credentials Check** — Breached password database checking
4. **Exposed Credentials Check** — Credentials in request body/URL

**WAF Attack Score (ML-based):**
- Score 1-99 per request (1 = most likely attack)
- Categories: SQLi, XSS, RCE (separate scores per attack class)
- Not regex-based; uses ML classification

### AWS WAF Managed Rule Groups

| Rule Group | WCU | What It Covers |
|-----------|-----|---------------|
| **AWSManagedRulesCommonRuleSet** | 700 | XSS, no UA, known bad UAs, LFI/RFI, large queries |
| **AWSManagedRulesSQLiRuleSet** | 200 | SQL injection patterns across DB engines |
| **AWSManagedRulesKnownBadInputsRuleSet** | 200 | Log4j, JNDI, known exploit payloads |
| **AWSManagedRulesLinuxRuleSet** | 200 | Linux-specific LFI patterns |
| **AWSManagedRulesUnixRuleSet** | 100 | Unix command injection |
| **AWSManagedRulesWindowsRuleSet** | 200 | Windows-specific patterns (PowerShell, cmd) |
| **AWSManagedRulesPHPRuleSet** | 100 | PHP-specific injection patterns |
| **AWSManagedRulesWordPressRuleSet** | 100 | WordPress-specific exploits |
| **AWSManagedRulesAnonymousIpList** | 50 | Tor, VPN, hosting provider IPs |
| **AWSManagedRulesBotControlRuleSet** | 50 | Bot categorization (verified/unverified) |
| **AWSManagedRulesATPRuleSet** | 50 | Account takeover protection (credential stuffing) |

### Missing Categories Compared to Commercial WAFs

1. **IP Reputation** — Cloudflare and AWS both use IP reputation lists; the package has IP whitelisting but no blacklisting or reputation scoring
2. **Leaked Credentials Check** — Checking against known breached credential databases
3. **Account Takeover Protection** — Specific auth endpoint rate limiting and credential stuffing detection
4. **Windows-Specific Patterns** — PowerShell, cmd.exe patterns
5. **Application-Specific Rules** — WordPress, Drupal, Joomla exploit signatures
6. **ML-Based Classification** — Scoring that goes beyond regex pattern matching

---

## 10. Paranoia Levels & False Positive Management

### ModSecurity CRS Paranoia Levels

| Level | Description | False Positives | Use Case |
|-------|-------------|----------------|----------|
| **PL1** | Baseline. Core rules only. Minimal FP. | Rare | Default for all sites |
| **PL2** | Extra regexp-based SQLi/XSS, additional keywords, code injection checks | Some, tunable | Moderate security needs, experienced operators |
| **PL3** | Uncommon attack patterns, broad keyword matching | Many | High security, dedicated WAF team |
| **PL4** | Ultra-paranoid, catches nearly everything | ~28,000 FPs per 10,000 requests | Extreme security, extensive tuning required |

### How This Maps to the Package's Detection Modes

| Package Mode | Closest CRS PL | Behavior |
|-------------|----------------|----------|
| `relaxed` | PL1 (partial) | Only high-severity patterns, min confidence 40 |
| `balanced` | PL1-PL2 | All patterns, min confidence 10 |
| `strict` | PL2 | All patterns, min confidence 0, +10 score boost |

**Gap:** The package has only 3 modes, while CRS has 4 levels with per-rule granularity. The package could benefit from:
- Per-pattern paranoia level assignment (PL1-PL4)
- More granular mode options
- Pattern-level severity scores (not just high/medium/low)

### CRS False Positive Handling Techniques

1. **Rule Exclusion by ID** — Disable specific rules entirely
2. **Rule Exclusion by Parameter** — Exclude specific field names from specific rules
3. **Rule Exclusion by URI** — Exclude rules for specific URL patterns
4. **Pre-built Application Profiles** — WordPress, Drupal, phpMyAdmin exclusion packages

**Package Equivalent:**
- `auth_paths` — Suppresses credential-related FPs on login routes
- `content_paths` — Only high-severity on content-editing routes
- `ExclusionRuleService` — Exclude by type + URL pattern
- `skip_paths` — Skip entire paths
- `custom_patterns` — Add/override patterns

**Gap:** The package lacks:
- Per-field exclusions (e.g., exclude `body.content` from XSS rules on blog post routes)
- Pre-built application profiles (WordPress, etc.)
- A concept of rule IDs for targeted exclusion

---

## 11. ReDoS Prevention & Pattern Efficiency

### Current Safeguards in the Package
- **Payload truncation:** `substr($segmentPayload, 0, 8000)` prevents scanning massive inputs
- **`@preg_match`:** Error suppression prevents crash on bad patterns
- **Custom pattern validation:** Invalid patterns logged and skipped

### Industry Best Practices

**Dangerous patterns to avoid:**
```
# BAD: Nested quantifiers cause exponential backtracking
/(a+)+$/
/(a|a)*$/
/(.*a){x}/ for large x

# BAD: Overlapping alternations with repetition
/(a|ab)*$/
```

**Safe pattern design principles:**
1. **Avoid nested quantifiers** — Never `(x+)+`, `(x*)*`, `(x+)*`
2. **Use possessive quantifiers where possible** — `x++` instead of `x+` (PCRE supports this)
3. **Use atomic groups** — `(?>x+)` to prevent backtracking
4. **Prefer character classes over alternation** — `[abc]` not `(a|b|c)`
5. **Anchor patterns when possible** — `^` and `$` reduce search space
6. **Use specific quantifiers** — `{1,100}` instead of `*` or `+`
7. **Set a regex timeout** — `pcre.backtrack_limit` in PHP (default 1M steps)

**Patterns in the package to review for ReDoS risk:**
```
# Potentially risky (from getDefaultThreatPatterns):
'/<script\b[^>]*>.*?<\/script>/is'
# The .*? is lazy but safe here because it's bounded by </script>

'/\b(or|and)\b\s+["\']?\d+["\']?\s*=\s*["\']?\d+["\']?/i'
# Multiple optional quotes with backtracking potential — LOW risk but review

# From custom_patterns:
'/\/graphql[^{]{0,200}\{[^}]{0,1000}\}/is'
# Bounded quantifiers — SAFE

'/\bpassword\s*=\s*["\']?.{8,40}["\']?/i'
# .{8,40} with bounded repetition — SAFE
```

**Recommendation:** Add a `pcre.backtrack_limit` configuration option and use possessive quantifiers in new patterns where supported.

### Cloudflare's Approach
After a ReDoS incident in 2019 that caused a global outage, Cloudflare rewrote their WAF to use Rust's `regex` crate, which uses a Thompson NFA algorithm that guarantees **linear time complexity** and is immune to catastrophic backtracking. This is the gold standard but not available in PHP's PCRE engine.

---

## 12. Current Package Coverage Summary

### What the Package Does Well
- **SQL Injection:** UNION, SELECT, boolean, CHAR encoding, time-based, benchmark, NoSQL operators
- **XSS:** Script tags, event handlers, JavaScript URIs, DOM access, dialog functions, iframe/embed/object
- **Command Injection:** Shell functions, command chains, curl/wget, nc, /bin/bash, chmod
- **Path Traversal / LFI:** `../`, protocol wrappers, /etc/passwd, sensitive file access
- **SSRF:** Localhost, 127.0.0.1, AWS metadata (169.254.169.254), GCP metadata, private IPs
- **Deserialization:** PHP Object serialization format
- **Log4Shell:** JNDI injection patterns
- **XXE:** ENTITY/DOCTYPE patterns
- **Template Injection:** Blade `{{}}`, JSP/ASP `<% %>`, Expression Language `${}`
- **Web Shells:** c99, r57, b374k, wso, FilesMan signatures
- **Bot/Scanner Detection:** 15 scanners + 8 suspicious bot categories
- **DDoS:** Rate-based detection with configurable thresholds
- **PII Detection:** Aadhaar, PAN, mobile, bank account, IFSC (India-specific)
- **Credential Leaks:** Passwords, API keys, bearer tokens, access tokens, session IDs, JWTs
- **Sensitive Files:** .env, .git, .ssh, .aws, composer.json, package.json, phpinfo
- **Evasion Resistance:** SQL comment evasion, double URL encoding detection, normalization

### Detection Architecture Strengths
- Context-aware scanning (query/body/headers with different weights)
- Auth-path awareness (suppresses credential FPs on login routes)
- Content-path awareness (only high-severity on CMS routes)
- Confidence scoring with attack-tool UA boost
- Three detection modes (strict/balanced/relaxed)
- Deduplication via cache
- Exclusion rules system

---

## 13. Gap Analysis: What We Are Missing

### CRITICAL GAPS (High-value, regex-detectable)

#### 1. CRLF Injection / HTTP Header Injection
Not detected at all. Relevant to CWE-113, CRS 921.
```regex
/%0[dD]%0[aA]/                               — URL-encoded CRLF
/\r\n/                                        — Raw CRLF in parameters
/%0[aA]/                                      — Lone LF injection
```

#### 2. LDAP Injection
Not detected. Relevant to CWE-90, OWASP A05.
```regex
/[)(|*\\].*\(.*=/                            — LDAP filter manipulation
/\(\|.*\(.*=/                                — LDAP OR injection
/\(\&.*\(.*=/                                — LDAP AND injection
```

#### 3. XPath Injection
Not detected. Relevant to CWE-643.
```regex
/\bxpath\b/i                                 — XPath keyword
/\[\s*@\w+\s*=/                              — XPath attribute selector
/\b(contains|substring|normalize-space)\s*\(/i — XPath functions
/'.*or\s+.*=\s*'/i                           — XPath boolean injection (overlaps with SQLi)
```

#### 4. Shellshock Pattern
Not detected despite being a top-scanned CVE pattern.
```regex
/\(\)\s*\{/                                  — Bash function definition
```

#### 5. Spring4Shell Pattern
Not detected.
```regex
/class\.module\.classLoader/i                — Spring classloader
/class\.classLoader/i                        — Alternative classloader path
```

#### 6. Null Byte Injection
Not detected. Used to bypass file extension checks.
```regex
/%00/                                        — URL-encoded null byte
/\x00/                                       — Raw null byte
```

#### 7. Server-Side Template Injection (SSTI) — Expanded
Partial coverage. Missing Jinja2, Twig, Freemarker, Velocity patterns.
```regex
/\{\{[0-9]+\*[0-9]+\}\}/                    — Mathematical SSTI probe ({{7*7}})
/\{\%\s*import/i                             — Jinja2 import
/\{\{\s*config\b/i                           — Jinja2 config access
/\{\{\s*self\b/i                             — Jinja2/Twig self reference
/#set\s*\(\s*\$/                             — Velocity template
/\<#assign\b/i                               — Freemarker assign
/\[#assign\b/i                               — Freemarker alternative syntax
```

#### 8. Java Deserialization Gadget Chains
Only PHP deserialization detected. Missing Java/Python/Ruby/.NET.
```regex
/rO0AB/                                      — Base64-encoded Java serialized object
/aced0005/i                                  — Hex-encoded Java serialization magic bytes
/(ysoserial|CommonsCollections|Jdk7u21)/i    — Known gadget chain names
```

#### 9. Windows-Specific Command Injection
Not detected. AWS WAF has a dedicated rule group for this.
```regex
/\b(cmd|cmd\.exe)\s*(\/[ckCK])/i            — Windows cmd execution
/\bpowershell\b/i                            — PowerShell
/\bpowershell\.exe\b/i                       — PowerShell executable
/\bwscript\b/i                               — Windows Script Host
/\bcscript\b/i                               — Windows Console Script Host
/\bnet\s+(user|localgroup)\b/i              — Windows net commands
```

#### 10. Unicode/Encoding Evasion
Only double URL encoding detected. Many more evasion techniques exist.
```regex
/\\u00[0-9a-fA-F]{2}/                       — Unicode escape sequences
/\\x[0-9a-fA-F]{2}/                         — Hex escape sequences
/%u[0-9a-fA-F]{4}/                           — IIS Unicode encoding
/&#x?[0-9a-fA-F]+;/                         — HTML entity encoding
```

### MODERATE GAPS (Useful additions)

#### 11. HTTP Request Smuggling Indicators
```regex
/Transfer-Encoding\s*:.*chunked.*Content-Length/is  — CL+TE conflict
/Content-Length\s*:.*Content-Length/is               — Duplicate CL headers
```

#### 12. GraphQL Introspection
```regex
/__schema\b/i                                — Schema introspection
/__type\b/i                                  — Type introspection
/\bintrospectionQuery\b/i                    — Named introspection
```

#### 13. Credit Card Numbers (PCI compliance)
```regex
/\b(?:4[0-9]{12}(?:[0-9]{3})?)\b/          — Visa
/\b(?:5[1-5][0-9]{14})\b/                   — Mastercard
/\b(?:3[47][0-9]{13})\b/                    — Amex
/\b(?:6(?:011|5[0-9]{2})[0-9]{12})\b/      — Discover
```
**False positive note:** Must be extremely careful with credit card patterns. Best limited to query strings and headers only, never POST body (payment forms).

#### 14. Open Redirect Detection
```regex
/(?:redirect|url|next|return|goto|dest)\s*=\s*https?:\/\//i  — URL redirect parameter
/\/\/[^\/]/                                   — Protocol-relative redirect
```

#### 15. Email Header Injection
```regex
/\b(to|cc|bcc|from)\s*:\s*[^@]+@[^@]+/i    — Email header in input (context: not email forms)
/%0[aAdD]\s*(to|cc|bcc|from)\s*:/i          — CRLF + email header injection
```

#### 16. XML Bomb / Billion Laughs (extend XXE)
```regex
/<!ENTITY\s+\w+\s+"[^"]*&\w+;/             — Entity referencing entity (XML bomb indicator)
```

#### 17. PHP-Specific Patterns (extend CRS 933)
```regex
/\bassert\s*\(/i                             — PHP assert() code execution
/\bcreate_function\s*\(/i                    — Deprecated but exploitable
/\bpreg_replace\s*\(.*\/e/i                 — preg_replace /e modifier (code execution)
/\bphp_uname\b/i                             — System info disclosure
/\bget_current_user\b/i                      — User info disclosure
/\bdisplay_errors\b/i                        — Error display toggle
/\ballow_url_include\b/i                     — Remote inclusion toggle
/\bphp:\/\/filter/i                          — PHP filter protocol (already partial)
```

#### 18. Known Endpoint Probes (Honeypot Enhancement)
```regex
/wp-login\.php/i                             — WordPress login
/wp-admin/i                                  — WordPress admin
/administrator\b/i                           — Joomla admin
/wp-content\/uploads/i                       — WordPress upload path
/xmlrpc\.php/i                               — WordPress XML-RPC
/\/cgi-bin\//i                               — CGI directory probe
/\/actuator\b/i                              — Spring Boot actuator
/\/wp-json\//i                               — WordPress REST API
/\.aspx?\b/i                                 — ASP/ASPX probe on non-IIS
/\.jsp\b/i                                   — JSP probe on non-Java
```

### LOWER PRIORITY (Specialized or low-signal)

#### 19. DNS Rebinding Indicators
```regex
/0x7f000001/i                                — Hex-encoded 127.0.0.1
/2130706433/                                 — Decimal 127.0.0.1
/017700000001/                               — Octal 127.0.0.1
/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.xip\.io/i — xip.io DNS rebinding
/\.nip\.io/i                                 — nip.io DNS rebinding
/\.sslip\.io/i                               — sslip.io DNS rebinding
```

#### 20. Prototype Pollution (JavaScript apps)
```regex
/__proto__/                                  — Prototype pollution attempt
/constructor\s*\[/                           — Constructor access
/constructor\.prototype/                     — Prototype access
```

#### 21. Server-Side Include (SSI) Injection
```regex
/<!--#\s*(exec|include|echo|config)\b/i     — SSI directive injection
```

---

## 14. Recommended Additions by Priority

### Tier 1: High Impact, Low False Positive Risk
These should be added to the default pattern set (`getDefaultThreatPatterns`):

1. **CRLF Injection** — `/%0[dD]%0[aA]/` and `/%0[aA]/`
2. **Null Byte Injection** — `/%00/`
3. **Shellshock** — `/\(\)\s*\{/`
4. **Spring4Shell** — `/class\.module\.classLoader/i`
5. **Windows Command Injection** — PowerShell, cmd.exe patterns
6. **SVG/MathML XSS** — `/<svg[^>]*\bon\w+\s*=/i`
7. **Additional SQL DDL/DML** — DROP, ALTER, INSERT, UPDATE, DELETE
8. **HTTP Request Smuggling indicators** (header context only)
9. **Java deserialization magic bytes** — `/rO0AB/` and `/aced0005/i`
10. **Expanded SSTI patterns** — `{{7*7}}`, Jinja2 config access

### Tier 2: Moderate Impact, Some FP Risk (Custom Patterns)
Best as configurable custom patterns or behind paranoia level 2+:

1. **LDAP Injection**
2. **XPath Injection**
3. **Open Redirect Detection**
4. **Credit Card Patterns** (query/header context only)
5. **GraphQL Introspection**
6. **Unicode/Encoding Evasion**
7. **Additional PHP functions** (assert, create_function, preg_replace /e)
8. **Known Endpoint Probes** (wp-login, actuator, cgi-bin)
9. **DNS Rebinding** indicators
10. **Additional bot signatures** (20+ missing scanners)

### Tier 3: Specialized / Niche
Useful for specific environments:

1. **Prototype Pollution** (Node.js apps behind Laravel API)
2. **SSI Injection**
3. **Email Header Injection**
4. **XML Bomb / Billion Laughs**
5. **Application-specific profiles** (WordPress, Drupal exclusion packs)

### Architectural Recommendations

1. **Paranoia Levels:** Consider adopting a CRS-like 4-level paranoia system where each pattern is assigned a PL. Default patterns = PL1, additional patterns enabled at PL2+.

2. **Per-Pattern Scoring:** Instead of only high/medium/low, assign numeric anomaly scores (1-5) per pattern match, similar to CRS anomaly scoring. Sum scores across all matches for final confidence.

3. **Per-Field Exclusions:** Allow users to exclude specific input fields from specific pattern categories (e.g., "skip XSS checks on `body.content` for routes matching `posts/*`").

4. **Normalization Pipeline:** Expand the normalization step to handle:
   - HTML entity decoding (`&#x3C;` -> `<`)
   - Unicode normalization
   - UTF-8 overlong encoding detection
   - Multiple URL decode passes (recursive decoding)
   - Case folding for consistent matching

5. **Response Inspection (Future):** Commercial WAFs inspect responses too (error messages, stack traces, data leakage). This is a bigger architectural change but high value.

---

## Sources

- [OWASP Top 10:2025](https://owasp.org/Top10/2025/en/)
- [OWASP Top 10 2025 Key Changes (Aikido)](https://www.aikido.dev/blog/owasp-top-10-2025-changes-for-developers)
- [OWASP Top 10 2025 (GitLab)](https://about.gitlab.com/blog/2025-owasp-top-10-whats-changed-and-why-it-matters/)
- [CRS Rule IDs Documentation](https://coreruleset.org/docs/3-about-rules/ruleid/)
- [CRS Paranoia Levels Documentation](https://coreruleset.org/docs/2-how-crs-works/2-2-paranoia_levels/)
- [Working with Paranoia Levels (CRS Blog)](https://coreruleset.org/20211028/working-with-paranoia-levels/)
- [CRS False Positives and Tuning](https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/)
- [Handling False Positives with CRS (Netnea)](https://www.netnea.com/cms/apache-tutorial-8_handling-false-positives-modsecurity-core-rule-set/)
- [Including OWASP CRS (Netnea)](https://www.netnea.com/cms/apache-tutorial-7_including-modsecurity-core-rules/)
- [2025 CWE Top 25 (MITRE)](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html)
- [2025 CWE Top 25 (CISA)](https://www.cisa.gov/news-events/alerts/2025/12/11/2025-cwe-top-25-most-dangerous-software-weaknesses)
- [2025 CWE Top 25 (Infosecurity Magazine)](https://www.infosecurity-magazine.com/news/top-25-dangerous-software/)
- [SANS Top 25 Software Errors](https://www.sans.org/top25-software-errors)
- [MITRE ATT&CK T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
- [OWASP API Security Top 10 Explained (Salt Security)](https://salt.security/blog/owasp-api-security-top-10-explained)
- [AWS WAF Managed Rule Groups - Baseline](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html)
- [AWS WAF Managed Rule Groups - Use Case](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-use-case.html)
- [Cloudflare WAF Managed Rules](https://developers.cloudflare.com/waf/managed-rules/)
- [Cloudflare OWASP Core Ruleset](https://developers.cloudflare.com/waf/managed-rules/reference/owasp-core-ruleset/)
- [Cloudflare WAF Attack Score](https://developers.cloudflare.com/waf/about/waf-attack-score/)
- [OWASP ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
- [Snyk ReDoS and Catastrophic Backtracking](https://snyk.io/blog/redos-and-catastrophic-backtracking/)
- [Preventing ReDoS (regular-expressions.info)](https://www.regular-expressions.info/redos.html)
- [Log4Shell Detection (Google Cloud)](https://cloud.google.com/logging/docs/log4j2-vulnerability)
- [Log4Shell Detection Regex (Neo23x0)](https://gist.github.com/Neo23x0/e4c8b03ff8cdf1fa63b7d15db6e3860b)
- [Spring4Shell Analysis (Huntress)](https://www.huntress.com/threat-library/vulnerabilities/spring4shell)
- [Shellshock CVE-2014-6271 (Huntress)](https://www.huntress.com/threat-library/vulnerabilities/cve-2014-6271)
- [SSRF Prevention (OWASP Cheat Sheet)](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [SSRF Prevention 2025 (Ghost Security)](https://ghostsecurity.com/blog/how-to-prevent-ssrf-attacks-in-2025)
- [HTTP Request Smuggling (PortSwigger)](https://portswigger.net/web-security/request-smuggling)
- [Prototype Pollution Server-Side (PortSwigger)](https://portswigger.net/web-security/prototype-pollution/server-side)
- [XSS Filter Evasion (OWASP Cheat Sheet)](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)
- [XSS Cheat Sheet 2026 (PortSwigger)](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [SQL Injection WAF Bypass (OWASP)](https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF)
- [SSTI Payloads (PayloadsAllTheThings)](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
- [SSTI Testing (OWASP WSTG)](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection)
- [Top 10 CVEs of 2025 (SOCRadar)](https://socradar.io/blog/top-10-cves-of-2025-vulnerabilities-trends/)
- [Bot Detection Guide 2025 (Human Security)](https://www.humansecurity.com/learn/topics/what-is-bot-detection/)
- [Suspicious User Agents (mthcht)](https://detect.fyi/threat-hunting-suspicious-user-agents-3dd764470bd0)
