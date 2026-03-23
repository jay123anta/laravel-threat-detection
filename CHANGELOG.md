# Changelog

All notable changes to `jayanta/laravel-threat-detection` will be documented in this file.

## [1.3.0] - 2026-03-23

### Added

- **45 New Detection Patterns** based on OWASP Top 10, CRS, CWE Top 25, and MITRE ATT&CK:
  - CRLF injection, LF injection, null byte injection (CRS 921, CWE-113/626)
  - Shellshock CVE-2014-6271, Spring4Shell CVE-2022-22965, PHPUnit RCE CVE-2017-9841
  - Windows command injection: cmd.exe, PowerShell, wscript, cscript, net user (CRS 932)
  - SVG/HTML event handler XSS, CSS expression XSS (CRS 941)
  - SQL DDL injection (DROP/ALTER/CREATE/TRUNCATE), SQL DML injection (INSERT/UPDATE/DELETE)
  - SQL file operations (INTO OUTFILE, LOAD_FILE), ORDER BY enumeration, HAVING injection, hex strings, UNHEX
  - Java deserialization (base64 `rO0AB` + hex `aced0005` magic bytes)
  - Expanded SSTI: mathematical probe `{{7*7}}`, Jinja2 import, config access, Velocity templates
  - Open redirect detection (CWE-601)
  - LDAP injection and LDAP OR injection (CWE-90)
  - XPath attribute and function injection (CWE-643)
  - PHP assert(), create_function(), preg_replace /e, php_uname(), allow_url_include (CRS 933)
  - HTTP request smuggling CL+TE indicator (CRS 921)
  - GraphQL introspection abuse (__schema, __type)
  - Prototype pollution (__proto__, constructor.prototype)
  - SSI injection (Server-Side Includes)
  - SSRF bypass: hex-encoded localhost (0x7f000001), decimal localhost (2130706433), DNS rebinding (xip.io, nip.io, sslip.io)
  - Drupalgeddon render array injection, Spring Boot actuator probe

- **30 New Bot/Scanner Signatures** (23 → 53 total):
  - Security scanners: Arachni, Netsparker, Qualys, Skipfish, Vega, Wapiti, JoomScan, DroopeScan, Commix, XSStrike, Dalfox, FeroxBuster, FFUF, HTTPX, Subfinder, Katana, Jaeles
  - AI scrapers: GPTBot, ChatGPT, ClaudeBot, Anthropic, ByteSpider, Cohere, Common Crawl
  - Headless browsers: HeadlessChrome, PhantomJS, Selenium, Puppeteer, Playwright
  - Aggressive crawlers: AhrefsBot, SEMRushBot, MJ12Bot, DotBot, PetalBot

- **404 Probe Tracking** — Detects reconnaissance probes hitting known vulnerable paths (`/wp-admin`, `/.env`, `/phpmyadmin`, `/actuator`, etc.). Logged with `[probe]` type tag. 50+ default probe paths. Configurable via `probe_tracking.paths` config. Enabled by default.

- **Fail2ban Export** (`threat-detection:export-fail2ban`) — Export detected IPs in fail2ban-compatible format. Supports `--level`, `--since`, `--min-hits`, `--format=fail2ban|plain`, and `--jail` options.

- **Blocklist Export** (`threat-detection:export-blocklist`) — Export IPs in multiple formats: `plain`, `csv`, `nginx` (deny directives), `apache` (Deny from directives). Same filtering options as fail2ban export.

- **Dashboard Auth Guard** — Configurable authentication for dashboard and API routes via `THREAT_DETECTION_DASHBOARD_GUARD`. Four modes: `none` (default), `auth` (Laravel auth), `role` (Spatie-compatible hasRole), `ip` (IP whitelist). Logs warning when dashboard is accessed without auth.

- **Safe Fields** — New `safe_fields` config to exclude specific form fields from scanning. Reduces false positives on CMS editors, code inputs, and search fields.

- **Expanded Evasion Detection** — 3 new evasion patterns: HTML entity encoding (`&#60;`), Unicode escape sequences (`\u003c`), IIS Unicode encoding (`%u003c`).

### Improved

- **Normalization Pipeline** — Now includes HTML entity decoding, Unicode escape decoding, hex escape decoding, and recursive URL decoding (3 passes max) in addition to SQL comment stripping.
- **Early Bailout** — `strpos()` pre-screen skips 150+ regex patterns for clean payloads with no suspicious characters. ~90% of legitimate requests skip regex entirely.
- **Batch DB Inserts** — Multiple threats from a single request are written in one INSERT instead of N separate writes.
- **Max Detections Per Request** — Configurable cap (`THREAT_DETECTION_MAX_DETECTIONS`) to stop scanning after N matches. Default: unlimited.
- **127 new full-cycle tests** — 86 → 213 tests, 338 → 640 assertions. Covers all new patterns, bot detection, probe tracking, export commands, dashboard auth, safe fields, and performance.

### Backward Compatibility

- **Zero breaking changes.** All new features use sensible defaults.
- Probe tracking is enabled by default but only adds log entries (passive).
- Dashboard guard defaults to `none`, preserving existing behavior.
- Safe fields defaults to empty array (all fields scanned, same as before).
- Existing published config files continue to work without changes.

## [1.2.0] - 2026-03-11

### Added

- **Route Whitelisting (`only_paths`)** — Scan only specific routes instead of all routes. Dramatically reduces overhead on high-traffic apps. Leave empty (default) to scan everything.
- **Queue Support** — Offload DB writes and Slack notifications to a queue (`THREAT_DETECTION_QUEUE=true`). Detection remains synchronous; only the write is deferred. Uses `StoreThreatLog` job with 3 retries and backoff.
- **Auto-Purge (Retention Policy)** — Automatically delete old threat logs on a daily schedule (`THREAT_DETECTION_RETENTION=true`). Configurable retention period in days.
- **ThreatDetected Event** — Every confirmed threat dispatches a `ThreatDetected` event. Listen to it for custom actions (Telegram alerts, SIEM feeds, blocklists, etc.).
- **Minimum Confidence Threshold** — `THREAT_DETECTION_MIN_CONFIDENCE` config option. Threats below this score are silently ignored and never written to the database.
- **API Rate Limiting** — `THREAT_DETECTION_API_THROTTLE` config option. Auto-applies throttle middleware to all API routes (default: 60 requests/minute).
- **Evasion Resistance** — Payload normalization layer defeats SQL comment insertion (`UNION/**/SELECT`), double URL encoding (`%2527`), and CHAR encoding bypasses (`CHAR(39)`). Evasion attempts are flagged as high severity.
- **SQL CHAR Encoding Detection** — New default pattern catches `CHAR(N)` SQL injection variants.
- **Expanded LFI Protocol Detection** — Added `phar://`, `expect://`, and `input://` to the LFI protocol pattern.
- **Full RFC 1918 Private IP Range** — Fixed private IP detection to cover the full `172.16.0.0/12` range (was only matching `172.16.x.x`).
- **Localhost SSRF with `0.0.0.0`** — Added `0.0.0.0` to the default localhost SSRF pattern.
- **16 new full-cycle feature tests** — End-to-end tests that send HTTP requests through the middleware, verify database records, confidence scores, event dispatch, and queue behavior.
- **4 new middleware unit tests** — Tests for `only_paths` whitelist mode and `only_paths` + `skip_paths` interaction.

### Improved

- **Query Consolidation** — `stats` endpoint and `threat-detection:stats` command reduced from 7-9 separate queries to 1 query using `CASE WHEN` aggregation.
- **N+1 Query Fix** — `detectCoordinatedAttacks()` and `detectAttackCampaigns()` use batch IP fetching with `whereIn()` instead of per-row queries.
- **Pattern Validation Caching** — Custom regex patterns are validated once per process lifecycle and cached statically. Invalid patterns are logged and skipped permanently.
- **Threat Level Lookup Caching** — `getThreatLevelByType()` results cached in a static array to avoid repeated config lookups.
- **Content-Type Awareness** — File upload binary fields are automatically excluded from scanning in multipart requests.
- **Cache Driver Compatibility** — DDoS detection gracefully skips on `file`, `database`, and `null` cache drivers (which don't support atomic increment) with a one-time warning log.
- **CSV Export Security** — Added formula injection prevention (prefixes cells starting with `=`, `+`, `-`, `@`, `\t`, `\r` with a single quote).
- **Log Injection Prevention** — Strips `\n`, `\r`, `\t` from type and URL before writing to Laravel log.
- **SSRF Prevention** — IP validation via `filter_var(FILTER_VALIDATE_IP)` before external API calls in the enrich command.
- **ReDoS Prevention** — Fixed 3 regex patterns (JSP/ASP template, GraphQL query, PHP deserialization) to use bounded negated character classes instead of greedy `.`.
- **Auth Fallback Fix** — Sanctum fallback only adds `auth` middleware when `auth:sanctum` was explicitly present (respects user-configured middleware).
- **Audit Trail** — Exclusion rule deletion now logs rule details for audit purposes.

### Removed

- **SQL Comment Syntax pattern** (`/(--|\#|\/\*)/`) — Removed from default patterns. This was the #1 false positive source (`--` matches CSS classes, CLI flags, markdown, URL slugs). Actual SQL comment evasion is now caught by the new normalization layer. Real SQL attacks continue to be caught by keyword patterns (UNION SELECT, exec, etc.).

### Backward Compatibility

- **Zero breaking changes.** All new features are opt-in with sensible defaults.
- Existing users upgrading from v1.1.0 do not need to change any config, code, or database schema.
- All 70 original tests continue to pass unchanged.
- The removed SQL Comment Syntax pattern was not asserted by any existing test.

## [1.1.0] - Previous release

Initial public release with 130+ detection patterns, dashboard, API, Slack notifications, confidence scoring, and geo-enrichment.
