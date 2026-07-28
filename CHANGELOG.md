# Changelog

All notable changes to `jayanta/laravel-threat-detection` will be documented in this file.

## [Unreleased]

### Added

- **Post-match validators (`pattern_validators`) — checksum-aware
  false-positive reduction.** A regex alone can't express every constraint:
  any 12-digit run matches the Aadhaar pattern, but a real Aadhaar number
  also passes the Verhoeff checksum. A pattern label (default or custom) can
  now be mapped to a named validator; a regex hit then only counts as a
  detection when at least one matched value passes it:

  ```php
  'pattern_validators' => ['Aadhaar Number Detected' => 'verhoeff'],
  ```

  Ships with `verhoeff` (Aadhaar) and `luhn` (credit/debit card numbers); the
  default config maps the Aadhaar pattern to `verhoeff`, so timestamps, order
  ids and barcodes are no longer logged as PII while genuine numbers still
  are. If several values match and only one passes, the detection still fires
  (a real number among noise is still a leak). An unknown validator name
  fails open with a one-time warning, so a typo can never silently disable a
  pattern. Fully backward-compatible: configs published before this feature
  don't have the key and keep their exact current behaviour. 14 new tests
  (232 → 246).

## [1.5.0] - 2026-07-28

### Added

- **`safe_paths` — path-aware false-positive control.** Like `safe_fields`, but
  matches by dot-notation *path* into the request (query or JSON/form body)
  instead of by field name anywhere. This is precise for nested JSON APIs: you
  can exempt one field's value — e.g. a search box whose value legitimately
  contains SQL keywords — without exempting that key name everywhere it appears.
  Supports `fnmatch` wildcards:

  ```php
  'safe_paths' => ['search.query', 'filters.*.value'],
  ```

  Fully backward-compatible (defaults to an empty array; `safe_fields` is
  unchanged). Directly addresses the JSON false-positive problem discussed on
  r/PHP — thanks to **u/Deep_Ad1959** for suggesting path-based allow-listing.

No changes to detection behaviour otherwise — all existing patterns scan exactly
as before. 5 new tests (227 → 232).

## [1.4.0] - 2026-07-23

### Added

- **Laravel 13 support.** Widened `illuminate/*` constraints to `^13.0` and dev
  tooling to `orchestra/testbench ^11.0` and `phpunit/phpunit ^12.0`. The package
  now supports Laravel 10, 11, 12, and 13. Based on the approach proposed by
  **@davidvandertuijn** in #1 — thank you!

### Changed

- **Minimum PHP raised to 8.2** (Laravel 13 itself requires PHP 8.3+). PHP 8.1
  reached end of security support in November 2025 and the current Laravel test
  tooling no longer supports it. If you are still on PHP 8.1, stay on v1.3.1.
- **Test methods migrated from the `@test` docblock annotation to the `#[Test]`
  attribute** across all 15 test files (227 methods). PHPUnit 12 (pulled in by
  Laravel 13) removed docblock metadata; `#[Test]` is supported by PHPUnit 10, 11,
  and 12, so Laravel 10/11/12 remain fully compatible.
- The no-op service double in `MiddlewareTest` now uses `createStub()` instead of
  `createMock()` (clears PHPUnit 12 "useless mock" notices).
- **CI matrix** now covers PHP 8.2/8.3/8.4 × Laravel 12 & 13 (Laravel 13 on PHP
  8.3+), with `fail-fast: false`. Laravel 10 & 11 remain supported in
  `composer.json` but are no longer in the CI matrix — they are end-of-life and
  their unpatched security advisories block a clean CI install.

No functional or API changes to detection behaviour.

## [1.3.1] - 2026-07-23

Correctness and false-positive fixes. No breaking changes: detection is still
passive (never blocks a request), all existing config keys keep working, and
published config files continue to function untouched. 14 new full-cycle
regression tests (213 → 227 tests, 640 → 657 assertions).

### Fixed — detection coverage (previously silent bypasses)

- **JSON request bodies are now scanned.** `buildPayloadSegments()` previously
  read only `$request->post()` (the form-data bag), so payloads sent as
  `application/json` — most modern API traffic — were never inspected. JSON
  bodies are now read via `$request->json()` and scanned like form fields
  (with the same `safe_fields` stripping).
- **A malformed UTF-8 byte no longer disables a segment.** `json_encode()`
  returns `false` on invalid UTF-8, which silently blanked the whole segment
  (e.g. appending `%FF` to a parameter). All segment encoding now uses
  `JSON_INVALID_UTF8_SUBSTITUTE`.
- **`api_route_filtering` can no longer be evaded via the query string.** The
  API-route check now keys off the route path (`$request->path()`) instead of
  the full URL, so appending `?x=/api/` can neither suppress detections nor
  wrongly filter a non-API page.
- **Remapped patterns that never fired now do:** the four NoSQL operator
  patterns (`$ne`, `$gt`, `$regex`, `$where`) are mapped to the `injection`
  category where their keywords live; web-shell signatures (`c99`, `r57`,
  `b374k`, `wso`, `c100`, `FilesMan`) and the space-less Shellshock variant
  (`(){`) and the Drupalgeddon `#pre_render` variant now have matching category
  and pre-screen keywords. Added exploit-recon probe paths
  (`/vendor/phpunit/*`, `/.aws/credentials`, `/.ssh/id_rsa`, `/.git/*`).

### Fixed — false positives (noise reduction)

- **The `Authorization` header is no longer scanned.** Ordinary authenticated
  traffic (Bearer / JWT tokens) was logged as a high-severity `JWT Token Found`
  / `Bearer Token Detected` per IP every 5 minutes. The header is now excluded
  from the headers segment (a token in the query string is still flagged).
- **`Private IP Access`** gained a leading word boundary so UA fragments like
  `Chrome/110.0.0.0` no longer match `10.0.0.0`.
- **`Localhost SSRF`** no longer matches `0.0.0.0` / `127.0.0.1` embedded in a
  longer digit run — a real Chrome user-agent (`Chrome/120.0.0.0`) was being
  logged as SSRF on nearly every request. Genuine `0.0.0.0`/`127.0.0.1` hosts
  still match. (Found by a live end-to-end run, not covered by the unit asserts.)
- **`zap`** (scanner list and confidence attack-tool list) is now matched as
  `owasp zap` / `zaproxy` instead of the bare substring, so integration UAs
  such as `Zapier` are no longer flagged / scored.

### Fixed — severity correctness

- Corrected severities that resolved to the wrong level: `Log4j/Log4Shell` and
  `JNDI` (→ high), `XXE` entity/DOCTYPE (→ high), `IFSC Code` (→ high, matching
  the other PII), web-shell / reverse-shell / encoded-eval (→ high), SQLi
  variant / time-based / benchmark / sleep (→ high), `API Key Exposure`
  (→ high), `File Inclusion` and `JavaScript URI` (→ medium). Removed the
  over-broad `Java` severity keyword that accidentally promoted `JavaScript URI`
  to high (deserialization stays high via the `Serialization` keyword).

### Fixed — hardening & robustness

- **Dashboard/API auth guard now fails closed.** An unrecognised guard value
  (typo) previously fell through and granted access; it now logs a warning and
  returns 403. `guard = role` with a user model that has no `hasRole()` method
  now denies (with a warning) instead of silently allowing.
- **Whitelist/allowed-IP env lists are trimmed** so `"1.2.3.4, 5.6.7.8"` no
  longer breaks the entries after the comma.
- **`export-blocklist` CSV reports the correct level.** `MAX(threat_level)` was
  lexicographic (`medium > low > high`); it now ranks severity numerically.
- **`enrich`** no longer marks unknown-geo IPs as `is_foreign` and skips
  private/reserved ranges (no wasted rate-limited API calls).
- **Dedup cache is marked only after a successful write**, so a failed insert no
  longer mutes a threat type for 5 minutes; within-request dedup is preserved.
- **Corrected default `skip_paths`** (`assets/*`, `css/*`, `js/*`, … instead of
  the never-matching `public/…` prefixes).
- **`purge`** cleans orphaned exclusion rules with a DB-side subquery instead of
  loading every purged id into memory.
- **`vendor:publish --tag=threat-detection-migrations` is idempotent** — already
  published migrations are skipped instead of creating duplicate timestamped
  copies.
- Declared the `illuminate/console`, `illuminate/events`, `illuminate/bus`, and
  `illuminate/queue` dependencies the package already uses.

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
- **Category-Based Lazy Pattern Loading** — Pre-checks keywords per attack category before running regex. Only relevant categories' patterns execute. Reduces regex evaluations by ~80% on average.
- **Early Bailout** — Keyword-based pre-screen skips 175+ regex patterns for clean payloads. Content-type aware — doesn't false-trigger on JSON structural characters.
- **Browser UA Short-Circuit** — Normal browsers (Mozilla/Gecko) skip 70+ scanner/bot str_contains checks. Only headless browser markers are checked.
- **Static Pattern Caching** — Default patterns, evasion patterns, and scanner/bot arrays cached as static properties (no array recreation per request).
- **Probe Path Hash Lookup** — Exact probe paths use O(1) hash table. Only wildcard paths use fnmatch.
- **Payload Deduplication** — Segments built once and reused for both detection and payload logging (eliminated 3 redundant json_encode calls).
- **Batch DB Inserts** — Multiple threats from a single request are written in one INSERT instead of N separate writes.
- **Max Detections Per Request** — Configurable cap (`THREAT_DETECTION_MAX_DETECTIONS`) to stop scanning after N matches. Default: unlimited.
- **Cache Key Optimization** — Direct string keys for dedup cache instead of md5 hashing.
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
