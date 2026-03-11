# Changelog

All notable changes to `jayanta/laravel-threat-detection` will be documented in this file.

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
