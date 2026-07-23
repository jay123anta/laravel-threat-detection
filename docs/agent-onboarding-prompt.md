# Onboarding Prompt — jayanta/laravel-threat-detection

> Copy everything below the line into a fresh agent session.

---

You are working on **`jayanta/laravel-threat-detection`**, a standalone Composer package (not an app) located at the repo root. Read this brief fully before touching code.

## What it is

A **passive** intrusion detection system (IDS) for Laravel, delivered as middleware. It scans every incoming HTTP request against ~175 regex patterns plus 53 bot/scanner user-agent signatures, scores a confidence value, and writes matches to a `threat_logs` database table. It also ships a Blade dashboard, a 15-endpoint REST API, Slack alerts, and export commands.

**Critical invariant: it NEVER blocks, rejects, or modifies a request.** It is an IDS, not an IPS, not a WAF. The middleware wraps its entire body in `try/catch` and logs errors so a detection failure can never break the host app. Any proposal that would block traffic, throw, or alter the response is out of scope — reject it and say why.

## Identity & conventions

| | |
|---|---|
| Package name | `jayanta/laravel-threat-detection` |
| Namespace | `JayAnta\ThreatDetection\` → `src/` |
| Tests namespace | `JayAnta\ThreatDetection\Tests\` → `tests/` |
| PHP | `^8.1` |
| Laravel | 10 / 11 / 12 (`illuminate/*` only — **no other runtime dependencies, keep it that way**) |
| Dev deps | `orchestra/testbench`, `phpunit` ^10/^11 |
| Author | Jay Anta (`jay123anta`) — commits carry **no co-author trailer** |
| Live version | v1.2.0 on GitHub + Packagist |
| Local version | v1.3.0, built but **not yet pushed** (15 commits ahead of `origin/main`) |
| Tests | 213 tests / 640 assertions, all passing — SQLite `:memory:` via Testbench |

## Architecture — request flow

```
HTTP request
  └─ ThreatDetectionMiddleware::handle()          src/Http/Middleware/
       ├─ enabled? / enabled_environments?        → bail to $next
       ├─ IP in whitelisted_ips (CIDR via IpUtils)→ bail
       ├─ only_paths (whitelist mode, fnmatch)    → bail if no match
       ├─ skip_paths (blacklist, fnmatch)         → bail
       ├─ auth_paths   → sets request attribute threat-detection:auth-path
       ├─ content_paths→ sets threat-detection:content-path
       ├─ ProbeDetectorService::detect(path)      → sets threat-detection:probe
       └─ ThreatDetectionService::detectAndLogFromRequest($request)
  └─ $next($request)   ← ALWAYS reached
```

### `ThreatDetectionService` (src/Services/ThreatDetectionService.php, ~1250 lines — the core)

Per request it:
1. Scans the User-Agent (`detectSuspiciousUserAgent`). Real browsers (`mozilla/` + `gecko`) short-circuit to a 5-marker headless check unless they contain a known spoofing bot substring, in which case it falls through to `fullUserAgentScan` over 35 scanners + 26 bots.
2. Checks DDoS via `Cache::increment("ddos:$ip")` — **auto-disabled with a one-time warning on `file`/`database`/`null` cache drivers** (no atomic increment).
3. Builds three payload *segments* once — `query`, `body`, `headers` — via `buildPayloadSegments()`. `safe_fields` config keys are stripped; multipart file fields are stripped; noisy headers (cookie, referer, origin, …) are excluded. The same segments are reused for the stored `payload` string (no duplicate `json_encode`).
4. `detectThreatPatternsWithContext()` per segment:
   - caps segment at 8000 chars (ReDoS guard);
   - `hasSuspiciousCharacters()` keyword pre-screen — bails out entirely on clean payloads. It deliberately excludes JSON structural chars (`"`, `{`, `[`, `:`) so JSON APIs don't trigger it;
   - runs **evasion patterns on the RAW payload** (double URL encoding, HTML entities, `%00`, `%0d%0a`, SQL comment splicing) — these must stay pre-normalization;
   - `normalizeForDetection()` — strips `/*…*/`, decodes HTML entities, `\uXXXX`, `\xXX`, then up to 3 recursive `urldecode` passes, then collapses whitespace;
   - `getRelevantCategories()` maps payload keywords to 14 attack categories (`sql`, `xss`, `rce`, `path`, `ssrf`, `cmd`, `injection`, `ssti`, `token`, `scanner`, `deser`, `cve`, `redirect`, `misc`), and `isPatternRelevant()` uses a static **exact-label → category map** to skip ~80% of regexes. Labels absent from the map always run (safe fallback);
   - runs default patterns then validated custom patterns; honours `detection_mode === 'relaxed'` (high only) and `max_detections_per_request`.
5. `ConfidenceScorer::calculate()` → 0–100 score + label (`low`/`medium`/`high`/`very_high`). Base 20, +15 per extra match (cap 3), +15 high-severity, +10 weighted context, +25 attack-tool UA, ±10 for strict/relaxed.
6. Threshold gate: `max(mode threshold, config min_confidence)` where mode gives strict=0, balanced=10, relaxed=40.
7. Per-threat filtering: API-route level suppression, content-path high-only suppression, `ExclusionRuleService::isExcluded()`, and 5-minute per-`ip+type` dedup cache.
8. Writes **one batched `DB::table()->insert()`** for all threats in the request (or dispatches `StoreThreatLog` when `queue.enabled`), logs a sanitized warning line (`\n\r\t` stripped — log-injection guard), and dispatches a `ThreatDetected` event per threat.

The service also has read-side analytics used by the API: `getIpStatistics`, `detectCoordinatedAttacks`, `detectAttackCampaigns`, `detectRapidAttacks`, `getCorrelationSummary` (all batch-fetch IPs with `whereIn` — the N+1 fix is intentional, don't regress it).

### Supporting classes

| File | Role |
|---|---|
| `src/Services/ProbeDetectorService.php` | 404-recon detection. Splits `probe_tracking.paths` into an O(1) lowercase hash for exact paths and an fnmatch list for wildcards; both cached in statics. |
| `src/Services/ConfidenceScorer.php` | Scoring + `isAttackToolUserAgent()`. |
| `src/Services/ExclusionRuleService.php` | False-positive rules from `threat_exclusion_rules`, cached 10 min. `tableExists()` guarded so a missing table degrades to "no rules". |
| `src/Http/Middleware/ThreatDashboardAuthMiddleware.php` | Guard modes `none` \| `auth` \| `role` (Spatie-style `hasRole`) \| `ip`. `none` logs a nag warning once per day. Takes a `dashboard`/`api` context arg. |
| `src/Jobs/StoreThreatLog.php` | Queued batch insert + Slack alert, 3 tries, 10s/30s backoff. |
| `src/Events/ThreatDetected.php` | Public hook: `$threatLog` array, `$ipAddress`, `$threatLevel`. |
| `src/Notifications/ThreatAlertSlack.php` | Uses `SlackMessage` on L10; falls back to a raw `Http::post` webhook on L11+ where the channel was removed. |
| `src/Http/Controllers/ThreatLogController.php` | The 15 API endpoints (~500 lines), incl. CSV export with formula-injection escaping. |
| `src/Facades/ThreatDetection.php` | Facade over the `threat-detection` singleton. |

### Service provider (`src/ThreatDetectionServiceProvider.php`)

Registers singletons; publishes config (`threat-detection-config`), 3 migration stubs (`threat-detection-migrations`), views (`threat-detection-views`); aliases middleware `threat-detect` and `threat-dashboard-auth`; conditionally loads `routes/api.php` and `routes/web.php`; registers 5 Artisan commands; schedules the purge at 02:00 daily when `retention.enabled`. Note the **Sanctum fallback**: if `Laravel\Sanctum` is absent, `auth:sanctum` is swapped for plain `auth` — but only when `auth:sanctum` was actually present, so a user-configured middleware stack is respected.

## Database

Migrations are **stubs** in `database/migrations/*.php.stub`, published into the host app.

- `threat_logs` — `ip_address`, `url`, `user_agent`, `type`, `payload` (truncated to 2000 chars), `threat_level`, `confidence_score`, `confidence_label`, `is_false_positive`, `action_taken`, `user_id`, geo columns (`country_code`, `country_name`, `city`, `isp`, `cloud_provider`, `is_foreign`, `is_cloud_ip`), timestamps. Confidence columns arrive via a second stub, `add_confidence_to_threat_logs_table`.
- `threat_exclusion_rules` — `pattern_label`, `path_pattern`, `created_from_threat_id`, `created_by_user_id`, `reason`, `is_active`.

`type` is always stored as `"[source] Label"` where source ∈ `middleware` / `custom` / `user-agent` / `probe` / `ddos`.

## Artisan commands

```
threat-detection:stats
threat-detection:purge            {--days=} {--force}
threat-detection:enrich           (only command that hits the network — free geo API, IP validated with FILTER_VALIDATE_IP)
threat-detection:export-fail2ban  {--level=} {--since=24h} {--min-hits=1} {--format=fail2ban|plain} {--jail=}
threat-detection:export-blocklist {--format=plain|csv|nginx|apache} + same filters
```

## Config (`config/threat-detection.php`, 543 lines)

Everything is env-overridable with `THREAT_DETECTION_*` keys. Key sections: `enabled`, `enabled_environments`, `table_name`, `only_paths`, `skip_paths`, `auth_paths`, `content_paths`, `safe_fields`, `min_confidence`, `max_detections_per_request`, `probe_tracking` (~50 default paths), `whitelisted_ips`, `ddos`, `threat_levels` (keyword→severity map), `api_route_filtering`, `detection_mode`, `context_weights` (query 1.5 / headers 1.3 / body 1.0), `notifications`, `custom_patterns` (~100 user-editable regexes incl. India-specific PII: Aadhaar, PAN, IFSC), `dashboard`, `api`, `retention`, `queue`.

**Severity is derived, not declared:** `getThreatLevelByType()` substring-matches a pattern's label against the `threat_levels` keyword lists. Renaming a label can silently change its severity — grep `threat_levels` before renaming anything.

## Tests

`tests/Unit/` (4 files) + `tests/Feature/` (9 `PhaseN*` files, mirroring the v1.3.0 commit phases). `tests/TestCase.php` extends Orchestra Testbench with SQLite in-memory and helper table builders.

**House style: prefer full-cycle feature tests** — issue a real HTTP request through the middleware, then assert on the `threat_logs` rows — over isolated unit tests. Run with `vendor/bin/phpunit` or `composer test`.

## Working rules for this repo

1. **Never block a request.** Passive logging only.
2. **Zero breaking changes** between versions. New features are opt-in with defaults that preserve existing behaviour. Published config files in host apps must keep working untouched.
3. **No new dependencies.** `illuminate/*` only.
4. **Stay lightweight.** Don't add features for hypothetical users; the package is deliberately narrow.
5. **Performance matters** — this runs on every request. The early bailout, category lazy-loading, browser short-circuit, static caches, probe hash lookup, and batch inserts are all deliberate. Don't undo them; benchmark anything you add to the hot path.
6. **New regex patterns must**: be bounded (no unbounded `.*` — ReDoS), get an entry in `$labelCategoryMap`, get a `threat_levels` keyword that resolves to the right severity, and come with a feature test. Add the category keyword to `$categoryKeywords` and, if needed, `hasSuspiciousCharacters()` — otherwise the pre-screen will skip your pattern and it will never fire.
7. Update `CHANGELOG.md` and `README.md` for any user-visible change.
8. Commits: no co-author trailer. Don't push or tag without being asked.

## Known context

- `docs/` is `export-ignore`d from the Composer tarball. `docs/security-standards-gap-analysis.md` maps OWASP Top 10 / CRS / CWE Top 25 / MITRE ATT&CK against current coverage and is the roadmap source for new patterns.
- The `--`/`#`/`/*` "SQL Comment Syntax" pattern was **removed in v1.2.0** as the #1 false-positive source. Don't reintroduce it; evasion normalization covers the real case.
- Default `custom_patterns` are India-centric (`home_country` defaults to `IN`) and documented as replaceable per region.
- The dashboard and API guards both default to `none` for backward compatibility — that's a deliberate trade-off, flagged by a daily warning log rather than a hard default change.
