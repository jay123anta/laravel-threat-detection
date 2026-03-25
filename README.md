<p align="center">
  <img src="https://img.shields.io/packagist/v/jayanta/laravel-threat-detection.svg?style=flat-square" alt="Latest Version">
  <img src="https://img.shields.io/github/actions/workflow/status/jay123anta/laravel-threat-detection/tests.yml?branch=main&style=flat-square&label=tests" alt="Tests">
  <img src="https://img.shields.io/packagist/dt/jayanta/laravel-threat-detection.svg?style=flat-square" alt="Total Downloads">
  <img src="https://img.shields.io/packagist/l/jayanta/laravel-threat-detection.svg?style=flat-square" alt="License">
  <img src="https://img.shields.io/php-version-support/jayanta/laravel-threat-detection?style=flat-square" alt="PHP Version">
</p>

# Laravel Threat Detection

**Know who's attacking your Laravel app — without changing a single line of application code.**

A middleware-based threat detection and logging system for Laravel. Drop it in, and it starts scanning every HTTP request for SQL injection, XSS, RCE, scanner bots, DDoS patterns, and 60+ other attack types — logging everything to your database with full geo-enrichment and a built-in dashboard.

> Extracted from a production application. Battle-tested with real traffic.

**Important:** This package **never blocks** any request. It only **logs** and **alerts**. Your application continues to handle every request normally, even when threats are detected.

---

## What This Is NOT

- **Not a WAF.** It does not block, filter, or modify any request. Use Cloudflare, mod_security, or a proper WAF for that.
- **Not a replacement for secure coding.** Parameterized queries, input validation, output escaping — those are your real defenses. This package assumes your code is already secure.
- **Not a Cloudflare replacement.** If you can use Cloudflare or a similar edge service, use it. This provides application-level visibility that edge services don't — you can see exactly what's hitting your routes, with full request context.

**What it IS:** A passive monitoring layer that sits alongside your existing security. Think of it as a security camera — it doesn't lock the door, but it shows you who's trying to get in, how often, and what techniques they're using. That visibility helps you make informed decisions (IP blocking via fail2ban, rate limiting, geo-blocking).

---

## Requirements

- PHP 8.1+
- Laravel 10.x, 11.x, or 12.x
- Any database supported by Laravel (MySQL, PostgreSQL, SQLite, SQL Server)

---

## How It Works

1. A middleware scans every incoming HTTP request
2. The request is checked against 175+ regex patterns covering SQL injection, XSS, RCE, file traversal, SSRF, LDAP, XPath, SSTI, and more
3. If a threat pattern matches, a record is written to your `threat_logs` database table with the IP, URL, threat type, severity level, and a confidence score
4. Optionally, a Slack alert is sent for high-severity threats
5. The request proceeds normally — **nothing is blocked**

No internet connection is needed for detection.

---

## Quick Start

### 1. Install the package

```bash
composer require jayanta/laravel-threat-detection
```

### 2. Publish migrations and run them

> **This step is required.** Without it, the package will detect threats but cannot store them in the database. If you skip this step, your `threat_logs` table won't exist and all detections will be silently lost (you'll only see errors in `storage/logs/laravel.log`).

```bash
php artisan vendor:publish --tag=threat-detection-migrations
php artisan migrate
```

This creates two tables: `threat_logs` (stores detected threats) and `threat_exclusion_rules` (stores false positive rules).

**Verify tables were created:**
```bash
php artisan migrate:status
```
Look for `create_threat_logs_table`, `add_confidence_to_threat_logs_table`, and `create_threat_exclusion_rules_table` — all should show `Ran`.

### 3. Register the middleware

The middleware is what scans requests. You need to add it to your `web` middleware group.

**If you use Laravel 11 or 12** — open `bootstrap/app.php`:

```php
->withMiddleware(function (Middleware $middleware) {
    $middleware->web(append: [
        \JayAnta\ThreatDetection\Http\Middleware\ThreatDetectionMiddleware::class,
    ]);
})
```

> **How to check your Laravel version:** Run `php artisan --version` in your terminal.

**If you use Laravel 10** — open `app/Http/Kernel.php`:

```php
protected $middlewareGroups = [
    'web' => [
        // ... existing middleware
        \JayAnta\ThreatDetection\Http\Middleware\ThreatDetectionMiddleware::class,
    ],
];
```

### 4. (Optional) Publish the config file

```bash
php artisan vendor:publish --tag=threat-detection-config
```

The package works with sensible defaults. Publishing the config lets you customize detection patterns, sensitivity modes, Slack notifications, and more. If you skip this step, everything still works.

**That's it.** Your app is now detecting threats.

---

## Verify It Works

After installation, trigger a test threat and confirm it was logged.

### Step 1: Start your app

```bash
php artisan serve
```

### Step 2: Open a test URL in your browser

Append a malicious query parameter to **any existing route** in your app (your homepage, a product page, etc.). For example:

**SQL Injection:**
```
http://localhost:8000/?q=' UNION SELECT * FROM users--
```

**XSS (Cross-Site Scripting):**
```
http://localhost:8000/?q=<script>alert(1)</script>
```

**Directory Traversal:**
```
http://localhost:8000/?file=../../etc/passwd
```

**RCE (Remote Code Execution):**
```
http://localhost:8000/?cmd=system('ls -la')
```

**Shellshock (CVE-2014-6271):**
```
http://localhost:8000/?cmd=() { :;}; /bin/bash
```

**Windows Command Injection:**
```
http://localhost:8000/?cmd=powershell -c whoami
```

**DROP TABLE (SQL DDL):**
```
http://localhost:8000/?q=DROP TABLE users
```

> Use a route that actually exists in your app (like `/`). If the URL returns a 404, the middleware may not have run.

### Step 3: Check that threats were logged

**Option A — Artisan command (quickest):**
```bash
php artisan threat-detection:stats
```
You should see a table with `Total Threats`, severity counts, and top IPs.

**Option B — Tinker:**
```bash
php artisan tinker
```
```php
DB::table('threat_logs')->latest()->take(5)->get(['ip_address', 'type', 'threat_level', 'confidence_score']);
```

**Option C — Laravel log file:**
Each detected threat is written as a warning to `storage/logs/laravel.log`:
```
[high] Threat Detected: [middleware] SQL Injection UNION from 127.0.0.1 (http://localhost:8000/?q=...) [confidence: 50%]
```

### Things to know when testing

| Behavior | Explanation |
|----------|-------------|
| Same threat only logs once per 5 minutes | Deduplication: same IP + same threat type is cached for 5 minutes. Use **different attack types** for each test, or wait between tests. |
| `curl` requests trigger extra detection | Using `curl` also logs a "cURL Command" user-agent detection (low severity). This is expected — the package detects automated tools. |
| The package never blocks requests | Your app continues to function normally. Detection is passive. |
| No Slack setup needed | Notifications are off by default. |
| No internet connection needed | Core detection is 100% local. Only the optional `threat-detection:enrich` command calls an external API for geo-data. |

### Troubleshooting

**"I tested but `threat-detection:stats` shows zero threats" / "Threats are not stored in the database"**

This is almost always because migrations were not published. The package detects threats but silently skips the DB write if the table doesn't exist (so your app keeps working). Check `storage/logs/laravel.log` for errors like `SQLSTATE: table threat_logs not found`.

| Check | How to verify |
|-------|---------------|
| Migrations were **published** | Run `php artisan migrate:status` — look for `create_threat_logs_table` and `create_threat_exclusion_rules_table`. If missing, you need to publish first (see below) |
| Migrations were **run** | Same command — status should show `Ran`, not `Pending` |
| Middleware is registered | Confirm `ThreatDetectionMiddleware` is in your `web` middleware group (see [Step 3](#3-register-the-middleware) above) |
| IP is not whitelisted | If you added `THREAT_DETECTION_WHITELISTED_IPS` to `.env`, remove it during testing |
| Environment is enabled | Default enabled environments: `production`, `staging`, `local`. Check `APP_ENV` in `.env` |
| Used an existing route | The test URL must match a real route (e.g., `/`). |
| Dedup cache | Same IP + same attack type is cached for 5 minutes — try a different attack type |

**"`threat-detection:stats` throws a database error" / "`threat_exclusion_rules` table not found"**

The tables don't exist yet. You need to **publish** the migrations first, then run them:
```bash
php artisan vendor:publish --tag=threat-detection-migrations
php artisan migrate
```
> **Note:** Running `php artisan migrate` alone is not enough — the migration files are inside the package and need to be published to your app's `database/migrations/` folder first.

**"API returns 401 Unauthorized"**

See [API Authentication](#api-authentication) below.

**"Dashboard shows 404"**

The dashboard is disabled by default. Add `THREAT_DETECTION_DASHBOARD=true` to `.env` and clear route cache:
```bash
php artisan route:clear
```

---

## Features

- **175+ Detection Patterns** — SQL injection (UNION, DDL, DML, file ops), XSS (script, SVG, CSS expression), RCE, directory traversal, SSRF, XXE, Log4Shell, NoSQL injection, command injection (Linux + Windows), LDAP injection, XPath injection, SSTI, CRLF injection, Java deserialization, and more
- **53 Bot/Scanner Signatures** — SQLMap, Nikto, Nmap, Burp Suite, FeroxBuster, FFUF, XSStrike, Dalfox, Netsparker, and 20+ other security scanners
- **AI Scraper Detection** — GPTBot, ClaudeBot, ByteSpider, Common Crawl, and other AI training bots
- **Headless Browser Detection** — HeadlessChrome, PhantomJS, Selenium, Puppeteer, Playwright
- **404 Probe Tracking** — Detects reconnaissance probes hitting known vulnerable paths (`/wp-admin`, `/.env`, `/phpmyadmin`, `/actuator`, etc.) with 50+ default probe paths
- **DDoS Monitoring** — Rate-based threshold detection with configurable windows
- **Confidence Scoring** — Each threat gets a 0-100 confidence score based on pattern count, context, and signals
- **Evasion Resistance** — Normalization pipeline defeats SQL comment insertion, double URL encoding, HTML entity encoding, Unicode escapes, and hex escapes before pattern matching
- **CVE Detection** — Shellshock (CVE-2014-6271), Spring4Shell (CVE-2022-22965), PHPUnit RCE (CVE-2017-9841), Drupalgeddon, Log4Shell
- **Context-Aware Detection** — Patterns found in query strings score higher than those in POST body
- **Safe Fields** — Exclude specific form fields from scanning (for CMS editors, code inputs, search fields)
- **False Positive Reporting** — Mark threats as false positives from the dashboard; auto-creates exclusion rules
- **Three Detection Modes** — `strict`, `balanced` (default), and `relaxed` — tunable sensitivity
- **Content Path Suppression** — Whitelist CMS/blog paths to suppress low/medium alerts from rich content
- **PII Detection** — Sensitive data exposure patterns (configurable per region)
- **Geo-Enrichment** — Country, city, ISP, cloud provider identification via free API
- **Slack Alerts** — Real-time notifications for high-severity threats (works on Laravel 10 and 11+)
- **Built-in Dashboard** — Dark-mode Blade dashboard (Alpine.js + Tailwind CDN, zero build step)
- **Dashboard Auth Guard** — Configurable authentication for dashboard and API (none, auth, role, or IP-based)
- **15 API Endpoints** — Full REST API for building custom Vue/React/mobile dashboards
- **Fail2ban Export** — Export detected IPs in fail2ban-compatible format or plain blocklist
- **Blocklist Export** — Export IPs in nginx deny, Apache deny, CSV, or plain format
- **CSV Export** — One-click threat log export (up to 10,000 rows)
- **Correlation Analysis** — Detect coordinated attacks and attack campaigns across IPs
- **Performance Optimized** — Category-based lazy pattern loading (only runs regex for relevant attack categories), early bailout for clean requests, browser UA short-circuit (skips 70+ checks for normal browsers), probe path hash lookup, batch DB inserts, configurable max detections per request
- **Database Agnostic** — MySQL, PostgreSQL, SQLite, SQL Server
- **Zero Config** — Works out of the box with sensible defaults
- **Safe by Design** — The middleware catches its own errors. If detection fails, your app keeps running. Requests are never blocked.

---

## Configuration

The package works without any `.env` changes. All values below are optional — add them only if you want to override the defaults.

```env
# Enable/disable detection globally (default: true)
THREAT_DETECTION_ENABLED=true

# Detection sensitivity (default: balanced)
# Options: strict, balanced, relaxed
THREAT_DETECTION_MODE=balanced

# Custom table name (default: threat_logs)
# THREAT_DETECTION_TABLE=threat_logs

# Whitelist IPs to skip detection entirely (default: empty)
# Supports CIDR notation. Comma-separated.
# THREAT_DETECTION_WHITELISTED_IPS=10.0.0.0/8,192.168.1.0/24

# DDoS detection thresholds (defaults shown)
# THREAT_DETECTION_DDOS_THRESHOLD=300
# THREAT_DETECTION_DDOS_WINDOW=60

# Minimum confidence score to log a threat (default: 0)
# Threats below this score are silently ignored.
# THREAT_DETECTION_MIN_CONFIDENCE=0

# Slack notifications (disabled by default)
# THREAT_DETECTION_NOTIFICATIONS=true
# THREAT_DETECTION_SLACK_WEBHOOK=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
# THREAT_DETECTION_SLACK_CHANNEL=#threat-alerts

# Dashboard (disabled by default)
# THREAT_DETECTION_DASHBOARD=true

# API endpoints (enabled by default)
# THREAT_DETECTION_API=true

# API rate limiting (default: 60 requests per minute)
# THREAT_DETECTION_API_THROTTLE=60,1

# Queue support — offload DB writes to a queue (disabled by default)
# THREAT_DETECTION_QUEUE=false
# THREAT_DETECTION_QUEUE_CONNECTION=redis
# THREAT_DETECTION_QUEUE_NAME=default

# Auto-purge old logs (disabled by default)
# Requires Laravel scheduler to be running.
# THREAT_DETECTION_RETENTION=false
# THREAT_DETECTION_RETENTION_DAYS=90

# 404 probe tracking (enabled by default)
# Detects bots hitting /wp-admin, /.env, /phpmyadmin, etc.
# THREAT_DETECTION_PROBE_TRACKING=true

# Max detections per request (default: 0 = unlimited)
# Stop scanning after N pattern matches per request.
# THREAT_DETECTION_MAX_DETECTIONS=0

# Dashboard auth guard (default: none)
# Options: none, auth, role, ip
# THREAT_DETECTION_DASHBOARD_GUARD=none
# THREAT_DETECTION_DASHBOARD_ROLE=admin
# THREAT_DETECTION_DASHBOARD_IPS=127.0.0.1

# API auth guard (default: none — uses existing middleware config)
# THREAT_DETECTION_API_GUARD=none
```

### Detection Modes

| Mode | Confidence Threshold | Behavior |
|------|---------------------|----------|
| `strict` | 0 (logs everything) | All patterns active, lowest thresholds. Catches everything but may flag legitimate traffic. |
| `balanced` | 10 | Default. Confidence scoring active, standard thresholds. Good for most apps. |
| `relaxed` | 40 | Only high-severity patterns trigger. Best for content-heavy sites with frequent false positives. |

### Enabled Environments

By default, detection runs in `production`, `staging`, and `local`. To change, publish the config and edit:

```php
'enabled_environments' => ['production', 'staging', 'local'],
```

To disable detection in your test suite, set `APP_ENV=testing` (not in the list above) or add to your `phpunit.xml`:
```xml
<env name="THREAT_DETECTION_ENABLED" value="false"/>
```

### Config Reference

Publish the config file to see all available options:

```bash
php artisan vendor:publish --tag=threat-detection-config
```

Key config sections: `skip_paths` (paths to skip), `only_paths` (whitelist mode), `auth_paths` (smart detection for login routes), `content_paths` (suppress non-high alerts), `safe_fields` (exclude specific fields from scanning), `probe_tracking` (404 probe detection), `context_weights` (scoring multipliers), `threat_levels` (severity keyword mapping), `api_route_filtering` (suppress low/medium on API routes), `queue` (async processing), `retention` (auto-purge), `max_detections_per_request` (performance cap), `dashboard.guard` / `api.guard` (auth mode).

### Route Whitelisting (`only_paths`)

If your app has many routes but you only care about a few, use `only_paths` to scan **only** those routes. All other routes are automatically skipped — no middleware overhead at all.

```php
// config/threat-detection.php
'only_paths' => [
    'admin/*',
    'api/*',
    'login',
    'register',
],
```

Leave empty (default) to scan all routes (subject to `skip_paths`). When both are configured, `only_paths` is checked first, then `skip_paths` applies within the matched set.

### Queue Support

By default, threat logging happens synchronously in the request cycle. For high-traffic apps, you can offload DB writes and Slack notifications to a queue:

```env
THREAT_DETECTION_QUEUE=true
THREAT_DETECTION_QUEUE_CONNECTION=redis
THREAT_DETECTION_QUEUE_NAME=threat-logs
```

This dispatches a `StoreThreatLog` job (3 retries, backoff 10s/30s). Detection still happens in real-time — only the write is deferred.

### Auto-Purge (Retention Policy)

Automatically delete old threat logs on a daily schedule:

```env
THREAT_DETECTION_RETENTION=true
THREAT_DETECTION_RETENTION_DAYS=90
```

Requires Laravel's scheduler to be running (`php artisan schedule:run`). Runs daily at 02:00 via `threat-detection:purge`.

### ThreatDetected Event

Every confirmed threat dispatches a `ThreatDetected` event that you can listen to:

```php
// app/Providers/EventServiceProvider.php
use JayAnta\ThreatDetection\Events\ThreatDetected;

protected $listen = [
    ThreatDetected::class => [
        YourCustomListener::class,
    ],
];
```

The event carries `$threatLog` (full DB row array), `$ipAddress`, and `$threatLevel`. Use it to trigger custom actions — send Telegram alerts, update a blocklist, feed a SIEM, etc.

---

## Slack Notifications

Slack alerts are disabled by default. To enable:

```env
THREAT_DETECTION_NOTIFICATIONS=true
THREAT_DETECTION_SLACK_WEBHOOK=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
THREAT_DETECTION_SLACK_CHANNEL=#threat-alerts
```

Only high-severity threats trigger notifications by default (configurable via `notify_levels` in the config).

**Laravel 10:** Uses the built-in `SlackMessage` notification class. No extra package needed.

**Laravel 11+:** The built-in Slack channel was removed. The package **automatically detects this and sends raw HTTP POST webhooks** to your Slack URL. No extra package needed. If you prefer the full notification channel, install:

```bash
composer require laravel/slack-notification-channel
```

---

## Dashboard

The package ships with a built-in dark-mode dashboard (Alpine.js + Tailwind CDN — no build step required).

```
+-------------------------------------------------------------------------+
|  Threat Detection Dashboard                                              |
+-------------------------------------------------------------------------+
|  Total: 847  |  High: 23  |  Med: 156  |  Low: 668  |  IPs: 94         |
+-------------------------------------------------------------------------+
|  [Timeline Chart - 7 Day Stacked Bar]                                   |
+-------------------------------------------------------------------------+
|  Search: [___________]  Level: [All]                                    |
|  Time         IP             Type            Level  Confidence  Actions  |
|  Mar 2 14:02  185.220.101.4  SQL Injection   HIGH   80%         [FP]    |
|  Mar 2 13:58  45.33.32.156   XSS Script Tag  HIGH   65%         [FP]    |
|  Mar 2 13:45  192.168.1.10   Scanner: Nikto  MED    35%         [FP]    |
+-------------------------------------------------------------------------+
|  Top IPs              |  Threats by Country                              |
|  185.220.101.4  [23]  |  US  234                                        |
|  45.33.32.156   [18]  |  CN  156                                        |
|  103.152.220.1  [12]  |  RU  98                                         |
+-------------------------------------------------------------------------+
```

### Enable the dashboard

Add to `.env`:
```env
THREAT_DETECTION_DASHBOARD=true
```

Visit: `http://your-app.test/threat-detection`

### Dashboard authentication

The dashboard uses `['web', 'auth']` middleware by default — users must be logged in.

**If your app does not have authentication set up yet** (e.g., during local development), you have two options:

**Option 1 — Use the built-in auth guard (recommended):**
```env
# In your .env file:
THREAT_DETECTION_DASHBOARD_GUARD=ip
THREAT_DETECTION_DASHBOARD_IPS=127.0.0.1
```
This restricts the dashboard to your local machine only. Other guard options: `auth` (login required), `role` (role-based), `none` (no auth — for local dev only). See [Dashboard Authentication](#dashboard-authentication) for all options.

**Option 2 — Remove auth middleware:**
```php
// config/threat-detection.php
'dashboard' => [
    'enabled' => true,
    'path' => 'threat-detection',
    'middleware' => ['web'],  // temporarily remove 'auth'
],
```

> Restore authentication before deploying to production.

**If the dashboard shows empty data**, make sure the API endpoints are accessible. The dashboard fetches data from the API. See [API Authentication](#api-authentication) for details.

---

## API Endpoints

The package provides 15 REST endpoints for building custom dashboards or integrations.

### API Authentication

API routes use `auth:sanctum` middleware by default. The package handles this gracefully:

- **Sanctum installed:** API requires authentication via Sanctum tokens or SPA session auth.
- **Sanctum NOT installed:** The package **automatically detects** that Sanctum is missing and falls back to `['api']` only. The API works without authentication.

**If you don't use Sanctum but want to protect your API**, you have two options:

**Option 1 — Use the built-in auth guard:**
```env
THREAT_DETECTION_API_GUARD=auth
```

**Option 2 — Change the middleware directly:**
```php
// config/threat-detection.php
'api' => [
    'enabled' => true,
    'prefix' => 'api/threat-detection',
    'middleware' => ['api', 'auth'],  // or 'auth:your-guard'
],
```

**For local testing** (if Sanctum blocks access), temporarily change:
```php
'middleware' => ['api'],  // remove 'auth:sanctum'
```
> Restore authentication before deploying to production.

### Endpoint Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/threat-detection/threats` | List threats (paginated, filterable) |
| GET | `/api/threat-detection/threats/{id}` | Single threat details |
| POST | `/api/threat-detection/threats/{id}/false-positive` | Mark threat as false positive |
| GET | `/api/threat-detection/stats` | Overall statistics |
| GET | `/api/threat-detection/summary` | Detailed breakdown by type, level, IP |
| GET | `/api/threat-detection/live-count` | Threats in last hour |
| GET | `/api/threat-detection/by-country` | Grouped by country |
| GET | `/api/threat-detection/by-cloud-provider` | Grouped by cloud provider |
| GET | `/api/threat-detection/top-ips` | Top offending IPs |
| GET | `/api/threat-detection/timeline` | Threat timeline (for charts) |
| GET | `/api/threat-detection/ip-stats?ip=x.x.x.x` | Stats for specific IP |
| GET | `/api/threat-detection/correlation` | Correlation analysis |
| GET | `/api/threat-detection/export` | Export to CSV |
| GET | `/api/threat-detection/exclusion-rules` | List exclusion rules |
| DELETE | `/api/threat-detection/exclusion-rules/{id}` | Delete an exclusion rule |

### Query Parameters for `/threats`

| Parameter | Description |
|-----------|-------------|
| `keyword` | Search in IP, URL, type |
| `ip` | Filter by IP address |
| `level` | Filter by threat level (`high`, `medium`, `low`) |
| `type` | Filter by threat type |
| `country` | Filter by country code |
| `is_foreign` | Filter foreign IPs (`true`/`false`) |
| `cloud_provider` | Filter by cloud provider |
| `is_false_positive` | Filter by false positive status (`true`/`false`) |
| `date_from` / `date_to` | Date range filter |
| `per_page` | Items per page (default: 20, max: 100) |

### Example API Response

**GET `/api/threat-detection/stats`:**
```json
{
  "success": true,
  "data": {
    "total_threats": 847,
    "high_severity": 23,
    "medium_severity": 156,
    "low_severity": 668,
    "unique_ips": 94,
    "foreign_ips": 67,
    "cloud_attacks": 12,
    "today": 34,
    "last_hour": 5
  }
}
```

### Building Custom Frontends

**Vue.js:**
```javascript
async mounted() {
    const response = await fetch('/api/threat-detection/stats');
    this.stats = await response.json();

    const threats = await fetch('/api/threat-detection/threats?per_page=20');
    this.threats = await threats.json();
}
```

**React:**
```jsx
useEffect(() => {
    fetch('/api/threat-detection/stats')
        .then(res => res.json())
        .then(data => setStats(data));
}, []);
```

> If your API uses `auth:sanctum`, include authentication headers or configure Sanctum SPA authentication for cookie-based requests.

---

## Artisan Commands

```bash
# View threat stats summary in the terminal
php artisan threat-detection:stats

# Enrich existing logs with geo-data (country, city, ISP, cloud provider)
# Uses the free ip-api.com service (rate-limited to 45 req/min, auto-throttled)
php artisan threat-detection:enrich --days=7

# Purge old logs to keep the database clean
php artisan threat-detection:purge --days=30

# Export threat IPs for fail2ban (pipe to file or run directly)
php artisan threat-detection:export-fail2ban --level=high --since=24h --min-hits=5
php artisan threat-detection:export-fail2ban --format=plain > /tmp/banlist.txt

# Export blocklist in various formats
php artisan threat-detection:export-blocklist --format=nginx > /etc/nginx/blocklist.conf
php artisan threat-detection:export-blocklist --format=apache > .htaccess-deny
php artisan threat-detection:export-blocklist --format=csv --since=7d
```

---

## 404 Probe Tracking

The package detects reconnaissance probes — bots that hit known vulnerable paths like `/wp-admin`, `/.env`, or `/phpmyadmin` on your non-WordPress, non-phpMyAdmin site. These have no malicious payload; the path itself is the signal.

Logged with a `[probe]` type tag, separate from payload-based detection. If a probe request also contains a malicious payload, both are logged independently.

Enabled by default with 50+ probe paths. Customize in `config/threat-detection.php`:

```php
'probe_tracking' => [
    'enabled' => true,
    'default_level' => 'medium',
    'paths' => [
        '/wp-admin' => 'WordPress Admin',
        '/wp-admin/*' => 'WordPress Admin',
        '/.env' => 'Environment File',
        '/phpmyadmin' => 'phpMyAdmin',
        '/actuator/*' => 'Spring Actuator',
        // Add your own probe paths...
    ],
],
```

Disable with `THREAT_DETECTION_PROBE_TRACKING=false`.

---

## Safe Fields (False Positive Reduction)

If specific form fields legitimately contain HTML, SQL keywords, or code (e.g., CMS editors, code snippet inputs), you can exclude them from scanning:

```php
// config/threat-detection.php
'safe_fields' => ['content', 'body', 'html', 'description', 'code'],
```

Fields listed here are stripped from both query params and POST body before detection runs. Other fields on the same request are still fully scanned.

---

## Dashboard Authentication

The dashboard and API support configurable auth guards via `.env`:

```env
# Options: none (default), auth, role, ip
THREAT_DETECTION_DASHBOARD_GUARD=auth

# For role-based guard (Spatie compatible):
THREAT_DETECTION_DASHBOARD_GUARD=role
THREAT_DETECTION_DASHBOARD_ROLE=admin

# For IP-based guard:
THREAT_DETECTION_DASHBOARD_GUARD=ip
THREAT_DETECTION_DASHBOARD_IPS=127.0.0.1,10.0.0.0/8
```

The same options are available for API routes with `THREAT_DETECTION_API_GUARD`.

When `guard=none` (default), the package logs a warning once per day to remind you to configure authentication.

---

## Custom Patterns

Add your own detection regex patterns in `config/threat-detection.php`:

```php
'custom_patterns' => [
    '/your-regex-here/i' => 'Your Threat Label',
],
```

**Example — detect a custom admin endpoint probe:**
```php
'/\/my-admin-panel/i' => 'Custom Admin Panel Probe',
```

> **Note:** Common probe paths like `/wp-login.php`, `/.env`, `/phpmyadmin` are now handled automatically by the [404 Probe Tracking](#404-probe-tracking) feature. You don't need custom patterns for those.

The threat level for each pattern is determined automatically by matching keywords in the label against the `threat_levels` config:

```php
'threat_levels' => [
    'high' => ['XSS', 'SQL Injection', 'SQL DDL', 'SQL DML', 'SQL File', 'SQL Hex', 'RCE', ..., 'Shellshock', 'Spring4Shell', 'PowerShell', 'CRLF', 'Null Byte', 'SSTI', 'Java', 'LDAP', 'XPath', 'PHP assert', ...],
    'medium' => ['Directory Traversal', 'LFI', 'SSRF', 'Sensitive', 'Config', ..., 'Open Redirect', 'LF Injection', 'GraphQL', 'Spring Boot Actuator', ...],
    'low' => ['User-Agent', 'JS Redirect', 'SEO Bot', 'Empty', 'Rate', 'Command-line Downloader', 'DNS Rebinding'],
],
```

If the label doesn't match any keyword, the threat defaults to `low` severity.

Invalid regex patterns are automatically skipped and logged as warnings — they won't crash your application.

---

## Using the Facade

For programmatic access to threat data outside of the middleware:

```php
use JayAnta\ThreatDetection\Facades\ThreatDetection;

// Get attack statistics for a specific IP
$stats = ThreatDetection::getIpStatistics('192.168.1.1');

// Detect coordinated attacks (multiple IPs targeting same URL within 15 minutes)
$attacks = ThreatDetection::detectCoordinatedAttacks(15, 3);

// Detect attack campaigns (same threat type from 5+ IPs in last 24 hours)
$campaigns = ThreatDetection::detectAttackCampaigns(24);

// Get a summary of all correlation data
$summary = ThreatDetection::getCorrelationSummary();
```

---

## Reducing False Positives

The package provides multiple tools to reduce false positives. Use whichever fits your situation:

### Safe Fields

If specific form fields legitimately contain HTML, SQL keywords, or code, exclude them from scanning entirely:

```php
// config/threat-detection.php
'safe_fields' => ['content', 'body', 'html', 'description', 'code'],
```

This is the simplest approach. The field is completely skipped — no detection runs on it. Use for CMS content editors, code snippet inputs, and rich text fields. See [Safe Fields](#safe-fields-false-positive-reduction) for details.

### Content Path Suppression

If you have CMS editors, blog post forms, or comment sections where users submit rich content, those paths often trigger false positives (e.g., a blog post containing `<script>` code samples). Add those paths to suppress low/medium alerts:

```php
// config/threat-detection.php
'content_paths' => [
    'admin/posts/*',
    'admin/pages/*',
    'blog/*/edit',
    'comments',
],
```

On these paths, only **high-severity** threats are logged.

### False Positive Reporting

Click the **FP** button on any threat in the dashboard to mark it as a false positive. This:
1. Flags the threat as `is_false_positive = true`
2. Auto-creates an exclusion rule so similar threats from the same URL/type are suppressed going forward

Manage exclusion rules via API:
```bash
GET  /api/threat-detection/exclusion-rules
DELETE /api/threat-detection/exclusion-rules/{id}
```

### Confidence Scoring

Every threat receives a confidence score (0-100) based on:
- Number of pattern matches in the same request
- Severity of the matched pattern
- Where the pattern was found (query string > headers > body)
- Whether the user-agent matches a known attack tool
- Current detection mode

Threats below the confidence threshold for your detection mode are not logged (see [Detection Modes](#detection-modes)).

---

## Detected Attack Types

| Category | Examples |
|----------|---------|
| **SQL Injection** | UNION, boolean, time-based, CHAR encoding, DDL (DROP/ALTER/CREATE), DML (INSERT/UPDATE/DELETE), file ops (INTO OUTFILE, LOAD_FILE), ORDER BY enumeration, hex strings, UNHEX |
| **NoSQL Injection** | MongoDB $ne, $gt, $regex, $where operators |
| **XSS** | Script tags, SVG event handlers (`<svg onload=`), HTML event handlers (`<body onload=`, `<img onerror=`), CSS expressions, JavaScript URIs, DOM manipulation |
| **Code Execution** | RCE shell functions, PHP deserialization, Java deserialization (base64 + hex magic bytes), template injection (Blade, JSP, ASP, Jinja2, Velocity), eval(), base64 decode, PHP assert(), create_function(), preg_replace /e |
| **SSTI** | Mathematical probes (`{{7*7}}`), Jinja2 import/config, Velocity templates, Expression Language |
| **Command Injection** | Linux (shell functions, command chains, curl, wget, nc), Windows (cmd.exe, PowerShell, wscript, cscript, net user) |
| **File Access** | Directory traversal, LFI/RFI protocols, sensitive file probes (.env, .git, composer.json) |
| **SSRF** | Localhost (127.0.0.1, 0.0.0.0, ::1), AWS/GCP metadata, private IPs, hex/decimal encoded localhost, DNS rebinding (xip.io, nip.io, sslip.io) |
| **LDAP Injection** | LDAP filter manipulation, OR injection |
| **XPath Injection** | Attribute selectors, XPath functions (contains, substring) |
| **CRLF / Header Injection** | URL-encoded CRLF (`%0d%0a`), LF injection, null byte injection |
| **Protocol Attacks** | HTTP request smuggling (CL+TE), SSI injection |
| **CVE Exploits** | Shellshock (CVE-2014-6271), Spring4Shell (CVE-2022-22965), PHPUnit RCE (CVE-2017-9841), Drupalgeddon, Log4Shell |
| **Probe Tracking** | WordPress (`/wp-admin`, `/wp-login.php`), config files (`/.env`, `/.git`), database tools (`/phpmyadmin`), technology probes (`.asp`, `.jsp`), Spring actuator, Swagger/API docs — 50+ paths |
| **Scanners** | SQLMap, Nikto, Nmap, Burp Suite, FeroxBuster, FFUF, XSStrike, Dalfox, Netsparker, Qualys, Nuclei, and 20+ others (53 total) |
| **AI Scrapers** | GPTBot, ClaudeBot, ChatGPT, ByteSpider, Cohere, Common Crawl |
| **Headless Browsers** | HeadlessChrome, PhantomJS, Selenium, Puppeteer, Playwright |
| **Bots** | Python scripts, Go HTTP clients, cURL, wget, AhrefsBot, SEMRushBot, empty user agents |
| **Authentication** | Brute force detection, token leaks, password exposure, session ID exposure |
| **DDoS** | Rate-based excessive request detection |
| **Evasion** | SQL comment insertion, double URL encoding, HTML entity encoding, Unicode escapes, IIS Unicode, hex escapes |
| **Other** | GraphQL introspection, prototype pollution, open redirect, XXE, web shells, crypto mining, PII detection |

---

## Running the Test Suite

```bash
composer test
```

The package includes 213 tests (640 assertions) covering detection patterns, middleware behavior, API endpoints, confidence scoring, exclusion rules, DDoS detection, evasion resistance, CVE patterns, LDAP/XPath/SSTI injection, bot/scanner detection, probe tracking, export commands, dashboard auth, safe fields, performance optimizations, and full-cycle HTTP-to-DB verification.

---

## License

MIT License. See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please submit a Pull Request.

## Credits

- [Jay Anta](https://github.com/jay123anta)
