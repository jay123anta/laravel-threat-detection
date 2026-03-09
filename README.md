<p align="center">
  <img src="https://img.shields.io/packagist/v/jayanta/laravel-threat-detection.svg?style=flat-square" alt="Latest Version">
  <img src="https://img.shields.io/github/actions/workflow/status/jay123anta/laravel-threat-detection/tests.yml?branch=main&style=flat-square&label=tests" alt="Tests">
  <img src="https://img.shields.io/packagist/dt/jayanta/laravel-threat-detection.svg?style=flat-square" alt="Total Downloads">
  <img src="https://img.shields.io/packagist/l/jayanta/laravel-threat-detection.svg?style=flat-square" alt="License">
  <img src="https://img.shields.io/php-version-support/jayanta/laravel-threat-detection?style=flat-square" alt="PHP Version">
</p>

# Laravel Threat Detection

**Know who's attacking your Laravel app — without changing a single line of application code.**

A middleware-based threat detection and logging system for Laravel. Drop it in, and it starts scanning every HTTP request for SQL injection, XSS, RCE, scanner bots, DDoS patterns, and 40+ other attack types — logging everything to your database with full geo-enrichment and a built-in dashboard.

> Extracted from a production application. Battle-tested with real traffic.

**Important:** This package **never blocks** any request. It only **logs** and **alerts**. Your application continues to handle every request normally, even when threats are detected.

---

## Requirements

- PHP 8.1+
- Laravel 10.x, 11.x, or 12.x
- Any database supported by Laravel (MySQL, PostgreSQL, SQLite, SQL Server)

---

## How It Works

1. A middleware scans every incoming HTTP request
2. The request is checked against 130+ regex patterns covering SQL injection, XSS, RCE, file traversal, SSRF, and more
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

```bash
php artisan vendor:publish --tag=threat-detection-migrations
php artisan migrate
```

This creates two tables: `threat_logs` (stores detected threats) and `threat_exclusion_rules` (stores false positive rules).

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

**"I tested but `threat-detection:stats` shows zero threats"**

| Check | How to verify |
|-------|---------------|
| Migrations were run | Run `php artisan migrate:status` — look for `threat_logs` and `threat_exclusion_rules` tables |
| Middleware is registered | Confirm `ThreatDetectionMiddleware` is in your `web` middleware group (see [Step 3](#3-register-the-middleware) above) |
| IP is not whitelisted | If you added `THREAT_DETECTION_WHITELISTED_IPS` to `.env`, remove it during testing |
| Environment is enabled | Default enabled environments: `production`, `staging`, `local`. Check `APP_ENV` in `.env` |
| Used an existing route | The test URL must match a real route (e.g., `/`). |
| Dedup cache | Same IP + same attack type is cached for 5 minutes — try a different attack type |

**"`threat-detection:stats` throws a database error"**

The `threat_logs` table doesn't exist yet. Run:
```bash
php artisan vendor:publish --tag=threat-detection-migrations
php artisan migrate
```

**"API returns 401 Unauthorized"**

See [API Authentication](#api-authentication) below.

**"Dashboard shows 404"**

The dashboard is disabled by default. Add `THREAT_DETECTION_DASHBOARD=true` to `.env` and clear route cache:
```bash
php artisan route:clear
```

---

## Features

- **130+ Detection Patterns** — SQL injection, XSS, RCE, directory traversal, SSRF, XXE, Log4Shell, NoSQL injection, command injection, and more
- **Scanner Detection** — SQLMap, Nikto, Nmap, Burp Suite, Acunetix, WPScan, Nessus, Nuclei, Metasploit, and others
- **Bot Detection** — Suspicious user agents, automated scripts, headless browsers
- **DDoS Monitoring** — Rate-based threshold detection with configurable windows
- **Confidence Scoring** — Each threat gets a 0-100 confidence score based on pattern count, context, and signals
- **Evasion Resistance** — Payload normalization defeats SQL comment insertion (`UNION/**/SELECT`), double URL encoding (`%2527`), and CHAR encoding bypasses
- **Context-Aware Detection** — Patterns found in query strings score higher than those in POST body
- **False Positive Reporting** — Mark threats as false positives from the dashboard; auto-creates exclusion rules
- **Three Detection Modes** — `strict`, `balanced` (default), and `relaxed` — tunable sensitivity
- **Content Path Suppression** — Whitelist CMS/blog paths to suppress low/medium alerts from rich content
- **PII Detection** — Sensitive data exposure patterns (configurable per region)
- **Geo-Enrichment** — Country, city, ISP, cloud provider identification via free API
- **Slack Alerts** — Real-time notifications for high-severity threats (works on Laravel 10 and 11+)
- **Built-in Dashboard** — Dark-mode Blade dashboard (Alpine.js + Tailwind CDN, zero build step)
- **15 API Endpoints** — Full REST API for building custom Vue/React/mobile dashboards
- **CSV Export** — One-click threat log export (up to 10,000 rows)
- **Correlation Analysis** — Detect coordinated attacks and attack campaigns across IPs
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

# Slack notifications (disabled by default)
# THREAT_DETECTION_NOTIFICATIONS=true
# THREAT_DETECTION_SLACK_WEBHOOK=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
# THREAT_DETECTION_SLACK_CHANNEL=#threat-alerts

# Dashboard (disabled by default)
# THREAT_DETECTION_DASHBOARD=true

# API endpoints (enabled by default)
# THREAT_DETECTION_API=true
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

Key config sections: `skip_paths` (paths to skip), `auth_paths` (smart detection for login routes), `content_paths` (suppress non-high alerts), `context_weights` (scoring multipliers), `threat_levels` (severity keyword mapping), `api_route_filtering` (suppress low/medium on API routes).

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

**If your app does not have authentication set up yet** (e.g., during local development), temporarily change the middleware in `config/threat-detection.php`:

```php
'dashboard' => [
    'enabled' => true,
    'path' => 'threat-detection',
    'middleware' => ['web'],  // temporarily remove 'auth'
],
```

> Restore `['web', 'auth']` before deploying to production.

**If the dashboard shows empty data**, make sure the API endpoints are accessible. The dashboard fetches data from the API. See [API Authentication](#api-authentication) for details.

---

## API Endpoints

The package provides 15 REST endpoints for building custom dashboards or integrations.

### API Authentication

API routes use `auth:sanctum` middleware by default. The package handles this gracefully:

- **Sanctum installed:** API requires authentication via Sanctum tokens or SPA session auth.
- **Sanctum NOT installed:** The package **automatically detects** that Sanctum is missing and falls back to `['api']` only. The API works without authentication.

**If you don't use Sanctum but want to protect your API**, add your own auth guard in `config/threat-detection.php`:

```php
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
```

---

## Custom Patterns

Add your own detection regex patterns in `config/threat-detection.php`:

```php
'custom_patterns' => [
    '/your-regex-here/i' => 'Your Threat Label',
],
```

**Example — detect requests to a WordPress login page:**
```php
'/\/wp-login\.php/i' => 'WordPress Login Probe',
```

The threat level for each pattern is determined automatically by matching keywords in the label against the `threat_levels` config:

```php
'threat_levels' => [
    'high' => ['XSS', 'SQL Injection', 'RCE', 'Token', 'Password', 'Deserialization', 'Evasion', 'Encoding'],
    'medium' => ['Directory Traversal', 'LFI', 'SSRF', 'Sensitive', 'Config', 'Recon Tool'],
    'low' => ['User-Agent', 'Bot', 'Rate'],
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
| **Injection** | SQL injection (UNION, boolean, time-based, CHAR encoding), NoSQL injection, command injection, LDAP injection |
| **XSS** | Script tags, event handlers, JavaScript URIs, DOM manipulation, encoded XSS |
| **Code Execution** | RCE, PHP deserialization, template injection (Blade, JSP, ASP), eval(), base64 decode |
| **File Access** | Directory traversal, LFI/RFI, sensitive file probes (.env, wp-config, composer.json, .git) |
| **SSRF** | Localhost access, AWS/GCP metadata endpoints, private IP ranges (10.x, 172.16-31.x, 192.168.x) |
| **Authentication** | Brute force detection, token leaks, password exposure, session ID exposure |
| **Scanners** | SQLMap, Nikto, Nmap, Burp Suite, Acunetix, WPScan, Nessus, Nuclei, Metasploit |
| **Bots** | Python scripts, Go HTTP clients, cURL, wget, empty user agents |
| **DDoS** | Rate-based excessive request detection |
| **XXE** | XML external entity attacks, DOCTYPE entity declarations |
| **Log4Shell** | JNDI injection attempts (LDAP, RMI, DNS) |
| **Evasion** | SQL comment insertion (`UNION/**/SELECT`), double URL encoding (`%2527`), CHAR encoding |
| **Web Shells** | c99, r57, b374k, WSO, FilesMan, encoded eval execution |
| **Crypto Mining** | Coinhive, CryptoNight, Monero script detection |

---

## Running the Test Suite

```bash
composer test
```

The package includes 66 tests covering detection patterns, middleware behavior, API endpoints, confidence scoring, exclusion rules, DDoS detection, evasion resistance, and input validation.

---

## License

MIT License. See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please submit a Pull Request.

## Credits

- [Jay Anta](https://github.com/jay123anta)
