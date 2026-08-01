<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Enable Threat Detection
    |--------------------------------------------------------------------------
    |
    | Enable or disable the threat detection system globally.
    |
    */
    'enabled' => env('THREAT_DETECTION_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Enabled Environments
    |--------------------------------------------------------------------------
    |
    | Specify which environments should have threat detection enabled.
    | Set to null or empty array to enable in all environments.
    |
    */
    'enabled_environments' => ['production', 'staging', 'local'],

    /*
    |--------------------------------------------------------------------------
    | Database Table Name
    |--------------------------------------------------------------------------
    |
    | The name of the table where threat logs will be stored.
    |
    */
    'table_name' => env('THREAT_DETECTION_TABLE', 'threat_logs'),

    /*
    |--------------------------------------------------------------------------
    | Home Country
    |--------------------------------------------------------------------------
    |
    | Your country's ISO 3166-1 alpha-2 code. Used by geo-enrichment to
    | flag foreign IPs. Change this to your country code (e.g., 'US', 'GB').
    |
    */
    'home_country' => env('THREAT_DETECTION_HOME_COUNTRY', 'IN'),

    /*
    |--------------------------------------------------------------------------
    | Skip Paths
    |--------------------------------------------------------------------------
    |
    | Paths that should be skipped from threat detection.
    | Supports wildcard patterns.
    |
    */
    /*
    |--------------------------------------------------------------------------
    | Only Paths (Whitelist Mode)
    |--------------------------------------------------------------------------
    |
    | If this array is NOT empty, ONLY these paths will be scanned.
    | All other paths are automatically skipped. This can dramatically
    | reduce overhead on high-traffic apps. Supports wildcard patterns.
    |
    | Leave empty (default) to scan all routes (subject to skip_paths).
    |
    */
    'only_paths' => [
        // 'admin/*',
        // 'api/*',
        // 'login',
        // 'register',
    ],

    'skip_paths' => [
        // Match against $request->path(), which has no leading "public/" segment.
        'assets/*',
        'images/*',
        'css/*',
        'js/*',
        'fonts/*',
        'build/*',
        'api/healthcheck',
        'favicon.ico',
        '_debugbar/*',
        'telescope/*',
        'horizon/*',
        'livewire/*',
    ],

    /*
    |--------------------------------------------------------------------------
    | Minimum Confidence Threshold
    |--------------------------------------------------------------------------
    |
    | Threats scoring below this confidence threshold are silently
    | ignored and never written to the database. Set to 0 to log
    | everything. This is applied AFTER the detection_mode threshold.
    |
    */
    'min_confidence' => env('THREAT_DETECTION_MIN_CONFIDENCE', 0),

    /*
    |--------------------------------------------------------------------------
    | Max Detections Per Request
    |--------------------------------------------------------------------------
    |
    | Stop scanning after this many pattern matches per request.
    | A request with 5+ detections is clearly malicious — no need to find all 20.
    | Set to 0 (default) for unlimited detections.
    |
    */
    'max_detections_per_request' => env('THREAT_DETECTION_MAX_DETECTIONS', 0),

    /*
    |--------------------------------------------------------------------------
    | Safe Fields (False Positive Reduction)
    |--------------------------------------------------------------------------
    |
    | Field names listed here are excluded from threat detection scanning.
    | Use this for fields that legitimately contain code, HTML, or SQL-like
    | content (e.g., CMS editors, code snippet fields, search queries).
    |
    | This applies to both query parameters and POST body fields.
    | Example: ['content', 'body', 'html', 'description', 'code', 'query_text']
    |
    */
    'safe_fields' => [],

    /*
    |--------------------------------------------------------------------------
    | Safe Paths (Path-Aware False Positive Reduction)
    |--------------------------------------------------------------------------
    |
    | Like safe_fields, but matches by dot-notation *path* into the request
    | (query or JSON/form body) instead of by field name anywhere. This is more
    | precise for nested JSON APIs: exclude one specific field's value without
    | exempting that key everywhere it appears.
    |
    | Supports fnmatch wildcards. Detection scans only leaf string values, so a
    | legitimate search term containing SQL keywords no longer trips a pattern
    | once its path is listed here.
    |
    | Example: ['search.query', 'filters.*.value', 'content.*.body']
    |
    */
    'safe_paths' => [],

    /*
    |--------------------------------------------------------------------------
    | 404 Probe Tracking
    |--------------------------------------------------------------------------
    |
    | Detect reconnaissance probes hitting known vulnerable paths.
    | These requests have no malicious payload — just the URL itself
    | is suspicious (e.g., /wp-admin on a non-WordPress site).
    | Logs to threat_logs with [probe] type tag.
    |
    */
    'probe_tracking' => [
        'enabled' => env('THREAT_DETECTION_PROBE_TRACKING', true),
        'default_level' => 'medium',
        'paths' => [
            // WordPress
            '/wp-admin' => 'WordPress Admin',
            '/wp-admin/*' => 'WordPress Admin',
            '/wp-login.php' => 'WordPress Login',
            '/wp-content/*' => 'WordPress Content',
            '/wp-includes/*' => 'WordPress Includes',
            '/xmlrpc.php' => 'WordPress XMLRPC',
            '/wp-cron.php' => 'WordPress Cron',
            '/wp-json/*' => 'WordPress REST API',

            // PHP / Config files
            '/.env' => 'Environment File',
            '/.env.backup' => 'Environment Backup',
            '/.env.old' => 'Environment Backup',
            '/phpinfo.php' => 'PHPInfo',
            '/info.php' => 'PHPInfo',
            '/.git/config' => 'Git Config',
            '/.git/HEAD' => 'Git HEAD',
            '/.svn/*' => 'SVN Directory',
            '/.htaccess' => 'Apache Config',
            '/web.config' => 'IIS Config',
            '/composer.json' => 'Composer File',
            '/composer.lock' => 'Composer Lock',
            '/package.json' => 'NPM Package File',

            // Database management
            '/phpmyadmin' => 'phpMyAdmin',
            '/phpmyadmin/*' => 'phpMyAdmin',
            '/pma' => 'phpMyAdmin',
            '/pma/*' => 'phpMyAdmin',
            '/adminer' => 'Adminer',
            '/adminer.php' => 'Adminer',

            // CMS / Admin panels
            '/administrator' => 'Joomla Admin',
            '/administrator/*' => 'Joomla Admin',

            // Server management
            '/cpanel' => 'cPanel',
            '/cgi-bin/*' => 'CGI Bin',
            '/server-status' => 'Apache Status',
            '/server-info' => 'Apache Info',

            // Backup / sensitive
            '/backup' => 'Backup Directory',
            '/backup/*' => 'Backup Directory',
            '/db.sql' => 'Database Dump',
            '/dump.sql' => 'Database Dump',
            '/database.sql' => 'Database Dump',

            // Technology probes (non-matching stack)
            '/*.asp' => 'ASP Probe',
            '/*.aspx' => 'ASPX Probe',
            '/*.jsp' => 'JSP Probe',

            // Framework / dependency exploit paths (path itself is the attack)
            '/vendor/phpunit/*' => 'PHPUnit RCE Probe',
            '/.aws/credentials' => 'AWS Credentials File',
            '/.ssh/id_rsa' => 'SSH Private Key Probe',
            '/.git/*' => 'Git Directory Probe',

            // Spring / Java
            '/actuator' => 'Spring Actuator',
            '/actuator/*' => 'Spring Actuator',

            // Swagger / API docs
            '/swagger' => 'Swagger UI',
            '/swagger/*' => 'Swagger UI',
            '/api-docs' => 'API Docs',
            '/api-docs/*' => 'API Docs',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Auth Paths
    |--------------------------------------------------------------------------
    |
    | Paths that need smart detection (allow legitimate credentials,
    | block actual attacks).
    |
    */
    'auth_paths' => [
        'login',
        'api/login',
        'auth/*',
        'api/auth/*',
        'oauth/*',
        'api/oauth/*',
        'register',
        'api/register',
        'password/*',
        'api/password/*',
    ],

    /*
    |--------------------------------------------------------------------------
    | Content Paths
    |--------------------------------------------------------------------------
    |
    | Paths where rich user content is expected (blog editors, CMS, comments).
    | On these paths, only HIGH severity patterns will trigger detection.
    | Medium and low severity matches are suppressed to reduce false positives.
    |
    */
    'content_paths' => [
        // 'admin/posts/*',
        // 'admin/pages/*',
        // 'blog/*/edit',
        // 'comments',
        // 'api/posts',
    ],

    /*
    |--------------------------------------------------------------------------
    | Whitelisted IPs
    |--------------------------------------------------------------------------
    |
    | IPs that should be excluded from threat detection.
    | Supports CIDR notation.
    |
    */
    'whitelisted_ips' => array_filter(array_map('trim', explode(',', env('THREAT_DETECTION_WHITELISTED_IPS', '')))),

    /*
    |--------------------------------------------------------------------------
    | DDoS Protection
    |--------------------------------------------------------------------------
    |
    | Configure DDoS detection thresholds.
    |
    */
    'ddos' => [
        'threshold' => env('THREAT_DETECTION_DDOS_THRESHOLD', 300),
        'window' => env('THREAT_DETECTION_DDOS_WINDOW', 60),
    ],

    /*
    |--------------------------------------------------------------------------
    | Threat Levels
    |--------------------------------------------------------------------------
    |
    | Map keywords to threat severity levels.
    |
    */
    'threat_levels' => [
        'high' => ['XSS', 'SQL Injection', 'SQL DDL', 'SQL DML', 'SQL File', 'SQL Hex', 'RCE', 'Aadhaar', 'PAN', 'Bank', 'Token', 'Password', 'JWT', 'Deserialization', 'Serialization', 'Metadata Access', 'Evasion', 'Encoding', 'Shellshock', 'Spring4Shell', 'PowerShell', 'Windows CMD', 'CRLF', 'Null Byte', 'SSTI', 'LDAP', 'XPath', 'PHP assert', 'PHP create_function', 'PHP preg_replace', 'HTTP Request Smuggling', 'Prototype Pollution', 'Prototype Chain', 'SSI Injection', 'Drupalgeddon', 'PHPUnit RCE', 'Log4j', 'JNDI', 'XXE', 'IFSC', 'Web Shell', 'File Manager', 'Reverse Shell', 'Encoded Eval', 'SQLi', 'Time-based', 'Benchmark', 'Sleep Attack', 'API Key'],
        'medium' => ['Directory Traversal', 'LFI', 'SSRF', 'Sensitive', 'Config', 'Session', 'Command Chain', 'Recon Tool', 'Raw PHP', 'Open Redirect', 'LF Injection', 'Windows Script', 'Windows Net', 'SQL ORDER', 'SQL HAVING', 'SQL UNHEX', 'GraphQL', 'Spring Boot Actuator', 'PHP System Info', 'PHP User Info', 'PHP Remote Include', 'File Inclusion', 'JavaScript URI'],
        'low' => ['User-Agent', 'JS Redirect', 'SEO Bot', 'Empty', 'Rate', 'Command-line Downloader', 'DNS Rebinding'],
    ],

    /*
    |--------------------------------------------------------------------------
    | API Route Filtering
    |--------------------------------------------------------------------------
    |
    | Drops threats at the listed severities on any route whose path contains
    | "/api/". Intended to keep first-party API chatter out of the log.
    |
    | IMPORTANT: the default suppresses MEDIUM as well as low, and several
    | attacks that are delivered mainly through API endpoints are classified
    | medium — SSRF (including the AWS/GCP metadata endpoints), directory
    | traversal, LFI protocol usage, command chain injection and open redirect.
    | With the default in place those are detected and then discarded before
    | being written.
    |
    | If your app is API-first, set this to ['low'] to keep medium-severity
    | attacks visible while still suppressing routine low-severity noise:
    |
    |   'suppress_levels' => ['low'],
    |
    */
    'api_route_filtering' => [
        'enabled' => true,
        'suppress_levels' => ['low', 'medium'],
    ],

    /*
    |--------------------------------------------------------------------------
    | Detection Mode (Sensitivity)
    |--------------------------------------------------------------------------
    |
    | Controls the overall strictness of threat detection.
    |
    | 'strict'   - All patterns active, low confidence threshold. Catches more
    |              but may produce more false positives.
    | 'balanced' - Default behavior. Confidence scoring active, standard thresholds.
    | 'relaxed'  - Only high-severity patterns trigger. Higher confidence threshold.
    |              Best for content-heavy sites that experience many false positives.
    |
    */
    'detection_mode' => env('THREAT_DETECTION_MODE', 'balanced'),

    /*
    |--------------------------------------------------------------------------
    | Context Weights
    |--------------------------------------------------------------------------
    |
    | Weight multipliers for where a pattern match was found in the request.
    | Higher weight = more suspicious. Used in confidence scoring.
    |
    */
    'context_weights' => [
        'path'    => 1.5,   // The URL path itself — nothing legitimate hides there
        'raw'     => 1.5,   // Still-encoded request; only evasion patterns scan it
        'query'   => 1.5,   // Patterns in query strings are most suspicious
        'headers' => 1.3,   // Patterns in headers are suspicious
        'body'    => 1.0,   // POST body is baseline (often contains legitimate content)
    ],

    /*
    |--------------------------------------------------------------------------
    | Notifications
    |--------------------------------------------------------------------------
    |
    | Configure notification channels for threat alerts.
    |
    */
    'notifications' => [
        'enabled' => env('THREAT_DETECTION_NOTIFICATIONS', false),
        'slack_channel' => env('THREAT_DETECTION_SLACK_CHANNEL', '#threat-alerts'),
        'slack_webhook' => env('THREAT_DETECTION_SLACK_WEBHOOK', ''),
        'slack_username' => env('THREAT_DETECTION_SLACK_USERNAME', 'ThreatBot'),
        'notify_levels' => ['high'],
    ],

    /*
    |--------------------------------------------------------------------------
    | Custom Patterns
    |--------------------------------------------------------------------------
    |
    | Add your own regex patterns for threat detection. Two value formats are
    | supported per pattern:
    |
    |   '/regex/i' => 'My Label',                        // simple
    |   '/regex/i' => [                                  // full control
    |       'label'     => 'My Label',                   // required
    |       'level'     => 'high',                       // low|medium|high (default: derived from threat_levels keywords)
    |       'contexts'  => ['query', 'body'],            // query|body|headers (default: all segments)
    |       'validator' => 'luhn',                       // optional post-match checksum (see pattern_validators)
    |   ],
    |
    | An inline 'validator' takes precedence over the pattern_validators label
    | map. Malformed options fail open (the pattern still scans, unrestricted)
    | with a logged warning — a config mistake never silently disables or
    | narrows a detection.
    |
    */
    'custom_patterns' => [

        // Regional PII Detection (India) — remove or replace with your region's patterns
        '/\b\d{12}\b(?!\s*\d)/' => 'Aadhaar Number Detected',
        '/\b[A-Z]{5}[0-9]{4}[A-Z]\b/' => 'PAN Number Detected',
        '/\b[6-9]\d{9}\b/' => 'Mobile Number Detected',
        '/\b\d{9,18}\b(?!\s*\d)/' => 'Bank Account Number Detected',
        '/\b[A-Z]{4}0[A-Z0-9]{6}\b/' => 'IFSC Code Detected',

        // Credential & Token Leaks
        '/access[_-]?token\s*=\s*["\']?[A-Za-z0-9\-_\.=]{32,}/i' => 'Access Token Leak',
        '/session[_-]?id\s*=\s*["\']?[A-Za-z0-9\-]{20,}/i' => 'Session ID Leak',
        '/\bpassword\s*=\s*["\']?.{8,40}["\']?/i' => 'Password Exposure',
        '/api[_-]?key\s*[=:]\s*["\']?[A-Za-z0-9\-_]{20,}/i' => 'API Key Exposure',
        '/bearer\s+[A-Za-z0-9\-_\.]{20,}/i' => 'Bearer Token Detected',

        // Sensitive File Access
        '/config\.(json|php|env)/i' => 'Sensitive Config File Access',
        '/\.env(\.|$)/i' => 'Environment File Access',
        '/composer\.(json|lock)/i' => 'Composer File Access',
        '/package(-lock)?\.json/i' => 'Package File Access',
        '/\.git(\/|\\\\)/i' => 'Git Directory Access Attempt',
        '/\.ssh(\/|\\\\)/i' => 'SSH Directory Access Attempt',
        '/\.aws(\/|\\\\)credentials/i' => 'AWS Credentials Access',
        '/web\.config|\.htaccess/i' => 'Server Config Access',
        '/phpinfo\(/i' => 'PHPInfo Function Call',

        // Path Traversal & Admin Access
        //
        // NOTE: these match the request path itself. Each is narrow — bare
        // "/admin" matches, "/admin/users" does not — but if your app serves
        // one of these routes legitimately you will see a low-severity entry
        // per IP every 5 minutes. Add the route to skip_paths (above) to
        // silence it, or delete the pattern here.
        '/\/admin\b(?![-\/])/i' => 'Admin Path Access Attempt',
        '/\/internal\b/i' => 'Internal Endpoint Probe',
        '/\/legacy\b/i' => 'Legacy System Access',
        '/\/backup\b/i' => 'Backup Directory Probe',
        '/\/test\b/i' => 'Test Endpoint Probe',
        '/\/debug\b/i' => 'Debug Endpoint Probe',
        '/\/console\b/i' => 'Console Access Attempt',

        // XSS Variants
        '/%3Cscript%3E/i' => 'Encoded XSS Detected',
        '/document\.location\s*=\s*["\']?.+/i' => 'JS Redirect',
        '/(fromCharCode|decodeURI|atob)\s*\(/i' => 'Obfuscated JS',
        '/<iframe\b[^>]*>/i' => 'Iframe Injection',
        '/<embed\b[^>]*>/i' => 'Embed Tag Injection',
        '/<object\b[^>]*>/i' => 'Object Tag Injection',
        '/\bonfocus\s*=/i' => 'OnFocus Event Handler',
        '/\bonerror\s*=/i' => 'OnError Event Handler',

        // Code Injection
        '/<\?php/i' => 'Raw PHP Code Detected',
        '/\{\{[^}]+\}\}/' => 'Blade/Liquid Template Injection',
        '/<%(=)?\s*[^%]{1,500}%>/s' => 'JSP/ASP Template Injection',
        '/\$\{[^}]+\}/i' => 'Expression Language Injection',

        // XXE (XML External Entity)
        '/<!ENTITY/i' => 'XXE Entity Declaration',
        '/<!DOCTYPE.*ENTITY/is' => 'XXE DOCTYPE Attack',

        // Log4j / Log4Shell
        '/\$\{jndi:(ldap|rmi|dns):\/\//i' => 'Log4j/Log4Shell Attack',
        '/\$\{jndi:/i' => 'JNDI Injection Attempt',

        // SSRF & DNS Rebinding
        '/169\.254\.169\.254/i' => 'AWS Metadata SSRF',
        '/metadata\.google\.internal/i' => 'GCP Metadata SSRF',
        '/\b(10|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.\d+\.\d+/i' => 'Private IP Access',

        // SQL Injection Variants
        '/\b(select|union|drop)\b\s+\*?\s*\bfrom\b\s+\w+/i' => 'SQLi Variant',
        '/\bwaitfor\s+delay\b/i' => 'SQL Time-based Blind',
        '/\bbenchmark\s*\(/i' => 'SQL Benchmark Attack',
        '/\bsleep\s*\(/i' => 'SQL Sleep Attack',
        '/\bconcat\s*\(/i' => 'SQL Concat Function',

        // NoSQL Injection
        '/\$ne\s*:|[\[\{]\s*\$ne\s*:/i' => 'NoSQL $ne Injection',
        '/\$gt\s*:|[\[\{]\s*\$gt\s*:/i' => 'NoSQL $gt Injection',
        '/\$regex\s*:/i' => 'NoSQL Regex Injection',
        '/\$where\s*:/i' => 'NoSQL $where Injection',

        // Command Injection
        '/\bcurl\s+["\']?https?:\/\//i' => 'Command Line Tool (curl)',
        '/\bwget\s+["\']?https?:\/\//i' => 'Command Line Tool (wget)',
        '/\bnc\s+-/i' => 'Netcat Usage',
        '/\/bin\/(bash|sh|zsh)/i' => 'Shell Execution Attempt',
        '/\bchmod\s+777/i' => 'Dangerous Permission Change',

        // Debug & Dev Tools
        '/--inspect\b/i' => 'Node.js Debug Mode',
        '/PHPSESSID=[a-zA-Z0-9]{10,}/i' => 'PHP Session Exposure',
        '/XDEBUG_SESSION/i' => 'XDebug Session',
        '/\btrace[_-]?id\b/i' => 'Trace ID Exposure',

        // API Abuse
        '/\b(v1|v2|v3)\/users\/\d+/i' => 'API User Enumeration',
        '/\/api\/.*\?.*limit=\d{3,}/i' => 'API High Limit Request',
        '/\/graphql[^{]{0,200}\{[^}]{0,1000}\}/is' => 'GraphQL Query Detected',

        // IDOR (Insecure Direct Object Reference)
        '/\/user(s)?\/\d+\/delete/i' => 'User Deletion Attempt',
        '/\/admin\/\d+/i' => 'Admin ID Enumeration',

        // Malware & Web Shells
        '/c99|r57|b374k|wso|c100/i' => 'Web Shell Signature',
        '/FilesMan/i' => 'File Manager Shell',
        '/eval\s*\(\s*base64_decode/i' => 'Encoded Eval Execution',

        // Bot & Scanner Detection
        '/\b(sqlmap|havij|acunetix|netsparker|appscan|burp)/i' => 'Security Scanner Detected',
        '/\b(masscan|zmap)\b/i' => 'Port Scanner',
        '/(python-requests|go-http-client)/i' => 'Scripted Request',

        // Crypto Mining
        '/coinhive|cryptonight|monero/i' => 'Crypto Mining Script',

        // Reverse Shell
        '/bash\s+-i\s*>|\/dev\/tcp/i' => 'Reverse Shell Attempt',
        '/nc\s+-e\s+\/bin/i' => 'Netcat Reverse Shell',
    ],

    /*
    |--------------------------------------------------------------------------
    | Post-Match Validators (Checksum-Aware False Positive Reduction)
    |--------------------------------------------------------------------------
    |
    | A regex alone can't express every constraint: any 12-digit run matches
    | the Aadhaar pattern, but a real Aadhaar number also passes the Verhoeff
    | checksum. Map a pattern label (default or custom) to a named validator
    | and a regex hit only counts when at least one matched value passes it.
    |
    | Available validators:
    |
    |   'verhoeff'  Verhoeff checksum (Aadhaar numbers)
    |   'luhn'      Luhn checksum (credit/debit card numbers)
    |
    | An unknown validator name fails open (the match still counts, with a
    | warning logged once), so a typo can never silently disable a pattern.
    |
    | Example — only checksum-valid card numbers trip a custom card pattern:
    |
    |   'custom_patterns'    => ['/\b(?:\d[ -]?){13,19}\b/' => 'Card Number Detected'],
    |   'pattern_validators' => ['Card Number Detected' => 'luhn'],
    |
    */
    'pattern_validators' => [
        'Aadhaar Number Detected' => 'verhoeff',
    ],

    /*
    |--------------------------------------------------------------------------
    | Redaction (Do Not Store What You Detect)
    |--------------------------------------------------------------------------
    |
    | Without this, detecting sensitive data causes that data to be written to
    | the log in cleartext: an Aadhaar number, a PAN, a bank account or a
    | password is matched, and the request payload containing it — plus the URL
    | if it was in the query string — is stored verbatim and kept for the whole
    | retention period. The detector becomes a second, concentrated copy of
    | exactly what it warns you about, readable by anyone with dashboard or
    | database access.
    |
    | When a pattern whose label is listed below fires, the value it matched is
    | masked in the stored payload and URL. Detection is unaffected — it has
    | already happened by then — so you still get the alert, the endpoint and
    | the attacking IP, without the secondary store.
    |
    | This does not replace safe_fields / safe_paths. Those stop a field being
    | *scanned* at all; this lets you keep scanning and stop storing.
    |
    */
    'redact' => [
        'enabled' => env('THREAT_DETECTION_REDACT', true),

        'mask' => '[REDACTED]',

        // Labels whose matched value must never be written to the log.
        'labels' => [
            // Regional PII
            'Aadhaar Number Detected',
            'PAN Number Detected',
            'Mobile Number Detected',
            'Bank Account Number Detected',
            'IFSC Code Detected',
            // Credentials and session material
            'Password Exposure',
            'API Key Exposure',
            'Access Token Leak',
            'Bearer Token Detected',
            'Session ID Leak',
            'JWT Token Found',
            'CSRF Token Reference',
            'PHP Session Exposure',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Web Dashboard
    |--------------------------------------------------------------------------
    |
    | Enable built-in web dashboard for viewing threat logs.
    |
    */
    'dashboard' => [
        'enabled' => env('THREAT_DETECTION_DASHBOARD', false),
        'path' => env('THREAT_DETECTION_DASHBOARD_PATH', 'threat-detection'),
        'middleware' => ['web', 'auth'],
        'guard' => env('THREAT_DETECTION_DASHBOARD_GUARD', 'none'),  // none|auth|role|ip
        'role' => env('THREAT_DETECTION_DASHBOARD_ROLE', 'admin'),   // used when guard=role
        'allowed_ips' => array_filter(array_map('trim', explode(',', env('THREAT_DETECTION_DASHBOARD_IPS', '')))),

        // Send Content-Security-Policy, X-Frame-Options, X-Content-Type-Options
        // and Referrer-Policy with the dashboard. Turn off only if you have
        // published and customised the view to load assets from other origins.
        'security_headers' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | API Routes
    |--------------------------------------------------------------------------
    |
    | Configure API routes for threat data.
    | WARNING: These routes expose sensitive security data. Always use
    | authentication middleware in production. The default includes 'auth:sanctum'.
    | Change to ['api', 'auth'] or your own guard as needed.
    |
    */
    'api' => [
        'enabled' => env('THREAT_DETECTION_API', true),
        'prefix' => env('THREAT_DETECTION_API_PREFIX', 'api/threat-detection'),
        'middleware' => ['api', 'auth:sanctum'],
        'throttle' => env('THREAT_DETECTION_API_THROTTLE', '60,1'),
        'guard' => env('THREAT_DETECTION_API_GUARD', 'none'),  // none|auth|role|ip
        'role' => env('THREAT_DETECTION_API_ROLE', 'admin'),   // used when guard=role
        'allowed_ips' => array_filter(array_map('trim', explode(',', env('THREAT_DETECTION_API_IPS', '')))),

        /*
        | Guard for the two endpoints that switch detection OFF: marking a
        | threat as a false positive, and deleting an exclusion rule. Both
        | silence a detection type for everyone, which is a different
        | privilege from reading the log — without this, any authenticated
        | user of your application could disable a detection.
        |
        | Applied to those routes only, so reading and the dashboard keep
        | working exactly as before. Accepts the same none|auth|role|ip values
        | as `guard`; 'role' uses the `role` setting above.
        |
        | Set THREAT_DETECTION_API_WRITE_GUARD=auth if your user model has no
        | hasRole(), or =none to restore the pre-1.7.0 behaviour.
        */
        'write_guard' => env('THREAT_DETECTION_API_WRITE_GUARD', 'role'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Retention Policy (Auto-Purge)
    |--------------------------------------------------------------------------
    |
    | Automatically purge old threat logs on a daily schedule.
    | Requires Laravel's scheduler to be running (cron).
    | Disabled by default — opt in via .env.
    |
    */
    'retention' => [
        'enabled' => env('THREAT_DETECTION_RETENTION', false),
        'days' => env('THREAT_DETECTION_RETENTION_DAYS', 90),
    ],

    /*
    |--------------------------------------------------------------------------
    | Queue Support
    |--------------------------------------------------------------------------
    |
    | When enabled, threat logging (DB insert + notifications) is dispatched
    | to a queue instead of running synchronously in the request cycle.
    | This reduces response latency on scanned routes.
    |
    */
    'queue' => [
        'enabled' => env('THREAT_DETECTION_QUEUE', false),
        'connection' => env('THREAT_DETECTION_QUEUE_CONNECTION', null),
        'queue' => env('THREAT_DETECTION_QUEUE_NAME', 'default'),
    ],

];
