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

    /*
    |--------------------------------------------------------------------------
    | Skip Paths
    |--------------------------------------------------------------------------
    |
    | Paths that should be skipped from threat detection.
    | Supports wildcard patterns.
    |
    */
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

        /*
        |----------------------------------------------------------------------
        | AI-infrastructure probes (opt-in, off by default)
        |----------------------------------------------------------------------
        |
        | Self-hosted LLM gateways are now a routine scanning target, and the
        | paths below are the ones attackers were measured hitting rather than
        | the ones that seemed likely. They come from Ollure, a honeypot
        | emulating the Ollama API, which recorded 290,887 interactions from
        | 2,793 unique source IPs over 84 days across four deployments:
        | mostly automated discovery, fingerprinting and model enumeration,
        | but also path traversal, SSRF, RCE, cryptomining payloads, resource
        | exhaustion and prompt injection.
        |
        |   OllamaDrama: Designing and Deploying a Honeypot to Measure Attacks
        |   on Exposed LLM Infrastructure — Elzer, Johansen & Vasilomanolakis,
        |   Technical University of Denmark, 2026. arXiv:2609.29757
        |
        | OFF by default: switching it on is the only thing that changes what
        | an existing install reports. Turn it on if your app does not itself
        | serve an LLM API — if it does, these are your own endpoints, and you
        | want this off or those paths in skip_paths.
        |
        | Entries may be a plain label, or ['label' => ..., 'level' => ...]
        | where one path deserves a different severity from the rest.
        |
        */
        'ai_infrastructure' => [
            'enabled' => env('THREAT_DETECTION_AI_PROBES', false),

            // Applies to every entry below that does not set its own level.
            // Higher than the general probe default: these paths exist on
            // almost no public app, so a request for one is a deliberate hunt
            // for exposed model infrastructure rather than broad spraying.
            'level' => 'high',

            'paths' => [
                // Ollama REST API — default port 11434, commonly proxied.
                // Enumeration first: what is running, and what is loaded.
                '/api/tags' => 'Ollama Model Enumeration',
                '/api/ps' => 'Ollama Running Models',
                '/api/show' => 'Ollama Model Details',
                '/api/version' => 'Ollama Version Probe',

                // Model management. Abuse of these is how an exposed instance
                // gets turned into someone else's compute, and /api/pull is
                // also the SSRF vector: the paper observed a pull request
                // whose "name" was an internal URL.
                '/api/pull' => 'Ollama Model Pull',
                '/api/push' => 'Ollama Model Push',
                '/api/create' => 'Ollama Model Create',
                '/api/copy' => 'Ollama Model Copy',
                '/api/delete' => 'Ollama Model Delete',

                // Inference endpoints — free compute, and the way in for
                // prompt injection against a self-hosted model.
                '/api/generate' => 'Ollama Inference Probe',
                '/api/chat' => 'Ollama Chat Probe',
                '/api/embed' => 'Ollama Embedding Probe',
                '/api/embeddings' => 'Ollama Embedding Probe',

                // OpenAI-compatible surface, exposed by Ollama, LiteLLM,
                // vLLM, LocalAI, Open WebUI and most gateways.
                '/v1/models' => 'OpenAI-Compatible Model Enumeration',
                '/v1/chat/completions' => 'OpenAI-Compatible Inference Probe',
                '/v1/completions' => 'OpenAI-Compatible Inference Probe',
                '/v1/embeddings' => 'OpenAI-Compatible Embedding Probe',

                // Model Context Protocol servers.
                '/mcp' => 'MCP Server Probe',
                '/mcp/*' => 'MCP Server Probe',
                '/sse' => 'MCP SSE Transport Probe',

                // Agent/IDE configuration files. Not infrastructure: these are
                // read for the instructions inside them, which is a different
                // and more interesting intent.
                '/.cursor/rules' => 'Agent Rules File Probe',
                '/.cursor/*' => 'Agent Config Probe',
                '/.aider.conf.yml' => 'Agent Config Probe',
                '/.continue/*' => 'Agent Config Probe',
                '/AGENTS.md' => 'Agent Instructions Probe',
                '/CLAUDE.md' => 'Agent Instructions Probe',
                '/llms.txt' => 'Agent Instructions Probe',

                // AI application frameworks with known RCE / auth-bypass
                // history. Dated so they can be pruned when they stop being
                // worth the entry.
                '/api/v1/validate/code' => 'Langflow Code Validation (CVE-2025-3248, 2025)',
                '/api/v1/*' => 'Langflow API Probe',
                '/health_check' => 'Langflow Health Probe',
                '/api/kernels/*' => 'Notebook Kernel Probe',
                '/lsp/*' => 'marimo LSP Probe',
                '/@file/*' => 'marimo File Access Probe',
                '/litellm/*' => 'LiteLLM Admin Probe',
                '/key/generate' => 'LiteLLM Key Generation Probe',
                '/ollama/*' => 'Open WebUI Ollama Proxy Probe',
                '/rag/api/*' => 'Open WebUI RAG Probe',
            ],
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
    | Blocklisted IPs (Operator Denylist)
    |--------------------------------------------------------------------------
    |
    | A static, operator-maintained denylist consumed by the
    | ThreatDetection::isBlocklisted($ip) helper. Supports CIDR notation.
    | The package itself never refuses a request based on this list —
    | enforcement stays in your own middleware (see the README recipe).
    | whitelisted_ips wins on overlap.
    |
    */
    'blocklisted_ips' => array_filter(array_map('trim', explode(',', env('THREAT_DETECTION_BLOCKLISTED_IPS', '')))),

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
        'path' => 1.5,   // The URL path itself — nothing legitimate hides there
        'raw' => 1.5,   // Still-encoded request; only evasion patterns scan it
        'query' => 1.5,   // Patterns in query strings are most suspicious
        'headers' => 1.3,   // Patterns in headers are suspicious
        'body' => 1.0,   // POST body is baseline (often contains legitimate content)
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

        /*
         * Field names whose value must never be written to the log, whether
         * or not a detection pattern noticed it.
         *
         * This is the counterpart to 'labels' below, and it exists because
         * labels alone could not do the job. The credential patterns are
         * written for the wire form (password=hunter2), while every scanned
         * segment is json_encoded first — "password":"hunter2" — so the
         * closing quote sits between the key and the separator and the
         * pattern never matches. Redaction keyed on those labels therefore
         * never ran on an ordinary login form, and any request that tripped
         * any other pattern stored the password in cleartext.
         *
         * Matching is on the field name in either shape: "field": "value" in
         * a JSON segment, and field=value in a query string. Only the value is
         * replaced, so you can still see that a credential was present.
         *
         * This is not the same as safe_fields. safe_fields stops a field being
         * *scanned*; this lets you keep scanning it and stop storing it.
         */
        'fields' => [
            // Passwords, in the shapes Laravel's own forms use
            'password',
            'password_confirmation',
            'current_password',
            'new_password',
            'old_password',
            'passwd',
            'pwd',
            // Application secrets
            'secret',
            'client_secret',
            'api_key',
            'apikey',
            'api_secret',
            'private_key',
            // Session and request tokens
            'token',
            '_token',
            'access_token',
            'refresh_token',
            'id_token',
            'auth_token',
            'csrf_token',
            'xsrf_token',
            'session_id',
            'sessionid',
            'phpsessid',
            'authorization',
            // Payment and step-up material
            'card_number',
            'credit_card',
            'cvv',
            'cvc',
            'pin',
            'otp',
        ],

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
    | Geo Enrichment
    |--------------------------------------------------------------------------
    |
    | Used only by `php artisan threat-detection:enrich`, which is opt-in —
    | nothing leaves your server unless you run it.
    |
    | Be aware of two things when you do. The attacking IP addresses being
    | looked up are disclosed to a third party, so the default endpoint is
    | HTTPS: over cleartext an on-path observer could read those addresses and
    | forge the replies, and the reply is written into your database and shown
    | on the dashboard.
    |
    | ip-api.com's free tier answers 403 over HTTPS, so enrichment will fail
    | there. It now fails *loudly* — the command reports how many lookups
    | succeeded and exits non-zero when none did — rather than printing
    | "Enrichment complete!" having enriched nothing. There is no fallback to
    | cleartext on failure: an attacker who can block the HTTPS request would
    | otherwise get the plaintext one for free.
    |
    | If you are on the free tier and accept the disclosure, set the endpoint
    | back explicitly:
    |
    |   THREAT_DETECTION_GEO_ENDPOINT=http://ip-api.com/json
    |
    | If you hold an ip-api key, or use another provider returning the same
    | field names (countryCode, country, city, isp, org), point this at it:
    |
    |   THREAT_DETECTION_GEO_ENDPOINT=https://pro.ip-api.com/json
    |
    */
    /*
    |--------------------------------------------------------------------------
    | LLM-safe threat log (opt-in, off by default)
    |--------------------------------------------------------------------------
    |
    | This table stores attacker-controlled text — request bodies, user agents,
    | URLs — and operators increasingly paste that text into an LLM to triage
    | it. That makes the log itself an injection vector: an attacker who wants
    | their intrusion summarised as "routine maintenance" does not need to
    | reach your SOC, only to send a request you will log.
    |
    | Measured, not hypothetical. Across GPT-4o, Claude 3.5 Sonnet and
    | Llama-3-70B, prompt injection planted in log fields succeeded 83.4% of
    | the time on average with no defences; the most vulnerable carriers were
    | JSON API payloads (88.9%) and HTTP headers such as User-Agent and
    | Referer (83-86%) — which are exactly the fields stored here.
    |
    |   Context Contamination in LLM Analysis of Network Security Logs
    |   — Karanjai, Lu, Madhavarao, Xu & Shi (University of Houston, PayPal,
    |   Kent State), 2026. arXiv:2607.14493
    |
    | Two independent switches, both off:
    |
    |   detect_injection  — report injection-shaped content as a threat, so you
    |                       can see someone targeting your analysis pipeline.
    |   spotlight_exports — wrap attacker-controlled cells in the CSV export in
    |                       an explicit trust boundary, so a log pasted into an
    |                       LLM carries its own "this is data, not instructions"
    |                       marker. In the paper this single measure cut attack
    |                       success from 87.3% to 51.4%; layered with others, to
    |                       8.4%. It is a mitigation, not a fix.
    |
    | Cost of detect_injection: injection is plain prose, so these patterns
    | carry no category and run even on requests the keyword pre-screen would
    | otherwise skip. That is roughly ten extra regexes on clean traffic — not
    | the full pattern set, because category-mapped patterns still skip.
    |
    */
    /*
    |--------------------------------------------------------------------------
    | Actor signals (opt-in, off by default)
    |--------------------------------------------------------------------------
    |
    | Substrate, not a detection. Nothing here reports a threat; it records the
    | attempt-level evidence that threat_logs deliberately cannot hold, so the
    | detections built on top of it have something to read.
    |
    | Why a second table. A detection is written to threat_logs once per IP per
    | type per five minutes, which is what stops a flood becoming a write per
    | request. It also means twenty distinct encodings of one injection collapse
    | into a single row — and those nineteen suppressed attempts are precisely
    | the evidence that somebody is iterating on a payload until it lands.
    |
    | Why fingerprints rather than payloads. An LLM asked for variants of a
    | payload produces output whose *structural* distance is high while its
    | *semantic* distance stays low: the implementations diverge widely without
    | changing behaviour, which is what defeats signature matching and
    | similarity clustering. The measured recommendation is to compare meaning
    | instead of surface — and this package already normalises payloads to a
    | fixed point before matching, so the fingerprint is taken there.
    |
    |   The Infinite Mutation Engine? Measuring Polymorphism in LLM-Generated
    |   Offensive Code — Universidad Carlos III de Madrid, 2026.
    |   arXiv:2605.03619
    |
    | Write profile. One row per *distinct* normalised payload per actor per
    | window: a repeat adds nothing, a new variant adds one row. Nothing is
    | written for a request that matched no pattern, so clean traffic never
    | touches this table.
    |
    | Requires the create_threat_actor_signals_table migration:
    |
    |   php artisan vendor:publish --tag=threat-detection-migrations
    |   php artisan migrate
    |
    */
    'actor_signals' => [
        'enabled' => env('THREAT_DETECTION_ACTOR_SIGNALS', false),

        'table' => env('THREAT_DETECTION_ACTOR_SIGNALS_TABLE', 'threat_actor_signals'),

        // How long one fingerprint counts as "already seen" for an actor.
        // Inside this window a repeat of the same normalised payload is not
        // written again.
        'dedupe_minutes' => 60,

        /*
         * Hard ceiling on rows one actor can add per window, so an attacker
         * cannot turn this table into a write amplifier by sending endless
         * random payloads that each hash differently.
         *
         * Enforced with the cache, like the DDoS counter, which means it is
         * per-process on the array driver and only properly effective on a
         * shared store (Redis, Memcached, database). That is the same caveat
         * the DDoS counter already carries.
         */
        'max_per_actor_per_window' => 200,
        'window_minutes' => 60,

        // Rows older than this are removed by threat-detection:purge, whatever
        // --days is set to for threat_logs. Attempt-level evidence is only
        // useful while it is recent, and it accumulates faster.
        'retention_days' => 7,
    ],

    /*
    |--------------------------------------------------------------------------
    | Actor risk score (opt-in, off by default)
    |--------------------------------------------------------------------------
    |
    | Read-only. Nothing is written and nothing runs during a request: the
    | score is computed on demand from threat_logs and, when available,
    | threat_actor_signals.
    |
    | Why a score at all. Sorting by severity alone is a weak way to decide who
    | to look at first. Evaluated across eight alert datasets from five
    | environments, prioritising by rule severity reached AUROC 0.72, while a
    | weighted combination of five dimensions — severity, accumulation,
    | variety, rarity and periodicity — reached 0.92.
    |
    |   Can Risk-Based Alerting Mitigate Cybersecurity Alert Fatigue? 2026.
    |   arXiv:2609.02465
    |
    | Why these weights add rather than average. A weighted average has a
    | mathematical ceiling: when every event scores the same s, the average is
    | s no matter how many events there are, so a persistent attacker scores
    | exactly like a single suspicious request and can never cross a threshold
    | above s. Accumulating fixes it. The peak + accumulation shape below —
    | peak, persistence, diversity, plus additive bonuses — reached 90.8%
    | recall at 1.20% false positives over 10,654 cases.
    |
    |   Peak + Accumulation: A Proxy-Level Scoring Formula for Multi-Turn LLM
    |   Attack Detection, 2026. arXiv:2602.11247
    |
    | The default weights are that paper's, and they were tuned for multi-turn
    | LLM conversations rather than for HTTP actors. They are a considered
    | starting point, not a transferred result: treat the thresholds as
    | something to tune against your own traffic, and read the score as a
    | ranking rather than a verdict.
    |
    */
    'actor_score' => [
        'enabled' => env('THREAT_DETECTION_ACTOR_SCORE', false),

        // How far back an actor's behaviour is considered.
        'window_minutes' => 60,

        /*
         * Peak severity contributes its full value on its own, so one
         * confirmed high-severity detection already scores 0.6 before any
         * accumulation. A lone low-severity match cannot reach the threshold
         * by itself, which is the intent.
         */
        'severity_weight' => [
            'high' => 0.6,
            'medium' => 0.35,
            'low' => 0.15,
        ],

        /*
         * Persistence. The count is saturating rather than linear: the
         * difference between one detection and six matters, the difference
         * between sixty and six hundred does not, and an unbounded term would
         * let volume alone dominate every other signal.
         */
        'persistence_factor' => 0.45,
        'persistence_saturation' => 6,

        // Variety. Probing several different weaknesses is more deliberate
        // than repeating one.
        'diversity_factor' => 0.15,

        /*
         * Kill-chain progression: reconnaissance *and* an exploit attempt from
         * the same actor inside the window. Someone who probes /.env and then
         * sends an injection has moved along the chain, which is a different
         * thing from doing either alone.
         */
        'progression_bonus' => 0.2,

        /*
         * Mutation. Confirmed retry behaviour is the strongest single
         * indicator in the source formula, and it is this package's own
         * speciality: many surface forms of one attack means something is
         * adapting to what you rejected. Requires actor signals.
         */
        'mutation_bonus' => 0.3,
        'mutation_min_variants' => 5,

        /*
         * Periodicity — the weakest term deliberately, and never enough to
         * matter on its own. Machine-regular spacing between attempts is
         * suggestive, but a page pulling twenty assets looks regular too, so
         * it only nudges an actor already scoring for other reasons.
         *
         * Needs at least this many timestamps before it is computed at all.
         */
        'cadence_bonus' => 0.1,
        'cadence_min_samples' => 5,
        'cadence_max_variation' => 0.25,
    ],

    /*
    |--------------------------------------------------------------------------
    | Second-Source Bot Identity (optional)
    |--------------------------------------------------------------------------
    |
    | Reads the `ai-guard.verdict/1` convention published by
    | jayanta/laravel-ai-guard: who a client claims to be, and whether that
    | claim survived a check. There is no Composer dependency in either
    | direction and no class is imported — see Integration\AiGuardContract.
    | With ai-guard absent, nothing fires and nothing costs anything.
    |
    | This only ever adjusts the actor score. It never creates a detection,
    | never suppresses a threat_logs row, and never touches a request.
    |
    | ── Why impersonation *adds* to the score ─────────────────────────────
    |
    | Because it is a deliberate technique, not noise. Imperva found 16.3% of
    | 1,000 sites subject to Googlebot impersonation; HUMAN Security measured
    | roughly 1 in 18 requests bearing an AI-crawler user-agent as forged; one
    | published site audit found 107 of 799 requests carrying Googlebot's name
    | were genuine. Attackers impersonate crawlers precisely to inherit the
    | trust sites extend to them, so a failed identity check next to our own
    | detections is corroboration we cannot derive on our own.
    |
    | ── Why verification only *discounts*, and never exempts ──────────────
    |
    | A blanket exemption rebuilds the hole the impersonation exists to find.
    | Research on bot defences (arXiv:2607.18659) locates the security boundary
    | at environment authenticity and shows trust signals are imitable once an
    | attacker accumulates them; identity-list defences catch 8–18% of bots
    | (arXiv:2603.28546). So a verified crawler's score is damped, not zeroed,
    | and the damping is withdrawn entirely from an actor that reached the
    | exploitation stage. A verified Googlebot sending UNION SELECT is either
    | compromised or verified wrongly, and neither deserves a discount.
    |
    */
    'ai_guard' => [
        'enabled' => env('THREAT_DETECTION_AI_GUARD', false),

        // How long one verdict describes an actor. Matches the score window.
        'ttl_minutes' => 60,

        // Added when a client claimed a verifiable identity and failed every
        // check ai-guard could run.
        'spoofed_bonus' => 0.25,

        // Subtracted when the identity held up. Never below zero, and never
        // applied to an actor with a high-severity non-probe detection.
        'verified_discount' => 0.25,

        /*
         * Only these categories earn the discount. A *verified* scraper or
         * data harvester is still a scraper — verification confirms who it
         * is, not that it is welcome — so the benefit of the doubt is
         * restricted to the categories whose traffic is ordinarily wanted.
         */
        'discount_categories' => [
            'search_engines',
            'ai_training',
            'ai_search',
            'ai_agents',
        ],
    ],

    'llm_log_safety' => [
        'detect_injection' => env('THREAT_DETECTION_LLM_INJECTION', false),

        'spotlight_exports' => env('THREAT_DETECTION_SPOTLIGHT_EXPORTS', false),

        // Wrapper used by spotlight_exports. Anything an LLM will read as a
        // boundary works; the point is that it is explicit and consistent.
        'spotlight_open' => '<<<UNTRUSTED_LOG_DATA',
        'spotlight_close' => 'END_UNTRUSTED_LOG_DATA>>>',

        /*
         * Same shape as custom_patterns: regex => label, or
         * regex => ['label' => ..., 'level' => ..., 'contexts' => [...]].
         *
         * Scoped to the carriers the paper measured. 'path' is excluded — a
         * URL path is too short to carry an instruction and too likely to
         * collide with ordinary routes.
         *
         * Your own custom_patterns entry for the same regex always wins.
         */
        'patterns' => [
            // Chat-template control tokens. These are not prose and have no
            // legitimate reason to appear in an HTTP request.
            '/<\|(?:im_start|im_end|system|user|assistant|endoftext)\|>/i' => [
                'label' => 'LLM Role Marker Injection',
                'level' => 'medium',
                'contexts' => ['query', 'body', 'headers'],
            ],
            '/\[\/?INST\]|\[\/?SYS\]/i' => [
                'label' => 'LLM Role Marker Injection',
                'level' => 'medium',
                'contexts' => ['query', 'body', 'headers'],
            ],
            '/#{2,}\s*(?:instruction|system|assistant)\s*:/i' => [
                'label' => 'LLM Role Marker Injection',
                'level' => 'medium',
                'contexts' => ['query', 'body', 'headers'],
            ],

            // The canonical override. Anchored on a verb plus an explicit
            // reference to earlier instructions, so ordinary prose containing
            // "ignore" on its own does not match.
            '/\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|the\s+)*(?:previous|prior|above|earlier|preceding|system)\s+(?:instruction|prompt|direction|rule|context|message)/i' => [
                'label' => 'LLM Instruction Override',
                'level' => 'medium',
                'contexts' => ['query', 'body', 'headers'],
            ],

            // Aimed squarely at a triage pipeline: telling the reader what
            // verdict to reach. This is the OBJ-CONCEAL / OBJ-FABRICATE shape,
            // and it is the reason this feature exists.
            // The optional noun matters: the shape actually used is
            // "summarize this alert as routine maintenance", not
            // "summarize this as ...". Without it the most likely phrasing of
            // the most important pattern here slipped straight through.
            '/\b(?:summari[sz]e|classify|categori[sz]e|report|mark|treat|label|flag)\s+(?:this|it|the)(?:\s+(?:alert|event|log|entry|incident|activity|request|finding))?\s+as\b/i' => [
                'label' => 'LLM Triage Manipulation',
                'level' => 'high',
                'contexts' => ['query', 'body', 'headers'],
            ],

            // OBJ-EXFIL: asking the analysing model to leak its own context.
            '/\b(?:append|send|post|output|reveal|print|repeat)\s+(?:the\s+|your\s+)?(?:system\s+prompt|initial\s+instruction|above\s+instruction|your\s+instruction)/i' => [
                'label' => 'LLM Prompt Exfiltration',
                'level' => 'high',
                'contexts' => ['query', 'body', 'headers'],
            ],

            // Level 3 obfuscation: the payload is encoded and the instruction
            // to decode it travels alongside.
            '/\b(?:decode|base64_decode|from\s*base64)\s+(?:the\s+)?(?:following|this|below|next)\b|\b(?:following|this)\s+is\s+base64[,:]/i' => [
                'label' => 'LLM Encoded Instruction',
                'level' => 'medium',
                'contexts' => ['query', 'body', 'headers'],
            ],
        ],
    ],

    'enrichment' => [
        'endpoint' => env('THREAT_DETECTION_GEO_ENDPOINT', 'https://ip-api.com/json'),
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
