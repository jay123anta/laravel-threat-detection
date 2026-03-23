<?php

namespace JayAnta\ThreatDetection\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Notification;
use JayAnta\ThreatDetection\Events\ThreatDetected;
use JayAnta\ThreatDetection\Jobs\StoreThreatLog;
use JayAnta\ThreatDetection\Notifications\ThreatAlertSlack;

class ThreatDetectionService
{
    protected int $ddosThreshold;
    protected int $ddosWindowSeconds;
    protected ConfidenceScorer $confidenceScorer;
    protected ExclusionRuleService $exclusionRuleService;

    public function __construct(
        ?ConfidenceScorer $confidenceScorer = null,
        ?ExclusionRuleService $exclusionRuleService = null
    ) {
        $this->ddosThreshold = config('threat-detection.ddos.threshold', 100);
        $this->ddosWindowSeconds = config('threat-detection.ddos.window', 60);
        $this->confidenceScorer = $confidenceScorer ?? new ConfidenceScorer();
        $this->exclusionRuleService = $exclusionRuleService ?? new ExclusionRuleService();
    }

    public function detectAndLogFromRequest(Request $request): void
    {
        $ip = $request->ip();
        $url = $request->fullUrl();
        $userAgent = $request->userAgent() ?? 'N/A';
        $isAuthPath = $request->attributes->get('threat-detection:auth-path', false);
        $isContentPath = $request->attributes->get('threat-detection:content-path', false);
        $mode = config('threat-detection.detection_mode', 'balanced');

        $botThreats = $this->detectSuspiciousUserAgent($userAgent);
        $isAttackTool = $this->confidenceScorer->isAttackToolUserAgent($userAgent);

        if ($this->isDdosSuspected($ip)) {
            $this->logDdosThreat($ip, $url, $userAgent);
        }

        // Probe detection: check for known vulnerable path probes
        $probeThreats = [];
        $probeResult = $request->attributes->get('threat-detection:probe');
        if ($probeResult) {
            $probeThreats[] = [$probeResult['label'], $probeResult['level'], 'probe'];
        }

        // Build segments once, reuse for both detection and payload logging
        $segments = $this->buildPayloadSegments($request);
        $payload = $this->buildSanitizedPayloadFromSegments($segments);
        $contextMatches = $this->detectThreatPatternsWithContext($segments, 'middleware', $isAuthPath);

        $patternThreats = [];
        $contextWeights = [];
        foreach ($contextMatches as $match) {
            $patternThreats[] = [$match['label'], $match['threat_level'], $match['source']];
            $weight = config('threat-detection.context_weights.' . $match['context'], 1.0);
            $contextWeights[$match['label']] = $weight;
        }

        $allThreats = array_merge($probeThreats, $botThreats, $patternThreats);

        $confidence = $this->confidenceScorer->calculate(
            $allThreats,
            $contextWeights,
            $isAttackTool,
            $mode
        );

        $modeMinConfidence = match ($mode) {
            'strict' => 0,
            'relaxed' => 40,
            default => 10,
        };

        // Apply the higher of: mode-based threshold OR config-based threshold
        $configMinConfidence = (int) config('threat-detection.min_confidence', 0);
        $minConfidence = max($modeMinConfidence, $configMinConfidence);

        if ($confidence['score'] < $minConfidence) {
            return;
        }

        // Collect all log entries for batch insert
        $batchLogData = [];
        $notificationQueue = [];
        $truncatedPayload = substr($payload, 0, 2000);
        $now = now();
        $userId = Auth::id();

        foreach ($allThreats as [$label, $level, $sourceTag]) {
            if (
                config('threat-detection.api_route_filtering.enabled', true)
                && str_contains($url, '/api/')
                && in_array($level, config('threat-detection.api_route_filtering.suppress_levels', ['low', 'medium']))
            ) {
                continue;
            }

            if ($isContentPath && $level !== 'high') {
                continue;
            }

            $type = "[$sourceTag] $label";

            if ($this->exclusionRuleService->isExcluded($type, $url)) {
                continue;
            }

            if ($this->isRecentlyLogged($ip, $type)) {
                continue;
            }
            $this->markAsLogged($ip, $type);

            $logData = [
                'ip_address' => $ip,
                'url' => $url,
                'user_agent' => $userAgent,
                'type' => $type,
                'payload' => $truncatedPayload,
                'threat_level' => $level,
                'confidence_score' => $confidence['score'],
                'confidence_label' => $confidence['label'],
                'user_id' => $userId,
                'created_at' => $now,
                'updated_at' => $now,
            ];

            $batchLogData[] = $logData;

            // Collect notification data
            if (
                config('threat-detection.notifications.enabled') &&
                in_array($level, config('threat-detection.notifications.notify_levels', ['high']))
            ) {
                $notificationQueue[] = ['type' => $type, 'level' => $level];
            }

            // Sanitize log output to prevent log injection via newlines/control chars
            $safeType = str_replace(["\n", "\r", "\t"], ' ', $type);
            $safeUrl = str_replace(["\n", "\r", "\t"], ' ', $url);
            Log::warning("[{$level}] Threat Detected: [{$safeType}] from {$ip} ({$safeUrl}) [confidence: {$confidence['score']}%]");

            // Dispatch event so users can hook in with custom listeners
            ThreatDetected::dispatch($logData, $ip, $level);
        }

        // Batch write: one INSERT or one queue job for all threats in this request
        if (!empty($batchLogData)) {
            if (config('threat-detection.queue.enabled', false)) {
                $job = new StoreThreatLog($batchLogData, !empty($notificationQueue) ? [
                    'webhook_url' => config('threat-detection.notifications.slack_webhook'),
                    'alert_data' => [
                        'ip_address' => $ip,
                        'url' => $url,
                        'type' => $batchLogData[0]['type'],
                        'threat_level' => $batchLogData[0]['threat_level'],
                        'action_taken' => 'logged',
                        'user_agent' => $userAgent,
                    ],
                ] : null);

                $connection = config('threat-detection.queue.connection');
                $queue = config('threat-detection.queue.queue', 'default');

                if ($connection) {
                    $job->onConnection($connection);
                }
                $job->onQueue($queue);

                dispatch($job);
            } else {
                DB::table(config('threat-detection.table_name', 'threat_logs'))->insert($batchLogData);

                if (!empty($notificationQueue)) {
                    $this->sendNotifications($ip, $url, $batchLogData[0]['type'], $batchLogData[0]['threat_level'], $userAgent);
                }
            }
        }
    }

    /**
     * Build sanitized payload string from pre-built segments.
     * Reuses segments to avoid duplicate json_encode calls.
     */
    private function buildSanitizedPayloadFromSegments(array $segments): string
    {
        $data = [];

        if (!empty($segments['query'])) {
            $data[] = "QUERY: " . $segments['query'];
        }
        if (!empty($segments['body'])) {
            $data[] = "BODY: " . $segments['body'];
        }
        if (!empty($segments['headers'])) {
            $data[] = "HEADERS: " . $segments['headers'];
        }

        return implode("\n", $data);
    }

    private function buildPayloadSegments(Request $request): array
    {
        $segments = ['query' => '', 'body' => '', 'headers' => ''];
        $safeFields = config('threat-detection.safe_fields', []);

        $queryData = $request->query();
        if (!empty($queryData)) {
            if (!empty($safeFields)) {
                $queryData = array_diff_key($queryData, array_flip($safeFields));
            }
            if (!empty($queryData)) {
                $segments['query'] = json_encode($queryData, JSON_UNESCAPED_SLASHES);
            }
        }

        // For multipart file uploads, only scan non-file form fields
        $postData = $request->post();
        if (!empty($postData)) {
            if (str_contains($request->header('Content-Type', ''), 'multipart/form-data')) {
                $fileKeys = array_keys($request->allFiles());
                $postData = array_diff_key($postData, array_flip($fileKeys));
            }
            if (!empty($safeFields)) {
                $postData = array_diff_key($postData, array_flip($safeFields));
            }
            if (!empty($postData)) {
                $segments['body'] = json_encode($postData, JSON_UNESCAPED_SLASHES);
            }
        }

        $headers = collect($request->headers->all())
            ->except(['cookie', 'x-xsrf-token', 'accept-language', 'accept-encoding', 'connection', 'host', 'referer', 'origin'])
            ->map(fn($v) => is_array($v) ? implode('; ', array_slice($v, 0, 2)) : $v);

        if ($headers->isNotEmpty()) {
            $segments['headers'] = json_encode($headers, JSON_UNESCAPED_SLASHES);
        }

        return $segments;
    }

    /**
     * Normalize payload to defeat evasion techniques.
     * Strips SQL comments, decodes HTML entities, decodes Unicode escapes,
     * performs recursive URL decoding, and collapses whitespace.
     */
    private function normalizeForDetection(string $payload): string
    {
        // Strip SQL inline comments: UNION/**/SELECT → UNION SELECT
        $normalized = preg_replace('/\/\*.*?\*\//s', ' ', $payload);

        // Decode HTML entities: &#60;script&#62; → <script>, &#x3c; → <
        $normalized = html_entity_decode($normalized, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        // Decode Unicode escape sequences: \u003c → <
        $normalized = preg_replace_callback('/\\\\u([0-9a-fA-F]{4})/', function ($m) {
            $code = hexdec($m[1]);
            return $code < 128 ? chr($code) : $m[0];
        }, $normalized);

        // Decode hex escape sequences: \x3c → <
        $normalized = preg_replace_callback('/\\\\x([0-9a-fA-F]{2})/', function ($m) {
            return chr(hexdec($m[1]));
        }, $normalized);

        // Recursive URL decoding (max 3 passes to prevent infinite loops)
        for ($i = 0; $i < 3; $i++) {
            $decoded = urldecode($normalized);
            if ($decoded === $normalized) {
                break;
            }
            $normalized = $decoded;
        }

        // Collapse whitespace
        $normalized = preg_replace('/\s+/', ' ', $normalized);

        return trim($normalized);
    }

    /** Patterns matched before normalization — detect evasion attempts themselves. */
    private static ?array $evasionPatterns = null;

    private function getEvasionPatterns(): array
    {
        if (self::$evasionPatterns !== null) {
            return self::$evasionPatterns;
        }

        return self::$evasionPatterns = [
            '/\w+\/\*[^*]*\*\/\w+/' => 'SQL Comment Evasion',
            '/%25[0-9a-fA-F]{2}/i' => 'Double URL Encoding',
            '/&#x?[0-9a-fA-F]+;/i' => 'HTML Entity Encoding Evasion',
            '/\\\\u00[0-9a-fA-F]{2}/i' => 'Unicode Escape Evasion',
            '/%u[0-9a-fA-F]{4}/i' => 'IIS Unicode Encoding Evasion',

            // CRLF / HTTP Header Injection (CRS 921, CWE-113) — must run on raw payload
            '/%0[dD]%0[aA]/' => 'CRLF Injection',
            '/%0[aA]/' => 'LF Injection',

            // Null Byte Injection (CWE-626) — must run on raw before URL decode
            '/%00/' => 'Null Byte Injection',
        ];
    }

    /**
     * Quick pre-screen: check if payload contains any suspicious substrings
     * before running 175+ regex patterns. Skips ~90% of legitimate requests.
     *
     * Uses keyword-based checks (not structural chars like quotes/brackets)
     * to avoid false triggers on JSON payloads.
     */
    private function hasSuspiciousCharacters(string $payload): bool
    {
        // Attack-indicative keywords and character sequences.
        // Excludes structural JSON chars (", {, }, [, ], :) which cause
        // false triggers on every JSON API request.
        static $suspects = [
            "'", '<', '>', '..', '0x', '|', ';', '`', '#', '(', '$',
            'select', 'union', 'script', 'alert', 'eval', 'exec',
            'system', 'cmd', 'powershell', 'drop', 'insert', 'delete',
            'passwd', 'etc/', 'localhost', '127.0', '0.0.0.0', 'proto', 'jndi',
            'onload', 'onerror', '__proto__', 'document.', 'javascript:',
            'base64', '../', 'chmod', 'wget', 'curl ', '/bin/',
            'class.module', 'actuator', '%00', '%0d', '%0a', '%25',
            'char(', 'phar:', 'expect:', 'input:', '172.', '192.168',
            'redirect=', 'url=http', 'next=http', 'goto=http',
            'phpunit', '#post_render', 'order by', '{{', '{%', '<%',
            'ro0ab', 'aced0005', '__schema', '__type', 'wscript',
            'net user', 'net localgroup', '@', 'contains(', 'substring(',
            '2130706433', 'redirect":', 'url":"http', 'next":"http',
        ];

        $lower = strtolower($payload);
        foreach ($suspects as $s) {
            if (str_contains($lower, $s)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Category keyword pre-checks. Each category has cheap str_contains keywords.
     * If none of a category's keywords appear, all regex patterns in that category are skipped.
     * This turns 175 regex evaluations into ~10-30 for typical requests.
     */
    private static array $categoryKeywords = [
        'sql' => ['select', 'union', 'insert', 'update', 'delete', 'drop', 'alter', 'create', 'truncate',
            'exec', 'having', 'order by', 'char(', 'concat(', 'unhex', 'load_file', 'outfile',
            'information_schema', 'pg_catalog', 'sysobjects', '0x', 'benchmark', 'sleep', 'waitfor'],
        'xss' => ['<script', 'javascript:', 'onerror', 'onload', 'onfocus', 'onclick', 'onmouse',
            '<img', '<svg', '<iframe', '<embed', '<object', '<body', '<video', '<audio', '<details',
            'alert(', 'confirm(', 'prompt(', 'document.', 'innerhtml', 'outerhtml', 'eval(',
            'expression(', 'setinterval', 'settimeout', 'function(', '<marquee', 'style='],
        'rce' => ['system(', 'shell_exec', 'passthru', 'proc_open', 'popen(', 'base64_decode',
            'include(', 'require(', 'assert(', 'create_function', 'preg_replace', 'php_uname',
            'get_current_user', 'allow_url_include', '<?php', '/bin/', 'chmod'],
        'path' => ['../', '..\\', '/etc/', 'passwd', 'win.ini', 'file://', 'php://', 'zip://',
            'data://', 'glob://', 'phar://', 'expect://', 'input://'],
        'ssrf' => ['localhost', '127.0.0.1', '0.0.0.0', '::1', '169.254.', 'metadata.google',
            '10.', '172.', '192.168.', '0x7f', '2130706433', 'xip.io', 'nip.io', 'sslip.io',
            '017700000001'],
        'cmd' => ['|', ';', '&&', '||', '`', 'curl ', 'wget ', 'nc ', 'cmd', 'powershell',
            'wscript', 'cscript', 'net user', 'net localgroup', 'chmod'],
        'injection' => ['jndi:', '<!entity', '<!doctype', 'class.module', '__proto__',
            'constructor', '#exec', '#include', 'ldap', 'xpath', 'contains(', 'substring(',
            'normalize-space(', '(|', '(&', '[@', '$ne', '$gt', '$regex', '$where'],
        'ssti' => ['{{', '{%', '<%', '${', '#set'],
        'token' => ['eyj', 'csrf', 'bearer', 'password', 'api_key', 'api-key', 'access_token',
            'session_id', 'session-id', 'phpsessid', 'xdebug'],
        'scanner' => ['nmap', 'sqlmap', 'nikto', 'acunetix', 'wpscan', 'dirbuster', 'fimap'],
        'deser' => ['o:', 'ro0ab', 'aced0005', 'ysoserial'],
        'cve' => ['() {', 'class.module', 'phpunit', 'actuator', '#post_render', '#lazy_builder'],
        'redirect' => ['redirect=', 'redirect":', 'url=http', 'url":"http', 'next=http', 'next":"http',
            'return=http', 'goto=http', 'dest=http'],
        'misc' => ['coinhive', 'cryptonight', 'monero', '--inspect', 'xdebug', 'trace_id',
            'graphql', '__schema', '__type', 'swagger', 'api-docs'],
    ];

    /**
     * Determine which pattern categories are relevant for a given payload.
     * Returns a set of category keys whose keywords were found.
     */
    private function getRelevantCategories(string $payload): array
    {
        $lower = strtolower($payload);
        $relevant = [];

        foreach (self::$categoryKeywords as $category => $keywords) {
            foreach ($keywords as $keyword) {
                if (str_contains($lower, $keyword)) {
                    $relevant[$category] = true;
                    break; // One keyword match activates the whole category
                }
            }
        }

        return $relevant;
    }

    /** @var array Direct label → category map (built once from pattern list) */
    private static ?array $labelCategoryMap = null;

    /**
     * Check if a pattern's label belongs to a relevant category.
     * Uses direct full-label lookup. Unknown labels always run (safe fallback).
     */
    private function isPatternRelevant(string $label, array $relevantCategories): bool
    {
        if (empty($relevantCategories)) {
            return false;
        }

        if (self::$labelCategoryMap === null) {
            // Direct full-label → category mapping. No substring ambiguity.
            self::$labelCategoryMap = [
                // SQL
                'SQL Injection UNION' => 'sql', 'SQL SELECT Query' => 'sql',
                'SQL Boolean Check' => 'sql', 'SQL exec()' => 'sql',
                'SQL Metadata Probe' => 'sql', 'SQL Injection CHAR Encoding' => 'sql',
                'SQL DDL Injection' => 'sql', 'SQL DML Injection' => 'sql',
                'SQL File Write' => 'sql', 'SQL File Read' => 'sql',
                'SQL ORDER BY Enumeration' => 'sql', 'SQL HAVING Injection' => 'sql',
                'SQL Hex Encoded String' => 'sql', 'SQL UNHEX Function' => 'sql',
                'SQLi Variant' => 'sql', 'SQL Time-based Blind' => 'sql',
                'SQL Benchmark Attack' => 'sql', 'SQL Sleep Attack' => 'sql',
                'SQL Concat Function' => 'sql',
                // XSS
                'XSS Script Tag' => 'xss', 'Inline JS Event Handler' => 'xss',
                'JavaScript URI' => 'xss', 'XSS DOM Access' => 'xss',
                'XSS Dialog Function' => 'xss', 'eval() Usage' => 'xss',
                'DOM HTML Injection' => 'xss', 'XSS SVG Event Handler' => 'xss',
                'XSS HTML Event Handler' => 'xss', 'XSS CSS Expression' => 'xss',
                'Encoded XSS Detected' => 'xss', 'JS Redirect' => 'xss',
                'Obfuscated JS' => 'xss', 'Iframe Injection' => 'xss',
                'Embed Tag Injection' => 'xss', 'Object Tag Injection' => 'xss',
                'OnFocus Event Handler' => 'xss', 'OnError Event Handler' => 'xss',
                // RCE / PHP
                'RCE base64 Decode' => 'rce', 'RCE Shell Function' => 'rce',
                'RCE Variable Execution' => 'rce', 'File Inclusion' => 'rce',
                'PHP assert() Execution' => 'rce', 'PHP create_function() Execution' => 'rce',
                'PHP preg_replace /e Execution' => 'rce', 'PHP System Info Disclosure' => 'rce',
                'PHP User Info Disclosure' => 'rce', 'PHP Remote Include Toggle' => 'rce',
                'Raw PHP Code Detected' => 'rce', 'PHPInfo Function Call' => 'rce',
                'Web Shell Signature' => 'rce', 'File Manager Shell' => 'rce',
                'Encoded Eval Execution' => 'rce', 'Reverse Shell Attempt' => 'cmd',
                'Netcat Reverse Shell' => 'cmd',
                // Path
                'Directory Traversal' => 'path', 'LFI Protocol Usage' => 'path',
                'Sensitive File Access' => 'path',
                // SSRF
                'Localhost SSRF' => 'ssrf', 'AWS Metadata SSRF' => 'ssrf',
                'GCP Metadata SSRF' => 'ssrf', 'Private IP Access' => 'ssrf',
                'SSRF Hex Encoded Localhost' => 'ssrf', 'SSRF Decimal Encoded Localhost' => 'ssrf',
                'SSRF DNS Rebinding Service' => 'ssrf',
                // Command
                'Command Chain Injection' => 'cmd', 'Command Downloader' => 'cmd',
                'Windows CMD Execution' => 'cmd', 'PowerShell Execution' => 'cmd',
                'Windows Script Host' => 'cmd', 'Windows Net Command' => 'cmd',
                'Shellshock CVE-2014-6271' => 'cve', 'Dangerous Permission Change' => 'cmd',
                'Shell Execution Attempt' => 'cmd', 'Netcat Usage' => 'cmd',
                // Injection
                'LDAP Injection' => 'injection', 'LDAP OR Injection' => 'injection',
                'XPath Attribute Injection' => 'injection', 'XPath Function Injection' => 'injection',
                'Prototype Pollution' => 'injection', 'Prototype Chain Access' => 'injection',
                'SSI Injection' => 'injection', 'XXE Entity Declaration' => 'injection',
                'XXE DOCTYPE Attack' => 'injection', 'Log4j/Log4Shell Attack' => 'injection',
                'JNDI Injection Attempt' => 'injection',
                'HTTP Request Smuggling CL+TE' => 'misc',
                // CVE
                'Spring4Shell CVE-2022-22965' => 'cve',
                'PHPUnit RCE Probe CVE-2017-9841' => 'cve',
                'Spring Boot Actuator Probe' => 'cve',
                'Drupalgeddon Render Injection' => 'cve',
                // SSTI
                'SSTI Mathematical Probe' => 'ssti', 'SSTI Config Access' => 'ssti',
                'SSTI Jinja2 Import' => 'ssti', 'SSTI Velocity Template' => 'ssti',
                'Blade/Liquid Template Injection' => 'ssti',
                'JSP/ASP Template Injection' => 'ssti', 'Expression Language Injection' => 'ssti',
                // Token
                'JWT Token Found' => 'token', 'CSRF Token Reference' => 'token',
                'Password Exposure' => 'token', 'API Key Exposure' => 'token',
                'Access Token Leak' => 'token', 'Session ID Leak' => 'token',
                'Bearer Token Detected' => 'token',
                'Aadhaar Number Detected' => 'token', 'PAN Number Detected' => 'token',
                'Bank Account Number Detected' => 'token', 'IFSC Code Detected' => 'token',
                'Mobile Number Detected' => 'token', 'PHP Session Exposure' => 'token',
                'XDebug Session' => 'token', 'Trace ID Exposure' => 'token',
                // Scanner
                'Scanner Tool Detected' => 'scanner', 'Security Scanner Detected' => 'scanner',
                'Port Scanner' => 'scanner', 'Scripted Request' => 'scanner',
                // Deserialization
                'PHP Object Deserialization' => 'deser', 'Java Deserialization' => 'deser',
                'Java Serialization Magic Bytes' => 'deser',
                // Redirect
                'Open Redirect' => 'redirect',
                // NoSQL
                'NoSQL $ne Injection' => 'sql', 'NoSQL $gt Injection' => 'sql',
                'NoSQL Regex Injection' => 'sql', 'NoSQL $where Injection' => 'sql',
                // GraphQL / Misc
                'GraphQL Introspection' => 'misc', 'GraphQL Type Introspection' => 'misc',
                'GraphQL Query Detected' => 'misc',
                'Crypto Mining Script' => 'misc', 'Node.js Debug Mode' => 'misc',
                // Sensitive files (custom)
                'Sensitive Config File Access' => 'path', 'Environment File Access' => 'path',
                'Composer File Access' => 'path', 'Package File Access' => 'path',
                'Git Directory Access Attempt' => 'path', 'SSH Directory Access Attempt' => 'path',
                'AWS Credentials Access' => 'path', 'Server Config Access' => 'path',
                // Endpoint probes (custom)
                'Admin Path Access Attempt' => 'cve', 'Internal Endpoint Probe' => 'cve',
                'Legacy System Access' => 'cve', 'Backup Directory Probe' => 'cve',
                'Test Endpoint Probe' => 'cve', 'Debug Endpoint Probe' => 'cve',
                'Console Access Attempt' => 'cve',
                // API
                'API User Enumeration' => 'misc', 'API High Limit Request' => 'misc',
                'User Deletion Attempt' => 'misc', 'Admin ID Enumeration' => 'misc',
            ];
        }

        // Direct lookup — O(1), no ambiguity
        if (isset(self::$labelCategoryMap[$label])) {
            return isset($relevantCategories[self::$labelCategoryMap[$label]]);
        }

        // Unknown pattern — always run it (safe fallback)
        return true;
    }

    public function detectThreatPatternsWithContext(
        array $segments,
        string $source = 'default',
        bool $isAuthPath = false
    ): array {
        $matches = [];
        $mode = config('threat-detection.detection_mode', 'balanced');
        $maxDetections = (int) config('threat-detection.max_detections_per_request', 0);

        $authExcludePatterns = [
            'Password Exposure', 'Mobile Number Detected', 'Aadhaar Number Detected',
            'PAN Number Detected', 'Bank Account Number Detected', 'IFSC Code Detected',
            'Session ID Leak', 'Bearer Token Detected', 'Access Token Leak', 'API Key Exposure',
        ];

        foreach ($segments as $context => $segmentPayload) {
            if (empty($segmentPayload)) {
                continue;
            }

            // Cap payload to prevent ReDoS on large inputs
            $segmentPayload = substr($segmentPayload, 0, 8000);

            // Early bailout: skip regex if payload has no suspicious characters
            if (!$this->hasSuspiciousCharacters($segmentPayload)) {
                continue;
            }

            // Evasion patterns run on raw payload
            foreach ($this->getEvasionPatterns() as $regex => $label) {
                if ($maxDetections > 0 && count($matches) >= $maxDetections) {
                    break 2;
                }
                if (@preg_match($regex, $segmentPayload)) {
                    $matches[] = [
                        'label' => $label,
                        'threat_level' => 'high',
                        'source' => $source,
                        'context' => $context,
                    ];
                }
            }

            $normalizedPayload = $this->normalizeForDetection($segmentPayload);

            // Category-based lazy loading: only run regex for categories whose
            // keywords appear in the payload. Skips ~80% of patterns on average.
            $relevantCategories = $this->getRelevantCategories($normalizedPayload);

            foreach ($this->getDefaultThreatPatterns() as $regex => $label) {
                if ($maxDetections > 0 && count($matches) >= $maxDetections) {
                    break 2;
                }

                $level = $this->getThreatLevelByType($label);

                if ($mode === 'relaxed' && $level !== 'high') {
                    continue;
                }

                // Skip patterns whose category keywords aren't in the payload
                if (!$this->isPatternRelevant($label, $relevantCategories)) {
                    continue;
                }

                if (@preg_match($regex, $normalizedPayload)) {
                    $matches[] = [
                        'label' => $label,
                        'threat_level' => $level,
                        'source' => $source,
                        'context' => $context,
                    ];
                }
            }

            foreach ($this->getValidatedCustomPatterns() as $regex => $label) {
                if ($maxDetections > 0 && count($matches) >= $maxDetections) {
                    break 2;
                }

                if ($isAuthPath && in_array($label, $authExcludePatterns)) {
                    continue;
                }

                $level = $this->getThreatLevelByType($label);

                if ($mode === 'relaxed' && $level !== 'high') {
                    continue;
                }

                if (!$this->isPatternRelevant($label, $relevantCategories)) {
                    continue;
                }

                if (@preg_match($regex, $normalizedPayload)) {
                    $matches[] = [
                        'label' => $label,
                        'threat_level' => $level,
                        'source' => 'custom',
                        'context' => $context,
                    ];
                }
            }
        }

        return $matches;
    }

    private function isRecentlyLogged(string $ip, string $type): bool
    {
        return Cache::has("threat_logged:{$ip}:{$type}");
    }

    private function markAsLogged(string $ip, string $type): void
    {
        Cache::put("threat_logged:{$ip}:{$type}", true, now()->addMinutes(5));
    }

    private static bool $ddosCacheWarned = false;

    private function isDdosSuspected(string $ip): bool
    {
        // Skip DDoS detection on cache drivers that don't support atomic increment
        $driver = config('cache.default');
        if (in_array($driver, ['file', 'database', 'null'])) {
            if (!self::$ddosCacheWarned) {
                Log::warning("Threat detection: DDoS detection is disabled because cache driver '{$driver}' does not support atomic increment. Use redis or memcached.");
                self::$ddosCacheWarned = true;
            }
            return false;
        }

        try {
            $key = "ddos:$ip";
            Cache::add($key, 0, now()->addSeconds($this->ddosWindowSeconds));
            $count = Cache::increment($key);
            return $count > $this->ddosThreshold;
        } catch (\Throwable $e) {
            Log::error('Threat detection DDoS check failed: ' . $e->getMessage());
            return false;
        }
    }

    private function logDdosThreat(string $ip, string $url, string $userAgent): void
    {
        $type = '[ddos] Excessive Requests';
        $level = 'high';

        if ($this->isRecentlyLogged($ip, $type)) return;
        $this->markAsLogged($ip, $type);

        DB::table(config('threat-detection.table_name', 'threat_logs'))->insert([
            'ip_address' => $ip,
            'url' => $url,
            'user_agent' => $userAgent,
            'type' => $type,
            'payload' => 'Request frequency exceeded threshold',
            'threat_level' => $level,
            'confidence_score' => 90,
            'confidence_label' => 'very_high',
            'user_id' => Auth::id(),
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        Log::warning("[$level] DDoS Threat Detected: $ip exceeded threshold.");
    }

    private static array $threatLevelCache = [];

    private function getThreatLevelByType(string $label): string
    {
        if (isset(self::$threatLevelCache[$label])) {
            return self::$threatLevelCache[$label];
        }

        $labelLower = strtolower($label);
        foreach (config('threat-detection.threat_levels', []) as $level => $keywords) {
            foreach ($keywords as $keyword) {
                if (str_contains($labelLower, strtolower($keyword))) {
                    self::$threatLevelCache[$label] = $level;
                    return $level;
                }
            }
        }

        self::$threatLevelCache[$label] = 'low';
        return 'low';
    }

    private static ?array $defaultPatterns = null;

    public function getDefaultThreatPatterns(): array
    {
        if (self::$defaultPatterns !== null) {
            return self::$defaultPatterns;
        }

        return self::$defaultPatterns = [
            '/<script\b[^>]*>.*?<\/script>/is' => 'XSS Script Tag',
            '/on\w+\s*=\s*["\']\s*javascript:/i' => 'Inline JS Event Handler',
            '/\bjavascript\s*:\s*/i' => 'JavaScript URI',
            '/document\.(cookie|location|write)/i' => 'XSS DOM Access',
            '/\b(alert|confirm|prompt)\s*\(/i' => 'XSS Dialog Function',
            '/\beval\s*\(/i' => 'eval() Usage',
            '/\b(innerHTML|outerHTML)\b/i' => 'DOM HTML Injection',

            '/\bunion\s+select\b/i' => 'SQL Injection UNION',
            '/\bselect\b\s+.+?\s+\bfrom\b/i' => 'SQL SELECT Query',
            '/\b(or|and)\b\s+["\']?\d+["\']?\s*=\s*["\']?\d+["\']?/i' => 'SQL Boolean Check',
            '/\bexec(?:ute)?\b\s*\(/i' => 'SQL exec()',
            '/\b(information_schema|pg_catalog|mysql\.|sysobjects)\b/i' => 'SQL Metadata Probe',
            '/\bCHAR\s*\(\s*\d+/i' => 'SQL Injection CHAR Encoding',

            '/\bbase64_decode\s*\(/i' => 'RCE base64 Decode',
            '/\b(system|shell_exec|exec|passthru|proc_open|popen)\s*\(/i' => 'RCE Shell Function',
            '/\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\[\s*["\'][^"\']+["\']\s*\]\s*\(/i' => 'RCE Variable Execution',
            '/\b(include|require)(_once)?\s*\(?\s*[\'"]?.+?\.(php|inc)[\'"]?\s*\)?/i' => 'File Inclusion',

            '/\.\.(\/|\\\\)/' => 'Directory Traversal',
            '/\b(file|php|zip|data|glob|phar|expect|input):\/\//i' => 'LFI Protocol Usage',
            '/\/etc\/passwd|\/proc\/self\/environ|c:\\\\windows\\\\win\.ini/i' => 'Sensitive File Access',
            '/(localhost|127\.0\.0\.1|0\.0\.0\.0|::1)(:\d+)?\b/i' => 'Localhost SSRF',

            '/(?<![a-z0-9])(?:;|&&|\|\|)(?![a-z0-9])/i' => 'Command Chain Injection',
            '/\b(curl|wget)\s+["\']?https?:\/\//i' => 'Command Downloader',

            '/eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/' => 'JWT Token Found',
            '/csrf[_-]?token\s*=\s*["\']?[a-z0-9\-_]{32,}/i' => 'CSRF Token Reference',

            '/O:\d+:"[A-Za-z_][A-Za-z0-9_]+":\d+:\{[^}]{0,500}\}/s' => 'PHP Object Deserialization',

            '/\b(nmap|sqlmap|nikto|acunetix|wpscan|dirbuster|fimap)\b/i' => 'Scanner Tool Detected',

            // Shellshock (CVE-2014-6271) — still top-scanned CVE
            '/\(\)\s*\{/' => 'Shellshock CVE-2014-6271',

            // Spring4Shell (CVE-2022-22965)
            '/class\.module\.classLoader/i' => 'Spring4Shell CVE-2022-22965',

            // Windows Command Injection (CRS 932, AWS WAF WindowsRuleSet)
            '/\b(cmd|cmd\.exe)\s*\/[ckCK]/i' => 'Windows CMD Execution',
            '/\bpowershell(\.exe)?\b/i' => 'PowerShell Execution',
            '/\b(wscript|cscript)(\.exe)?\b/i' => 'Windows Script Host',
            '/\bnet\s+(user|localgroup)\b/i' => 'Windows Net Command',

            // SVG/MathML XSS vectors (CRS 941 — major bypass for <script> filters)
            '/<svg[^>]*\bon\w+\s*=/i' => 'XSS SVG Event Handler',
            '/<(body|img|video|audio|details|marquee)[^>]*\bon\w+\s*=/i' => 'XSS HTML Event Handler',
            '/style\s*=\s*[^>]*expression\s*\(/i' => 'XSS CSS Expression',

            // SQL DDL/DML Injection (CRS 942 — destructive operations)
            '/\b(ALTER|CREATE|DROP|TRUNCATE)\s+(TABLE|DATABASE|INDEX)\b/i' => 'SQL DDL Injection',
            '/\b(INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b/i' => 'SQL DML Injection',
            '/\bINTO\s+(OUT|DUMP)FILE\b/i' => 'SQL File Write',
            '/\bLOAD_FILE\s*\(/i' => 'SQL File Read',

            // Java Deserialization (CWE-502 — ysoserial gadget chains)
            '/rO0AB[a-zA-Z0-9+\/=]{10,}/' => 'Java Deserialization',
            '/aced0005[0-9a-fA-F]{8,}/i' => 'Java Serialization Magic Bytes',

            // Expanded SSTI — Server-Side Template Injection (CRS 944)
            '/\{\{\s*\d+\s*\*\s*\d+\s*\}\}/' => 'SSTI Mathematical Probe',
            '/\{\{\s*(config|self|request|cycler)\b/i' => 'SSTI Config Access',
            '/\{%\s*import\b/i' => 'SSTI Jinja2 Import',
            '/#set\s*\(\s*\$/i' => 'SSTI Velocity Template',

            // Open Redirect (CWE-601, OWASP A01) — matches both query string and JSON-encoded formats
            '/(?:redirect|url|next|return|goto|dest)["\s]*[=:]["\s]*"?https?:\/\//i' => 'Open Redirect',

            // ── Phase 2: Missing Attack Categories ───────────────────

            // LDAP Injection (CWE-90, OWASP A05)
            '/[)(|*\\\\].*\(.*=/s' => 'LDAP Injection',
            '/\(\|[^)]*\([^)]*=/' => 'LDAP OR Injection',

            // XPath Injection (CWE-643)
            '/\[\s*@\w+\s*=/' => 'XPath Attribute Injection',
            '/\b(contains|substring|normalize-space)\s*\(/i' => 'XPath Function Injection',

            // PHP Extended Patterns (CRS 933)
            '/\bassert\s*\(/i' => 'PHP assert() Execution',
            '/\bcreate_function\s*\(/i' => 'PHP create_function() Execution',
            '/\bpreg_replace\s*\([^)]*\/[^)]*e/i' => 'PHP preg_replace /e Execution',
            '/\bphp_uname\s*\(/i' => 'PHP System Info Disclosure',
            '/\bget_current_user\s*\(/i' => 'PHP User Info Disclosure',
            '/\ballow_url_include\b/i' => 'PHP Remote Include Toggle',

            // HTTP Request Smuggling indicators (CRS 921)
            '/Transfer-Encoding\s*:.*chunked.*Content-Length/is' => 'HTTP Request Smuggling CL+TE',

            // Additional SQL patterns (CRS 942)
            '/\bORDER\s+BY\s+\d+/i' => 'SQL ORDER BY Enumeration',
            '/\bGROUP\s+BY\s+.{0,50}\bHAVING\b/i' => 'SQL HAVING Injection',
            '/0x[0-9a-fA-F]{8,}/i' => 'SQL Hex Encoded String',
            '/\bUNHEX\s*\(/i' => 'SQL UNHEX Function',

            // GraphQL Introspection abuse (OWASP API7)
            '/__schema\b/i' => 'GraphQL Introspection',
            '/__type\b/i' => 'GraphQL Type Introspection',

            // Prototype Pollution (JavaScript apps)
            '/__proto__/' => 'Prototype Pollution',
            '/constructor\s*\[\s*["\']prototype/' => 'Prototype Chain Access',

            // SSI Injection (Server-Side Includes)
            '/<!--#\s*(exec|include|echo|config)\b/i' => 'SSI Injection',

            // DNS Rebinding / SSRF bypass
            '/0x7f000001/i' => 'SSRF Hex Encoded Localhost',
            '/2130706433/' => 'SSRF Decimal Encoded Localhost',
            '/\.(xip|nip|sslip)\.io\b/i' => 'SSRF DNS Rebinding Service',

            // Known exploit endpoint probes
            '/vendor\/phpunit\/phpunit/i' => 'PHPUnit RCE Probe CVE-2017-9841',
            '/\/actuator\b/i' => 'Spring Boot Actuator Probe',
            '/#(post_render|lazy_builder|pre_render)/i' => 'Drupalgeddon Render Injection',
        ];
    }

    private static ?array $validatedCustomPatterns = null;

    /**
     * Returns custom patterns that have been validated once per process lifecycle.
     * Invalid patterns are logged and skipped permanently.
     */
    private function getValidatedCustomPatterns(): array
    {
        if (self::$validatedCustomPatterns !== null) {
            return self::$validatedCustomPatterns;
        }

        self::$validatedCustomPatterns = [];
        foreach (config('threat-detection.custom_patterns', []) as $regex => $label) {
            if (@preg_match($regex, '') === false) {
                Log::warning("Threat detection: invalid custom pattern skipped: {$regex}");
                continue;
            }
            self::$validatedCustomPatterns[$regex] = $label;
        }

        return self::$validatedCustomPatterns;
    }

    public function detectThreatPatterns(string $payload, string $source = 'default', bool $isAuthPath = false): array
    {
        $matches = [];

        foreach ($this->getDefaultThreatPatterns() as $regex => $label) {
            if (@preg_match($regex, $payload)) {
                $matches[] = [$label, $this->getThreatLevelByType($label), $source];
            }
        }

        $authExcludePatterns = [
            'Password Exposure',
            'Mobile Number Detected',
            'Aadhaar Number Detected',
            'PAN Number Detected',
            'Bank Account Number Detected',
            'IFSC Code Detected',
            'Session ID Leak',
            'Bearer Token Detected',
            'Access Token Leak',
            'API Key Exposure',
        ];

        foreach ($this->getValidatedCustomPatterns() as $regex => $label) {
            if (@preg_match($regex, $payload)) {
                if ($isAuthPath && in_array($label, $authExcludePatterns)) {
                    continue;
                }

                $matches[] = [$label, $this->getThreatLevelByType($label), 'custom'];
            }
        }

        return $matches;
    }

    private static ?array $cachedScanners = null;
    private static ?array $cachedBots = null;

    private function detectSuspiciousUserAgent(string $userAgent): array
    {
        // Short-circuit: standard browsers skip all 70+ checks
        $userAgentLower = strtolower($userAgent);
        if (str_contains($userAgentLower, 'mozilla/') && str_contains($userAgentLower, 'gecko')) {
            // Looks like a real browser — only check for headless/automation markers
            $threats = [];
            $headlessMarkers = ['headlesschrome', 'phantomjs', 'selenium', 'puppeteer', 'playwright'];
            foreach ($headlessMarkers as $marker) {
                if (str_contains($userAgentLower, $marker)) {
                    $threats[] = [ucfirst($marker) . ' detected', 'medium', 'user-agent'];
                }
            }
            // Still check for scanner UAs that spoof Mozilla (e.g., GPTBot includes Mozilla)
            $spoofCheckMarkers = ['gptbot', 'claudebot', 'bytespider', 'ahrefsbot', 'semrushbot',
                'mj12bot', 'dotbot', 'petalbot', 'censys', 'shodan'];
            foreach ($spoofCheckMarkers as $marker) {
                if (str_contains($userAgentLower, $marker)) {
                    // Fall through to full check
                    return $this->fullUserAgentScan($userAgentLower, $userAgent);
                }
            }
            return $threats;
        }

        return $this->fullUserAgentScan($userAgentLower, $userAgent);
    }

    private function fullUserAgentScan(string $userAgentLower, string $userAgent): array
    {
        $threats = [];

        if (self::$cachedScanners === null) {
            self::$cachedScanners = [
            // Existing scanners
            'sqlmap' => ['label' => 'SQLMap Scanner', 'level' => 'high'],
            'nikto' => ['label' => 'Nikto Scanner', 'level' => 'high'],
            'nmap' => ['label' => 'Nmap Scanner', 'level' => 'high'],
            'acunetix' => ['label' => 'Acunetix Scanner', 'level' => 'high'],
            'wpscan' => ['label' => 'WPScan Tool', 'level' => 'medium'],
            'nessus' => ['label' => 'Nessus Scanner', 'level' => 'high'],
            'openvas' => ['label' => 'OpenVAS Scanner', 'level' => 'high'],
            'nuclei' => ['label' => 'Nuclei Scanner', 'level' => 'high'],
            'burp' => ['label' => 'Burp Suite', 'level' => 'medium'],
            'zap' => ['label' => 'OWASP ZAP', 'level' => 'medium'],
            'metasploit' => ['label' => 'Metasploit', 'level' => 'high'],
            'w3af' => ['label' => 'W3AF Scanner', 'level' => 'high'],
            'havij' => ['label' => 'Havij SQLi Tool', 'level' => 'high'],
            'dirbuster' => ['label' => 'DirBuster', 'level' => 'medium'],
            'gobuster' => ['label' => 'GoBuster', 'level' => 'medium'],

            // Phase 3: Additional security scanners
            'arachni' => ['label' => 'Arachni Scanner', 'level' => 'high'],
            'netsparker' => ['label' => 'Netsparker Scanner', 'level' => 'high'],
            'qualys' => ['label' => 'Qualys Scanner', 'level' => 'high'],
            'skipfish' => ['label' => 'Skipfish Scanner', 'level' => 'high'],
            'vega/' => ['label' => 'Vega Scanner', 'level' => 'high'],
            'wapiti' => ['label' => 'Wapiti Scanner', 'level' => 'high'],
            'joomscan' => ['label' => 'JoomScan Scanner', 'level' => 'high'],
            'droopescan' => ['label' => 'DroopeScan Scanner', 'level' => 'high'],
            'commix' => ['label' => 'Commix Tool', 'level' => 'high'],
            'xsstrike' => ['label' => 'XSStrike Tool', 'level' => 'high'],
            'dalfox' => ['label' => 'Dalfox XSS Scanner', 'level' => 'high'],
            'feroxbuster' => ['label' => 'FeroxBuster', 'level' => 'high'],
            'ffuf' => ['label' => 'FFUF Fuzzer', 'level' => 'high'],
            'httpx' => ['label' => 'HTTPX Scanner', 'level' => 'medium'],
            'subfinder' => ['label' => 'Subfinder Tool', 'level' => 'medium'],
            'katana' => ['label' => 'Katana Crawler', 'level' => 'medium'],
            'jaeles' => ['label' => 'Jaeles Scanner', 'level' => 'high'],
        ];
        }

        if (self::$cachedBots === null) {
            self::$cachedBots = [
            // Existing bots
            'masscan' => ['label' => 'MassScan Tool', 'level' => 'high'],
            'zgrab' => ['label' => 'ZGrab Scanner', 'level' => 'high'],
            'shodan' => ['label' => 'Shodan Bot', 'level' => 'medium'],
            'censys' => ['label' => 'Censys Bot', 'level' => 'medium'],
            'python-requests' => ['label' => 'Python Script', 'level' => 'low'],
            'curl/' => ['label' => 'cURL Command', 'level' => 'low'],
            'wget/' => ['label' => 'wget Command', 'level' => 'low'],
            'go-http-client' => ['label' => 'Go HTTP Client', 'level' => 'low'],

            // Phase 3: Aggressive/abusive crawlers
            'ahrefsbot' => ['label' => 'Ahrefs Bot', 'level' => 'low'],
            'semrushbot' => ['label' => 'SEMRush Bot', 'level' => 'low'],
            'mj12bot' => ['label' => 'Majestic Bot', 'level' => 'low'],
            'dotbot' => ['label' => 'DotBot Crawler', 'level' => 'low'],
            'petalbot' => ['label' => 'PetalBot Crawler', 'level' => 'low'],

            // Phase 3: AI scrapers
            'gptbot' => ['label' => 'GPTBot AI Scraper', 'level' => 'low'],
            'chatgpt-user' => ['label' => 'ChatGPT User Agent', 'level' => 'low'],
            'claudebot' => ['label' => 'ClaudeBot AI Scraper', 'level' => 'low'],
            'anthropic-ai' => ['label' => 'Anthropic AI Bot', 'level' => 'low'],
            'bytespider' => ['label' => 'ByteSpider Crawler', 'level' => 'low'],
            'cohere-ai' => ['label' => 'Cohere AI Bot', 'level' => 'low'],
            'ccbot' => ['label' => 'Common Crawl Bot', 'level' => 'low'],

            // Phase 3: Headless browsers / automation
            'headlesschrome' => ['label' => 'Headless Chrome', 'level' => 'medium'],
            'phantomjs' => ['label' => 'PhantomJS Browser', 'level' => 'medium'],
            'selenium' => ['label' => 'Selenium WebDriver', 'level' => 'medium'],
            'puppeteer' => ['label' => 'Puppeteer Automation', 'level' => 'medium'],
            'playwright' => ['label' => 'Playwright Automation', 'level' => 'medium'],
        ];
        }

        foreach (self::$cachedScanners as $pattern => $info) {
            if (str_contains($userAgentLower, $pattern)) {
                $threats[] = [$info['label'], $info['level'], 'user-agent'];
            }
        }

        foreach (self::$cachedBots as $pattern => $info) {
            if (str_contains($userAgentLower, $pattern)) {
                $threats[] = [$info['label'], $info['level'], 'user-agent'];
            }
        }

        if (empty($userAgent) || $userAgent === 'N/A' || $userAgent === '-') {
            $threats[] = ['Empty User Agent', 'low', 'user-agent'];
        }

        return $threats;
    }

    private function sendNotifications(string $ip, string $url, string $type, string $level, string $userAgent): void
    {
        try {
            $webhookUrl = config('threat-detection.notifications.slack_webhook');
            if (!$webhookUrl) {
                return;
            }

            $alert = new ThreatAlertSlack([
                'ip_address' => $ip,
                'url' => $url,
                'type' => $type,
                'threat_level' => $level,
                'action_taken' => 'logged',
                'user_agent' => $userAgent,
            ]);

            if (class_exists(\Illuminate\Notifications\Messages\SlackMessage::class)) {
                Notification::route('slack', $webhookUrl)->notify($alert);
            } else {
                \Illuminate\Support\Facades\Http::post($webhookUrl, $alert->toWebhookPayload());
            }
        } catch (\Throwable $e) {
            Log::error('Failed to send threat notification: ' . $e->getMessage());
        }
    }

    public function getIpStatistics(string $ip): array
    {
        $table = config('threat-detection.table_name', 'threat_logs');

        $totalThreats = DB::table($table)
            ->where('ip_address', $ip)
            ->count();

        $highThreats = DB::table($table)
            ->where('ip_address', $ip)
            ->where('threat_level', 'high')
            ->count();

        $firstSeen = DB::table($table)
            ->where('ip_address', $ip)
            ->min('created_at');

        $lastSeen = DB::table($table)
            ->where('ip_address', $ip)
            ->max('created_at');

        $threatTypes = DB::table($table)
            ->where('ip_address', $ip)
            ->select('type', DB::raw('COUNT(*) as count'))
            ->groupBy('type')
            ->orderByDesc('count')
            ->limit(5)
            ->get();

        return [
            'total_threats' => $totalThreats,
            'high_threats' => $highThreats,
            'first_seen' => $firstSeen,
            'last_seen' => $lastSeen,
            'top_threat_types' => $threatTypes,
        ];
    }

    public function detectCoordinatedAttacks(int $timeWindowMinutes = 15, int $minIpCount = 3): array
    {
        $table = config('threat-detection.table_name', 'threat_logs');
        $timeThreshold = now()->subMinutes($timeWindowMinutes);

        $coordinatedAttacks = DB::table($table)
            ->select(
                'url',
                DB::raw('COUNT(DISTINCT ip_address) as unique_ips'),
                DB::raw('COUNT(*) as total_attempts'),
                DB::raw('MIN(created_at) as first_attack'),
                DB::raw('MAX(created_at) as last_attack')
            )
            ->where('created_at', '>=', $timeThreshold)
            ->groupBy('url')
            ->havingRaw('COUNT(DISTINCT ip_address) >= ?', [$minIpCount])
            ->orderByDesc('unique_ips')
            ->limit(20)
            ->get();

        // Batch-fetch all attacking IPs in a single query to avoid N+1
        $urls = $coordinatedAttacks->pluck('url')->toArray();
        $ipsByUrl = [];
        if (!empty($urls)) {
            $allIps = DB::table($table)
                ->select('url', 'ip_address')
                ->whereIn('url', $urls)
                ->where('created_at', '>=', $timeThreshold)
                ->distinct()
                ->get();

            foreach ($allIps as $row) {
                $ipsByUrl[$row->url][] = $row->ip_address;
            }
        }

        return $coordinatedAttacks->map(function ($attack) use ($ipsByUrl) {
            return [
                'url' => $attack->url,
                'unique_ips' => $attack->unique_ips,
                'total_attempts' => $attack->total_attempts,
                'first_attack' => $attack->first_attack,
                'last_attack' => $attack->last_attack,
                'attacking_ips' => $ipsByUrl[$attack->url] ?? [],
                'duration_minutes' => round((strtotime($attack->last_attack) - strtotime($attack->first_attack)) / 60, 2),
            ];
        })->toArray();
    }

    public function detectAttackCampaigns(int $hoursBack = 24): array
    {
        $table = config('threat-detection.table_name', 'threat_logs');
        $timeThreshold = now()->subHours($hoursBack);

        $campaigns = DB::table($table)
            ->select(
                'type',
                DB::raw('COUNT(DISTINCT ip_address) as unique_ips'),
                DB::raw('COUNT(*) as total_threats'),
                DB::raw('MIN(created_at) as campaign_start'),
                DB::raw('MAX(created_at) as campaign_end')
            )
            ->where('created_at', '>=', $timeThreshold)
            ->groupBy('type')
            ->havingRaw('COUNT(DISTINCT ip_address) >= ?', [5])
            ->orderByDesc('unique_ips')
            ->limit(15)
            ->get();

        // Batch-fetch sample IPs for all campaigns in a single query
        $types = $campaigns->pluck('type')->toArray();
        $ipsByType = [];
        if (!empty($types)) {
            $allIps = DB::table($table)
                ->select('type', 'ip_address')
                ->whereIn('type', $types)
                ->where('created_at', '>=', $timeThreshold)
                ->distinct()
                ->get();

            foreach ($allIps as $row) {
                if (!isset($ipsByType[$row->type]) || count($ipsByType[$row->type]) < 10) {
                    $ipsByType[$row->type][] = $row->ip_address;
                }
            }
        }

        return $campaigns->map(function ($campaign) use ($ipsByType) {
            return [
                'threat_type' => $campaign->type,
                'unique_ips' => $campaign->unique_ips,
                'total_threats' => $campaign->total_threats,
                'campaign_start' => $campaign->campaign_start,
                'campaign_end' => $campaign->campaign_end,
                'duration_hours' => round((strtotime($campaign->campaign_end) - strtotime($campaign->campaign_start)) / 3600, 2),
                'sample_ips' => $ipsByType[$campaign->type] ?? [],
            ];
        })->toArray();
    }

    public function detectRapidAttacks(int $minutesBack = 5, int $minThreshold = 10): array
    {
        $table = config('threat-detection.table_name', 'threat_logs');
        $timeThreshold = now()->subMinutes($minutesBack);

        $rapidAttackers = DB::table($table)
            ->select(
                'ip_address',
                DB::raw('COUNT(*) as threat_count'),
                DB::raw('COUNT(DISTINCT type) as unique_threat_types'),
                DB::raw('MIN(created_at) as first_threat'),
                DB::raw('MAX(created_at) as last_threat')
            )
            ->where('created_at', '>=', $timeThreshold)
            ->groupBy('ip_address')
            ->havingRaw('COUNT(*) >= ?', [$minThreshold])
            ->orderByDesc('threat_count')
            ->limit(20)
            ->get();

        return $rapidAttackers->map(function ($attacker) {
            return [
                'ip_address' => $attacker->ip_address,
                'threat_count' => $attacker->threat_count,
                'unique_threat_types' => $attacker->unique_threat_types,
                'first_threat' => $attacker->first_threat,
                'last_threat' => $attacker->last_threat,
                'attacks_per_minute' => round($attacker->threat_count / max((strtotime($attacker->last_threat) - strtotime($attacker->first_threat)) / 60, 1), 2),
            ];
        })->toArray();
    }

    public function getCorrelationSummary(): array
    {
        return [
            'coordinated_attacks' => count($this->detectCoordinatedAttacks(15, 3)),
            'active_campaigns' => count($this->detectAttackCampaigns(24)),
            'rapid_attackers' => count($this->detectRapidAttacks(5, 10)),
        ];
    }
}
