<?php

namespace JayAnta\ThreatDetection\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Notification;
use JayAnta\ThreatDetection\Events\DdosThresholdExceeded;
use JayAnta\ThreatDetection\Events\ThreatDetected;
use JayAnta\ThreatDetection\Jobs\StoreThreatLog;
use JayAnta\ThreatDetection\Notifications\ThreatAlertSlack;
use Symfony\Component\HttpFoundation\IpUtils;

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

    /**
     * Whether the IP is on the operator whitelist (exact or CIDR).
     * Whitelisted clients are exempt from detection and from isBlocklisted().
     */
    public function isWhitelisted(string $ip): bool
    {
        return $this->ipMatches($ip, config('threat-detection.whitelisted_ips', []));
    }

    /**
     * Whether the IP is on the static operator denylist (exact or CIDR).
     *
     * The package never acts on this itself — it exposes the decision so
     * operators can enforce it in their own middleware (see the README
     * recipe). The whitelist wins on overlap.
     */
    public function isBlocklisted(string $ip): bool
    {
        if ($this->isWhitelisted($ip)) {
            return false;
        }

        return $this->ipMatches($ip, config('threat-detection.blocklisted_ips', []));
    }

    /**
     * Whether the IP matches any entry (exact or CIDR) in the given list.
     *
     * Entries are trimmed before matching: IpUtils::checkIp() treats an entry
     * with stray whitespace (" 1.2.3.4") as unparsable and silently never
     * matches it. The shipped config trims on parse, but an application
     * running a stale published copy of it would pass untrimmed entries here —
     * and a whitelist that silently stopped matching must not take effect.
     */
    private function ipMatches(string $ip, mixed $list): bool
    {
        $entries = array_filter(array_map(
            static fn($entry): string => is_string($entry) ? trim($entry) : '',
            (array) $list
        ), static fn(string $entry): bool => $entry !== '');

        return $ip !== '' && $entries !== [] && IpUtils::checkIp($ip, array_values($entries));
    }

    public function detectAndLogFromRequest(Request $request): void
    {
        $ip = $request->ip();
        $url = $request->fullUrl();
        // Route path only (never the query string) so api_route_filtering
        // cannot be toggled on/off by an attacker appending ?x=/api/ to the URL.
        $isApiRoute = str_contains('/' . trim($request->path(), '/') . '/', '/api/');
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
            // Keep the most suspicious context a label was seen in. Plain
            // assignment let a later low-weight segment (body, 1.0) erase the
            // score bonus earned by an earlier high-weight one (query, 1.5).
            $contextWeights[$match['label']] = max($contextWeights[$match['label']] ?? 0, $weight);
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
        $seenTypes = [];   // within-request dedup; cache mark deferred until after a successful write

        // Detection is finished; from here on we are deciding what to *keep*.
        // Mask the values of any sensitive pattern that fired, so the log does
        // not become a second cleartext copy of the data it just warned about.
        // The URL matters as much as the body — a PAN in a query string lands
        // in the url column otherwise.
        $sensitive = $this->sensitiveLabelsAmong($allThreats);
        $truncatedPayload = $this->redact(substr($payload, 0, 2000), $sensitive);
        $storedUrl = $this->redact($url, $sensitive);

        $now = now();
        $userId = Auth::id();

        foreach ($allThreats as [$label, $level, $sourceTag]) {
            if (
                config('threat-detection.api_route_filtering.enabled', true)
                && $isApiRoute
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

            // Skip if logged in a recent request (cross-request dedup) or already
            // queued for this request (within-request dedup). The 5-minute cache
            // mark is applied only after a successful write (see below), so a
            // failed insert does not silently mute this threat.
            if ($this->isRecentlyLogged($ip, $type) || isset($seenTypes[$type])) {
                continue;
            }
            $seenTypes[$type] = true;

            $logData = [
                'ip_address' => $ip,
                'url' => $storedUrl,
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
            $safeUrl = str_replace(["\n", "\r", "\t"], ' ', $storedUrl);
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
                        'url' => $storedUrl,
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

                // Job is queued (it retries on failure), so mark these as logged.
                $this->markTypesLogged($ip, array_keys($seenTypes));
            } else {
                // A failing insert throws here and is caught by the middleware;
                // in that case the types are NOT marked and will be retried.
                try {
                    DB::table(config('threat-detection.table_name', 'threat_logs'))->insert($batchLogData);
                } catch (\Throwable $e) {
                    $this->reportWriteFailure($e);
                    throw $e;
                }

                $this->markTypesLogged($ip, array_keys($seenTypes));

                if (!empty($notificationQueue)) {
                    $this->sendNotifications($ip, $storedUrl, $batchLogData[0]['type'], $batchLogData[0]['threat_level'], $userAgent);
                }
            }
        }
    }

    /**
     * Which of the labels that fired this request are marked as sensitive.
     *
     * @param array $threats [label, level, sourceTag] tuples
     * @return string[]
     */
    private function sensitiveLabelsAmong(array $threats): array
    {
        if (!config('threat-detection.redact.enabled', true)) {
            return [];
        }

        $sensitive = config('threat-detection.redact.labels', []);

        if (empty($sensitive) || empty($threats)) {
            return [];
        }

        return array_values(array_unique(array_intersect(array_column($threats, 0), $sensitive)));
    }

    /**
     * Mask the values matched by the given labels' patterns.
     *
     * Runs each label's own regex over the text and replaces what it matches.
     * That keeps the mask aligned with what the detector actually considers
     * sensitive: a label added to redact.labels by a user, with a custom
     * pattern behind it, is redacted on the same terms as a shipped one.
     *
     * Nothing is scanned here that has not already been detected — this runs
     * on at most a 2 KB payload and only when a sensitive label fired.
     */
    private function redact(string $text, array $sensitiveLabels): string
    {
        if ($sensitiveLabels === [] || $text === '') {
            return $text;
        }

        $mask = (string) config('threat-detection.redact.mask', '[REDACTED]');

        foreach ($this->regexesForLabels($sensitiveLabels) as $regex) {
            $masked = @preg_replace($regex, $mask, $text);

            // preg_replace returns null on failure (bad pattern, backtrack
            // limit). Keeping the unmasked text would defeat the point, so
            // treat a failure as "cannot prove this is clean" and drop it.
            if ($masked === null) {
                return $mask;
            }

            $text = $masked;
        }

        return $text;
    }

    /** @var array<string, string[]>|null label => regexes, built once */
    private static ?array $labelRegexMap = null;

    /**
     * @param string[] $labels
     * @return string[]
     */
    private function regexesForLabels(array $labels): array
    {
        if (self::$labelRegexMap === null) {
            self::$labelRegexMap = [];

            foreach ($this->getDefaultThreatPatterns() as $regex => $label) {
                self::$labelRegexMap[$label][] = $regex;
            }

            foreach ($this->getValidatedCustomPatterns() as $regex => $spec) {
                self::$labelRegexMap[$spec['label']][] = $regex;
            }
        }

        $out = [];

        foreach ($labels as $label) {
            foreach (self::$labelRegexMap[$label] ?? [] as $regex) {
                $out[] = $regex;
            }
        }

        return $out;
    }

    /** @var bool Whether a write failure has already been explained this process */
    private static bool $writeFailureWarned = false;

    /**
     * Explain a failed write once, in words an operator can act on.
     *
     * A failed insert is invisible from the outside: the middleware swallows it
     * to keep the detector passive, so the dashboard simply stays empty — which
     * reads as "no threats" rather than "nothing is being recorded". The most
     * common cause is an out-of-date table: confidence scoring (v1.2.0) and
     * false-positive tracking added columns in a separate migration, and an
     * app that upgraded the package without publishing and running it drops
     * every single detection while logging only a raw SQL error.
     */
    private function reportWriteFailure(\Throwable $e): void
    {
        if (self::$writeFailureWarned) {
            return;
        }
        self::$writeFailureWarned = true;

        $message = $e->getMessage();
        $table = config('threat-detection.table_name', 'threat_logs');

        if (preg_match('/(no column named|has no column|unknown column|column not found|no such column)/i', $message)) {
            Log::error(
                "Threat detection: the '{$table}' table is missing a column, so NO threats are being recorded. "
                . 'Run: php artisan vendor:publish --tag=threat-detection-migrations && php artisan migrate. '
                . "Original error: {$message}"
            );

            return;
        }

        Log::error(
            "Threat detection: writing to '{$table}' failed, so threats are not being recorded. "
            . "Original error: {$message}"
        );
    }

    private function markTypesLogged(string $ip, array $types): void
    {
        foreach ($types as $type) {
            $this->markAsLogged($ip, $type);
        }
    }

    /**
     * Build sanitized payload string from pre-built segments.
     * Reuses segments to avoid duplicate json_encode calls.
     *
     * 'path' and 'raw' are scanned but not logged here: the path is already in
     * the url column, and raw is the same bytes as query/body before decoding.
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

    /**
     * json_encode flags used for every segment.
     * JSON_INVALID_UTF8_SUBSTITUTE ensures a single malformed byte (e.g. an
     * appended %FF evasion attempt) does not make json_encode() return false
     * and silently blank the whole segment.
     */
    private const SEGMENT_JSON_FLAGS = JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE;

    private function buildPayloadSegments(Request $request): array
    {
        // 'raw' is built last and scanned last — see detectThreatPatternsWithContext().
        $segments = ['path' => '', 'query' => '', 'body' => '', 'headers' => '', 'raw' => ''];
        $safeFields = config('threat-detection.safe_fields', []);
        $safePaths  = config('threat-detection.safe_paths', []);

        // The request path itself. Roughly twenty shipped patterns are
        // path-shaped (/.env, /.git/, /actuator, vendor/phpunit/phpunit,
        // /users/<id>/delete); without this segment they could only ever match
        // when the path fragment appeared inside a query or body *value*.
        // safe_fields/safe_paths are field-oriented and do not apply here.
        //
        // Skipped when the probe tracker already flagged this request. Probe
        // tracking (v1.3.0, path list extended in v1.3.1) is the package's
        // first-class answer for known recon paths and reports a better label
        // at a higher severity; scanning the path again would just add a
        // second, weaker row for the same request. The pattern engine still
        // covers everything the fixed probe list misses — a nested
        // /deep/path/vendor/phpunit/... does not match the '/vendor/phpunit/*'
        // probe entry, but does match the pattern.
        if (!$request->attributes->get('threat-detection:probe')) {
            $segments['path'] = '/' . ltrim($request->path(), '/');
        }

        $queryData = $request->query();
        if (!empty($queryData)) {
            if (!empty($safeFields)) {
                $queryData = array_diff_key($queryData, array_flip($safeFields));
            }
            if (!empty($safePaths)) {
                $queryData = $this->stripSafePaths($queryData, $safePaths, '');
            }
            if (!empty($queryData)) {
                $segments['query'] = json_encode($queryData, self::SEGMENT_JSON_FLAGS);
            }
        }

        // Body: form fields for standard requests, decoded JSON for JSON requests.
        // $request->post() only returns the form-data bag, so JSON API bodies
        // (Content-Type: application/json) must be read via $request->json().
        if ($request->isJson()) {
            $postData = (array) $request->json()->all();
        } else {
            $postData = $request->post();
        }

        if (!empty($postData)) {
            // For multipart file uploads, only scan non-file form fields
            if (str_contains($request->header('Content-Type', ''), 'multipart/form-data')) {
                $fileKeys = array_keys($request->allFiles());
                $postData = array_diff_key($postData, array_flip($fileKeys));
            }
            if (!empty($safeFields)) {
                $postData = array_diff_key($postData, array_flip($safeFields));
            }
            if (!empty($safePaths)) {
                $postData = $this->stripSafePaths($postData, $safePaths, '');
            }
            if (!empty($postData)) {
                $segments['body'] = json_encode($postData, self::SEGMENT_JSON_FLAGS);
            }
        }

        // 'authorization' is excluded so ordinary authenticated traffic
        // (Bearer/JWT tokens) is not logged as a high-severity token threat.
        $headers = collect($request->headers->all())
            ->except(['cookie', 'authorization', 'x-xsrf-token', 'accept-language', 'accept-encoding', 'connection', 'host', 'referer', 'origin'])
            ->map(fn($v) => is_array($v) ? implode('; ', array_slice($v, 0, 2)) : $v);

        if ($headers->isNotEmpty()) {
            $segments['headers'] = json_encode($headers, self::SEGMENT_JSON_FLAGS);
        }

        $segments['raw'] = $this->buildRawSegment($request);

        return $segments;
    }

    /**
     * The request as it arrived, still percent-encoded.
     *
     * The evasion patterns for %00, %0d%0a and %0a can only fire here: every
     * other segment is built from $request->query()/post(), which Laravel has
     * already URL-decoded, so a single-encoded null byte reaches them as a raw
     * NUL and a single-encoded CRLF as real control characters — neither of
     * which the literal "%00"/"%0d%0a" patterns can match.
     */
    private function buildRawSegment(Request $request): string
    {
        $parts = [];

        $queryString = (string) ($request->server->get('QUERY_STRING') ?? '');
        if ($queryString === '') {
            $queryString = (string) ($request->getQueryString() ?? '');
        }
        if ($queryString !== '') {
            $parts[] = $queryString;
        }

        $body = $this->rawBody($request);
        if ($body !== '') {
            $parts[] = $body;
        }

        return implode("\n", $parts);
    }

    /**
     * Largest raw body worth buffering. Only the first 8 KB is ever scanned,
     * so this exists purely to bound memory: getContent() materialises the
     * whole stream, and for content types nothing else parses (text/plain,
     * application/xml, octet-stream) this would otherwise be the first and
     * only reader — turning a large upload into a memory spike on every
     * request. A body over the cap is skipped; its decoded counterpart is
     * still scanned by the query/body segments.
     */
    private const MAX_RAW_BODY_BYTES = 65536;

    private function rawBody(Request $request): string
    {
        // Multipart bodies are not readable from php://input, and file content
        // is not worth scanning byte-for-byte; skip them.
        if (str_contains($request->header('Content-Type', ''), 'multipart/form-data')) {
            return '';
        }

        // No declared length (chunked transfer) means no way to bound the read
        // before making it, so decline rather than gamble.
        $length = (int) ($request->server->get('CONTENT_LENGTH') ?: 0);

        if ($length <= 0 || $length > self::MAX_RAW_BODY_BYTES) {
            return '';
        }

        try {
            return substr((string) $request->getContent(), 0, 8000);
        } catch (\Throwable $e) {
            return '';
        }
    }

    /**
     * Recursively remove any entry whose dot-notation path matches a safe_paths
     * pattern (fnmatch — e.g. "search.query", "filters.*.value"). Path-aware
     * false-positive control: exempt one specific field's value in a nested
     * JSON/form body without exempting that key name everywhere it appears.
     */
    private function stripSafePaths(array $data, array $safePaths, string $prefix): array
    {
        $out = [];
        foreach ($data as $key => $value) {
            $path = $prefix === '' ? (string) $key : $prefix . '.' . $key;
            foreach ($safePaths as $sp) {
                if (fnmatch($sp, $path)) {
                    continue 2;
                }
            }
            if (is_array($value)) {
                $child = $this->stripSafePaths($value, $safePaths, $path);
                if (!empty($child)) {
                    $out[$key] = $child;
                }
            } else {
                $out[$key] = $value;
            }
        }
        return $out;
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
     * Quick pre-screen: does the payload contain any substring that a
     * keyword-based pattern could key off? A miss lets the caller skip the
     * keyword-mapped patterns; it does NOT skip format-shaped ones.
     *
     * Uses keyword-based checks (not structural chars like quotes/brackets)
     * to avoid false triggers on JSON payloads. Note that the list is
     * deliberately fail-open and includes single characters ('@', '%', '(',
     * '$'), so any body carrying an email address or a percent-encoded value
     * passes it — treat it as a cheap filter, not a tight one.
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
            'class.module', 'actuator', '%00', '%0d', '%0a', '%25', '%u',
            '%', '\\',
            'char(', 'phar:', 'expect:', 'input:', '172.', '192.168',
            'redirect=', 'url=http', 'next=http', 'goto=http',
            'phpunit', '#post_render', '#pre_render', 'order by', '{{', '{%', '<%',
            'ro0ab', 'aced0005', '__schema', '__type', 'wscript',
            'net user', 'net localgroup', '@', 'contains(', 'substring(',
            '2130706433', 'redirect":', 'url":"http', 'next":"http',
            'filesman', 'c99', 'r57', 'b374k',
            // PII field-name words, mirroring the 'pii' category. Without these
            // a clean body such as {"aadhaar":"..."} carries no suspect
            // substring at all and never reaches the regex stage.
            'aadhaar', 'aadhar', 'uidai', 'ifsc', 'account', 'acct', 'bank',
            'mobile', 'msisdn', 'beneficiary', 'kyc', '"pan"', 'pan_', 'pancard',
            // Cloud-metadata and DNS-rebinding hosts. The 'ssrf' category has
            // always listed these, but the pre-screen did not, so a body like
            // {"callback":"http://169.254.169.254/..."} was dropped before the
            // category check ever ran. Only field names containing 'url'/
            // 'redirect'/'next' happened to get through.
            '169.254', 'metadata.google', 'xip.io', 'nip.io', 'sslip.io', '::1',
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
            'get_current_user', 'allow_url_include', '<?php', '/bin/', 'chmod',
            'c99', 'r57', 'b374k', 'wso', 'c100', 'filesman'],
        'path' => ['../', '..\\', '/etc/', 'passwd', 'win.ini', 'file://', 'php://', 'zip://',
            'data://', 'glob://', 'phar://', 'expect://', 'input://',
            // Sensitive-file labels map here; without these keywords a probe of
            // /.env or /.git/config activated no category and never ran.
            '.env', '.git', '.ssh', '.aws', 'composer.', 'package.json', 'package-lock',
            'web.config', '.htaccess', 'config.json', 'config.php', 'phpinfo'],
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
        'cve' => ['() {', '(){', 'class.module', 'phpunit', 'actuator', '#post_render', '#lazy_builder', '#pre_render'],
        'redirect' => ['redirect=', 'redirect":', 'url=http', 'url":"http', 'next=http', 'next":"http',
            'return=http', 'goto=http', 'dest=http'],
        'misc' => ['coinhive', 'cryptonight', 'monero', '--inspect', 'xdebug', 'trace_id',
            'graphql', '__schema', '__type', 'swagger', 'api-docs'],
        'endpoint' => ['/admin', '/internal', '/legacy', '/backup', '/test', '/debug',
            '/console', '/user', '/users', '/v1/', '/v2/', '/v3/', 'limit='],
        // Field-name words that accompany real PII. Deliberately narrow: one
        // keyword activates the whole category, and the category contains bare
        // digit-run patterns, so a loose word here (a plain 'pan', which is a
        // substring of "company", "expand", "japan") would put every order id
        // and epoch timestamp back in front of them.
        'pii' => ['aadhaar', 'aadhar', 'uidai', 'ifsc', 'account', 'acct', 'bank',
            'mobile', 'phone', 'msisdn', 'beneficiary', 'kyc',
            '"pan"', 'pan_', 'pan-', 'pancard', 'pan card'],
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
     *
     * Uses direct full-label lookup. A label that is not in the map is
     * "format-shaped" rather than keyword-shaped — a card number, an Aadhaar
     * number or a user-defined reference code contains no attack keyword by
     * definition, so no keyword pre-check can decide whether to run it. Those
     * always run. Short-circuiting on an empty category set here would skip
     * them too, which silently disabled every user-defined custom pattern.
     */
    private function isPatternRelevant(string $label, array $relevantCategories): bool
    {
        $this->primeLabelCategoryMap();

        // Direct lookup — O(1), no ambiguity
        if (isset(self::$labelCategoryMap[$label])) {
            return isset($relevantCategories[self::$labelCategoryMap[$label]]);
        }

        // Unknown (format-shaped) pattern — always run it
        return true;
    }

    private function primeLabelCategoryMap(): void
    {
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
                'PHP Session Exposure' => 'token',
                'XDebug Session' => 'token', 'Trace ID Exposure' => 'misc',
                // Regional PII keys off 'pii', not 'token'. The old mapping was
                // the bug — 'token' keywords are credential words (bearer, csrf,
                // api_key) that a bare Aadhaar or account number never contains,
                // so these patterns almost never ran. They stay gated rather
                // than always-run because the loose ones are bare digit runs:
                // ungated, "Bank Account Number Detected" (9-18 digits, high
                // severity, no checksum) fires on every timestamp and order id.
                'Aadhaar Number Detected' => 'pii', 'PAN Number Detected' => 'pii',
                'Bank Account Number Detected' => 'pii', 'IFSC Code Detected' => 'pii',
                'Mobile Number Detected' => 'pii',
                // Scanner
                'Scanner Tool Detected' => 'scanner', 'Security Scanner Detected' => 'scanner',
                'Port Scanner' => 'scanner', 'Scripted Request' => 'scanner',
                // Deserialization
                'PHP Object Deserialization' => 'deser', 'Java Deserialization' => 'deser',
                'Java Serialization Magic Bytes' => 'deser',
                // Redirect
                'Open Redirect' => 'redirect',
                // NoSQL — keywords ($ne, $gt, $regex, $where) live in the 'injection' category
                'NoSQL $ne Injection' => 'injection', 'NoSQL $gt Injection' => 'injection',
                'NoSQL Regex Injection' => 'injection', 'NoSQL $where Injection' => 'injection',
                // GraphQL / Misc
                'GraphQL Introspection' => 'misc', 'GraphQL Type Introspection' => 'misc',
                'GraphQL Query Detected' => 'misc',
                'Crypto Mining Script' => 'misc', 'Node.js Debug Mode' => 'misc',
                // Sensitive files (custom)
                'Sensitive Config File Access' => 'path', 'Environment File Access' => 'path',
                'Composer File Access' => 'path', 'Package File Access' => 'path',
                'Git Directory Access Attempt' => 'path', 'SSH Directory Access Attempt' => 'path',
                'AWS Credentials Access' => 'path', 'Server Config Access' => 'path',
                // Endpoint probes (custom) — these are path-shaped, so they key
                // off the 'endpoint' category, not 'cve'. Mapping them to 'cve'
                // gated them behind keywords ('phpunit', 'actuator', '(){') that
                // a probe of /admin or /debug never contains.
                'Admin Path Access Attempt' => 'endpoint', 'Internal Endpoint Probe' => 'endpoint',
                'Legacy System Access' => 'endpoint', 'Backup Directory Probe' => 'endpoint',
                'Test Endpoint Probe' => 'endpoint', 'Debug Endpoint Probe' => 'endpoint',
                'Console Access Attempt' => 'endpoint',
                // API
                'API User Enumeration' => 'endpoint', 'API High Limit Request' => 'endpoint',
                'User Deletion Attempt' => 'endpoint', 'Admin ID Enumeration' => 'endpoint',
                // Command-line downloaders (custom)
                'Command Line Tool (curl)' => 'cmd', 'Command Line Tool (wget)' => 'cmd',
            ];
        }
    }

    /** @var bool|null Whether any pattern in play is format-shaped (unmapped label) */
    private static ?bool $hasAlwaysRunPatterns = null;

    /**
     * Whether any active pattern has an unmapped (format-shaped) label. When
     * none do, a segment that fails the keyword pre-screen can be skipped
     * outright, preserving the original fast path.
     */
    private function hasAlwaysRunPatterns(): bool
    {
        if (self::$hasAlwaysRunPatterns !== null) {
            return self::$hasAlwaysRunPatterns;
        }

        $this->primeLabelCategoryMap();

        foreach ($this->getDefaultThreatPatterns() as $label) {
            if (!isset(self::$labelCategoryMap[$label])) {
                return self::$hasAlwaysRunPatterns = true;
            }
        }

        foreach ($this->getValidatedCustomPatterns() as $spec) {
            if (!isset(self::$labelCategoryMap[$spec['label']])) {
                return self::$hasAlwaysRunPatterns = true;
            }
        }

        return self::$hasAlwaysRunPatterns = false;
    }

    /**
     * Drop every process-lifetime cache. Config changes (custom_patterns,
     * threat_levels, probe paths) are read once and memoised for speed, so a
     * runtime change — a test switching config, or a deploy under Octane —
     * needs this to take effect.
     */
    public static function flushCaches(): void
    {
        self::$defaultPatterns = null;
        self::$validatedCustomPatterns = null;
        self::$labelCategoryMap = null;
        self::$hasAlwaysRunPatterns = null;
        self::$evasionPatterns = null;
        self::$cachedScanners = null;
        self::$cachedBots = null;
        self::$threatLevelCache = [];
        self::$validatorWarned = [];
        self::$writeFailureWarned = false;
        self::$labelRegexMap = null;
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

        // Evasion labels already recorded this request. The 'raw' segment is the
        // same data in a different encoding, not an independent occurrence, so
        // it must not double-count a label the decoded segments already found.
        $seenEvasionLabels = [];

        foreach ($segments as $context => $segmentPayload) {
            if (empty($segmentPayload)) {
                continue;
            }

            // Cap payload to prevent ReDoS on large inputs
            $segmentPayload = substr($segmentPayload, 0, 8000);

            // The still-encoded request. Only the evasion patterns run here —
            // every other pattern would duplicate the decoded segments.
            if ($context === 'raw') {
                foreach ($this->getEvasionPatterns() as $regex => $label) {
                    if ($maxDetections > 0 && count($matches) >= $maxDetections) {
                        break 2;
                    }
                    if (isset($seenEvasionLabels[$label])) {
                        continue;
                    }
                    if ($this->patternMatches($regex, $segmentPayload, $label)) {
                        $seenEvasionLabels[$label] = true;
                        $matches[] = [
                            'label' => $label,
                            'threat_level' => 'high',
                            'source' => $source,
                            'context' => $context,
                        ];
                    }
                }
                continue;
            }

            // Keyword pre-screen. It gates the keyword-mapped patterns only:
            // format-shaped patterns (PII, custom rules with no category) must
            // still run, since a bare Aadhaar or card number contains no attack
            // keyword by definition. With no such pattern in play the segment
            // can be skipped outright, as before.
            //
            // The path is exempt: the pre-screen exists to keep large bodies off
            // the regex engine, and a URL is a few dozen bytes. Screening it
            // discarded the highest-signal segment there is — "/.env" and
            // "/admin" contain no keyword from the list, which is precisely why
            // they are worth matching.
            $prescreened = $context === 'path'
                || $this->hasSuspiciousCharacters($segmentPayload);

            if (!$prescreened && !$this->hasAlwaysRunPatterns()) {
                continue;
            }

            // Evasion patterns run on the un-normalized payload
            if ($prescreened) {
                foreach ($this->getEvasionPatterns() as $regex => $label) {
                    if ($maxDetections > 0 && count($matches) >= $maxDetections) {
                        break 2;
                    }
                    if ($this->patternMatches($regex, $segmentPayload, $label)) {
                        $seenEvasionLabels[$label] = true;
                        $matches[] = [
                            'label' => $label,
                            'threat_level' => 'high',
                            'source' => $source,
                            'context' => $context,
                        ];
                    }
                }
            }

            $normalizedPayload = $this->normalizeForDetection($segmentPayload);

            // Category-based lazy loading: only run regex for categories whose
            // keywords appear in the payload. Skips ~80% of patterns on average.
            $relevantCategories = $prescreened ? $this->getRelevantCategories($normalizedPayload) : [];

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

                if ($this->patternMatches($regex, $normalizedPayload, $label)) {
                    $matches[] = [
                        'label' => $label,
                        'threat_level' => $level,
                        'source' => $source,
                        'context' => $context,
                    ];
                }
            }

            foreach ($this->getValidatedCustomPatterns() as $regex => $spec) {
                if ($maxDetections > 0 && count($matches) >= $maxDetections) {
                    break 2;
                }

                $label = $spec['label'];

                if ($isAuthPath && in_array($label, $authExcludePatterns)) {
                    continue;
                }

                if ($spec['contexts'] !== null && !in_array($context, $spec['contexts'], true)) {
                    continue;
                }

                $level = $spec['level'] ?? $this->getThreatLevelByType($label);

                if ($mode === 'relaxed' && $level !== 'high') {
                    continue;
                }

                if (!$this->isPatternRelevant($label, $relevantCategories)) {
                    continue;
                }

                if ($this->patternMatches($regex, $normalizedPayload, $label, $spec['validator'])) {
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

    /** @var array<string, bool> Unknown validator names already warned about */
    private static array $validatorWarned = [];

    /**
     * Post-match validation. A pattern label mapped to a named validator in
     * config('threat-detection.pattern_validators') only counts as a match
     * when at least one matched value passes that validator — e.g. a 12-digit
     * run is only an Aadhaar number if its Verhoeff checksum holds. Labels
     * without a validator keep the plain boolean regex check, so this costs
     * nothing on the hot path unless explicitly configured.
     *
     * An array-form custom pattern can name its validator inline; that takes
     * precedence over the pattern_validators label map.
     */
    private function patternMatches(string $regex, string $payload, string $label, ?string $inlineValidator = null): bool
    {
        $validator = $inlineValidator ?? config('threat-detection.pattern_validators', [])[$label] ?? null;

        if ($validator === null) {
            return (bool) @preg_match($regex, $payload);
        }

        if (!PatternValidators::known($validator)) {
            // Fail open on a typo — a misconfigured validator must never
            // silently disable a detection pattern.
            if (!isset(self::$validatorWarned[$validator])) {
                Log::warning("Threat detection: unknown pattern validator '{$validator}' for '{$label}'; matches are counted unvalidated.");
                self::$validatorWarned[$validator] = true;
            }

            return (bool) @preg_match($regex, $payload);
        }

        if (!@preg_match_all($regex, $payload, $found)) {
            return false;
        }

        foreach ($found[0] as $value) {
            if (PatternValidators::passes($validator, $value)) {
                return true;
            }
        }

        return false;
    }

    private function isRecentlyLogged(string $ip, string $type): bool
    {
        return Cache::has("threat_logged:{$ip}:{$type}");
    }

    private function markAsLogged(string $ip, string $type): void
    {
        Cache::put("threat_logged:{$ip}:{$type}", true, now()->addMinutes(5));
    }

    /**
     * The IP's request count in the current DDoS window — a read-only peek at
     * the counter the detection middleware maintains, so it never inflates
     * the count it reports. Counts only requests that reached detection
     * (skip_paths / whitelisted / disabled requests are never counted), and
     * stays 0 on cache drivers where DDoS detection is disabled.
     */
    public function ddosRequestCount(string $ip): int
    {
        try {
            return (int) Cache::get("ddos:$ip", 0);
        } catch (\Throwable $e) {
            return 0;
        }
    }

    /**
     * Whether the IP is over the configured DDoS threshold right now.
     *
     * Read-only counterpart of the internal flood check, for operators who
     * want to refuse over-threshold clients (e.g. a 429 with Retry-After)
     * from their own middleware — the package itself never refuses.
     */
    public function isDdosThresholdExceeded(string $ip): bool
    {
        return $this->ddosRequestCount($ip) > $this->ddosThreshold;
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

        // Mark only after the write succeeds. v1.3.1 made this change for the
        // main detection path but not for this one, so a failed DDoS insert
        // still muted the flood for five minutes.
        try {
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
        } catch (\Throwable $e) {
            $this->reportWriteFailure($e);
            throw $e;
        }

        $this->markAsLogged($ip, $type);

        // Dispatched after the write, not before it. Same throttle as the log
        // row, so a flood notifies listeners once per window rather than once
        // per request — and a listener never fires for a threat that failed to
        // record, which the pre-rebase ordering allowed.
        DdosThresholdExceeded::dispatch(
            $ip,
            $this->ddosRequestCount($ip),
            $this->ddosThreshold,
            $this->ddosWindowSeconds
        );

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
            // (?<!\d) on the numeric hosts prevents matching 0.0.0.0 / 127.0.0.1
            // inside longer number runs such as a Chrome UA "Chrome/120.0.0.0".
            '/(?:localhost|::1|(?<!\d)127\.0\.0\.1|(?<!\d)0\.0\.0\.0)(?::\d+)?\b/i' => 'Localhost SSRF',

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
     * Segment names a custom pattern's 'contexts' list may name. 'raw' is not
     * offered: only the built-in evasion patterns scan that segment.
     */
    private const PATTERN_CONTEXTS = ['path', 'query', 'body', 'headers'];

    /**
     * Returns custom patterns that have been validated once per process
     * lifecycle, normalized to a spec array. Invalid patterns are logged and
     * skipped permanently.
     *
     * Two config formats are accepted per pattern:
     *
     *   '/regex/i' => 'My Label'                       // simple
     *   '/regex/i' => [                                // full control
     *       'label'     => 'My Label',                 // required
     *       'level'     => 'high',                     // low|medium|high
     *       'contexts'  => ['query', 'body'],          // default: all segments
     *       'validator' => 'luhn',                     // post-match checksum
     *   ]
     *
     * Malformed options fail open (the pattern still scans, unrestricted)
     * with a warning — a config mistake must never silently disable or
     * narrow a detection.
     *
     * @return array<string, array{label: string, level: ?string, contexts: ?array, validator: ?string}>
     */
    private function getValidatedCustomPatterns(): array
    {
        if (self::$validatedCustomPatterns !== null) {
            return self::$validatedCustomPatterns;
        }

        self::$validatedCustomPatterns = [];
        foreach (config('threat-detection.custom_patterns', []) as $regex => $entry) {
            if (@preg_match($regex, '') === false) {
                Log::warning("Threat detection: invalid custom pattern skipped: {$regex}");
                continue;
            }

            if (is_string($entry)) {
                $entry = ['label' => $entry];
            }

            if (!is_array($entry) || !is_string($entry['label'] ?? null) || $entry['label'] === '') {
                Log::warning("Threat detection: custom pattern without a label skipped: {$regex}");
                continue;
            }

            $level = $entry['level'] ?? null;
            if ($level !== null && !in_array($level, ['low', 'medium', 'high'], true)) {
                Log::warning("Threat detection: custom pattern '{$entry['label']}' has unknown level '{$level}'; deriving from threat_levels keywords instead.");
                $level = null;
            }

            $contexts = null;
            if (is_array($entry['contexts'] ?? null) && $entry['contexts'] !== []) {
                $contexts = array_values(array_intersect($entry['contexts'], self::PATTERN_CONTEXTS));
                if ($unknown = array_diff($entry['contexts'], self::PATTERN_CONTEXTS)) {
                    Log::warning("Threat detection: custom pattern '{$entry['label']}' names unknown contexts (" . implode(', ', $unknown) . '); valid contexts are ' . implode('|', self::PATTERN_CONTEXTS) . '.');
                }
                if ($contexts === []) {
                    $contexts = null;
                }
            }

            $validator = is_string($entry['validator'] ?? null) ? $entry['validator'] : null;

            self::$validatedCustomPatterns[$regex] = [
                'label' => $entry['label'],
                'level' => $level,
                'contexts' => $contexts,
                'validator' => $validator,
            ];
        }

        return self::$validatedCustomPatterns;
    }

    public function detectThreatPatterns(string $payload, string $source = 'default', bool $isAuthPath = false): array
    {
        $matches = [];

        foreach ($this->getDefaultThreatPatterns() as $regex => $label) {
            if ($this->patternMatches($regex, $payload, $label)) {
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

        // Context restrictions don't apply here — this method scans a single
        // opaque payload, so there is no segment to restrict by.
        foreach ($this->getValidatedCustomPatterns() as $regex => $spec) {
            $label = $spec['label'];
            if ($this->patternMatches($regex, $payload, $label, $spec['validator'])) {
                if ($isAuthPath && in_array($label, $authExcludePatterns)) {
                    continue;
                }

                $matches[] = [$label, $spec['level'] ?? $this->getThreatLevelByType($label), 'custom'];
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
            // 'owasp zap'/'zaproxy' rather than bare 'zap' — avoids matching
            // legitimate integration UAs such as "Zapier".
            'owasp zap' => ['label' => 'OWASP ZAP', 'level' => 'medium'],
            'zaproxy' => ['label' => 'OWASP ZAP', 'level' => 'medium'],
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
