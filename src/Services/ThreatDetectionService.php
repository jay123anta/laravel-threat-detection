<?php

namespace JayAnta\ThreatDetection\Services;

use Illuminate\Contracts\Bus\Dispatcher as BusDispatcher;
use Illuminate\Http\Request;
use Illuminate\Notifications\Messages\SlackMessage;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Notification;
use JayAnta\ThreatDetection\Events\DdosThresholdExceeded;
use JayAnta\ThreatDetection\Events\ThreatDetected;
use JayAnta\ThreatDetection\Jobs\StoreThreatLog;
use JayAnta\ThreatDetection\Notifications\ThreatAlertSlack;
use JayAnta\ThreatDetection\Support\LogsQuietly;
use Symfony\Component\HttpFoundation\IpUtils;

class ThreatDetectionService
{
    use LogsQuietly;

    protected int $ddosThreshold;

    protected int $ddosWindowSeconds;

    protected ConfidenceScorer $confidenceScorer;

    protected ExclusionRuleService $exclusionRuleService;

    protected ThreatCorrelationService $correlation;

    protected ActorSignalRecorder $actorSignals;

    public function __construct(
        ?ConfidenceScorer $confidenceScorer = null,
        ?ExclusionRuleService $exclusionRuleService = null,
        ?ThreatCorrelationService $correlation = null,
        ?ActorSignalRecorder $actorSignals = null
    ) {
        // Both have a floor of 1. A threshold of 0 or below makes every single
        // request a flood; a window of 0 or below expires the counter as fast
        // as it is written, so nothing is ever counted. Neither is a setting
        // anyone means, and both are silent when they happen.
        $this->ddosThreshold = self::intSetting('threat-detection.ddos.threshold', 100, 1);
        $this->ddosWindowSeconds = self::intSetting('threat-detection.ddos.window', 60, 1);
        $this->confidenceScorer = $confidenceScorer ?? new ConfidenceScorer;
        $this->exclusionRuleService = $exclusionRuleService ?? new ExclusionRuleService;
        $this->correlation = $correlation ?? new ThreatCorrelationService;
        $this->actorSignals = $actorSignals ?? new ActorSignalRecorder;
    }

    /** @var array<string, bool> Settings already reported as unusable */
    private static array $badSettingWarned = [];

    /**
     * An integer setting, or the default if the configured value is not a
     * number.
     *
     * These land in typed int properties, and this constructor runs while the
     * container is building the middleware — before handle(), so the
     * try/catch that keeps the detector passive is not yet on the stack. A
     * plain assignment therefore turned a mistyped .env value into a
     * TypeError on *every* request to the application.
     *
     * Values from .env arrive as strings, so "300" has to keep working and
     * only genuine nonsense ("1k", "300/min", a stray quote) may fall back.
     * Falling back is announced once per process: a threshold that silently
     * reverted to the default would be its own kind of surprise.
     */
    private static function intSetting(string $key, int $default, ?int $minimum = null): int
    {
        $value = config($key, $default);

        if (!is_numeric($value)) {
            self::warnAboutSetting(
                $key,
                "config('{$key}') is not a number, so the default of {$default} is being used. "
                . 'Check the matching THREAT_DETECTION_* value in your .env.'
            );

            return $default;
        }

        $value = (int) $value;

        if ($minimum !== null && $value < $minimum) {
            self::warnAboutSetting(
                $key,
                "config('{$key}') is {$value}, which is below the minimum of {$minimum}; "
                . "using {$minimum} instead."
            );

            return $minimum;
        }

        return $value;
    }

    private static function warnAboutSetting(string $key, string $message): void
    {
        if (isset(self::$badSettingWarned[$key])) {
            return;
        }

        self::$badSettingWarned[$key] = true;
        self::logQuietly('warning', 'Threat detection: ' . $message);
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
            static fn ($entry): string => is_string($entry) ? trim($entry) : '',
            (array) $list
        ), static fn (string $entry): bool => $entry !== '');

        return $ip !== '' && $entries !== [] && IpUtils::checkIp($ip, array_values($entries));
    }

    public function detectAndLogFromRequest(Request $request): void
    {
        $ip = $request->ip();
        $url = $this->storable($request->fullUrl());
        // Route path only (never the query string) so api_route_filtering
        // cannot be toggled on/off by an attacker appending ?x=/api/ to the URL.
        $isApiRoute = str_contains('/' . trim($request->path(), '/') . '/', '/api/');
        $userAgent = $this->storable($request->userAgent() ?? 'N/A');
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

        /*
         * The floor a detection must clear to be kept, per mode.
         *
         * 'relaxed' was 40, which no single detection could ever reach. In
         * relaxed mode only high-severity patterns run at all, and
         * ConfidenceScorer subtracts 10 from every score, so one match scores
         *
         *     20 base + 15 high-severity + 10 context - 10 relaxed = 35
         *
         * and just 25 from a request body, where the context weight is 1.0 and
         * earns no bonus. Both sat below 40, so relaxed silently discarded
         * every attack that tripped exactly one pattern unless the client also
         * carried an attack-tool user agent (+25) — that is, unless the
         * attacker announced themselves. In practice it was a two-signature
         * minimum, offered to operators as "only high-severity patterns
         * trigger".
         *
         * 25 is the lowest score a lone high-severity match can produce, so
         * the floor now admits exactly what the mode says it admits. Relaxed
         * is still much stricter than balanced: its severity filter, not its
         * confidence floor, is what does the work.
         */
        /*
         * Recorded here, above the confidence floor and above the five-minute
         * dedup, because both of those gates exist to keep threat_logs small
         * and both destroy the evidence of an actor iterating on a payload.
         *
         * A request that matched nothing reaches this with an empty array and
         * writes nothing, so clean traffic is untouched. Off by default.
         */
        $this->actorSignals->record((string) $ip, $contextMatches);

        $modeMinConfidence = match ($mode) {
            'strict' => 0,
            'relaxed' => 25,
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
        //
        // Two independent passes, because they answer different questions.
        //
        // redact() masks the values matched by sensitive patterns that fired,
        // so the log does not become a second cleartext copy of the data it
        // just warned about.
        //
        // redactSensitiveFields() masks anything sitting under a credential
        // field name, whether or not a pattern noticed it. That distinction is
        // the whole point: the credential patterns are written for the wire
        // form (password=…), and every segment is json_encoded before matching
        // ("password":"…"), so the closing quote before the separator meant
        // they never fired on an ordinary login form — and redaction keyed on
        // them therefore never ran. Every password posted to a login route
        // during an attack was stored in cleartext for the whole retention
        // period.
        //
        // The URL matters as much as the body: a credential or a PAN in a
        // query string lands in the url column otherwise.
        $sensitive = $this->sensitiveLabelsAmong($allThreats);
        $truncatedPayload = $this->redactSensitiveFields(
            $this->redact(substr($payload, 0, 2000), $sensitive)
        );
        $storedUrl = $this->bounded($this->redactSensitiveFields($this->redact($url, $sensitive)));
        $storedUserAgent = $this->bounded($userAgent);

        $now = now();
        $userId = $this->signedInUserId();

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
                'user_agent' => $storedUserAgent,
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
            self::logQuietly('warning', "[{$level}] Threat Detected: [{$safeType}] from {$ip} ({$safeUrl}) [confidence: {$confidence['score']}%]");

            // Dispatch event so users can hook in with custom listeners
            $this->announce(new ThreatDetected($logData, $ip, $level));
        }

        // Batch write: one INSERT or one queue job for all threats in this request
        if (!empty($batchLogData)) {
            $queued = false;

            if (config('threat-detection.queue.enabled', false)) {
                // The webhook URL is a credential and is not put in the job:
                // it would be written to the queue store, and to failed_jobs
                // when a job fails. The job reads it from config when it runs.
                $job = new StoreThreatLog($batchLogData, !empty($notificationQueue) ? [
                    'alert_data' => [
                        'ip_address' => $ip,
                        'url' => $storedUrl,
                        'type' => $batchLogData[0]['type'],
                        'threat_level' => $batchLogData[0]['threat_level'],
                        'action_taken' => 'logged',
                        'user_agent' => $storedUserAgent,
                    ],
                ] : null);

                $connection = config('threat-detection.queue.connection');
                $queue = config('threat-detection.queue.queue', 'default');

                if ($connection) {
                    $job->onConnection($connection);
                }
                $job->onQueue($queue);

                $queued = $this->pushToQueue($job);

                // Job is queued (it retries on failure), so mark these as logged.
                if ($queued) {
                    $this->markTypesLogged($ip, array_keys($seenTypes));
                }
            }

            // Written here without a queue, and when the queue could not take
            // the job: the row went nowhere else, so a failed push used to
            // lose the detection outright.
            if (!$queued) {
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
                    $this->sendNotifications($ip, $storedUrl, $batchLogData[0]['type'], $batchLogData[0]['threat_level'], $storedUserAgent);
                }
            }
        }
    }

    /**
     * Dispatch one of the package's events, isolated from its listeners.
     *
     * Listeners are the application's code. ThreatDetected goes out before
     * the batch is written and DdosThresholdExceeded before pattern
     * detection runs, so a listener that threw — its own bug, its own
     * dependency down — used to take the batch, or the request's patterns,
     * with it. It is logged instead, every time, as the application's error.
     */
    private function announce(object $event): void
    {
        try {
            event($event);
        } catch (\Throwable $e) {
            self::logQuietly('error', 'Threat detection: a listener for ' . class_basename($event) . ' failed, and the detection was '
                . 'recorded without it: ' . $this->storable($e->getMessage()));
        }
    }

    /**
     * Who is signed in, or null when that cannot be found out.
     *
     * Asked once per detecting request, and it runs the application's guard
     * — its user provider, its database. It is metadata on the row; a guard
     * that throws must not cost the row itself.
     */
    private function signedInUserId(): int|string|null
    {
        try {
            return Auth::id();
        } catch (\Throwable) {
            return null;
        }
    }

    private static bool $queueFailureWarned = false;

    /**
     * Hand the write to the queue, or report that it could not be.
     *
     * Through the bus dispatcher rather than dispatch(), whose PendingDispatch
     * pushes from its destructor — outside any try around the call.
     */
    private function pushToQueue(StoreThreatLog $job): bool
    {
        try {
            app(BusDispatcher::class)->dispatch($job);

            return true;
        } catch (\Throwable $e) {
            if (!self::$queueFailureWarned) {
                self::$queueFailureWarned = true;
                self::logQuietly('warning', 'Threat detection: the queue cannot take threat writes, so they are written directly '
                    . 'until it can: ' . $this->storable($e->getMessage()));
            }

            return false;
        }
    }

    /**
     * Which of the labels that fired this request are marked as sensitive.
     *
     * @param  array  $threats  [label, level, sourceTag] tuples
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

    /** @var string|null Alternation of configured credential field names */
    private static ?string $sensitiveFieldAlternation = null;

    /**
     * Mask credential values that appear in *string* form: a query string in
     * the url column, or a credential embedded inside another field's value
     * (a "next=/login?password=…" redirect target, say).
     *
     * Structured data is handled by redactArray() before it is ever encoded;
     * this is the pass for text that was never an array to begin with.
     *
     * Only the value is replaced — the field name stays, so an operator can
     * still see that a credential was present and where.
     *
     * A listed name also covers a longer name ending in it — `partner_api_key`,
     * `vault_token` — through one optional run of at most 64 of the name's own
     * characters. There is no nested quantifier and no alternation inside a
     * repetition, and the run is bounded because an unbounded one backtracks
     * once per character: a parameter name a million characters long would
     * reach pcre.backtrack_limit. That matters, because redaction fails closed
     * and a regex that gave up would blank the entire row.
     *
     * A name may also sit inside brackets, as a nested query parameter's does.
     * Symfony normalises `user[password]=…` to `user%5Bpassword%5D=…`, and the
     * `B` of `%5B` read as part of a longer name, so the value was kept in
     * cleartext. The lookbehinds are fixed-length and add no repetition.
     */
    private function redactSensitiveFields(string $text): string
    {
        if ($text === '' || !config('threat-detection.redact.enabled', true)) {
            return $text;
        }

        $alternation = $this->sensitiveFieldAlternation();

        if ($alternation === '') {
            return $text;
        }

        $mask = (string) config('threat-detection.redact.mask', '[REDACTED]');

        // password=hunter2 -> password=[REDACTED]
        // The value runs to the next separator; a percent-encoded '&' inside
        // the value is not a separator, which is why '%26' does not end it.
        return $this->replaceOrMask(
            '/(?:(?<=%5B)|(?<![A-Za-z0-9_-]))((?:[A-Za-z0-9_-]{0,64}[-_])?(?:' . $alternation . '))((?:%5D|\])?=)[^&\s"\\\\]*/i',
            fn (array $m): string => $m[1] . $m[2] . $mask,
            $text,
            $mask
        );
    }

    /**
     * preg_replace_callback that treats failure as "cannot prove this is
     * clean" and masks the whole text, matching redact()'s stance. Returning
     * the original on a backtrack-limit failure would leave exactly the
     * cleartext this exists to remove.
     */
    private function replaceOrMask(string $regex, callable $callback, string $text, string $mask): string
    {
        $result = @preg_replace_callback($regex, $callback, $text);

        return $result === null ? $mask : $result;
    }

    /**
     * The field names masked when config does not say otherwise.
     *
     * Duplicated from config/threat-detection.php on purpose. mergeConfigFrom()
     * merges top-level keys only, so an application that published its config
     * before this list existed keeps its own 'redact' block wholesale and would
     * never receive the new key — which would leave exactly the installs that
     * have been storing cleartext passwords still storing them, silently,
     * after upgrading. A security default has to live in code, where an
     * upgrade actually delivers it; config then overrides rather than enables.
     *
     * An explicit empty array in config still switches it off, because that is
     * a deliberate statement rather than an absent key.
     */
    private const DEFAULT_SENSITIVE_FIELDS = [
        'password', 'password_confirmation', 'current_password', 'new_password',
        'old_password', 'passwd', 'pwd',
        'secret', 'client_secret', 'api_key', 'apikey', 'api_secret', 'private_key',
        'token', '_token', 'access_token', 'refresh_token', 'id_token', 'auth_token',
        'csrf_token', 'xsrf_token', 'session_id', 'sessionid', 'phpsessid', 'authorization',
        'card_number', 'credit_card', 'cvv', 'cvc', 'pin', 'otp',
    ];

    /** @var array<string, true>|null normalised field name => true */
    private static ?array $sensitiveFieldNames = null;

    /**
     * The configured sensitive field names, normalised and indexed for O(1)
     * lookup.
     *
     * @return array<string, true>
     */
    private function sensitiveFieldNames(): array
    {
        if (self::$sensitiveFieldNames !== null) {
            return self::$sensitiveFieldNames;
        }

        if (!config('threat-detection.redact.enabled', true)) {
            return self::$sensitiveFieldNames = [];
        }

        $configured = config('threat-detection.redact.fields');
        $fields = is_array($configured) ? $configured : self::DEFAULT_SENSITIVE_FIELDS;

        $names = [];

        foreach ($fields as $field) {
            if (!is_string($field) || trim($field) === '') {
                continue;
            }
            $names[$this->normaliseFieldName($field)] = true;
        }

        return self::$sensitiveFieldNames = $names;
    }

    private function sensitiveFieldAlternation(): string
    {
        if (self::$sensitiveFieldAlternation !== null) {
            return self::$sensitiveFieldAlternation;
        }

        $names = array_keys($this->sensitiveFieldNames());

        // Longest first, so 'password_confirmation' is matched whole rather
        // than as 'password' followed by a stray suffix.
        usort($names, static fn ($a, $b) => strlen($b) <=> strlen($a));

        // Each normalised name is expanded back into the spellings it came
        // from: either separator, and an optional 'x-' prefix, so a query
        // string carrying x-api-key= is masked as readily as api_key=.
        $expanded = array_map(
            static fn (string $name): string => '(?:x[-_])?' . implode(
                '[-_]',
                array_map(static fn (string $part): string => preg_quote($part, '/'), explode('_', $name))
            ),
            $names
        );

        return self::$sensitiveFieldAlternation = implode('|', $expanded);
    }

    /** @var array<string, string[]>|null label => regexes, built once */
    private static ?array $labelRegexMap = null;

    /**
     * @param  string[]  $labels
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

        // A query exception quotes its bound values, and those are request
        // data. Unescaped, they would put an attacker's control sequences
        // into laravel.log for whoever tails it.
        $message = $this->storable($e->getMessage());
        $table = config('threat-detection.table_name', 'threat_logs');

        if (preg_match('/(no column named|has no column|unknown column|column not found|no such column)/i', $message)) {
            self::logQuietly('error',
                "Threat detection: the '{$table}' table is missing a column, so NO threats are being recorded. "
                . 'Run: php artisan vendor:publish --tag=threat-detection-migrations && php artisan migrate. '
                . "Original error: {$message}"
            );

            return;
        }

        self::logQuietly('error',
            "Threat detection: writing to '{$table}' failed, so threats are not being recorded. "
            . "Original error: {$message}"
        );
    }

    /**
     * A value off the wire, made safe to store and to read later.
     *
     * Two separate problems, both in fields this package stores as sent:
     *
     * **Bytes that are not UTF-8.** A strict MySQL connection — Laravel's
     * default — and PostgreSQL both reject them for a text column, and every
     * detection in a request is written in one batched INSERT. So a single
     * \xFF in the User-Agent failed the whole statement, and the attack in the
     * same request was never logged: a one-byte bypass, invisible on the
     * SQLite the test suite ran on. They are replaced, not dropped, so the
     * row still shows that something was there.
     *
     * **Control characters.** The row is read later by a human — in a
     * terminal, a log tail, a pager — and an escape sequence stored raw can
     * repaint what they see (the class behind CVE-2025-55193). C0 controls,
     * DEL and the C1 range, which some terminals honour as escape
     * introducers, become visible `\xNN` / `\uNNNN` text. Tab is left alone.
     *
     * **Bidirectional overrides.** U+202A–202E and U+2066–2069 reorder how
     * the text around them is displayed — the "Trojan Source" class — so a
     * stored URL could read differently from what it is. They get the same
     * visible `\uNNNN` treatment. Right-to-left *letters* are untouched; only
     * the invisible controls that force an order are.
     *
     * Everything else is untouched, so ordinary traffic is stored exactly as
     * before.
     */
    private function storable(string $value): string
    {
        if (!mb_check_encoding($value, 'UTF-8')) {
            $value = mb_scrub($value, 'UTF-8');
        }

        return preg_replace_callback(
            '/[\x00-\x08\x0A-\x1F\x7F]|\xC2[\x80-\x9F]|\xE2\x80[\xAA-\xAE]|\xE2\x81[\xA6-\xA9]/',
            fn (array $m) => strlen($m[0]) === 1
                ? sprintf('\x%02X', ord($m[0]))
                : sprintf('\u%04X', mb_ord($m[0], 'UTF-8')),
            $value
        ) ?? $value;
    }

    /**
     * The most of a URL or User-Agent that is stored, in bytes.
     *
     * Both columns are TEXT: 65,535 bytes on MySQL, where a strict connection
     * rejects anything longer — and it rejects the whole INSERT, which carries
     * every detection in the request. Header size is the web server's limit,
     * not this package's, and escaping grows a control byte to four
     * characters, so the stored copy is bounded here. 8 KB is what nginx and
     * Apache accept by default, so ordinary traffic is never cut.
     */
    private const MAX_STORED_BYTES = 8192;

    private const TRUNCATION_MARK = '…[truncated]';

    /**
     * The stored copy of a value, cut on a character boundary and marked when
     * cut. Detection has already read the whole value; only what is written
     * is bounded.
     */
    private function bounded(string $value): string
    {
        if (strlen($value) <= self::MAX_STORED_BYTES) {
            return $value;
        }

        return mb_strcut($value, 0, self::MAX_STORED_BYTES, 'UTF-8') . self::TRUNCATION_MARK;
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

        foreach (['query' => 'QUERY', 'body' => 'BODY', 'headers' => 'HEADERS'] as $segment => $label) {
            if (empty($segments[$segment])) {
                continue;
            }

            // Encode a masked copy of the structured data rather than the
            // segment the detector scanned. Detection has already run against
            // the unmasked version, so nothing is lost by storing less.
            //
            // Re-encoding is skipped entirely when nothing matched, which is
            // the overwhelmingly common case — most requests carry no
            // credential field at all, and paying for a second json_encode of
            // every segment on every request to cover the few that do is not a
            // trade worth making.
            $rendered = false;

            if (isset($this->segmentData[$segment])) {
                $masked = $this->redactArray($this->segmentData[$segment], $changed);

                if ($changed) {
                    $rendered = json_encode($masked, self::SEGMENT_JSON_FLAGS);
                }
            }

            // json_encode can still fail on input no flag can rescue; fall back
            // to the already-built segment rather than dropping the entry.
            $data[] = $label . ': ' . ($rendered !== false ? $rendered : $segments[$segment]);
        }

        return implode("\n", $data);
    }

    /**
     * Replace the value of any key whose name is configured as sensitive, at
     * any depth and whatever its type.
     *
     * Key comparison is exact against a normalised name, so nothing is matched
     * by accident: 'password' does not match 'password_hint' unless that name
     * is listed too. Normalisation folds case, treats '-' and '_' as the same
     * separator and ignores a leading 'x-', which is what makes the header
     * spellings ('X-Api-Key', 'x-auth-token') resolve to the same entry as the
     * body spellings ('api_key', 'auth_token').
     *
     * @param  array<mixed>  $data
     * @param  bool|null  $changed  set to true when anything was actually masked
     * @return array<mixed>
     */
    private function redactArray(array $data, ?bool &$changed = null): array
    {
        $changed ??= false;
        $sensitive = $this->sensitiveFieldNames();

        if ($sensitive === []) {
            return $data;
        }

        $mask = (string) config('threat-detection.redact.mask', '[REDACTED]');
        $out = [];

        foreach ($data as $key => $value) {
            if ($this->isSensitiveName($this->normaliseFieldName((string) $key), $sensitive)) {
                $out[$key] = $mask;
                $changed = true;

                continue;
            }

            $out[$key] = is_array($value) ? $this->redactArray($value, $changed) : $value;
        }

        return $out;
    }

    /**
     * A listed name, or a longer one ending in `_<listed>`.
     *
     * Exact matching let a credential through under any prefix: `api_key` was
     * masked and `partner_api_key` — `X-Partner-Api-Key` as a header — was
     * not, nor `vault_token`, `webhook_secret` or `proxy_authorization`. A
     * name that only *starts* with a listed word, such as `password_hint`,
     * is still not a match.
     *
     * @param  array<string, true>  $sensitive
     */
    private function isSensitiveName(string $name, array $sensitive): bool
    {
        if (isset($sensitive[$name])) {
            return true;
        }

        foreach ($sensitive as $listed => $unused) {
            if (str_ends_with($name, '_' . $listed)) {
                return true;
            }
        }

        return false;
    }

    private function normaliseFieldName(string $name): string
    {
        $name = strtolower(trim($name));
        $name = (string) preg_replace('/^x[-_]/', '', $name);

        return str_replace('-', '_', $name);
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
        $this->segmentData = [];
        $safeFields = config('threat-detection.safe_fields', []);
        $safePaths = config('threat-detection.safe_paths', []);

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
                $this->segmentData['query'] = $queryData;
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
                $this->segmentData['body'] = $postData;
            }
        }

        // 'authorization' is excluded so ordinary authenticated traffic
        // (Bearer/JWT tokens) is not logged as a high-severity token threat.
        $headers = collect($request->headers->all())
            ->except(['cookie', 'authorization', 'x-xsrf-token', 'accept-language', 'accept-encoding', 'connection', 'host', 'referer', 'origin'])
            ->map(fn ($v) => is_array($v) ? implode('; ', array_slice($v, 0, 2)) : $v);

        if ($headers->isNotEmpty()) {
            $segments['headers'] = json_encode($headers, self::SEGMENT_JSON_FLAGS);
            $this->segmentData['headers'] = $headers->all();
        }

        $segments['raw'] = $this->buildRawSegment($request);

        return $segments;
    }

    /**
     * The structured data behind the query, body and headers segments, kept so
     * the stored payload can be built from a *redacted copy* of it.
     *
     * Redacting the encoded JSON with a regex instead was the first attempt and
     * it was wrong in two ways: it only recognised string values, so a numeric
     * PIN or an array of tokens went to the log in cleartext, and the
     * string-matching subpattern exhausted the PCRE JIT stack above about
     * 8 KB — which, given redaction fails closed, would have blanked the whole
     * row. Masking the array before it is encoded has neither problem: keys are
     * compared exactly, every value type is covered, nesting is free, and there
     * is no regex to get wrong.
     *
     * Reset per request rather than accumulated, because the service is a
     * singleton and would otherwise carry one request's data into the next
     * under Octane.
     *
     * @var array<string, array<mixed>>
     */
    private array $segmentData = [];

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
    /**
     * How many times the decoding sequence is applied.
     *
     * One pass was not enough. Each decoder can *reveal* input for another —
     * percent-decoding produces an escape sequence, entity-decoding produces a
     * SQL comment — and running them once each in a fixed order meant whichever
     * decoder ran earlier never saw what a later one uncovered. Stacking two
     * encodings in the right order defeated the pipeline: a comment written as
     * HTML entities survived the comment strip, and a hex escape hidden behind
     * two layers of percent encoding was never decoded at all.
     *
     * Three is the same budget the percent decoder already used on its own, and
     * the loop stops as soon as a pass changes nothing, so ordinary traffic
     * still costs a single pass.
     */
    private const MAX_NORMALIZATION_PASSES = 3;

    private function normalizeForDetection(string $payload): string
    {
        $normalized = $payload;

        for ($pass = 0; $pass < self::MAX_NORMALIZATION_PASSES; $pass++) {
            $before = $normalized;
            $normalized = $this->decodeOnce($normalized);

            if ($normalized === $before) {
                break;
            }
        }

        // Collapse whitespace. `?? $normalized` throughout normalisation: a
        // replace that fails returns null, and a null here used to become an
        // empty payload — every pattern then saw nothing, and the request was
        // clean. A failed step leaves the text as it was instead.
        $normalized = preg_replace('/\s+/', ' ', $normalized) ?? $normalized;

        return trim($normalized);
    }

    /**
     * One decoding pass: comments, entities, escape sequences, percent
     * encoding.
     *
     * On the backslash counts below. Every segment is json_encode()d before it
     * reaches here, and json_encode escapes a backslash as two. The escape
     * decoders used to require exactly one, so they consumed the *second*
     * backslash of the pair and left the first in place: a hex-escaped "<"
     * normalized to a backslash followed by "<" rather than to "<", and the
     * XSS Script Tag pattern — which needs a literal closing script tag —
     * stopped matching. Accepting a run of backslashes handles the
     * JSON-escaped and the raw form alike, and costs nothing on input that has
     * neither.
     */
    private function decodeOnce(string $text): string
    {
        /*
         * Cheap bail-out for text nothing here can change.
         *
         * Every decoder below needs one of a handful of characters to have
         * anything to do: '&' for an HTML entity, a backslash for a \x or \u
         * escape, '%' for percent or IIS encoding, '+' for the space urldecode
         * turns it into, and "/*" for a SQL comment. Ordinary request data
         * contains none of them, and without this the loop pays for a whole
         * second pass on every clean request purely to discover that the first
         * one changed nothing.
         *
         * Skipping is safe by construction: if none of these bytes is present,
         * every operation below is the identity.
         */
        if (strpbrk($text, '&\\%+') === false && !str_contains($text, '/*')) {
            return $text;
        }

        // Strip SQL inline comments: UNION/**/SELECT -> UNION SELECT
        $text = preg_replace('/\/\*.*?\*\//s', ' ', $text) ?? $text;

        // Decode HTML entities: &#60;script&#62; -> <script>, &#x3c; -> <
        $text = html_entity_decode($text, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        // Decode JavaScript unicode escapes (backslash, u, four hex digits).
        $text = preg_replace_callback('/\\\\+u([0-9a-fA-F]{4})/', function ($m) {
            $code = hexdec($m[1]);

            return $code < 128 ? chr($code) : $m[0];
        }, $text) ?? $text;

        // Decode IIS-style %uXXXX. The evasion pattern flags this encoding but
        // nothing ever decoded it, so a %u-encoded attack was reported only as
        // "someone used IIS encoding" and the attack itself never identified.
        $text = preg_replace_callback('/%u([0-9a-fA-F]{4})/i', function ($m) {
            $code = hexdec($m[1]);

            return $code < 128 ? chr($code) : $m[0];
        }, $text) ?? $text;

        // Decode hex escapes (backslash, x, two hex digits).
        $text = preg_replace_callback('/\\\\+x([0-9a-fA-F]{2})/', function ($m) {
            return chr(hexdec($m[1]));
        }, $text) ?? $text;

        // Percent decoding, one layer per pass.
        $decoded = urldecode($text);
        if ($decoded !== $text) {
            $text = $decoded;
        }

        return $text;
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
     *
     * Checked against two views of the payload: as normalized, and with all
     * whitespace removed. Stripping a SQL comment leaves a space behind —
     * "\x73ystem/​*​*​/(" normalizes to "system (" — and a keyword written
     * without one ("system(") then failed to match, so the whole 'rce'
     * category was skipped and the pattern that would have caught it never
     * ran. The space is deliberate and cannot simply be dropped: removing it
     * would fuse "UNION/​*​*​/SELECT" into "UNIONSELECT".
     *
     * Widening the category set only ever enables more patterns to run; each
     * still has to match on its own, so this cannot introduce a false
     * positive. Keywords that contain a space of their own ("order by",
     * "net user") still match through the first view.
     */
    private function getRelevantCategories(string $payload): array
    {
        $lower = strtolower($payload);
        // str_replace, not preg_replace: normalizeForDetection() has already
        // collapsed every run of whitespace to a single space, so there is
        // nothing left for a regex to do that a literal replace cannot.
        $collapsed = str_replace(' ', '', $lower);

        $relevant = [];

        foreach (self::$categoryKeywords as $category => $keywords) {
            foreach ($keywords as $keyword) {
                if (str_contains($lower, $keyword) || str_contains($collapsed, $keyword)) {
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
        self::$patternFailureWarned = [];
        self::$writeFailureWarned = false;
        self::$labelRegexMap = null;
        // Warn-once flags are process-lifetime state too. Missing this one
        // meant the "cache driver cannot increment atomically" warning could
        // never be emitted a second time, including after the config change
        // that would make it newly relevant — which is what flushCaches()
        // exists for under Octane.
        self::$ddosCacheWarned = false;
        self::$cacheFailureWarned = false;
        self::$queueFailureWarned = false;
        self::$badSettingWarned = [];
        self::$sensitiveFieldAlternation = null;
        self::$sensitiveFieldNames = null;
    }

    public function detectThreatPatternsWithContext(
        array $segments,
        string $source = 'default',
        bool $isAuthPath = false
    ): array {
        $matches = [];
        $this->patternFailures = [];
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
                    if ($this->capIsUnbeatable($matches, $maxDetections)) {
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
                    if ($this->capIsUnbeatable($matches, $maxDetections)) {
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

            /*
             * The semantic identity of this segment: what the payload *means*
             * once decoded, not what it looked like on the wire.
             *
             * Computed once per segment and carried on every match from it, so
             * ActorSignalRecorder can count distinct meanings per actor without
             * re-normalising or storing the text. Callers that do not know the
             * key simply ignore it.
             *
             * Only the normalised stage gets one. An evasion match describes
             * the encoding rather than the payload, and the whole point of the
             * fingerprint is that encoding is the part that varies.
             */
            $fingerprint = $this->fingerprintOf($normalizedPayload);

            /*
             * And the surface form, which is the half that varies.
             *
             * A mutation chain is many *different* raw payloads that mean the
             * *same* thing, so counting distinct fingerprints would count it
             * as one: normalisation is what collapses them. The signal is the
             * number of distinct variants sharing one fingerprint.
             */
            $variant = $this->variantOf($segmentPayload);

            // Category-based lazy loading: only run regex for categories whose
            // keywords appear in the payload. Skips ~80% of patterns on average.
            $relevantCategories = $prescreened ? $this->getRelevantCategories($normalizedPayload) : [];

            foreach ($this->getDefaultThreatPatterns() as $regex => $label) {
                if ($this->capIsUnbeatable($matches, $maxDetections)) {
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
                        'fingerprint' => $fingerprint,
                        'variant' => $variant,
                    ];
                }
            }

            foreach ($this->getValidatedCustomPatterns() as $regex => $spec) {
                if ($this->capIsUnbeatable($matches, $maxDetections)) {
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
                        'fingerprint' => $fingerprint,
                        'variant' => $variant,
                    ];
                }
            }
        }

        $reported = $this->applySeverityCap($matches, $maxDetections);

        // After the cap, not before it: padding a request with cheap matches
        // must not be a way to push this out of the report.
        if ($this->patternFailures !== []) {
            $reported[] = [
                'label' => self::PATTERN_FAILURE_LABEL,
                'threat_level' => 'medium',
                'source' => 'engine',
                'context' => 'engine',
            ];
        }

        return $reported;
    }

    /**
     * TD-011. Report the most severe matches, not the first ones found.
     *
     * max_detections_per_request stopped the scan as soon as the cap was full,
     * and patterns are evaluated in list order — so an attacker who padded a
     * request with cheap matches that sit earlier in that order consumed the
     * budget before the real payload was reached. With the cap at 3, a request
     * carrying three XSS matches and a SQL injection recorded the three XSS
     * matches and not the injection.
     *
     * Raising the cap would not fix it; ordering does. The cap now bounds what
     * is *reported*, and what survives is chosen by severity rather than by
     * position in the pattern list.
     *
     * usort is stable on PHP 8, so matches of equal severity keep the order
     * they were found in and the output stays deterministic.
     *
     * @param  array<int, array{label: string, threat_level: string, source: string, context: string}>  $matches
     * @return array<int, array{label: string, threat_level: string, source: string, context: string}>
     */
    private function applySeverityCap(array $matches, int $maxDetections): array
    {
        if ($maxDetections <= 0 || count($matches) <= $maxDetections) {
            return $matches;
        }

        $rank = ['high' => 3, 'medium' => 2, 'low' => 1];

        usort(
            $matches,
            static fn ($a, $b) => ($rank[$b['threat_level']] ?? 0) <=> ($rank[$a['threat_level']] ?? 0)
        );

        return array_slice($matches, 0, $maxDetections);
    }

    /**
     * Whether scanning further could still change what gets reported.
     *
     * Once the cap is filled with high-severity matches nothing found later can
     * outrank them, so the scan can stop — which keeps the early exit for the
     * clearly-malicious request the config comment describes, without letting a
     * padded one decide what is kept.
     *
     * @param  array<int, array{threat_level: string}>  $matches
     */
    private function capIsUnbeatable(array $matches, int $maxDetections): bool
    {
        if ($maxDetections <= 0) {
            return false;
        }

        $high = 0;

        foreach ($matches as $match) {
            if ($match['threat_level'] === 'high' && ++$high >= $maxDetections) {
                return true;
            }
        }

        return false;
    }

    /** @var array<string, bool> Unknown validator names already warned about */
    private static array $validatorWarned = [];

    /** Reported in place of silence when a detection pattern cannot be evaluated. */
    public const PATTERN_FAILURE_LABEL = 'Pattern Evaluation Failure';

    /** @var array<string, true> Labels whose pattern failed during the current scan */
    private array $patternFailures = [];

    /** @var array<string, true> Labels already warned about in this process */
    private static array $patternFailureWarned = [];

    /**
     * Match, no match — or the engine gave up, which is neither.
     *
     * PHP stops catastrophic backtracking with pcre.backtrack_limit and
     * pcre.jit's stack limit, and preg_match() then returns false. Reading
     * that as "no match" — as this did until now — turns the resource limit
     * that exists to stop a denial of service into a silent bypass: craft an
     * input that makes one pattern blow up, and that pattern stops existing
     * for your request. It is the oldest lesson in regex-based detection:
     * backtracking in Snort's rule matching made inspection up to 1.5 million
     * times slower, and 4.0 kbps perpetually disabled an unmodified NIDS
     * (Smith, Estan and Jha, ACSAC 2006). The SoK on ReDoS (arXiv:2406.11618)
     * lists these limits as PHP's defence — which is exactly why a PHP
     * detector has to notice when they fire.
     *
     * The v1.8.0 audit rewrote one pattern that failed this way. This handles
     * the failure mode itself: any pattern, shipped or an operator's own,
     * present or future. The request is reported rather than passed, and the
     * pattern is named in the log so it can be fixed.
     *
     * Impure: a failure is recorded on the instance for the current scan.
     *
     * @phpstan-impure
     */
    private function evaluate(string $regex, string $payload, string $label): bool
    {
        $result = @preg_match($regex, $payload);

        if ($result === false) {
            $this->notePatternFailure($label, preg_last_error_msg());

            return false;
        }

        return $result === 1;
    }

    private function notePatternFailure(string $label, string $error): void
    {
        $this->patternFailures[$label] = true;

        if (isset(self::$patternFailureWarned[$label])) {
            return;
        }
        self::$patternFailureWarned[$label] = true;

        self::logQuietly('warning',
            "Threat detection: the pattern for '{$label}' could not be evaluated ({$error}). "
            . "The request was reported as '" . self::PATTERN_FAILURE_LABEL . "' rather than passed. "
            . 'A pattern that fails on real traffic backtracks badly and should be rewritten.'
        );
    }

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
     *
     * Impure: an evaluation failure is recorded for the current scan.
     *
     * @phpstan-impure
     */
    private function patternMatches(string $regex, string $payload, string $label, ?string $inlineValidator = null): bool
    {
        $validator = $inlineValidator ?? config('threat-detection.pattern_validators', [])[$label] ?? null;

        if ($validator === null) {
            return $this->evaluate($regex, $payload, $label);
        }

        if (!PatternValidators::known($validator)) {
            // Fail open on a typo — a misconfigured validator must never
            // silently disable a detection pattern.
            if (!isset(self::$validatorWarned[$validator])) {
                self::logQuietly('warning', "Threat detection: unknown pattern validator '{$validator}' for '{$label}'; matches are counted unvalidated.");
                self::$validatorWarned[$validator] = true;
            }

            return $this->evaluate($regex, $payload, $label);
        }

        $count = @preg_match_all($regex, $payload, $found);

        if ($count === false) {
            $this->notePatternFailure($label, preg_last_error_msg());

            return false;
        }

        if ($count === 0) {
            return false;
        }

        foreach ($found[0] as $value) {
            if (PatternValidators::passes($validator, $value)) {
                return true;
            }
        }

        return false;
    }

    /**
     * What the payload *means*: a short identity for its normalised form.
     *
     * Two requests share this when they decode to the same thing, however they
     * were encoded — the property the mutation-chain signal is built on.
     *
     * Case is folded here, and nowhere else. normalizeForDetection() does not
     * lowercase — it has no reason to, because every pattern is matched
     * case-insensitively — but "UNION SELECT" and "Union Select" are the same
     * attack, and changing case is about the cheapest bypass mutation there
     * is. Without folding, an actor alternating case split into several
     * fingerprints and the chain that should have been one read as two. An
     * end-to-end run caught that; the per-feature tests never used mixed case.
     *
     * Whitespace is *not* re-collapsed: normalizeForDetection() already
     * collapses and trims as its final step, so doing it again was dead code.
     *
     * Truncated SHA-256 rather than the text, for two reasons. Normalisation
     * runs before redaction, so the text can contain credentials; and 16 hex
     * characters is 64 bits, ample for grouping attempts inside an hour and
     * narrow enough to index on every supported database.
     */
    private function fingerprintOf(string $normalizedPayload): string
    {
        return substr(hash('sha256', mb_strtolower($normalizedPayload)), 0, 16);
    }

    /**
     * What the payload *looked like*: a short identity for the bytes as they
     * arrived, before any decoding.
     *
     * Deliberately not canonicalised. Re-spacing a payload to slip a signature
     * is a surface mutation like any other, and collapsing whitespace here
     * would hide exactly the variation this column exists to count. That is
     * the whole split: the fingerprint is meant to collapse, the variant is
     * meant not to.
     */
    private function variantOf(string $rawPayload): string
    {
        return substr(hash('sha256', $rawPayload), 0, 16);
    }

    /**
     * Whether this IP and type were recorded in the last five minutes.
     *
     * An unreachable cache answers "no". Unguarded, the exception ended
     * detection for the request — for every request, while the cache was
     * down. Without dedup a repeated attack is recorded more than once,
     * which is the direction a detector can afford.
     */
    private function isRecentlyLogged(string $ip, string $type): bool
    {
        try {
            return Cache::has($this->loggedKey($ip, $type));
        } catch (\Throwable $e) {
            $this->reportCacheFailure($e);

            return false;
        }
    }

    private function markAsLogged(string $ip, string $type): void
    {
        try {
            Cache::put($this->loggedKey($ip, $type), true, now()->addMinutes(5));
        } catch (\Throwable $e) {
            $this->reportCacheFailure($e);
        }
    }

    private static bool $cacheFailureWarned = false;

    private function reportCacheFailure(\Throwable $e): void
    {
        if (self::$cacheFailureWarned) {
            return;
        }

        self::$cacheFailureWarned = true;
        self::logQuietly('warning', 'Threat detection: the cache cannot be reached, so deduplication is off and repeated '
            . 'detections are each recorded until it is back: ' . $this->storable($e->getMessage()));
    }

    /**
     * The dedup mark's cache key.
     *
     * Memcached's text protocol refuses a key containing whitespace or longer
     * than 250 bytes, and every type contains a space ("[query] SQL Injection
     * UNION"). There every read and write of the mark failed silently, so
     * dedup never engaged: a row, and an alert, for every attacking request
     * instead of one per five minutes. On memcached the key is hashed; other
     * stores keep the readable key they have always had.
     */
    private function loggedKey(string $ip, string $type): string
    {
        $key = "threat_logged:{$ip}:{$type}";
        $driver = config('cache.stores.' . config('cache.default') . '.driver');

        return $driver === 'memcached' ? 'threat_logged:' . sha1($key) : $key;
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
                self::logQuietly('warning', "Threat detection: DDoS detection is disabled because cache driver '{$driver}' does not support atomic increment. Use redis or memcached.");
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
            self::logQuietly('error', 'Threat detection DDoS check failed: ' . $e->getMessage());

            return false;
        }
    }

    private function logDdosThreat(string $ip, string $url, string $userAgent): void
    {
        $type = '[ddos] Excessive Requests';
        $level = 'high';

        if ($this->isRecentlyLogged($ip, $type)) {
            return;
        }

        // Mark only after the write succeeds. v1.3.1 made this change for the
        // main detection path but not for this one, so a failed DDoS insert
        // still muted the flood for five minutes.
        try {
            DB::table(config('threat-detection.table_name', 'threat_logs'))->insert([
                'ip_address' => $ip,
                // A flood is still a request, and its query string can carry a
                // credential like any other. This row skipped redaction
                // entirely because it is written on its own path.
                'url' => $this->bounded($this->redactSensitiveFields($url)),
                'user_agent' => $this->bounded($userAgent),
                'type' => $type,
                'payload' => 'Request frequency exceeded threshold',
                'threat_level' => $level,
                'confidence_score' => 90,
                'confidence_label' => 'very_high',
                'user_id' => $this->signedInUserId(),
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
        $this->announce(new DdosThresholdExceeded(
            $ip,
            $this->ddosRequestCount($ip),
            $this->ddosThreshold,
            $this->ddosWindowSeconds
        ));

        self::logQuietly('warning', "[$level] DDoS Threat Detected: $ip exceeded threshold.");
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
            //
            // Written with negated classes and possessive quantifiers rather
            // than the obvious /[)(|*\\].*\(.*=/s. That form has two greedy
            // .* under /s over a subject made of the character class's own
            // members, which backtracks quadratically: appending about 1,500
            // '(' characters to a real LDAP injection exhausted
            // pcre.backtrack_limit, and patternMatches() reads the resulting
            // false as "no threat". 1.5 KB of padding switched this detection
            // off.
            //
            // The acceptance set is unchanged. The question either form asks
            // is "a metacharacter, then later a '(', then later an '='"; and
            // taking the *first* '(' after the metacharacter cannot lose a
            // match, because any '=' following a later '(' also follows the
            // first one.
            '/[)(|*\\\\][^(]*+\([^=]*+=/' => 'LDAP Injection',
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
    /**
     * The configured custom patterns, plus the prompt-injection pack when it
     * is turned on.
     *
     * The pack rides on custom_patterns rather than getting a loader of its
     * own: that reuses the regex validation, the label/level/contexts shape
     * and the per-process memoisation already built here, and it means an
     * operator can override or delete any pack entry using a mechanism they
     * already know.
     *
     * Union, not array_merge — `+` keeps the LEFT side on a key collision, so
     * an operator's own entry for the same regex wins over the pack's.
     *
     * @return array<string, mixed>
     */
    private function customPatternSource(): array
    {
        $configured = (array) config('threat-detection.custom_patterns', []);

        if (!config('threat-detection.llm_log_safety.detect_injection', false)) {
            return $configured;
        }

        return $configured + (array) config('threat-detection.llm_log_safety.patterns', []);
    }

    private function getValidatedCustomPatterns(): array
    {
        if (self::$validatedCustomPatterns !== null) {
            return self::$validatedCustomPatterns;
        }

        self::$validatedCustomPatterns = [];
        foreach ($this->customPatternSource() as $regex => $entry) {
            if (@preg_match($regex, '') === false) {
                self::logQuietly('warning', "Threat detection: invalid custom pattern skipped: {$regex}");

                continue;
            }

            if (is_string($entry)) {
                $entry = ['label' => $entry];
            }

            if (!is_array($entry) || !is_string($entry['label'] ?? null) || $entry['label'] === '') {
                self::logQuietly('warning', "Threat detection: custom pattern without a label skipped: {$regex}");

                continue;
            }

            $level = $entry['level'] ?? null;
            if ($level !== null && !in_array($level, ['low', 'medium', 'high'], true)) {
                self::logQuietly('warning', "Threat detection: custom pattern '{$entry['label']}' has unknown level '{$level}'; deriving from threat_levels keywords instead.");
                $level = null;
            }

            $contexts = null;
            if (is_array($entry['contexts'] ?? null) && $entry['contexts'] !== []) {
                $contexts = array_values(array_intersect($entry['contexts'], self::PATTERN_CONTEXTS));
                if ($unknown = array_diff($entry['contexts'], self::PATTERN_CONTEXTS)) {
                    self::logQuietly('warning', "Threat detection: custom pattern '{$entry['label']}' names unknown contexts (" . implode(', ', $unknown) . '); valid contexts are ' . implode('|', self::PATTERN_CONTEXTS) . '.');
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
        $this->patternFailures = [];

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

        if ($this->patternFailures !== []) {
            $matches[] = [self::PATTERN_FAILURE_LABEL, 'medium', 'engine'];
        }

        return $matches;
    }

    private static ?array $cachedScanners = null;

    private static ?array $cachedBots = null;

    private function detectSuspiciousUserAgent(string $userAgent): array
    {
        $userAgentLower = strtolower($userAgent);

        /*
         * TD-009. A user agent claiming to be a browser is checked against the
         * same list as one that does not.
         *
         * This used to short-circuit on "mozilla/" plus "gecko" and then
         * compare against ten hard-coded names — the AI crawlers — before
         * giving up. Every other scanner was skipped, so "Mozilla/5.0 (X11;
         * Linux) Gecko/20100101 sqlmap/1.7.2" was not reported as sqlmap while
         * the bare "sqlmap/1.7.2" was. The list existed precisely to catch
         * agents that embed Mozilla; it just held the wrong ten.
         *
         * The cheap path is kept, because it is what stops every ordinary
         * request paying for the full scan — but the thing it now tests is
         * whether the agent matches *any* known scanner or bot, which is the
         * same question the full scan asks. A browser matches none of them and
         * still returns immediately.
         */
        if (str_contains($userAgentLower, 'mozilla/') && str_contains($userAgentLower, 'gecko')) {
            if (!$this->matchesAnyKnownAgent($userAgentLower)) {
                return [];
            }
        }

        return $this->fullUserAgentScan($userAgentLower, $userAgent);
    }

    /**
     * Whether the agent contains any name the scanner or bot lists know about.
     *
     * Used by the browser fast path so it asks the same question the full scan
     * does, rather than a ten-name approximation of it.
     */
    private function matchesAnyKnownAgent(string $userAgentLower): bool
    {
        $this->primeUserAgentLists();

        foreach (self::$cachedScanners as $pattern => $info) {
            if (str_contains($userAgentLower, $pattern)) {
                return true;
            }
        }

        foreach (self::$cachedBots as $pattern => $info) {
            if (str_contains($userAgentLower, $pattern)) {
                return true;
            }
        }

        return false;
    }

    private function fullUserAgentScan(string $userAgentLower, string $userAgent): array
    {
        $threats = [];

        $this->primeUserAgentLists();

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

    /** Build the scanner and bot lists once per process. */
    private function primeUserAgentLists(): void
    {
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

            if (class_exists(SlackMessage::class)) {
                Notification::route('slack', $webhookUrl)->notify($alert);
            } else {
                Http::post($webhookUrl, $alert->toWebhookPayload());
            }
        } catch (\Throwable $e) {
            self::logQuietly('error', 'Failed to send threat notification: ' . $e->getMessage());
        }
    }

    /*
     * Reporting lives in ThreatCorrelationService. These delegate so the
     * facade and existing call sites keep working unchanged.
     */

    public function getIpStatistics(string $ip): array
    {
        return $this->correlation->getIpStatistics($ip);
    }

    public function detectCoordinatedAttacks(int $timeWindowMinutes = 15, int $minIpCount = 3): array
    {
        return $this->correlation->detectCoordinatedAttacks($timeWindowMinutes, $minIpCount);
    }

    public function detectAttackCampaigns(int $hoursBack = 24): array
    {
        return $this->correlation->detectAttackCampaigns($hoursBack);
    }

    public function detectRapidAttacks(int $minutesBack = 5, int $minThreshold = 10): array
    {
        return $this->correlation->detectRapidAttacks($minutesBack, $minThreshold);
    }

    public function detectMutationChains(int $minutesBack = 60, int $minVariants = 5): array
    {
        return $this->correlation->detectMutationChains($minutesBack, $minVariants);
    }

    public function detectPayloadClusters(int $minutesBack = 60, int $minActors = 3, int $minFingerprints = 2): array
    {
        return $this->correlation->detectPayloadClusters($minutesBack, $minActors, $minFingerprints);
    }

    public function detectRetryBursts(int $minutesBack = 60, int $minPayloads = 5): array
    {
        return $this->correlation->detectRetryBursts($minutesBack, $minPayloads);
    }

    public function getCorrelationSummary(): array
    {
        return $this->correlation->getCorrelationSummary();
    }
}
