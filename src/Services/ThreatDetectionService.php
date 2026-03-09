<?php

namespace JayAnta\ThreatDetection\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Notification;
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
        $payload = $this->buildSanitizedPayload($request);
        $isAuthPath = $request->attributes->get('threat-detection:auth-path', false);
        $isContentPath = $request->attributes->get('threat-detection:content-path', false);
        $mode = config('threat-detection.detection_mode', 'balanced');

        $botThreats = $this->detectSuspiciousUserAgent($userAgent);
        $isAttackTool = $this->confidenceScorer->isAttackToolUserAgent($userAgent);

        if ($this->isDdosSuspected($ip)) {
            $this->logDdosThreat($ip, $url, $userAgent);
        }

        $segments = $this->buildPayloadSegments($request);
        $contextMatches = $this->detectThreatPatternsWithContext($segments, 'middleware', $isAuthPath);

        $patternThreats = [];
        $contextWeights = [];
        foreach ($contextMatches as $match) {
            $patternThreats[] = [$match['label'], $match['threat_level'], $match['source']];
            $weight = config('threat-detection.context_weights.' . $match['context'], 1.0);
            $contextWeights[$match['label']] = $weight;
        }

        $allThreats = array_merge($botThreats, $patternThreats);

        $confidence = $this->confidenceScorer->calculate(
            $allThreats,
            $contextWeights,
            $isAttackTool,
            $mode
        );

        $minConfidence = match ($mode) {
            'strict' => 0,
            'relaxed' => 40,
            default => 10,
        };

        if ($confidence['score'] < $minConfidence) {
            return;
        }

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

            DB::table(config('threat-detection.table_name', 'threat_logs'))->insert([
                'ip_address' => $ip,
                'url' => $url,
                'user_agent' => $userAgent,
                'type' => $type,
                'payload' => substr($payload, 0, 2000),
                'threat_level' => $level,
                'confidence_score' => $confidence['score'],
                'confidence_label' => $confidence['label'],
                'user_id' => Auth::id(),
                'created_at' => now(),
                'updated_at' => now(),
            ]);

            Log::warning("[$level] Threat Detected: [$type] from $ip ($url) [confidence: {$confidence['score']}%]");

            if (
                config('threat-detection.notifications.enabled') &&
                in_array($level, config('threat-detection.notifications.notify_levels', ['high']))
            ) {
                $this->sendNotifications($ip, $url, $type, $level, $userAgent);
            }
        }
    }

    private function buildSanitizedPayload(Request $request): string
    {
        $data = [];

        if (!empty($request->query())) {
            $data[] = "QUERY: " . json_encode($request->query(), JSON_UNESCAPED_SLASHES);
        }

        if (!empty($request->post())) {
            $data[] = "BODY: " . json_encode($request->post(), JSON_UNESCAPED_SLASHES);
        }

        $headers = collect($request->headers->all())
            ->except(['cookie', 'x-xsrf-token', 'accept-language', 'accept-encoding', 'connection', 'host', 'referer', 'origin'])
            ->map(fn($v) => is_array($v) ? implode('; ', array_slice($v, 0, 2)) : $v);

        if ($headers->isNotEmpty()) {
            $data[] = "HEADERS: " . json_encode($headers, JSON_UNESCAPED_SLASHES);
        }

        return implode("\n", $data);
    }

    private function buildPayloadSegments(Request $request): array
    {
        $segments = ['query' => '', 'body' => '', 'headers' => ''];

        if (!empty($request->query())) {
            $segments['query'] = json_encode($request->query(), JSON_UNESCAPED_SLASHES);
        }

        if (!empty($request->post())) {
            $segments['body'] = json_encode($request->post(), JSON_UNESCAPED_SLASHES);
        }

        $headers = collect($request->headers->all())
            ->except(['cookie', 'x-xsrf-token', 'accept-language', 'accept-encoding', 'connection', 'host', 'referer', 'origin'])
            ->map(fn($v) => is_array($v) ? implode('; ', array_slice($v, 0, 2)) : $v);

        if ($headers->isNotEmpty()) {
            $segments['headers'] = json_encode($headers, JSON_UNESCAPED_SLASHES);
        }

        return $segments;
    }

    /** Strip SQL inline comments and collapse whitespace. */
    private function normalizeForDetection(string $payload): string
    {
        $normalized = preg_replace('/\/\*.*?\*\//s', ' ', $payload);
        $normalized = preg_replace('/\s+/', ' ', $normalized);

        return trim($normalized);
    }

    /** Patterns matched before normalization. */
    private function getEvasionPatterns(): array
    {
        return [
            '/\w+\/\*[^*]*\*\/\w+/' => 'SQL Comment Evasion',
            '/%25[0-9a-fA-F]{2}/i' => 'Double URL Encoding',
        ];
    }

    public function detectThreatPatternsWithContext(
        array $segments,
        string $source = 'default',
        bool $isAuthPath = false
    ): array {
        $matches = [];
        $mode = config('threat-detection.detection_mode', 'balanced');

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

            // Evasion patterns run on raw payload
            foreach ($this->getEvasionPatterns() as $regex => $label) {
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

            foreach ($this->getDefaultThreatPatterns() as $regex => $label) {
                $level = $this->getThreatLevelByType($label);

                if ($mode === 'relaxed' && $level !== 'high') {
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

            foreach (config('threat-detection.custom_patterns', []) as $regex => $label) {
                if ($isAuthPath && in_array($label, $authExcludePatterns)) {
                    continue;
                }

                $level = $this->getThreatLevelByType($label);

                if ($mode === 'relaxed' && $level !== 'high') {
                    continue;
                }

                $result = @preg_match($regex, $normalizedPayload);
                if ($result === false) {
                    Log::warning("Threat detection: invalid custom pattern skipped: {$regex}");
                    continue;
                }
                if ($result) {
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
        return Cache::has('threat_logged:' . md5($ip . $type));
    }

    private function markAsLogged(string $ip, string $type): void
    {
        Cache::put('threat_logged:' . md5($ip . $type), true, now()->addMinutes(5));
    }

    private function isDdosSuspected(string $ip): bool
    {
        $key = "ddos:$ip";
        Cache::add($key, 0, now()->addSeconds($this->ddosWindowSeconds));
        $count = Cache::increment($key);
        return $count > $this->ddosThreshold;
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

    private function getThreatLevelByType(string $label): string
    {
        foreach (config('threat-detection.threat_levels', []) as $level => $keywords) {
            foreach ($keywords as $keyword) {
                if (str_contains(strtolower($label), strtolower($keyword))) return $level;
            }
        }
        return 'low';
    }

    public function getDefaultThreatPatterns(): array
    {
        return [
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

            '/O:\d+:"[A-Za-z_][A-Za-z0-9_]+":\d+:\{.{0,500}\}/s' => 'PHP Object Deserialization',

            '/\b(nmap|sqlmap|nikto|acunetix|wpscan|dirbuster|fimap)\b/i' => 'Scanner Tool Detected',
        ];
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

        foreach (config('threat-detection.custom_patterns', []) as $regex => $label) {
            $result = @preg_match($regex, $payload);
            if ($result === false) {
                Log::warning("Threat detection: invalid custom pattern skipped: {$regex}");
                continue;
            }
            if ($result) {
                if ($isAuthPath && in_array($label, $authExcludePatterns)) {
                    continue;
                }

                $matches[] = [$label, $this->getThreatLevelByType($label), 'custom'];
            }
        }

        return $matches;
    }

    private function detectSuspiciousUserAgent(string $userAgent): array
    {
        $threats = [];

        $scanners = [
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
        ];

        $suspiciousBots = [
            'masscan' => ['label' => 'MassScan Tool', 'level' => 'high'],
            'zgrab' => ['label' => 'ZGrab Scanner', 'level' => 'high'],
            'shodan' => ['label' => 'Shodan Bot', 'level' => 'medium'],
            'censys' => ['label' => 'Censys Bot', 'level' => 'medium'],
            'python-requests' => ['label' => 'Python Script', 'level' => 'low'],
            'curl/' => ['label' => 'cURL Command', 'level' => 'low'],
            'wget/' => ['label' => 'wget Command', 'level' => 'low'],
            'go-http-client' => ['label' => 'Go HTTP Client', 'level' => 'low'],
        ];

        $userAgentLower = strtolower($userAgent);

        foreach ($scanners as $pattern => $info) {
            if (str_contains($userAgentLower, strtolower($pattern))) {
                $threats[] = [$info['label'], $info['level'], 'user-agent'];
            }
        }

        foreach ($suspiciousBots as $pattern => $info) {
            if (str_contains($userAgentLower, strtolower($pattern))) {
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

        return $coordinatedAttacks->map(function ($attack) use ($table, $timeThreshold) {
            $attackingIps = DB::table($table)
                ->where('url', $attack->url)
                ->where('created_at', '>=', $timeThreshold)
                ->distinct()
                ->pluck('ip_address')
                ->toArray();

            return [
                'url' => $attack->url,
                'unique_ips' => $attack->unique_ips,
                'total_attempts' => $attack->total_attempts,
                'first_attack' => $attack->first_attack,
                'last_attack' => $attack->last_attack,
                'attacking_ips' => $attackingIps,
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

        return $campaigns->map(function ($campaign) use ($table) {
            $sampleIps = DB::table($table)
                ->where('type', $campaign->type)
                ->where('created_at', '>=', $campaign->campaign_start)
                ->distinct()
                ->limit(10)
                ->pluck('ip_address')
                ->toArray();

            return [
                'threat_type' => $campaign->type,
                'unique_ips' => $campaign->unique_ips,
                'total_threats' => $campaign->total_threats,
                'campaign_start' => $campaign->campaign_start,
                'campaign_end' => $campaign->campaign_end,
                'duration_hours' => round((strtotime($campaign->campaign_end) - strtotime($campaign->campaign_start)) / 3600, 2),
                'sample_ips' => $sampleIps,
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
