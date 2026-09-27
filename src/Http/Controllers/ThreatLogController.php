<?php

namespace JayAnta\ThreatDetection\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Response;
use JayAnta\ThreatDetection\Services\ExclusionRuleService;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;

class ThreatLogController extends Controller
{
    protected string $table;

    public function __construct()
    {
        $this->table = config('threat-detection.table_name', 'threat_logs');
    }

    private function safe(\Closure $callback): JsonResponse
    {
        try {
            $response = $callback();
        } catch (\Throwable $e) {
            Log::error('Threat detection API error: ' . $e->getMessage());

            $response = response()->json([
                'success' => false,
                'message' => 'Database query failed. Has the threat_logs migration been run?',
            ], 500);
        }

        $this->addSecurityHeaders($response);

        return $response;
    }

    /**
     * TD-004. Send the anti-sniffing header the dashboard route already sends.
     *
     * These responses carry attacker-controlled strings — URLs, types, user
     * agents — and json_encode does not hex-escape '<' or '>'. A browser will
     * not sniff application/json as HTML, so this is defence in depth rather
     * than a live hole; it is sent because the package already decided these
     * headers were worth sending on the other route, and an inconsistency in a
     * security package gets noticed by an attacker before an operator.
     *
     * Only nosniff and Referrer-Policy: the dashboard's CSP and frame options
     * describe a document, and applying them to a JSON API would say nothing
     * useful.
     *
     * Mutates in place and returns nothing, so it can take a JsonResponse and
     * a plain Response without either a union return type or a generic that
     * promises more than Symfony's base class offers.
     */
    private function addSecurityHeaders(SymfonyResponse $response): void
    {
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('Referrer-Policy', 'no-referrer');
    }

    public function index(Request $request): JsonResponse
    {
        $request->validate([
            'per_page' => 'sometimes|integer|min:1|max:100',
            'level' => 'sometimes|in:high,medium,low',
            'date_from' => 'sometimes|date',
            'date_to' => 'sometimes|date',
        ]);

        return $this->safe(function () use ($request) {
            $query = DB::table($this->table)
                ->select('id', 'ip_address', 'url', 'type', 'threat_level', 'confidence_score', 'confidence_label', 'is_false_positive', 'action_taken', 'country_code', 'country_name', 'cloud_provider', 'is_cloud_ip', 'is_foreign', 'created_at');

            if ($request->has('keyword')) {
                $keyword = '%' . $request->input('keyword') . '%';
                $query->where(function ($q) use ($keyword) {
                    $q->where('ip_address', 'like', $keyword)
                        ->orWhere('type', 'like', $keyword)
                        ->orWhere('url', 'like', $keyword);
                });
            }

            if ($request->filled('ip')) {
                $query->where('ip_address', $request->input('ip'));
            }
            if ($request->filled('type')) {
                $query->where('type', 'like', '%' . $request->input('type') . '%');
            }
            if ($request->filled('level')) {
                $query->where('threat_level', $request->input('level'));
            }
            if ($request->filled('country')) {
                $query->where('country_code', $request->input('country'));
            }
            if ($request->filled('is_foreign')) {
                $query->where('is_foreign', $request->boolean('is_foreign'));
            }
            if ($request->filled('cloud_provider')) {
                $query->where('cloud_provider', $request->input('cloud_provider'));
            }
            if ($request->has('is_false_positive')) {
                $query->where('is_false_positive', $request->boolean('is_false_positive'));
            }
            if ($request->filled('date_from')) {
                $query->where('created_at', '>=', $request->input('date_from'));
            }
            if ($request->filled('date_to')) {
                $query->where('created_at', '<=', $request->input('date_to'));
            }

            return response()->json([
                'success' => true,
                'data' => $query->latest()->paginate($request->get('per_page', 20)),
            ]);
        });
    }

    public function summary(): JsonResponse
    {
        return $this->safe(function () {
            $byType = DB::table($this->table)
                ->select('type', DB::raw('COUNT(*) as count'))
                ->groupBy('type')
                ->orderByDesc('count')
                ->limit(10)
                ->get();

            $byLevel = DB::table($this->table)
                ->select('threat_level', DB::raw('COUNT(*) as count'))
                ->groupBy('threat_level')
                ->orderByDesc('count')
                ->get();

            $byIP = DB::table($this->table)
                ->select('ip_address', 'country_name', 'cloud_provider', DB::raw('COUNT(*) as count'))
                ->groupBy('ip_address', 'country_name', 'cloud_provider')
                ->orderByDesc('count')
                ->limit(10)
                ->get();

            $byCountry = DB::table($this->table)
                ->select('country_code', 'country_name', DB::raw('COUNT(*) as count'))
                ->whereNotNull('country_code')
                ->groupBy('country_code', 'country_name')
                ->orderByDesc('count')
                ->limit(10)
                ->get();

            $byCloudProvider = DB::table($this->table)
                ->select('cloud_provider', DB::raw('COUNT(*) as count'))
                ->whereNotNull('cloud_provider')
                ->groupBy('cloud_provider')
                ->orderByDesc('count')
                ->limit(50)
                ->get();

            $byDate = DB::table($this->table)
                ->selectRaw('CAST(created_at AS DATE) as date, COUNT(*) as count')
                ->where('created_at', '>=', now()->subDays(30))
                ->groupByRaw('CAST(created_at AS DATE)')
                ->orderBy('date', 'asc')
                ->get();

            return response()->json([
                'success' => true,
                'data' => [
                    'byType' => $byType,
                    'byLevel' => $byLevel,
                    'byIP' => $byIP,
                    'byCountry' => $byCountry,
                    'byCloudProvider' => $byCloudProvider,
                    'byDate' => $byDate,
                ],
            ]);
        });
    }

    public function stats(): JsonResponse
    {
        return $this->safe(function () {
            $today = today()->toDateString();
            $lastHour = now()->subHour();

            $row = DB::table($this->table)
                ->selectRaw('COUNT(*) as total_threats')
                ->selectRaw("SUM(CASE WHEN threat_level = 'high' THEN 1 ELSE 0 END) as high_severity")
                ->selectRaw("SUM(CASE WHEN threat_level = 'medium' THEN 1 ELSE 0 END) as medium_severity")
                ->selectRaw("SUM(CASE WHEN threat_level = 'low' THEN 1 ELSE 0 END) as low_severity")
                ->selectRaw('COUNT(DISTINCT ip_address) as unique_ips')
                ->selectRaw('COUNT(DISTINCT CASE WHEN is_foreign = 1 THEN ip_address END) as foreign_ips')
                ->selectRaw('SUM(CASE WHEN cloud_provider IS NOT NULL THEN 1 ELSE 0 END) as cloud_attacks')
                ->selectRaw('SUM(CASE WHEN DATE(created_at) = ? THEN 1 ELSE 0 END) as today', [$today])
                ->selectRaw('SUM(CASE WHEN created_at >= ? THEN 1 ELSE 0 END) as last_hour', [$lastHour])
                ->first();

            $stats = [
                'total_threats' => (int) ($row->total_threats ?? 0),
                'high_severity' => (int) ($row->high_severity ?? 0),
                'medium_severity' => (int) ($row->medium_severity ?? 0),
                'low_severity' => (int) ($row->low_severity ?? 0),
                'unique_ips' => (int) ($row->unique_ips ?? 0),
                'foreign_ips' => (int) ($row->foreign_ips ?? 0),
                'cloud_attacks' => (int) ($row->cloud_attacks ?? 0),
                'today' => (int) ($row->today ?? 0),
                'last_hour' => (int) ($row->last_hour ?? 0),
            ];

            return response()->json([
                'success' => true,
                'data' => $stats,
            ]);
        });
    }

    public function liveCount(): JsonResponse
    {
        return $this->safe(function () {
            $count = DB::table($this->table)
                ->where('created_at', '>=', now()->subHour())
                ->count();

            return response()->json([
                'success' => true,
                'data' => ['count' => $count],
            ]);
        });
    }

    public function show(int $id): JsonResponse
    {
        return $this->safe(function () use ($id) {
            $threat = DB::table($this->table)
                ->where('id', $id)
                ->first();

            if (!$threat) {
                return response()->json(['success' => false, 'message' => 'Threat not found'], 404);
            }

            return response()->json([
                'success' => true,
                'data' => $threat,
            ]);
        });
    }

    public function ipStats(Request $request, ThreatDetectionService $service): JsonResponse
    {
        $request->validate(['ip' => 'required|ip']);

        return $this->safe(function () use ($request, $service) {
            $ip = $request->input('ip');
            $stats = $service->getIpStatistics($ip);

            $recentThreats = DB::table($this->table)
                ->where('ip_address', $ip)
                ->select('id', 'url', 'type', 'threat_level', 'created_at')
                ->orderByDesc('created_at')
                ->limit(10)
                ->get();

            $levelBreakdown = DB::table($this->table)
                ->where('ip_address', $ip)
                ->select('threat_level', DB::raw('COUNT(*) as count'))
                ->groupBy('threat_level')
                ->get()
                ->pluck('count', 'threat_level')
                ->toArray();

            return response()->json([
                'success' => true,
                'data' => [
                    'ip_address' => $ip,
                    'statistics' => $stats,
                    'recent_threats' => $recentThreats,
                    'level_breakdown' => [
                        'high' => $levelBreakdown['high'] ?? 0,
                        'medium' => $levelBreakdown['medium'] ?? 0,
                        'low' => $levelBreakdown['low'] ?? 0,
                    ],
                ],
            ]);
        });
    }

    public function correlation(Request $request, ThreatDetectionService $service): JsonResponse
    {
        $request->validate(['type' => 'sometimes|in:all,coordinated,campaigns,rapid']);

        return $this->safe(function () use ($request, $service) {
            $type = $request->input('type', 'all');
            $data = [];

            if ($type === 'all' || $type === 'coordinated') {
                $data['coordinated_attacks'] = $service->detectCoordinatedAttacks(15, 3);
            }

            if ($type === 'all' || $type === 'campaigns') {
                $data['attack_campaigns'] = $service->detectAttackCampaigns(24);
            }

            if ($type === 'all' || $type === 'rapid') {
                $data['rapid_attackers'] = $service->detectRapidAttacks(5, 10);
            }

            if ($type === 'all') {
                $data['summary'] = $service->getCorrelationSummary();
            }

            return response()->json([
                'success' => true,
                'data' => $data,
            ]);
        });
    }

    public function export(Request $request)
    {
        try {
            $query = DB::table($this->table)
                ->select('id', 'created_at', 'ip_address', 'url', 'type', 'threat_level', 'confidence_score', 'is_false_positive', 'action_taken', 'country_name', 'cloud_provider');

            if ($request->filled('keyword')) {
                $keyword = '%' . $request->input('keyword') . '%';
                $query->where(function ($q) use ($keyword) {
                    $q->where('ip_address', 'like', $keyword)
                        ->orWhere('url', 'like', $keyword)
                        ->orWhere('type', 'like', $keyword);
                });
            }

            if ($request->filled('level')) {
                $query->where('threat_level', $request->input('level'));
            }

            $logs = $query->orderByDesc('created_at')->limit(10000)->get();

            $csvHeader = ['ID', 'Time', 'IP Address', 'URL', 'Type', 'Level', 'Confidence', 'False Positive', 'Action', 'Country', 'Cloud Provider'];
            $csvData = $logs->map(function ($log) {
                // Every free-text cell goes through the sanitizer. Country and
                // provider come from geo-enrichment and action_taken from the
                // DB, so they are lower risk than url/type — but a partially
                // sanitized export is a hole waiting to be found.
                return [
                    $log->id,
                    $this->sanitizeCsvCell($log->created_at),
                    // TD-005. The IP column is the one field a downstream tool
                    // is likely to feed straight into a firewall rule, so it
                    // leaves here as an address or not at all. fputcsv already
                    // stops a newline splitting the record; this stops the cell
                    // carrying something that was never an address.
                    $this->sanitizeIpCell($log->ip_address),
                    // url and type are the two cells carrying attacker-chosen
                    // text, so they are the two that get a trust boundary when
                    // spotlighting is on.
                    $this->spotlight($this->sanitizeCsvCell($log->url)),
                    $this->spotlight($this->sanitizeCsvCell($log->type)),
                    $log->threat_level,
                    ($log->confidence_score ?? 0) . '%',
                    ($log->is_false_positive ?? false) ? 'Yes' : 'No',
                    $this->sanitizeCsvCell($log->action_taken),
                    $this->sanitizeCsvCell($log->country_name) ?: 'N/A',
                    $this->sanitizeCsvCell($log->cloud_provider) ?: 'N/A',
                ];
            })->toArray();

            $filename = 'threat_logs_' . now()->format('Ymd_His') . '.csv';

            $handle = fopen('php://temp', 'r+');
            fputcsv($handle, $csvHeader);
            foreach ($csvData as $row) {
                fputcsv($handle, $row);
            }
            rewind($handle);
            $csvOutput = stream_get_contents($handle);
            fclose($handle);

            // TD-004. The CSV is defended by Content-Disposition: attachment,
            // but nosniff costs nothing and closes the gap for a client that
            // ignores it.
            $csvResponse = Response::make($csvOutput, 200, [
                'Content-Type' => 'text/csv',
                'Content-Disposition' => "attachment; filename=\"$filename\"",
            ]);

            $this->addSecurityHeaders($csvResponse);

            return $csvResponse;
        } catch (\Throwable $e) {
            Log::error('Threat detection API error: ' . $e->getMessage());

            $errorResponse = response()->json([
                'success' => false,
                'message' => 'Database query failed. Has the threat_logs migration been run?',
            ], 500);

            $this->addSecurityHeaders($errorResponse);

            return $errorResponse;
        }
    }

    public function byCountry(): JsonResponse
    {
        return $this->safe(function () {
            $data = DB::table($this->table)
                ->select('country_code', 'country_name', DB::raw('COUNT(*) as count'), DB::raw('COUNT(DISTINCT ip_address) as unique_ips'))
                ->whereNotNull('country_code')
                ->groupBy('country_code', 'country_name')
                ->orderByDesc('count')
                ->limit(20)
                ->get();

            return response()->json([
                'success' => true,
                'data' => $data,
            ]);
        });
    }

    public function byCloudProvider(): JsonResponse
    {
        return $this->safe(function () {
            $data = DB::table($this->table)
                ->select('cloud_provider', DB::raw('COUNT(*) as count'), DB::raw('COUNT(DISTINCT ip_address) as unique_ips'))
                ->whereNotNull('cloud_provider')
                ->groupBy('cloud_provider')
                ->orderByDesc('count')
                ->get();

            return response()->json([
                'success' => true,
                'data' => $data,
            ]);
        });
    }

    public function topIps(Request $request): JsonResponse
    {
        $request->validate(['limit' => 'sometimes|integer|min:1|max:100']);

        return $this->safe(function () use ($request) {
            $limit = $request->get('limit', 20);

            $data = DB::table($this->table)
                ->select('ip_address', 'country_name', 'cloud_provider', 'is_foreign', DB::raw('COUNT(*) as threat_count'))
                ->groupBy('ip_address', 'country_name', 'cloud_provider', 'is_foreign')
                ->orderByDesc('threat_count')
                ->limit($limit)
                ->get();

            return response()->json([
                'success' => true,
                'data' => $data,
            ]);
        });
    }

    public function timeline(Request $request): JsonResponse
    {
        $request->validate(['days' => 'sometimes|integer|min:1|max:365']);

        return $this->safe(function () use ($request) {
            $days = $request->get('days', 7);

            $data = DB::table($this->table)
                ->selectRaw('CAST(created_at AS DATE) as date, threat_level, COUNT(*) as count')
                ->where('created_at', '>=', now()->subDays($days))
                ->groupByRaw('CAST(created_at AS DATE), threat_level')
                ->orderBy('date')
                ->get();

            return response()->json([
                'success' => true,
                'data' => $data,
            ]);
        });
    }

    public function markFalsePositive(Request $request, int $id, ExclusionRuleService $exclusionService): JsonResponse
    {
        return $this->safe(function () use ($request, $id, $exclusionService) {
            $threat = DB::table($this->table)->where('id', $id)->first();

            if (!$threat) {
                return response()->json(['success' => false, 'message' => 'Threat not found'], 404);
            }

            DB::table($this->table)->where('id', $id)->update([
                'is_false_positive' => true,
                'updated_at' => now(),
            ]);

            $rule = $exclusionService->createFromThreat(
                $id,
                $request->user()?->id,
                $request->input('reason')
            );

            return response()->json([
                'success' => true,
                'message' => 'Marked as false positive and exclusion rule created.',
                'data' => [
                    'threat_id' => $id,
                    'exclusion_rule' => $rule,
                ],
            ]);
        });
    }

    public function exclusionRules(ExclusionRuleService $exclusionService): JsonResponse
    {
        return $this->safe(function () use ($exclusionService) {
            return response()->json([
                'success' => true,
                'data' => $exclusionService->all(),
            ]);
        });
    }

    public function deleteExclusionRule(int $id, ExclusionRuleService $exclusionService): JsonResponse
    {
        return $this->safe(function () use ($id, $exclusionService) {
            $deleted = $exclusionService->delete($id);

            if (!$deleted) {
                return response()->json(['success' => false, 'message' => 'Rule not found'], 404);
            }

            return response()->json([
                'success' => true,
                'message' => 'Exclusion rule deleted.',
            ]);
        });
    }

    /**
     * Sanitize a CSV cell to prevent formula injection in spreadsheet applications.
     * Prefixes cells starting with =, +, -, @, \t, \r with a single quote.
     */
    /**
     * TD-005. An ip_address cell that is not an address is replaced rather
     * than escaped.
     *
     * Escaping would keep the value readable while leaving it able to be
     * copied into a firewall rule by whatever reads the export. Replacing it
     * keeps the row — the URL, the type and the timestamp are still evidence —
     * while making the bad value obvious to the analyst.
     */
    private function sanitizeIpCell(?string $value): string
    {
        if ($value !== null && filter_var($value, FILTER_VALIDATE_IP) !== false) {
            return $value;
        }

        Log::warning(
            'Threat detection: a threat_logs row has an ip_address that is not a valid IP; '
            . 'it was replaced in the CSV export. Value: ' . var_export($value, true)
        );

        return '[INVALID IP]';
    }

    /**
     * Wrap an attacker-controlled cell in an explicit trust boundary, so a log
     * pasted into an LLM says which parts of itself are data rather than
     * instructions.
     *
     * This is "spotlighting", and it is a mitigation rather than a fix: in the
     * study that measured it, marking untrusted regions cut prompt-injection
     * success from 87.3% to 51.4% on its own, and to 8.4% only when layered
     * with input filtering and output validation. It also degrades as the
     * context window grows. Worth doing; not worth trusting alone.
     *
     * Off by default — it changes the bytes of an established export format,
     * and a pipeline parsing that CSV should not have its columns rewritten
     * because the package shipped an upgrade.
     *
     * An empty cell is left alone: wrapping nothing communicates nothing and
     * only makes the file harder to read.
     */
    private function spotlight(string $value): string
    {
        if ($value === '' || !config('threat-detection.llm_log_safety.spotlight_exports', false)) {
            return $value;
        }

        $open = (string) config('threat-detection.llm_log_safety.spotlight_open', '<<<UNTRUSTED_LOG_DATA');
        $close = (string) config('threat-detection.llm_log_safety.spotlight_close', 'END_UNTRUSTED_LOG_DATA>>>');

        // A payload that contains the closing marker could otherwise appear to
        // end the untrusted region early and have the rest read as trusted.
        $value = str_replace([$open, $close], '', $value);

        return $open . ' ' . $value . ' ' . $close;
    }

    private function sanitizeCsvCell(?string $value): string
    {
        if ($value === null) {
            return '';
        }

        /*
         * TD-003. The formula character does not have to be the first
         * character — only the first *meaningful* one.
         *
         * This tested /^[=+\-@\t\r]/, which anchors on position zero, so
         * " =1+1" and "\n=1+1" passed through unescaped. fputcsv keeps both
         * inside one quoted field, and whether the spreadsheet then evaluates
         * them depends on the importer: Excel treats a leading space as text,
         * LibreOffice's import dialog has a trim-spaces option that does not.
         *
         * Leading whitespace is now skipped before looking for the formula
         * character. The bare \t and \r case is kept as its own alternative:
         * a cell that begins with a control character is worth escaping
         * whatever follows it.
         */
        if (preg_match('/^\s*[=+\-@]/', $value) || preg_match('/^[\t\r]/', $value)) {
            return "'" . $value;
        }

        return $value;
    }
}
