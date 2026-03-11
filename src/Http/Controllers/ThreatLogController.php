<?php

namespace JayAnta\ThreatDetection\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Response;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Services\ExclusionRuleService;

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
            return $callback();
        } catch (\Throwable $e) {
            \Illuminate\Support\Facades\Log::error('Threat detection API error: ' . $e->getMessage());

            return response()->json([
                'success' => false,
                'message' => 'Database query failed. Has the threat_logs migration been run?',
            ], 500);
        }
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
                'data' => $query->latest()->paginate($request->get('per_page', 20))
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
                ->selectRaw("CAST(created_at AS DATE) as date, COUNT(*) as count")
                ->where('created_at', '>=', now()->subDays(30))
                ->groupByRaw("CAST(created_at AS DATE)")
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
                ]
            ]);
        });
    }

    public function stats(): JsonResponse
    {
        return $this->safe(function () {
            $today = today()->toDateString();
            $lastHour = now()->subHour();

            $row = DB::table($this->table)
                ->selectRaw("COUNT(*) as total_threats")
                ->selectRaw("SUM(CASE WHEN threat_level = 'high' THEN 1 ELSE 0 END) as high_severity")
                ->selectRaw("SUM(CASE WHEN threat_level = 'medium' THEN 1 ELSE 0 END) as medium_severity")
                ->selectRaw("SUM(CASE WHEN threat_level = 'low' THEN 1 ELSE 0 END) as low_severity")
                ->selectRaw("COUNT(DISTINCT ip_address) as unique_ips")
                ->selectRaw("COUNT(DISTINCT CASE WHEN is_foreign = 1 THEN ip_address END) as foreign_ips")
                ->selectRaw("SUM(CASE WHEN cloud_provider IS NOT NULL THEN 1 ELSE 0 END) as cloud_attacks")
                ->selectRaw("SUM(CASE WHEN DATE(created_at) = ? THEN 1 ELSE 0 END) as today", [$today])
                ->selectRaw("SUM(CASE WHEN created_at >= ? THEN 1 ELSE 0 END) as last_hour", [$lastHour])
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
                'data' => $stats
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
                'data' => ['count' => $count]
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
                'data' => $threat
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
                ]
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
                'data' => $data
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
                return [
                    $log->id,
                    $log->created_at,
                    $this->sanitizeCsvCell($log->ip_address),
                    $this->sanitizeCsvCell($log->url),
                    $this->sanitizeCsvCell($log->type),
                    $log->threat_level,
                    ($log->confidence_score ?? 0) . '%',
                    ($log->is_false_positive ?? false) ? 'Yes' : 'No',
                    $log->action_taken,
                    $log->country_name ?? 'N/A',
                    $log->cloud_provider ?? 'N/A',
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

            return Response::make($csvOutput, 200, [
                'Content-Type' => 'text/csv',
                'Content-Disposition' => "attachment; filename=\"$filename\"",
            ]);
        } catch (\Throwable $e) {
            \Illuminate\Support\Facades\Log::error('Threat detection API error: ' . $e->getMessage());

            return response()->json([
                'success' => false,
                'message' => 'Database query failed. Has the threat_logs migration been run?',
            ], 500);
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
                'data' => $data
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
                'data' => $data
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
                'data' => $data
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
                'data' => $data
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
    private function sanitizeCsvCell(?string $value): string
    {
        if ($value === null) {
            return '';
        }

        if (preg_match('/^[=+\-@\t\r]/', $value)) {
            return "'" . $value;
        }

        return $value;
    }
}
