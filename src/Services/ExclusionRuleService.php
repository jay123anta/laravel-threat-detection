<?php

namespace JayAnta\ThreatDetection\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

class ExclusionRuleService
{
    private const CACHE_KEY = 'threat_detection:exclusion_rules';
    private const CACHE_TTL_MINUTES = 10;

    public function getActiveRules(): array
    {
        return Cache::remember(self::CACHE_KEY, now()->addMinutes(self::CACHE_TTL_MINUTES), function () {
            if (!$this->tableExists()) {
                return [];
            }

            return DB::table('threat_exclusion_rules')
                ->where('is_active', true)
                ->get()
                ->toArray();
        });
    }

    public function isExcluded(string $type, string $url): bool
    {
        $path = parse_url($url, PHP_URL_PATH) ?? '/';
        $path = ltrim($path, '/');

        foreach ($this->getActiveRules() as $rule) {
            if ($this->labelMatches($rule->pattern_label, $type)) {
                if (empty($rule->path_pattern) || fnmatch($rule->path_pattern, $path)) {
                    return true;
                }
            }
        }

        return false;
    }

    public function createFromThreat(int $threatId, ?int $userId = null, ?string $reason = null): ?object
    {
        $tableName = config('threat-detection.table_name', 'threat_logs');
        $threat = DB::table($tableName)->where('id', $threatId)->first();

        if (!$threat) {
            return null;
        }

        $label = $threat->type;
        if (preg_match('/^\[.*?\]\s*(.+)$/', $label, $m)) {
            $label = $m[1];
        }

        $path = parse_url($threat->url, PHP_URL_PATH) ?? '/';
        $path = ltrim($path, '/');

        $id = DB::table('threat_exclusion_rules')->insertGetId([
            'pattern_label' => $label,
            'path_pattern' => $path ?: null,
            'created_from_threat_id' => $threatId,
            'created_by_user_id' => $userId,
            'reason' => $reason,
            'is_active' => true,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->clearCache();

        return DB::table('threat_exclusion_rules')->where('id', $id)->first();
    }

    public function delete(int $ruleId): bool
    {
        $deleted = DB::table('threat_exclusion_rules')->where('id', $ruleId)->delete();
        $this->clearCache();

        return $deleted > 0;
    }

    public function all(): array
    {
        if (!$this->tableExists()) {
            return [];
        }

        return DB::table('threat_exclusion_rules')
            ->orderByDesc('created_at')
            ->get()
            ->toArray();
    }

    public function clearCache(): void
    {
        Cache::forget(self::CACHE_KEY);
    }

    private function tableExists(): bool
    {
        try {
            return \Illuminate\Support\Facades\Schema::hasTable('threat_exclusion_rules');
        } catch (\Throwable $e) {
            return false;
        }
    }

    private function labelMatches(string $ruleLabel, string $threatType): bool
    {
        return str_contains($threatType, $ruleLabel);
    }
}
