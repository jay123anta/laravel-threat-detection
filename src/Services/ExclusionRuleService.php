<?php

namespace JayAnta\ThreatDetection\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Schema;

class ExclusionRuleService
{
    private const CACHE_KEY = 'threat_detection:exclusion_rules';

    private const CACHE_TTL_MINUTES = 10;

    /** The width of threat_exclusion_rules.path_pattern: a plain string() column. */
    private const MAX_PATH_LENGTH = 255;

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
        $path = $this->pathOf($url);

        foreach ($this->getActiveRules() as $rule) {
            if ($this->labelMatches($rule->pattern_label, $type) && $this->coversPath($rule, $path)) {
                return true;
            }
        }

        return false;
    }

    /**
     * A URL's path as rules store it — no leading slash, the root as '' — or
     * null when the URL cannot be parsed.
     *
     * parse_url() returns null for a URL with no path, which is the root, and
     * false for one it cannot read at all. The two used to be folded together
     * by `?? '/'`, which lets false through: an unreadable URL came out as ''.
     */
    private function pathOf(string $url): ?string
    {
        $path = parse_url($url, PHP_URL_PATH);

        if ($path === false) {
            return null;
        }

        return ltrim($path ?? '', '/');
    }

    /**
     * Does this rule reach this path?
     *
     * A rule built from a logged row names that row's path, literally.
     * Matching it with fnmatch() made the requester's path a glob — and the
     * requester chose it. A request for `/*` carrying an injection, marked as
     * noise, silenced that label on every path of the site, permanently.
     * Exclusions are the part of a detector that ratchets: across nine years
     * of SigmaHQ rules they were added 5.4 times for every one removed, and
     * 64.1% of path exclusions were satisfiable by an unprivileged attacker
     * (arXiv:2608.31062).
     *
     * The same holds for a row-derived rule with no path. Earlier versions
     * stored the root's empty path as null, which on a hand-written rule means
     * every path — so one false-positive click on the home page silenced the
     * label site-wide. On a row-derived rule it means the root.
     *
     * Deciding by origin rather than by rewriting the stored path means rules
     * that already exist are fixed too, with no migration. A rule an operator
     * wrote by hand is still a glob, and still label-wide when it has no path:
     * there, the pattern is theirs.
     *
     * A path that could not be parsed matches no path-scoped rule.
     */
    private function coversPath(object $rule, ?string $path): bool
    {
        if (!empty($rule->created_from_threat_id)) {
            return $path !== null && (string) ($rule->path_pattern ?? '') === $path;
        }

        if (empty($rule->path_pattern)) {
            return true;
        }

        return $path !== null && fnmatch($rule->path_pattern, $path);
    }

    /**
     * An exclusion rule scoped to one row's label and exact path.
     *
     * Null when the row does not exist, or when its path cannot be stored
     * exactly — unparseable, or longer than the column.
     */
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

        // A rule that cannot hold the row's exact path is not made at all.
        // Widening it — to null, which reads as every path — is the one
        // outcome worse than making the operator write the rule by hand.
        $path = $this->pathOf((string) $threat->url);

        if ($path === null || mb_strlen($path) > self::MAX_PATH_LENGTH) {
            return null;
        }

        $id = DB::table('threat_exclusion_rules')->insertGetId([
            'pattern_label' => $label,
            'path_pattern' => $path,
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
        $rule = DB::table('threat_exclusion_rules')->where('id', $ruleId)->first();

        $deleted = DB::table('threat_exclusion_rules')->where('id', $ruleId)->delete();
        $this->clearCache();

        if ($deleted > 0 && $rule) {
            Log::info('Threat exclusion rule deleted', [
                'rule_id' => $ruleId,
                'pattern_label' => $rule->pattern_label,
                'path_pattern' => $rule->path_pattern ?? '*',
            ]);
        }

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
            return Schema::hasTable('threat_exclusion_rules');
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * Match on the label portion of a "[source] Label" type, exactly.
     *
     * Substring matching here gave a rule an unbounded blast radius: a row with
     * pattern_label 'SQL' would silently disable all nineteen SQL patterns, and
     * 'Admin Path Access' would also swallow 'Admin Path Access Attempt'.
     * createFromThreat() has always stored the exact label, so this is a
     * tightening, not a behaviour change, for rules the package created itself.
     */
    private function labelMatches(string $ruleLabel, string $threatType): bool
    {
        $label = preg_match('/^\[.*?\]\s*(.+)$/', $threatType, $m) ? $m[1] : $threatType;

        return $label === $ruleLabel;
    }
}
