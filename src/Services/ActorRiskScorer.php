<?php

namespace JayAnta\ThreatDetection\Services;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * Ranks actors by how much their behaviour, taken together, looks like a
 * deliberate campaign rather than a passing scan.
 *
 * Read-only and on demand. Nothing is written, and nothing here runs during a
 * request — it reads threat_logs, plus threat_actor_signals when that is
 * available.
 *
 * ── Why not just sort by severity ──────────────────────────────────────────
 *
 * Because it barely works. Across eight alert datasets from five environments,
 * prioritising by rule severity scored AUROC 0.72, while a weighted
 * combination of severity, accumulation, variety, rarity and periodicity
 * scored 0.92 (arXiv:2609.02465). Severity is one dimension of five, and it is
 * the one this package already had.
 *
 * ── Why the terms add instead of averaging ─────────────────────────────────
 *
 * A weighted average has a proven ceiling: when every event scores the same s,
 * the average is s regardless of how many events there are. A persistent
 * attacker therefore scores identically to one suspicious request and can
 * never cross a threshold above s — the exact opposite of the intuition that
 * persistence should raise suspicion. Accumulating fixes it. The shape used
 * here — peak, plus persistence, plus diversity, plus additive bonuses —
 * reached 90.8% recall at 1.20% false positives over 10,654 cases
 * (arXiv:2602.11247).
 *
 * The weights are that paper's defaults, tuned for multi-turn LLM
 * conversations rather than HTTP actors. They are a considered starting point,
 * not a transferred result. Read the output as a ranking, not a verdict.
 */
class ActorRiskScorer
{
    private ?ActorAttributionStore $attribution;

    /**
     * The store is optional so `new ActorRiskScorer` keeps working; the
     * container injects the shared instance.
     */
    public function __construct(?ActorAttributionStore $attribution = null)
    {
        $this->attribution = $attribution;
    }

    /**
     * Score one actor's behaviour in the window.
     *
     * Returns the score out of 100 alongside every term that produced it, so
     * an operator can see *why* an actor ranks where it does. A score with no
     * visible reasoning is not actionable, and this one is a ranking heuristic
     * rather than a measurement — showing the parts is what keeps it honest.
     *
     * @return array<string, mixed>
     */
    public function score(string $actorKey, ?int $minutesBack = null): array
    {
        $minutes = $minutesBack ?? $this->intSetting('window_minutes', 60);
        $since = now()->subMinutes(max($minutes, 1));
        $table = config('threat-detection.table_name', 'threat_logs');

        $rows = DB::table($table)
            ->select('type', 'threat_level', 'created_at')
            ->where('ip_address', $actorKey)
            ->where('created_at', '>=', $since)
            ->orderBy('created_at')
            ->limit(500)
            ->get();

        if ($rows->isEmpty()) {
            return $this->emptyScore($actorKey, $minutes);
        }

        $weights = (array) config('threat-detection.actor_score.severity_weight', []);

        // Peak: the single most severe thing this actor did. A lower bound on
        // how much attention they deserve.
        $peak = 0.0;
        foreach ($rows as $row) {
            $peak = max($peak, (float) ($weights[$row->threat_level] ?? 0));
        }

        $types = $rows->pluck('type')->unique();

        /*
         * Persistence, saturating and scaled by severity.
         *
         * Saturating because one detection versus six matters while six
         * hundred versus sixty does not, and an unbounded term would let
         * volume drown out everything else.
         *
         * Scaled because persistence should amplify real evidence, not
         * manufacture it. Unscaled, six low-severity detections — the kind a
         * pasted SQL error or a chatty integration produces — reached the same
         * 0.45 as six confirmed injections, and a steady trickle of them
         * scored 70/100 on its own. A test caught that, and the fix is to make
         * repetition worth as much as the thing being repeated.
         */
        $saturation = max($this->intSetting('persistence_saturation', 6), 1);
        $severityCeiling = max(array_map('floatval', $weights ?: [1.0])) ?: 1.0;
        $persistence = min(1.0, $rows->count() / $saturation)
            * $this->floatSetting('persistence_factor', 0.45)
            * ($peak / $severityCeiling);

        // Variety: probing several weaknesses is more deliberate than
        // repeating one.
        $diversity = max(0, $types->count() - 1) * $this->floatSetting('diversity_factor', 0.15);

        // Kill-chain progression: reconnaissance and an exploit attempt from
        // the same actor. Either alone is ordinary; both is a sequence.
        $recon = $types->contains(fn ($type) => str_starts_with((string) $type, '[probe]'));
        $exploit = $rows->contains(
            fn ($row) => $row->threat_level === 'high' && !str_starts_with((string) $row->type, '[probe]')
        );
        $progression = $recon && $exploit ? $this->floatSetting('progression_bonus', 0.2) : 0.0;

        // Mutation: many surface forms of one attack. The strongest single
        // indicator in the source formula, and the one this package is built
        // to see.
        $variants = $this->peakVariantCount($actorKey, $since);
        $mutation = $variants >= max($this->intSetting('mutation_min_variants', 5), 2)
            ? $this->floatSetting('mutation_bonus', 0.3)
            : 0.0;

        // Periodicity: the weakest term, and never decisive alone. Measured on
        // first sightings, never on threat_logs rows — see
        // firstSightingTimes() for why.
        $cadence = $this->cadenceBonus($this->firstSightingTimes($actorKey, $since));

        // Identity, when a second source has an opinion about it. Empty —
        // and absent from the output — unless the integration is enabled.
        $identity = $this->identityTerms($actorKey, $exploit);

        $total = $peak + $persistence + $diversity + $progression + $mutation + $cadence['bonus']
            + array_sum($identity);
        $score = (int) round(min(1.0, max(0.0, $total)) * 100);

        return [
            'actor_key' => $actorKey,
            'score' => $score,
            'window_minutes' => $minutes,
            'detections' => $rows->count(),
            'distinct_types' => $types->count(),
            'peak_variants' => $variants,
            'reached_recon' => $recon,
            'reached_exploit' => $exploit,
            'components' => [
                'peak' => round($peak, 3),
                'persistence' => round($persistence, 3),
                'diversity' => round($diversity, 3),
                'progression' => round($progression, 3),
                'mutation' => round($mutation, 3),
                'cadence' => round($cadence['bonus'], 3),
            ] + array_map(fn (float $value) => round($value, 3), $identity),
            'cadence_variation' => $cadence['variation'],
        ];
    }

    /**
     * The actors worth looking at first.
     *
     * Candidates come from threat_logs rather than from every address seen, so
     * an actor with no detections is never scored.
     *
     * @return array<int, array<string, mixed>>
     */
    public function topActors(?int $minutesBack = null, int $limit = 10): array
    {
        if (!config('threat-detection.actor_score.enabled', false)) {
            return [];
        }

        $minutes = $minutesBack ?? $this->intSetting('window_minutes', 60);
        $table = config('threat-detection.table_name', 'threat_logs');

        $candidates = DB::table($table)
            ->select('ip_address', DB::raw('COUNT(*) as detections'))
            ->where('created_at', '>=', now()->subMinutes(max($minutes, 1)))
            ->groupBy('ip_address')
            // Score the busiest candidates rather than every address: the
            // score needs a query per actor, and an actor with one low
            // detection cannot reach a useful score anyway.
            ->orderByDesc('detections')
            ->limit(max($limit, 1) * 5)
            ->get();

        $scored = [];
        foreach ($candidates as $candidate) {
            $scored[] = $this->score((string) $candidate->ip_address, $minutes);
        }

        usort($scored, fn ($a, $b) => $b['score'] <=> $a['score']);

        return array_slice($scored, 0, max($limit, 1));
    }

    /**
     * What a second source says about who this actor is.
     *
     * Two terms, and the asymmetry between them is the whole design:
     *
     * **impersonation** adds. A client that claimed a verifiable identity and
     * failed every check is doing something deliberate. Imperva found 16.3% of
     * 1,000 sites subject to Googlebot impersonation; one published audit
     * found 107 of 799 requests bearing Googlebot's name were genuine. The
     * reason attackers do it is to inherit the trust sites extend to crawlers
     * — so next to detections of our own it is corroboration, not noise.
     *
     * **attribution** subtracts, and only ever subtracts a little. The
     * tempting version of this feature exempts verified crawlers outright,
     * which rebuilds precisely the hole the impersonation is hunting for.
     * Trust signals are imitable once an attacker accumulates them
     * (arXiv:2607.18659), and identity-based classification catches 8–18% of
     * bots (arXiv:2603.28546), so a verified verdict lowers the ranking rather
     * than clearing it — and not at all for an actor that already reached the
     * exploitation stage. A verified Googlebot sending UNION SELECT is
     * compromised, proxied or wrongly verified; none of those earns a
     * discount.
     *
     * @return array<string, float> Empty when the integration is off, which
     *                              keeps the output shape byte-identical.
     */
    private function identityTerms(string $actorKey, bool $reachedExploit): array
    {
        if (!config('threat-detection.ai_guard.enabled', false)) {
            return [];
        }

        $terms = ['impersonation' => 0.0, 'attribution' => 0.0];

        $known = $this->attributionStore()->forActor($actorKey);
        $status = $known['status'] ?? null;

        if ($status === ActorAttributionStore::STATUS_SPOOFED) {
            $terms['impersonation'] = $this->aiGuardFloat('spoofed_bonus', 0.25);

            return $terms;
        }

        if ($status !== ActorAttributionStore::STATUS_VERIFIED || $reachedExploit) {
            return $terms;
        }

        $categories = config('threat-detection.ai_guard.discount_categories', []);

        if (is_array($categories) && in_array($known['category'] ?? null, $categories, true)) {
            $terms['attribution'] = -1 * abs($this->aiGuardFloat('verified_discount', 0.25));
        }

        return $terms;
    }

    private function attributionStore(): ActorAttributionStore
    {
        return $this->attribution ??= new ActorAttributionStore;
    }

    private function aiGuardFloat(string $key, float $default): float
    {
        $value = config("threat-detection.ai_guard.{$key}", $default);

        return is_numeric($value) ? (float) $value : $default;
    }

    /**
     * The largest number of distinct surface forms this actor produced for any
     * single normalised payload — the length of their longest mutation chain.
     *
     * Zero when actor signals are unavailable, which simply removes the term.
     */
    private function peakVariantCount(string $actorKey, \DateTimeInterface $since): int
    {
        if (!config('threat-detection.actor_signals.enabled', false)) {
            return 0;
        }

        $table = config('threat-detection.actor_signals.table', 'threat_actor_signals');

        if (!is_string($table) || $table === '' || !Schema::hasTable($table)) {
            return 0;
        }

        $peak = DB::table($table)
            ->select(DB::raw('COUNT(DISTINCT variant) as variant_count'))
            ->where('actor_key', $actorKey)
            ->where('created_at', '>=', $since)
            ->groupBy('fingerprint')
            ->orderByDesc('variant_count')
            ->limit(1)
            ->value('variant_count');

        return (int) ($peak ?? 0);
    }

    /**
     * When this actor first sent each distinct thing — the only timestamps
     * the package records that the attacker's pace alone produced.
     *
     * Not threat_logs rows. Those are deduplicated to one per IP per type per
     * five minutes, so an actor repeating one attack for half an hour leaves
     * rows almost exactly 300 seconds apart whatever its real pace — near-zero
     * variation, and the cadence bonus awarded for the package's own dedup
     * window. And not raw signal rows either: those are deduplicated per
     * variant for an hour, so the same artefact returns at a longer period.
     * The first sighting of each variant is set by the attacker and nothing
     * else, which makes the gaps between them the real iteration pace.
     *
     * Empty — and the term therefore zero — without actor signals. Better no
     * cadence than a measurement of ourselves.
     *
     * @return array<int, mixed>
     */
    private function firstSightingTimes(string $actorKey, \DateTimeInterface $since): array
    {
        if (!config('threat-detection.actor_signals.enabled', false)) {
            return [];
        }

        $table = config('threat-detection.actor_signals.table', 'threat_actor_signals');

        if (!is_string($table) || $table === '' || !Schema::hasTable($table)) {
            return [];
        }

        $firstSeen = DB::table($table)
            ->select(DB::raw('MIN(created_at) as first_seen'))
            ->where('actor_key', $actorKey)
            ->where('created_at', '>=', $since)
            ->groupBy('variant')
            ->orderBy('first_seen')
            ->limit(500)
            ->pluck('first_seen')
            ->all();

        // Distinct moments, not distinct rows. One request matching three
        // labels, or carrying payloads in two places, is one event; left as
        // three same-second timestamps its zero gaps swamp the variation and
        // hide a genuinely scripted rhythm.
        return array_values(array_unique(array_map('strval', $firstSeen)));
    }

    /**
     * How machine-regular the spacing between attempts is.
     *
     * Read this as *scripted regularity*, never as a sign of AI. All four
     * "pause-think-act" timing features were removed by backward elimination
     * with no loss of agent recall (arXiv:2607.26935, browser telemetry);
     * GPT-4o agents averaged 1.20 s between replies in the calibration of an
     * SSH honeypot, against 0.67 s for bots in the wild (arXiv:2410.13919);
     * and timestamps here are whole seconds, too coarse to separate those
     * even if it were meaningful. Metronomic spacing is what scripts do.
     *
     * Measured as the coefficient of variation of the gaps: near zero means
     * metronomic. Deliberately the weakest term in the score, because a page
     * pulling twenty assets is regular too — it nudges an actor that is
     * already scoring for other reasons, and can never carry one alone.
     *
     * @param  array<int, mixed>  $timestamps
     * @return array{bonus: float, variation: float|null}
     */
    private function cadenceBonus(array $timestamps): array
    {
        $minSamples = max($this->intSetting('cadence_min_samples', 5), 3);

        if (count($timestamps) < $minSamples) {
            return ['bonus' => 0.0, 'variation' => null];
        }

        $times = [];
        foreach ($timestamps as $timestamp) {
            $parsed = strtotime((string) $timestamp);
            if ($parsed !== false) {
                $times[] = $parsed;
            }
        }

        sort($times);

        $gaps = [];
        for ($i = 1, $n = count($times); $i < $n; $i++) {
            $gaps[] = $times[$i] - $times[$i - 1];
        }

        if (count($gaps) < 2) {
            return ['bonus' => 0.0, 'variation' => null];
        }

        $mean = array_sum($gaps) / count($gaps);

        // Everything in the same second tells us the requests were fast, not
        // that they were evenly spaced; the DB stores whole seconds, so the
        // gaps are all zero and the ratio is undefined. Persistence already
        // covers a burst.
        if ($mean <= 0.0) {
            return ['bonus' => 0.0, 'variation' => null];
        }

        $variance = 0.0;
        foreach ($gaps as $gap) {
            $variance += ($gap - $mean) ** 2;
        }
        $variation = sqrt($variance / count($gaps)) / $mean;

        $bonus = $variation <= $this->floatSetting('cadence_max_variation', 0.25)
            ? $this->floatSetting('cadence_bonus', 0.1)
            : 0.0;

        return ['bonus' => $bonus, 'variation' => round($variation, 3)];
    }

    /**
     * An actor this package never detected anything from.
     *
     * The identity terms are reported as zero rather than applied, even for
     * an actor caught impersonating a crawler. That finding belongs to the
     * other package; scoring it here would mean this one reporting a detection
     * it did not make. The terms adjust our own evidence — they never stand in
     * for it.
     *
     * @return array<string, mixed>
     */
    private function emptyScore(string $actorKey, int $minutes): array
    {
        return [
            'actor_key' => $actorKey,
            'score' => 0,
            'window_minutes' => $minutes,
            'detections' => 0,
            'distinct_types' => 0,
            'peak_variants' => 0,
            'reached_recon' => false,
            'reached_exploit' => false,
            'components' => [
                'peak' => 0.0,
                'persistence' => 0.0,
                'diversity' => 0.0,
                'progression' => 0.0,
                'mutation' => 0.0,
                'cadence' => 0.0,
            ] + (config('threat-detection.ai_guard.enabled', false)
                ? ['impersonation' => 0.0, 'attribution' => 0.0]
                : []),
            'cadence_variation' => null,
        ];
    }

    private function floatSetting(string $key, float $default): float
    {
        $value = config("threat-detection.actor_score.{$key}", $default);

        return is_numeric($value) ? (float) $value : $default;
    }

    private function intSetting(string $key, int $default): int
    {
        $value = config("threat-detection.actor_score.{$key}", $default);

        return is_numeric($value) && (int) $value > 0 ? (int) $value : $default;
    }
}
