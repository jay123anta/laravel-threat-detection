<?php

namespace JayAnta\ThreatDetection\Services;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * Read-only reporting over the threat log.
 *
 * Split out of ThreatDetectionService, which had grown past 1,900 lines by
 * carrying both the request-time detection path and this after-the-fact
 * analysis. Nothing here runs during a request: every method is an aggregate
 * query answering "what has been happening", for the dashboard, the API and
 * the stats command.
 *
 * ThreatDetectionService still exposes these methods and delegates to this
 * class, so the facade and any existing call sites keep working unchanged.
 */
class ThreatCorrelationService
{
    /*
     * How many addresses or actors a report lists beside its exact count.
     *
     * These reports are read while an attack is under way, and the lists
     * behind them are as long as the attacker makes them. They were fetched
     * whole — every distinct address in one query — so a distributed attack
     * from a hundred thousand addresses loaded that many rows into PHP, and
     * the coordinated report returned them all. The lists are now samples,
     * fetched with a limit; the counts stay exact.
     */
    private const SAMPLE_ADDRESSES = 50;

    private const SAMPLE_CAMPAIGN_ADDRESSES = 10;

    private const SAMPLE_ACTORS = 200;

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

        // A bounded sample per URL — at most 20 small queries — rather than
        // every distinct address in one. unique_ips stays the exact count.
        $ipsByUrl = [];
        foreach ($coordinatedAttacks as $attack) {
            $ipsByUrl[$attack->url] = DB::table($table)
                ->where('url', $attack->url)
                ->where('created_at', '>=', $timeThreshold)
                ->distinct()
                ->orderBy('ip_address')
                ->limit(self::SAMPLE_ADDRESSES)
                ->pluck('ip_address')
                ->all();
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

        // A bounded sample per campaign — at most 15 small queries. The
        // single query this replaced fetched every address and kept ten.
        $ipsByType = [];
        foreach ($campaigns as $campaign) {
            $ipsByType[$campaign->type] = DB::table($table)
                ->where('type', $campaign->type)
                ->where('created_at', '>=', $timeThreshold)
                ->distinct()
                ->orderBy('ip_address')
                ->limit(self::SAMPLE_CAMPAIGN_ADDRESSES)
                ->pluck('ip_address')
                ->all();
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

    /**
     * Actors iterating on a payload: many distinct surface forms of one attack
     * from one actor inside a window.
     *
     * This is the signature the whole AI-attacker line is named for. A human
     * with a scanner sends a fixed list; something adapting to your defences
     * sends a payload, sees it fail, rewrites it and sends it again — which
     * shows up as the variant count climbing while the fingerprint stays put.
     *
     * Reading it requires both hashes and nothing else. Distinct *variants*
     * per (actor, fingerprint) is the count: distinct fingerprints would score
     * a bypass loop as one event, because normalisation is exactly what makes
     * the mutations converge.
     *
     * Returns [] unless actor signals are enabled and the table exists — a
     * reporting call must never be the thing that breaks a dashboard.
     *
     * @return array<int, array<string, mixed>>
     */
    public function detectMutationChains(int $minutesBack = 60, int $minVariants = 5): array
    {
        $table = $this->signalsTable();

        if ($table === null) {
            return [];
        }

        $chains = DB::table($table)
            ->select(
                'actor_key',
                'fingerprint',
                'label',
                DB::raw('COUNT(DISTINCT variant) as variant_count'),
                DB::raw('MIN(created_at) as first_seen'),
                DB::raw('MAX(created_at) as last_seen')
            )
            ->where('created_at', '>=', now()->subMinutes(max($minutesBack, 1)))
            ->groupBy('actor_key', 'fingerprint', 'label')
            ->havingRaw('COUNT(DISTINCT variant) >= ?', [max($minVariants, 2)])
            ->orderByDesc('variant_count')
            ->limit(20)
            ->get();

        return $chains->map(function ($chain) {
            $seconds = max(strtotime((string) $chain->last_seen) - strtotime((string) $chain->first_seen), 1);

            return [
                'actor_key' => $chain->actor_key,
                'fingerprint' => $chain->fingerprint,
                'label' => $chain->label,
                'variant_count' => (int) $chain->variant_count,
                'first_seen' => $chain->first_seen,
                'last_seen' => $chain->last_seen,
                // How fast they are iterating. A person editing a payload by
                // hand manages a few a minute; a loop manages more.
                'variants_per_minute' => round($chain->variant_count / max($seconds / 60, 1), 2),
            ];
        })->toArray();
    }

    /**
     * One actor, many *different* payloads of one attack class.
     *
     * The complement of a mutation chain. A chain is one payload in many
     * encodings — what a tamper script produces — and it is grouped by
     * fingerprint, so an attacker who writes a genuinely new payload each
     * time shows up as a row of one-variant chains and is never seen.
     * That is how a generating attacker iterates: an LLM-driven web
     * exploitation agent converged in 10–40 newly generated payload
     * attempts, averaging 10, 20 and 40 by difficulty (AWE,
     * arXiv:2603.00960), while LLMs are poor at the encoding tricks a chain
     * detects.
     *
     * Adaptive, not AI: a scanner iterating a payload list leaves the same
     * shape. The default minimum of five sits below the easiest level AWE
     * reported.
     *
     * @return array<int, array<string, mixed>>
     */
    public function detectRetryBursts(int $minutesBack = 60, int $minPayloads = 5): array
    {
        $table = $this->signalsTable();

        if ($table === null) {
            return [];
        }

        $bursts = DB::table($table)
            ->select(
                'actor_key',
                'label',
                DB::raw('COUNT(DISTINCT fingerprint) as payload_count'),
                DB::raw('MIN(created_at) as first_seen'),
                DB::raw('MAX(created_at) as last_seen')
            )
            ->where('created_at', '>=', now()->subMinutes(max($minutesBack, 1)))
            ->groupBy('actor_key', 'label')
            ->havingRaw('COUNT(DISTINCT fingerprint) >= ?', [max($minPayloads, 2)])
            ->orderByDesc('payload_count')
            ->limit(20)
            ->get();

        return $bursts->map(fn ($burst) => [
            'actor_key' => $burst->actor_key,
            'label' => $burst->label,
            'payload_count' => (int) $burst->payload_count,
            'first_seen' => $burst->first_seen,
            'last_seen' => $burst->last_seen,
        ])->toArray();
    }

    /**
     * One payload seen from many actors: a campaign whose egress rotates.
     *
     * Clustering on the *fingerprint* is what makes this work. Serverless and
     * worker-pool egress gives an attacker a fresh IP per request almost for
     * free, so grouping by address finds nothing — but the payload still means
     * the same thing after normalisation however many addresses it arrives
     * from.
     *
     * A single shared fingerprint is weak evidence: every install on the
     * internet is hit by the same handful of off-the-shelf scanner strings.
     * The interesting case is *several* fingerprints shared by the same set of
     * actors, so minFingerprints defaults above one.
     *
     * @return array<int, array<string, mixed>>
     */
    public function detectPayloadClusters(int $minutesBack = 60, int $minActors = 3, int $minFingerprints = 2): array
    {
        $table = $this->signalsTable();

        if ($table === null) {
            return [];
        }

        $since = now()->subMinutes(max($minutesBack, 1));

        $shared = DB::table($table)
            ->select('fingerprint', 'label', DB::raw('COUNT(DISTINCT actor_key) as actor_count'))
            ->where('created_at', '>=', $since)
            ->groupBy('fingerprint', 'label')
            ->havingRaw('COUNT(DISTINCT actor_key) >= ?', [max($minActors, 2)])
            ->orderByDesc('actor_count')
            ->limit(50)
            ->get();

        if ($shared->isEmpty()) {
            return [];
        }

        $clusters = [];

        foreach ($shared as $row) {
            // Which actors sent it: a bounded, ordered sample, so the same
            // set of actors always yields the same sample and still groups.
            // actor_count comes from the aggregate and stays exact.
            $actors = DB::table($table)
                ->where('fingerprint', $row->fingerprint)
                ->where('created_at', '>=', $since)
                ->distinct()
                ->orderBy('actor_key')
                ->limit(self::SAMPLE_ACTORS)
                ->pluck('actor_key');

            // Group fingerprints by the exact set of actors that sent them, so
            // one campaign spread over five addresses reads as one cluster
            // rather than as five unrelated coincidences.
            $key = $actors->implode(',');

            if (!isset($clusters[$key])) {
                $clusters[$key] = [
                    'actors' => $actors->all(),
                    'actor_count' => 0,
                    'fingerprints' => [],
                    'labels' => [],
                ];
            }

            $clusters[$key]['actor_count'] = max($clusters[$key]['actor_count'], (int) $row->actor_count);

            $clusters[$key]['fingerprints'][] = $row->fingerprint;
            $clusters[$key]['labels'][] = $row->label;
        }

        $result = [];

        foreach ($clusters as $cluster) {
            if (count($cluster['fingerprints']) < max($minFingerprints, 1)) {
                continue;
            }

            $cluster['labels'] = array_values(array_unique($cluster['labels']));
            $cluster['fingerprint_count'] = count($cluster['fingerprints']);
            $result[] = $cluster;
        }

        usort($result, fn ($a, $b) => $b['fingerprint_count'] <=> $a['fingerprint_count']);

        return array_slice($result, 0, 20);
    }

    /**
     * The actor-signals table, or null when it cannot be read.
     *
     * Both analyses above are optional extras over an opt-in feature. If the
     * feature is off, or the migration has not been run, they report nothing
     * rather than raising — the correlation endpoint and the dashboard call
     * these, and neither should fail because a later feature is not set up.
     */
    private function signalsTable(): ?string
    {
        if (!config('threat-detection.actor_signals.enabled', false)) {
            return null;
        }

        $table = config('threat-detection.actor_signals.table', 'threat_actor_signals');

        if (!is_string($table) || $table === '' || !Schema::hasTable($table)) {
            return null;
        }

        return $table;
    }

    public function getCorrelationSummary(): array
    {
        $summary = [
            'coordinated_attacks' => count($this->detectCoordinatedAttacks(15, 3)),
            'active_campaigns' => count($this->detectAttackCampaigns(24)),
            'rapid_attackers' => count($this->detectRapidAttacks(5, 10)),
        ];

        /*
         * The two signal-backed counts appear only when actor signals are
         * available, so the summary an existing install receives is exactly
         * the summary it received before this release — same keys, same order.
         *
         * Adding keys that are always zero would have been easier and is
         * usually harmless, but this array is compared whole by the package's
         * own tests and may be by somebody else's. "Off by default" should
         * mean the shape does not move either.
         */
        if ($this->signalsTable() !== null) {
            $summary['mutation_chains'] = count($this->detectMutationChains(60, 5));
            $summary['payload_clusters'] = count($this->detectPayloadClusters(60, 3, 2));
        }

        return $summary;
    }
}
