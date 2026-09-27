<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use JayAnta\ThreatDetection\Services\ActorRiskScorer;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * Actor risk scoring — read-only ranking, opt-in.
 *
 * The property that drove the design, and the one most of this file defends:
 * the terms **accumulate**, they do not average.
 *
 * A weighted average has a proven ceiling — when every event scores the same
 * s, the average is s regardless of how many events there are, so a persistent
 * attacker scores exactly like one suspicious request and can never cross a
 * threshold above s (arXiv:2602.11247). That is the opposite of what anyone
 * means by a risk score, and it is an easy mistake to ship because the formula
 * looks reasonable. `persistence_raises_the_score_above_any_single_event`
 * exists to make it impossible to reintroduce.
 *
 * Severity is one dimension of several, not the score. Prioritising by
 * severity alone measured AUROC 0.72 against 0.92 for a weighted combination
 * across eight datasets (arXiv:2609.02465).
 */
class ActorRiskScorerTest extends TestCase
{
    private const SIGNALS = 'threat_actor_signals';

    private ActorRiskScorer $scorer;

    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        config(['threat-detection.actor_score.enabled' => true]);

        $this->scorer = new ActorRiskScorer;
    }

    private function createSignalsTable(): void
    {
        Schema::create(self::SIGNALS, function (Blueprint $table) {
            $table->id();
            $table->string('actor_key', 100);
            $table->string('fingerprint', 32);
            $table->string('variant', 32);
            $table->string('label', 100);
            $table->string('context', 20);
            $table->date('observed_on');
            $table->timestamp('created_at')->nullable();
        });

        config([
            'threat-detection.actor_signals.enabled' => true,
            'threat-detection.actor_signals.table' => self::SIGNALS,
        ]);
    }

    private function detection(string $ip, string $type, string $level, ?string $at = null): void
    {
        $when = $at ?? now()->toDateTimeString();

        DB::table('threat_logs')->insert([
            'ip_address' => $ip,
            'url' => 'https://example.com/x',
            'user_agent' => 'curl/8.0',
            'type' => $type,
            'payload' => 'x',
            'threat_level' => $level,
            'confidence_score' => 80,
            'confidence_label' => 'high',
            'action_taken' => 'logged',
            'created_at' => $when,
            'updated_at' => $when,
        ]);
    }

    // ── the property that matters ──────────────────────────────────────────

    /**
     * Ten identical medium detections must outscore one. Under a weighted
     * average they would score the same, and the attacker would be invisible
     * to any threshold above a single event's value.
     */
    #[Test]
    public function persistence_raises_the_score_above_any_single_event(): void
    {
        $this->detection('203.0.113.1', '[middleware] SQL Injection UNION', 'medium');
        $one = $this->scorer->score('203.0.113.1')['score'];

        for ($i = 0; $i < 10; $i++) {
            $this->detection('203.0.113.2', '[middleware] SQL Injection UNION', 'medium');
        }
        $many = $this->scorer->score('203.0.113.2')['score'];

        $this->assertGreaterThan(
            $one,
            $many,
            'ten identical detections scored no higher than one — the terms are averaging, not accumulating'
        );
    }

    /** Persistence saturates, so volume alone cannot dominate the score. */
    #[Test]
    public function persistence_saturates_rather_than_growing_without_bound(): void
    {
        for ($i = 0; $i < 6; $i++) {
            $this->detection('203.0.113.3', '[middleware] SQL Injection UNION', 'low');
        }
        $atSaturation = $this->scorer->score('203.0.113.3')['components']['persistence'];

        for ($i = 0; $i < 300; $i++) {
            $this->detection('203.0.113.4', '[middleware] SQL Injection UNION', 'low');
        }
        $farPast = $this->scorer->score('203.0.113.4')['components']['persistence'];

        $this->assertSame($atSaturation, $farPast, 'persistence kept climbing, so sheer volume drowns the other terms');
    }

    // ── the individual dimensions ──────────────────────────────────────────

    #[Test]
    public function peak_severity_contributes_and_a_high_outranks_a_low(): void
    {
        $this->detection('203.0.113.5', '[middleware] XSS Script Tag', 'low');
        $this->detection('203.0.113.6', '[middleware] XSS Script Tag', 'high');

        $this->assertGreaterThan(
            $this->scorer->score('203.0.113.5')['score'],
            $this->scorer->score('203.0.113.6')['score']
        );
    }

    #[Test]
    public function probing_several_weaknesses_outscores_repeating_one(): void
    {
        for ($i = 0; $i < 4; $i++) {
            $this->detection('203.0.113.7', '[middleware] SQL Injection UNION', 'medium');
        }

        foreach (['SQL Injection UNION', 'XSS Script Tag', 'Directory Traversal', 'RCE Shell Function'] as $type) {
            $this->detection('203.0.113.8', "[middleware] {$type}", 'medium');
        }

        $this->assertGreaterThan(
            $this->scorer->score('203.0.113.7')['score'],
            $this->scorer->score('203.0.113.8')['score'],
            'variety added nothing, so a scanner sweeping four weaknesses ranks like one repeated probe'
        );
    }

    /**
     * Kill-chain progression. Recon and exploitation from the same actor is a
     * sequence; either on its own is ordinary traffic on the internet.
     */
    #[Test]
    public function recon_followed_by_exploitation_scores_above_either_alone(): void
    {
        $this->detection('203.0.113.9', '[probe] Environment File', 'medium');
        $reconOnly = $this->scorer->score('203.0.113.9');

        $this->detection('203.0.113.10', '[middleware] SQL Injection UNION', 'high');
        $exploitOnly = $this->scorer->score('203.0.113.10');

        $this->detection('203.0.113.11', '[probe] Environment File', 'medium');
        $this->detection('203.0.113.11', '[middleware] SQL Injection UNION', 'high');
        $both = $this->scorer->score('203.0.113.11');

        $this->assertFalse($reconOnly['reached_exploit']);
        $this->assertFalse($exploitOnly['reached_recon']);
        $this->assertTrue($both['reached_recon']);
        $this->assertTrue($both['reached_exploit']);

        $this->assertGreaterThan(0, $both['components']['progression']);
        $this->assertSame(0.0, $reconOnly['components']['progression']);
        $this->assertSame(0.0, $exploitOnly['components']['progression']);
    }

    #[Test]
    public function a_mutation_chain_adds_to_the_score_when_signals_are_available(): void
    {
        $this->detection('203.0.113.12', '[middleware] SQL Injection UNION', 'medium');
        $without = $this->scorer->score('203.0.113.12');

        $this->createSignalsTable();
        for ($i = 1; $i <= 6; $i++) {
            DB::table(self::SIGNALS)->insert([
                'actor_key' => '203.0.113.12',
                'fingerprint' => 'fp-union',
                'variant' => "variant-{$i}",
                'label' => 'SQL Injection UNION',
                'context' => 'query',
                'observed_on' => now()->toDateString(),
                'created_at' => now()->toDateTimeString(),
            ]);
        }

        $with = $this->scorer->score('203.0.113.12');

        $this->assertSame(0, $without['peak_variants']);
        $this->assertSame(6, $with['peak_variants']);
        $this->assertGreaterThan($without['score'], $with['score']);
    }

    /**
     * Signals are optional. With them absent the term is simply zero, not an
     * error — the score still works on threat_logs alone.
     */
    #[Test]
    public function scoring_works_with_no_signals_table_at_all(): void
    {
        $this->detection('203.0.113.13', '[middleware] SQL Injection UNION', 'high');

        $result = $this->scorer->score('203.0.113.13');

        $this->assertGreaterThan(0, $result['score']);
        $this->assertSame(0, $result['peak_variants']);
        $this->assertSame(0.0, $result['components']['mutation']);
    }

    // ── cadence: deliberately weak ─────────────────────────────────────────
    //
    // Measured on the first sighting of each distinct variant in
    // threat_actor_signals, never on threat_logs rows: those are deduplicated
    // to one per type per five minutes, so a repeated attack leaves rows 300 s
    // apart whatever the attacker's pace. The fixtures below seed what the
    // scorer actually reads; CadenceArtefactTest drives it through HTTP.

    /** One distinct variant this actor sent, first seen at $at. */
    private function sighting(string $ip, string $variant, string $at): void
    {
        DB::table(self::SIGNALS)->insert([
            'actor_key' => $ip,
            'fingerprint' => 'fp-' . $variant,
            'variant' => $variant,
            'label' => 'SQL Injection UNION',
            'context' => 'query',
            'observed_on' => substr($at, 0, 10),
            'created_at' => $at,
        ]);
    }

    /**
     * A detection, so the actor is scored at all, plus first sightings at
     * these offsets.
     *
     * @param  array<int, int>  $secondsAgo
     */
    private function actorWithSightings(string $ip, array $secondsAgo): void
    {
        $this->detection($ip, '[middleware] SQL Injection UNION', 'low');

        foreach ($secondsAgo as $i => $offset) {
            $this->sighting($ip, "v{$i}", now()->subSeconds($offset)->toDateTimeString());
        }
    }

    #[Test]
    public function metronomic_spacing_adds_a_little_and_irregular_spacing_adds_nothing(): void
    {
        $this->createSignalsTable();

        $this->actorWithSightings('203.0.113.14', [300, 270, 240, 210, 180, 150]);
        $this->actorWithSightings('203.0.113.15', [300, 297, 250, 120, 119, 5]);

        $regular = $this->scorer->score('203.0.113.14');
        $irregular = $this->scorer->score('203.0.113.15');

        $this->assertGreaterThan(0, $regular['components']['cadence'], 'perfectly even spacing earned nothing');
        $this->assertSame(0.0, $irregular['components']['cadence'], 'irregular spacing was treated as machine-like');
    }

    /**
     * Cadence must never be enough on its own. A handful of low-severity
     * events at a steady rhythm is a cron job, not an attacker.
     */
    #[Test]
    public function cadence_alone_cannot_produce_a_high_score(): void
    {
        $this->createSignalsTable();
        $this->actorWithSightings('203.0.113.16', [300, 270, 240, 210, 180, 150]);

        $this->assertLessThan(
            70,
            $this->scorer->score('203.0.113.16')['score'],
            'steady low-severity traffic scored as if it were an attack'
        );
    }

    #[Test]
    public function too_few_samples_means_no_cadence_verdict(): void
    {
        $this->createSignalsTable();
        $this->actorWithSightings('203.0.113.17', [60, 30]);

        $result = $this->scorer->score('203.0.113.17');

        $this->assertNull($result['cadence_variation']);
        $this->assertSame(0.0, $result['components']['cadence']);
    }

    /**
     * Four perfectly even sightings, one below the minimum of five.
     *
     * This is the case that makes the minimum observable. At two samples there
     * is only one gap, so a later guard refuses anyway and the threshold could
     * be deleted without any test noticing. Four samples give three usable
     * gaps and a variation of exactly zero — so if the minimum were not
     * honoured, this would earn the bonus.
     */
    #[Test]
    public function an_evenly_spaced_run_just_below_the_minimum_earns_no_cadence(): void
    {
        $this->createSignalsTable();
        $this->actorWithSightings('203.0.113.24', [200, 170, 140, 110]);

        $result = $this->scorer->score('203.0.113.24');

        $this->assertNull($result['cadence_variation'], 'cadence was computed below the minimum sample count');
        $this->assertSame(0.0, $result['components']['cadence']);
    }

    /**
     * Exactly the rows deduplication produces for one attack repeated for half
     * an hour: 300 seconds apart. Scored from threat_logs, this earned the
     * bonus for the package's own dedup window. Without signals there is no
     * honest measurement, so there is no cadence.
     */
    #[Test]
    public function deduplicated_log_rows_never_produce_cadence(): void
    {
        for ($i = 0; $i < 7; $i++) {
            $this->detection('203.0.113.25', '[middleware] SQL Injection UNION', 'low', now()->subSeconds(1800 - $i * 300)->toDateTimeString());
        }

        $result = $this->scorer->score('203.0.113.25');

        $this->assertSame(7, $result['detections'], 'the fixture did not create the dedup-shaped rows');
        $this->assertNull($result['cadence_variation'], 'cadence was computed from deduplicated log rows');
        $this->assertSame(0.0, $result['components']['cadence']);
    }

    /**
     * Re-sightings of one variant after its signal dedup expires are the same
     * artefact at an hourly period. Only first sightings count.
     */
    #[Test]
    public function repeated_sightings_of_one_variant_are_not_a_rhythm(): void
    {
        $this->createSignalsTable();
        $this->detection('203.0.113.26', '[middleware] SQL Injection UNION', 'low');

        foreach ([3600, 2880, 2160, 1440, 720, 0] as $offset) {
            $this->sighting('203.0.113.26', 'the-same-variant', now()->subSeconds($offset)->toDateTimeString());
        }

        $result = $this->scorer->score('203.0.113.26', 120);

        $this->assertNull($result['cadence_variation'], 'one variant seen repeatedly was scored as a rhythm');
        $this->assertSame(0.0, $result['components']['cadence']);
    }

    /**
     * The shipped default, read from the config file rather than from the test
     * environment — every other test in this file switches the feature on, so
     * without this the default could flip to true unnoticed.
     */
    #[Test]
    public function the_shipped_default_leaves_scoring_switched_off(): void
    {
        $shipped = require __DIR__ . '/../../config/threat-detection.php';

        $this->assertFalse($shipped['actor_score']['enabled'], 'actor scoring is no longer off by default');
    }

    // ── bounds, windows and ranking ────────────────────────────────────────

    #[Test]
    public function the_score_is_bounded_at_one_hundred(): void
    {
        $this->createSignalsTable();

        for ($i = 0; $i < 50; $i++) {
            $this->detection('203.0.113.18', "[middleware] Attack Type {$i}", 'high', now()->subSeconds(500 - $i * 10)->toDateTimeString());
        }
        $this->detection('203.0.113.18', '[probe] Environment File', 'medium');
        for ($i = 1; $i <= 10; $i++) {
            DB::table(self::SIGNALS)->insert([
                'actor_key' => '203.0.113.18', 'fingerprint' => 'fp', 'variant' => "v{$i}",
                'label' => 'SQL Injection UNION', 'context' => 'query',
                'observed_on' => now()->toDateString(), 'created_at' => now()->toDateTimeString(),
            ]);
        }

        $this->assertSame(100, $this->scorer->score('203.0.113.18')['score']);
    }

    #[Test]
    public function an_actor_with_nothing_in_the_window_scores_zero(): void
    {
        $this->detection('203.0.113.19', '[middleware] SQL Injection UNION', 'high', now()->subHours(5)->toDateTimeString());

        $result = $this->scorer->score('203.0.113.19', 60);

        $this->assertSame(0, $result['score']);
        $this->assertSame(0, $result['detections']);
    }

    #[Test]
    public function the_ranking_puts_the_more_dangerous_actor_first(): void
    {
        $this->detection('203.0.113.20', '[middleware] SQL SELECT Query', 'low');

        $this->detection('203.0.113.21', '[probe] Environment File', 'medium');
        foreach (['SQL Injection UNION', 'XSS Script Tag', 'RCE Shell Function'] as $type) {
            $this->detection('203.0.113.21', "[middleware] {$type}", 'high');
        }

        $top = $this->scorer->topActors(60, 5);

        $this->assertNotEmpty($top);
        $this->assertSame('203.0.113.21', $top[0]['actor_key']);
        $this->assertGreaterThan($top[1]['score'], $top[0]['score']);
    }

    #[Test]
    public function the_ranking_is_empty_when_the_feature_is_off(): void
    {
        config(['threat-detection.actor_score.enabled' => false]);
        $this->detection('203.0.113.22', '[middleware] SQL Injection UNION', 'high');

        $this->assertSame([], $this->scorer->topActors(60, 5));
    }

    /**
     * The score has to explain itself. A number with no visible reasoning is
     * not actionable, and this one is a ranking heuristic rather than a
     * measurement — the parts are what keep it honest.
     */
    #[Test]
    public function the_result_shows_every_term_that_produced_it(): void
    {
        $this->detection('203.0.113.23', '[middleware] SQL Injection UNION', 'high');

        $components = $this->scorer->score('203.0.113.23')['components'];

        $this->assertSame(
            ['peak', 'persistence', 'diversity', 'progression', 'mutation', 'cadence'],
            array_keys($components)
        );
    }
}
