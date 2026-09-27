<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use JayAnta\ThreatDetection\Services\ThreatCorrelationService;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * Mutation chains and cross-actor payload clusters — the two analyses that
 * read the actor-signals table.
 *
 * Both are read-only aggregates, like the rest of ThreatCorrelationService.
 * Nothing here runs during a request.
 *
 * The distinction they rest on is worth restating, because it is what makes
 * them work and it is easy to get backwards:
 *
 *   fingerprint — the payload after normalisation. Collapses encoding.
 *   variant     — the payload as it arrived. Collapses nothing.
 *
 * A mutation chain is many variants sharing one fingerprint: the attacker
 * keeps changing the surface while the meaning stays put. A cluster is one
 * fingerprint arriving from many actors: one campaign behind rotating egress.
 */
class MutationChainDetectionTest extends TestCase
{
    private const SIGNALS = 'threat_actor_signals';

    private ThreatCorrelationService $correlation;

    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createSignalsTable();

        config([
            'threat-detection.actor_signals.enabled' => true,
            'threat-detection.actor_signals.table' => self::SIGNALS,
        ]);

        $this->correlation = new ThreatCorrelationService;
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
    }

    private function signal(
        string $actor,
        string $fingerprint,
        string $variant,
        string $label = 'SQL Injection UNION',
        ?string $at = null,
    ): void {
        $when = $at ?? now()->toDateTimeString();

        DB::table(self::SIGNALS)->insert([
            'actor_key' => $actor,
            'fingerprint' => $fingerprint,
            'variant' => $variant,
            'label' => $label,
            'context' => 'query',
            'observed_on' => substr($when, 0, 10),
            'created_at' => $when,
        ]);
    }

    // ── mutation chains ────────────────────────────────────────────────────

    #[Test]
    public function an_actor_rewriting_one_payload_is_reported_as_a_chain(): void
    {
        for ($i = 1; $i <= 6; $i++) {
            $this->signal('203.0.113.5', 'fp-union', "variant-{$i}");
        }

        $chains = $this->correlation->detectMutationChains(60, 5);

        $this->assertCount(1, $chains);
        $this->assertSame('203.0.113.5', $chains[0]['actor_key']);
        $this->assertSame(6, $chains[0]['variant_count']);
        $this->assertSame('SQL Injection UNION', $chains[0]['label']);
    }

    /**
     * The control that stops the chain detector being a volume detector. An
     * actor hammering the *same* payload is noisy, not adaptive, and the
     * recorder deduplicates it anyway — but if the query counted rows instead
     * of distinct variants it would still be reported.
     */
    #[Test]
    public function repeating_one_payload_is_not_a_chain(): void
    {
        for ($i = 0; $i < 20; $i++) {
            $this->signal('203.0.113.6', 'fp-union', 'the-same-variant');
        }

        $this->assertSame([], $this->correlation->detectMutationChains(60, 5));
    }

    /**
     * And the other way: variants of *different* attacks are not one chain.
     * Somebody running a scanner across many payload types is a different
     * thing from somebody iterating on one.
     */
    #[Test]
    public function variants_of_different_attacks_are_not_one_chain(): void
    {
        for ($i = 1; $i <= 6; $i++) {
            $this->signal('203.0.113.7', "fp-{$i}", "variant-{$i}");
        }

        $this->assertSame([], $this->correlation->detectMutationChains(60, 5));
    }

    /**
     * The reported number must be variety, not volume.
     *
     * The recorder deduplicates a repeated variant inside its window, but a
     * long-lived actor can cross that window and write the same variant twice.
     * If the count were COUNT(*) the chain would read as longer than it is,
     * and "this actor tried eight different payloads" would be false — which
     * is the number an operator would act on.
     */
    #[Test]
    public function the_reported_count_is_distinct_variants_not_rows(): void
    {
        for ($i = 1; $i <= 6; $i++) {
            $this->signal('203.0.113.13', 'fp-union', "variant-{$i}");
        }

        // Two repeats, as a later dedupe window would produce.
        $this->signal('203.0.113.13', 'fp-union', 'variant-1');
        $this->signal('203.0.113.13', 'fp-union', 'variant-2');

        $this->assertSame(8, DB::table(self::SIGNALS)->count(), 'the fixture did not create repeated rows');

        $chains = $this->correlation->detectMutationChains(60, 5);

        $this->assertCount(1, $chains);
        $this->assertSame(
            6,
            $chains[0]['variant_count'],
            'the chain reported row count rather than distinct variants, overstating how much the actor adapted'
        );
    }

    #[Test]
    public function a_chain_below_the_threshold_is_not_reported(): void
    {
        for ($i = 1; $i <= 4; $i++) {
            $this->signal('203.0.113.8', 'fp-union', "variant-{$i}");
        }

        $this->assertSame([], $this->correlation->detectMutationChains(60, 5));
        $this->assertCount(1, $this->correlation->detectMutationChains(60, 4));
    }

    #[Test]
    public function signals_outside_the_window_are_not_counted(): void
    {
        for ($i = 1; $i <= 3; $i++) {
            $this->signal('203.0.113.9', 'fp-union', "old-{$i}", 'SQL Injection UNION', now()->subHours(5)->toDateTimeString());
        }
        for ($i = 1; $i <= 3; $i++) {
            $this->signal('203.0.113.9', 'fp-union', "new-{$i}");
        }

        $this->assertSame([], $this->correlation->detectMutationChains(60, 5), 'stale signals were counted into a live chain');
        $this->assertCount(1, $this->correlation->detectMutationChains(600, 5));
    }

    #[Test]
    public function two_actors_iterating_separately_are_two_chains(): void
    {
        foreach (['203.0.113.10', '203.0.113.11'] as $actor) {
            for ($i = 1; $i <= 5; $i++) {
                $this->signal($actor, 'fp-union', "variant-{$i}");
            }
        }

        $this->assertCount(2, $this->correlation->detectMutationChains(60, 5));
    }

    #[Test]
    public function the_reported_rate_reflects_how_fast_the_actor_iterated(): void
    {
        for ($i = 1; $i <= 6; $i++) {
            $this->signal('203.0.113.12', 'fp-union', "variant-{$i}", 'SQL Injection UNION', now()->subMinutes(6 - $i)->toDateTimeString());
        }

        $chains = $this->correlation->detectMutationChains(60, 5);

        $this->assertCount(1, $chains);
        $this->assertGreaterThan(0, $chains[0]['variants_per_minute']);
        $this->assertLessThanOrEqual(6, $chains[0]['variants_per_minute']);
    }

    // ── cross-actor clusters ───────────────────────────────────────────────

    #[Test]
    public function one_payload_from_many_actors_is_reported_as_a_cluster(): void
    {
        foreach (['198.51.100.1', '198.51.100.2', '198.51.100.3'] as $actor) {
            $this->signal($actor, 'fp-a', 'v-a');
            $this->signal($actor, 'fp-b', 'v-b');
        }

        $clusters = $this->correlation->detectPayloadClusters(60, 3, 2);

        $this->assertCount(1, $clusters);
        $this->assertSame(3, $clusters[0]['actor_count']);
        $this->assertSame(2, $clusters[0]['fingerprint_count']);
    }

    /**
     * A single shared fingerprint is background noise — every install is hit
     * by the same off-the-shelf scanner strings from unrelated addresses. The
     * evidence of a campaign is several payloads shared by the same set.
     */
    #[Test]
    public function one_shared_payload_alone_is_not_a_cluster(): void
    {
        foreach (['198.51.100.4', '198.51.100.5', '198.51.100.6'] as $actor) {
            $this->signal($actor, 'fp-common', 'v-common');
        }

        $this->assertSame([], $this->correlation->detectPayloadClusters(60, 3, 2));
    }

    #[Test]
    public function a_payload_from_too_few_actors_is_not_a_cluster(): void
    {
        foreach (['198.51.100.7', '198.51.100.8'] as $actor) {
            $this->signal($actor, 'fp-a', 'v-a');
            $this->signal($actor, 'fp-b', 'v-b');
        }

        $this->assertSame([], $this->correlation->detectPayloadClusters(60, 3, 2));
        $this->assertCount(1, $this->correlation->detectPayloadClusters(60, 2, 2));
    }

    /**
     * Rotating egress is the case this exists for: the same two payloads from
     * six addresses that share nothing else.
     */
    #[Test]
    public function rotating_addresses_do_not_hide_a_campaign(): void
    {
        for ($i = 1; $i <= 6; $i++) {
            $this->signal("198.51.100.1{$i}", 'fp-x', 'v-x');
            $this->signal("198.51.100.1{$i}", 'fp-y', 'v-y');
        }

        $clusters = $this->correlation->detectPayloadClusters(60, 3, 2);

        $this->assertCount(1, $clusters);
        $this->assertSame(6, $clusters[0]['actor_count']);
    }

    // ── safe when switched off ─────────────────────────────────────────────

    #[Test]
    public function both_analyses_report_nothing_when_the_feature_is_off(): void
    {
        for ($i = 1; $i <= 6; $i++) {
            $this->signal('203.0.113.20', 'fp-union', "variant-{$i}");
        }

        config(['threat-detection.actor_signals.enabled' => false]);

        $this->assertSame([], $this->correlation->detectMutationChains(60, 5));
        $this->assertSame([], $this->correlation->detectPayloadClusters(60, 3, 2));
    }

    /**
     * The table is created by a migration the operator has to publish. Until
     * they do, a dashboard calling this must get an empty list rather than an
     * exception.
     */
    #[Test]
    public function both_analyses_report_nothing_when_the_table_is_missing(): void
    {
        Schema::drop(self::SIGNALS);

        $this->assertSame([], $this->correlation->detectMutationChains(60, 5));
        $this->assertSame([], $this->correlation->detectPayloadClusters(60, 3, 2));
    }

    #[Test]
    public function the_summary_counts_both_without_failing_when_unavailable(): void
    {
        for ($i = 1; $i <= 6; $i++) {
            $this->signal('203.0.113.21', 'fp-union', "variant-{$i}");
        }

        $summary = $this->correlation->getCorrelationSummary();

        $this->assertSame(1, $summary['mutation_chains']);
        $this->assertArrayHasKey('payload_clusters', $summary);

        // With signals unavailable the summary returns to exactly its previous
        // shape — the keys are absent rather than present-and-zero, so an
        // install that never opts in sees no change at all.
        Schema::drop(self::SIGNALS);
        $summary = $this->correlation->getCorrelationSummary();

        $this->assertArrayNotHasKey('mutation_chains', $summary);
        $this->assertArrayNotHasKey('payload_clusters', $summary);
        $this->assertSame(
            ['coordinated_attacks', 'active_campaigns', 'rapid_attackers'],
            array_keys($summary)
        );
    }
}
