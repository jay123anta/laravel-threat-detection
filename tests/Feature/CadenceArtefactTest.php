<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Services\ActorRiskScorer;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * Cadence through the real pipeline, where the artefact lived.
 *
 * The cadence term used to be computed from threat_logs rows, which are
 * deduplicated to one per IP per type per five minutes. An actor repeating one
 * attack for half an hour therefore left rows almost exactly 300 seconds
 * apart, whatever its real pace — near-zero variation, and the bonus awarded
 * for the package's own dedup window. A unit test seeded rows 30 seconds
 * apart, a state real traffic cannot produce, so nothing noticed.
 *
 * These drive requests through the middleware with time moving, and ask the
 * scorer about what actually landed.
 */
class CadenceArtefactTest extends TestCase
{
    private const SIGNALS = 'threat_actor_signals';

    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();

        config(['threat-detection.actor_signals.table' => self::SIGNALS]);
        (require __DIR__ . '/../../database/migrations/create_threat_actor_signals_table.php.stub')->up();

        config([
            'cache.default' => 'array',
            'threat-detection.enabled' => true,
            'threat-detection.detection_mode' => 'strict',
            'threat-detection.min_confidence' => 0,
            'threat-detection.skip_paths' => [],
            'threat-detection.only_paths' => [],
            'threat-detection.whitelisted_ips' => [],
            'threat-detection.api_route_filtering.enabled' => false,
            'threat-detection.content_paths' => [],
            'threat-detection.notifications.enabled' => false,
            'threat-detection.queue.enabled' => false,
            'threat-detection.actor_signals.enabled' => true,
            'threat-detection.actor_score.enabled' => true,
        ]);

        ThreatDetectionService::flushCaches();

        Route::middleware('threat-detect')->get('/search', fn () => response('OK'));
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    /**
     * One probe re-requested every 30 seconds for half an hour. A single type,
     * so dedup leaves one row per five minutes and nothing else — the purest
     * form of the artefact. (A payload matching several labels leaves
     * same-second clusters whose zero gaps happened to mask it.)
     */
    #[Test]
    public function one_probe_repeated_for_half_an_hour_earns_no_cadence(): void
    {
        config(['threat-detection.probe_tracking.enabled' => true]);
        Route::middleware('threat-detect')->get('/.env', fn () => response('Not Found', 404));

        for ($i = 0; $i < 60; $i++) {
            $this->get('/.env');
            $this->travel(30)->seconds();
        }

        $types = DB::table('threat_logs')->distinct()->pluck('type')->all();
        $this->assertCount(1, $types, 'more than one type was logged, so the rows are not the single-type artefact: ' . implode(', ', $types));
        $this->assertGreaterThanOrEqual(5, DB::table('threat_logs')->count(), 'dedup did not produce the periodic rows this test exists for');

        $score = (new ActorRiskScorer)->score('127.0.0.1');

        $this->assertSame(0.0, $score['components']['cadence'], 'the package\'s own five-minute dedup window was scored as the attacker\'s rhythm');
    }

    /**
     * Positive control: a script iterating through distinct payloads at a
     * fixed pace is exactly what the term is for, and must still earn it.
     */
    #[Test]
    public function distinct_payloads_at_a_scripted_pace_still_earn_cadence(): void
    {
        foreach (['a', 'b', 'c', 'd', 'e', 'f', 'g'] as $column) {
            $this->get('/search?q=' . urlencode("' UNION SELECT {$column} FROM users--"))->assertStatus(200);
            $this->travel(20)->seconds();
        }

        $score = (new ActorRiskScorer)->score('127.0.0.1');

        $this->assertGreaterThan(0, $score['components']['cadence'], 'a scripted run of distinct payloads earned no cadence, so the fix switched the term off rather than correcting it');
    }

    /**
     * The same run, each request carrying its payload in two places. Two new
     * variants in one second are one event; counted as two, their zero gap
     * would swamp the variation and hide the rhythm.
     */
    #[Test]
    public function a_payload_in_two_places_is_one_moment(): void
    {
        foreach (['a', 'b', 'c', 'd', 'e', 'f', 'g'] as $column) {
            $payload = "' UNION SELECT {$column} FROM users--";

            $this->withHeaders(['X-Search' => $payload])
                ->get('/search?q=' . urlencode($payload))
                ->assertStatus(200);
            $this->travel(20)->seconds();
        }

        $contexts = DB::table(self::SIGNALS)->distinct()->pluck('context')->all();
        $this->assertGreaterThan(1, count($contexts), 'the payload was only recorded in one place, so this proves nothing');

        $this->assertGreaterThan(0, (new ActorRiskScorer)->score('127.0.0.1')['components']['cadence']);
    }
}
