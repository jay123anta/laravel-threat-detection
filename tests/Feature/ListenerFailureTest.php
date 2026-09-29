<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Events\DdosThresholdExceeded;
use JayAnta\ThreatDetection\Events\ThreatDetected;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * An application's listener failing must not cost the detection.
 *
 * ThreatDetected is dispatched for each detection before the batch is
 * written, and DdosThresholdExceeded before pattern detection runs. A
 * listener that threw — its own bug, its own dependency down — sent the
 * exception to the middleware's catch: the batch was never written, or the
 * request's patterns were never checked. The listener is the application's
 * code; whether an attack is recorded must not depend on it.
 */
class ListenerFailureTest extends TestCase
{
    private const SQLI = "' UNION SELECT password FROM users--";

    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();

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
        ]);

        ThreatDetectionService::flushCaches();

        Route::middleware('threat-detect')->get('/search', fn () => response('OK'));
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    private function injectionsLogged(): int
    {
        return DB::table('threat_logs')->where('type', 'like', '%SQL Injection UNION%')->count();
    }

    #[Test]
    public function a_failing_threat_listener_does_not_lose_the_row(): void
    {
        Event::listen(ThreatDetected::class, fn () => throw new \RuntimeException('the listener is broken'));

        $this->get('/search?q=' . urlencode(self::SQLI))->assertStatus(200);

        $this->assertGreaterThan(0, $this->injectionsLogged(), 'a broken listener switched detection off');
    }

    #[Test]
    public function a_failing_flood_listener_does_not_stop_pattern_detection(): void
    {
        config(['threat-detection.ddos.threshold' => 1, 'threat-detection.ddos.window' => 60]);
        Event::listen(DdosThresholdExceeded::class, fn () => throw new \RuntimeException('the listener is broken'));

        $this->get('/search');
        $this->get('/search?q=' . urlencode(self::SQLI))->assertStatus(200);

        $this->assertGreaterThan(0, $this->injectionsLogged(), 'a broken flood listener stopped pattern detection');
    }

    /** Positive control: a working listener still hears every detection. */
    #[Test]
    public function a_working_listener_still_hears_the_detection(): void
    {
        $heard = 0;
        Event::listen(ThreatDetected::class, function () use (&$heard) {
            $heard++;
        });

        $this->get('/search?q=' . urlencode(self::SQLI))->assertStatus(200);

        $this->assertGreaterThan(0, $heard);
    }
}
