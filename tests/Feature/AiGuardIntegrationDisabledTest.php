<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Integration\AiGuardContract;
use JayAnta\ThreatDetection\Services\ActorAttributionStore;
use JayAnta\ThreatDetection\Tests\Fixtures\AiGuard\FakeAiGuardMiddleware;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * The integration at its default: off.
 *
 * A separate class because the listeners are registered while the provider
 * boots, so "off at boot" and "on at boot" cannot share a setUp. This is the
 * state nearly every install is in, and the claim under test is the one every
 * feature in this line makes — switched off, it is not there.
 */
class AiGuardIntegrationDisabledTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config(['cache.default' => 'array']);
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    #[Test]
    public function it_is_off_by_default(): void
    {
        $this->assertFalse((bool) config('threat-detection.ai_guard.enabled'));
    }

    #[Test]
    public function no_listener_is_registered_when_off(): void
    {
        foreach (AiGuardContract::events() as $event) {
            $this->assertFalse(Event::hasListeners($event), "a listener for {$event} was registered while the integration is off");
        }
    }

    #[Test]
    public function the_middleware_ignores_the_attribute_when_off(): void
    {
        $this->createThreatLogsTable();

        config([
            'threat-detection.enabled' => true,
            'threat-detection.skip_paths' => [],
            'threat-detection.only_paths' => [],
            'threat-detection.whitelisted_ips' => [],
        ]);

        Route::middleware([FakeAiGuardMiddleware::class, 'threat-detect'])
            ->get('/agent-page-off', fn () => response('OK'));

        $this->get('/agent-page-off')->assertStatus(200);

        // Turn the store on only to look inside it: nothing may have been
        // written while the integration was off.
        config(['threat-detection.ai_guard.enabled' => true]);

        $this->assertNull(app(ActorAttributionStore::class)->forActor('127.0.0.1'));
    }
}
