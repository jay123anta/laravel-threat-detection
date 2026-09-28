<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use JayAnta\ThreatDetection\Services\ProbeDetectorService;
use JayAnta\ThreatDetection\Tests\TestCase;
use JayAnta\ThreatDetection\ThreatDetectionServiceProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * An install that published its config before 1.9 still gets 1.9's features.
 *
 * mergeConfigFrom() merges top-level keys only, so a published file wins
 * outright for every key it defines. New top-level keys (actor_signals,
 * ai_guard, …) arrive untouched, but the AI-infrastructure pack lives *inside*
 * probe_tracking, which every published config already has. Its block
 * replaced the package's whole, the pack vanished, and
 * THREAT_DETECTION_AI_PROBES=true did nothing at all — silently, for exactly
 * the operators engaged enough to have published their config. doctor could
 * not see it either: it compared top-level keys.
 *
 * The provider now fills keys added inside an existing top-level key, and
 * only those, from the package's own file — leaving everything the operator
 * wrote exactly as written.
 */
class PublishedConfigUpgradeTest extends TestCase
{
    /**
     * A real app loads its published config and *then* registers providers.
     * Testbench does the reverse — the provider has already merged by the
     * time getEnvironmentSetUp() runs — so the published block is set here
     * and the provider registered again, which reproduces the real order.
     * (A first draft set it in getEnvironmentSetUp(), where no fix could
     * ever have passed.)
     */
    protected function setUp(): void
    {
        parent::setUp();

        putenv('THREAT_DETECTION_AI_PROBES=true');

        config(['threat-detection.probe_tracking' => [
            'enabled' => true,
            'default_level' => 'medium',
            'paths' => [
                '/.env' => 'Environment File',
                '/our-legacy-admin' => 'Our Own Probe Path',
                // '/wp-admin' deliberately removed by this operator.
            ],
        ]]);

        // Positive control: this is the state a pre-1.9 published file left.
        $this->assertArrayNotHasKey('ai_infrastructure', config('threat-detection.probe_tracking'));

        $this->app->register(ThreatDetectionServiceProvider::class, true);
    }

    protected function tearDown(): void
    {
        putenv('THREAT_DETECTION_AI_PROBES');
        ProbeDetectorService::flushCaches();
        parent::tearDown();
    }

    #[Test]
    public function the_ai_pack_reaches_an_install_with_a_published_config(): void
    {
        $this->assertTrue(
            (bool) config('threat-detection.probe_tracking.ai_infrastructure.enabled'),
            'THREAT_DETECTION_AI_PROBES=true did nothing because the published probe_tracking block hid the pack'
        );

        ProbeDetectorService::flushCaches();
        $hit = (new ProbeDetectorService)->detect('/v1/models');

        $this->assertNotNull($hit, 'the AI pack was switched on and still matched nothing');
        $this->assertSame(ProbeDetectorService::AI_PACK, $hit['pack'] ?? null);
    }

    /** Filling a missing key must not touch a single thing the operator wrote. */
    #[Test]
    public function the_operators_own_block_is_left_exactly_as_written(): void
    {
        $block = config('threat-detection.probe_tracking');

        $this->assertSame('Our Own Probe Path', $block['paths']['/our-legacy-admin']);
        $this->assertArrayNotHasKey('/wp-admin', $block['paths'], 'a path the operator removed came back');
        $this->assertCount(2, $block['paths']);
        $this->assertSame(['enabled', 'default_level', 'paths', 'ai_infrastructure'], array_keys($block));
    }

    /** An operator who already has their own pack block keeps it. */
    #[Test]
    public function an_existing_pack_block_is_never_overwritten(): void
    {
        config(['threat-detection.probe_tracking.ai_infrastructure' => [
            'enabled' => false,
            'paths' => ['/only-this' => 'Operator Pack Entry'],
        ]]);

        $this->app->register(ThreatDetectionServiceProvider::class, true);

        $this->assertSame(
            ['enabled' => false, 'paths' => ['/only-this' => 'Operator Pack Entry']],
            config('threat-detection.probe_tracking.ai_infrastructure')
        );
    }

    /** A probe_tracking that is not an array is the operator's choice, not a gap. */
    #[Test]
    public function a_non_array_parent_is_left_alone(): void
    {
        config(['threat-detection.probe_tracking' => false]);

        $this->app->register(ThreatDetectionServiceProvider::class, true);

        $this->assertFalse(config('threat-detection.probe_tracking'));
    }
}
