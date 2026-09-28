<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Services\ProbeDetectorService;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * A probe's severity must be one the rest of the package can read.
 *
 * Probe levels were stored exactly as configured. Everything downstream —
 * the API's level filter, /stats, the severity counts, `notify_levels` —
 * speaks high, medium and low, and on PostgreSQL and SQLite compares them
 * case-sensitively. A probe configured as `High` or `hgih` was recorded, but
 * counted as nothing and never alerted. Custom patterns already validated
 * their level; probes now do too, falling back entry → pack → default →
 * medium.
 */
class ProbeLevelValidationTest extends TestCase
{
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
            'threat-detection.probe_tracking.enabled' => true,
            'threat-detection.probe_tracking.default_level' => 'medium',
        ]);

        Route::middleware('threat-detect')->get('/secret-panel', fn () => response('OK'));
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    private function probeLevel(array $probeConfig): ?string
    {
        config($probeConfig);
        ThreatDetectionService::flushCaches();
        ProbeDetectorService::flushCaches();

        $this->get('/secret-panel')->assertStatus(200);

        return DB::table('threat_logs')->where('type', '[probe] Secret Panel Probe')->value('threat_level');
    }

    public static function levels(): array
    {
        return [
            'capitalised' => ['High', 'high'],
            'upper case with space' => [' LOW ', 'low'],
            'a typo falls back to the default' => ['hgih', 'medium'],
            'an unknown name falls back to the default' => ['critical', 'medium'],
            'valid, unchanged' => ['high', 'high'],
        ];
    }

    #[Test]
    #[DataProvider('levels')]
    public function an_entry_level_is_normalised_or_replaced(string $configured, string $expected): void
    {
        $level = $this->probeLevel([
            'threat-detection.probe_tracking.paths' => ['/secret-panel' => ['label' => 'Secret Panel Probe', 'level' => $configured]],
        ]);

        $this->assertSame($expected, $level);
    }

    #[Test]
    public function an_unusable_default_level_falls_back_to_medium(): void
    {
        $level = $this->probeLevel([
            'threat-detection.probe_tracking.default_level' => 'CRITICAL!',
            'threat-detection.probe_tracking.paths' => ['/secret-panel' => 'Secret Panel Probe'],
        ]);

        $this->assertSame('medium', $level);
    }

    #[Test]
    public function a_capitalised_default_level_is_normalised(): void
    {
        $level = $this->probeLevel([
            'threat-detection.probe_tracking.default_level' => 'High',
            'threat-detection.probe_tracking.paths' => ['/secret-panel' => 'Secret Panel Probe'],
        ]);

        $this->assertSame('high', $level);
    }
}
