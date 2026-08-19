<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * v1.5.0: Path-aware false-positive control (safe_paths).
 *
 * safe_paths lets you exempt one specific field's value in a nested JSON/form
 * body by dot-notation path (with wildcards) — more precise than safe_fields,
 * which exempts a key name everywhere it appears. Detection of everything else
 * is unchanged.
 */
class SafePathsTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();

        config([
            'threat-detection.enabled' => true,
            'threat-detection.detection_mode' => 'strict',
            'threat-detection.min_confidence' => 0,
            'threat-detection.skip_paths' => [],
            'threat-detection.only_paths' => [],
            'threat-detection.whitelisted_ips' => [],
            'threat-detection.api_route_filtering.enabled' => false,
            'threat-detection.content_paths' => [],
            'threat-detection.safe_fields' => [],
            'threat-detection.safe_paths' => [],
            'threat-detection.notifications.enabled' => false,
            'threat-detection.queue.enabled' => false,
            'cache.default' => 'array',
        ]);

        Route::middleware('threat-detect')->post('/phase10-test', fn () => response('OK', 200));
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    #[Test]
    public function nested_json_value_is_detected_by_default(): void
    {
        // Baseline: a SQL-looking value in a nested JSON field IS scanned.
        $this->postJson('/phase10-test', ['search' => ['query' => 'SELECT id FROM products']]);

        $this->assertDatabaseHas('threat_logs', ['type' => '[middleware] SQL SELECT Query']);
    }

    #[Test]
    public function safe_path_exempts_a_specific_nested_value(): void
    {
        config(['threat-detection.safe_paths' => ['search.query']]);

        $this->postJson('/phase10-test', ['search' => ['query' => 'SELECT id FROM products']]);

        $this->assertDatabaseMissing('threat_logs', ['type' => '[middleware] SQL SELECT Query']);
    }

    #[Test]
    public function safe_paths_support_wildcards(): void
    {
        config(['threat-detection.safe_paths' => ['filters.*.value']]);

        $this->postJson('/phase10-test', [
            'filters' => [
                ['field' => 'name', 'value' => 'UNION SELECT card FROM payments'],
            ],
        ]);

        $this->assertDatabaseMissing('threat_logs', ['type' => '[middleware] SQL Injection UNION']);
    }

    #[Test]
    public function safe_path_is_precise_and_does_not_exempt_the_key_elsewhere(): void
    {
        // Exempt only a.query — the SAME key name under search.query, which
        // carries a real attack, must still be detected.
        config(['threat-detection.safe_paths' => ['a.query']]);

        $this->postJson('/phase10-test', [
            'a' => ['query' => 'harmless text'],
            'search' => ['query' => 'UNION SELECT card FROM payments'],
        ]);

        $this->assertDatabaseHas('threat_logs', ['type' => '[middleware] SQL Injection UNION']);
    }

    #[Test]
    public function a_safe_path_does_not_suppress_attacks_in_other_fields(): void
    {
        config(['threat-detection.safe_paths' => ['search.query']]);

        // search.query is exempt, but a genuine attack in another field logs.
        $this->postJson('/phase10-test', [
            'search' => ['query' => 'SELECT id FROM products'],
            'redirect' => 'http://evil.example.com/steal',
        ]);

        $this->assertDatabaseMissing('threat_logs', ['type' => '[middleware] SQL SELECT Query']);
        $this->assertDatabaseHas('threat_logs', ['type' => '[middleware] Open Redirect']);
    }
}
