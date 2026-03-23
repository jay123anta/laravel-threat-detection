<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use JayAnta\ThreatDetection\Tests\TestCase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Cache;

/**
 * Phase 4 v1.3.0: Full-cycle tests for performance optimizations.
 *
 * Tests early bailout (no suspicious chars = skip regex),
 * batch DB inserts, and max_detections_per_request cap.
 */
class Phase4PerformanceTest extends TestCase
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
            'threat-detection.notifications.enabled' => false,
            'threat-detection.queue.enabled' => false,
            'threat-detection.max_detections_per_request' => 0,
            'cache.default' => 'array',
        ]);

        Route::middleware('threat-detect')->group(function () {
            Route::get('/perf-test', fn() => response('OK', 200));
            Route::post('/perf-test', fn() => response('OK', 200));
        });
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    // ────────────────────────────────────────────
    //  Early Bailout: clean payloads skip regex
    // ────────────────────────────────────────────

    /** @test */
    public function full_cycle_clean_request_produces_no_threat_logs(): void
    {
        $this->get('/perf-test?name=John&city=London&age=30');

        // No suspicious characters → early bailout, no threats logged
        $count = DB::table('threat_logs')->where('type', 'like', '[middleware]%')->count();
        $this->assertEquals(0, $count);
    }

    /** @test */
    public function full_cycle_clean_post_body_produces_no_threat_logs(): void
    {
        $this->call('POST', '/perf-test', [
            'name' => 'Jane Doe',
            'email' => 'jane@example.com',
            'message' => 'Hello this is a normal message about web development',
        ]);

        $count = DB::table('threat_logs')->where('type', 'like', '[middleware]%')->count();
        $this->assertEquals(0, $count);
    }

    /** @test */
    public function full_cycle_suspicious_chars_still_trigger_detection(): void
    {
        // Contains suspicious char '<' → early bailout skipped, regex runs
        $this->call('POST', '/perf-test', ['input' => '<script>alert(1)</script>']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] XSS Script Tag',
        ]);
    }

    // ────────────────────────────────────────────
    //  Batch Insert: multiple threats in one INSERT
    // ────────────────────────────────────────────

    /** @test */
    public function full_cycle_multiple_threats_stored_in_single_request(): void
    {
        // This payload triggers multiple patterns at once
        $this->get("/perf-test?q=UNION+SELECT+*+FROM+users--");

        // Should have multiple entries from one request
        $count = DB::table('threat_logs')->count();
        $this->assertGreaterThan(1, $count, 'Multiple threats should be logged from a single request');

        // All entries should have the same IP and URL
        $ips = DB::table('threat_logs')->distinct()->pluck('ip_address');
        $this->assertEquals(1, $ips->count());
    }

    /** @test */
    public function full_cycle_batch_insert_preserves_all_threat_types(): void
    {
        // Payload that triggers SQL + other patterns
        $this->call('POST', '/perf-test', ['q' => "UNION SELECT * FROM users; DROP TABLE users"]);

        // Verify specific types are all present
        $this->assertDatabaseHas('threat_logs', ['type' => '[middleware] SQL Injection UNION']);
        $this->assertDatabaseHas('threat_logs', ['type' => '[middleware] SQL DDL Injection']);
    }

    // ────────────────────────────────────────────
    //  Max Detections Per Request
    // ────────────────────────────────────────────

    /** @test */
    public function full_cycle_max_detections_caps_pattern_matches(): void
    {
        config(['threat-detection.max_detections_per_request' => 2]);

        // Payload that would normally trigger 5+ patterns
        $this->call('POST', '/perf-test', [
            'q' => "UNION SELECT * FROM users; DROP TABLE sessions; <script>alert(1)</script>",
        ]);

        // Context matches should be capped at 2 (but bot detection runs separately)
        $middlewareCount = DB::table('threat_logs')
            ->where('type', 'like', '[middleware]%')
            ->count();

        $this->assertLessThanOrEqual(2, $middlewareCount, 'Max detections should cap pattern matches');
    }

    /** @test */
    public function full_cycle_max_detections_zero_means_unlimited(): void
    {
        config(['threat-detection.max_detections_per_request' => 0]);

        $this->call('POST', '/perf-test', [
            'q' => "UNION SELECT * FROM users; DROP TABLE sessions",
        ]);

        // Should log all matches without cap
        $count = DB::table('threat_logs')->where('type', 'like', '[middleware]%')->count();
        $this->assertGreaterThan(2, $count);
    }

    // ────────────────────────────────────────────
    //  Response time: all still return 200
    // ────────────────────────────────────────────

    /** @test */
    public function full_cycle_performance_optimizations_dont_break_passive_mode(): void
    {
        $this->get('/perf-test?name=normal')->assertStatus(200);
        $this->get('/perf-test?q=DROP+TABLE+users')->assertStatus(200);

        config(['threat-detection.max_detections_per_request' => 1]);
        $this->call('POST', '/perf-test', ['x' => '<script>alert(1)</script>'])->assertStatus(200);
    }
}
