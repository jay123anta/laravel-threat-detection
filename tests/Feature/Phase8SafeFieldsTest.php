<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Cache;

/**
 * Phase 8 v1.3.0: Full-cycle tests for safe fields (false positive reduction).
 *
 * Tests that configured safe fields are excluded from detection scanning,
 * while other fields on the same request are still scanned.
 */
class Phase8SafeFieldsTest extends TestCase
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
            'threat-detection.safe_fields' => [],
            'cache.default' => 'array',
        ]);

        Route::middleware('threat-detect')->group(function () {
            Route::get('/safe-test', fn() => response('OK', 200));
            Route::post('/safe-test', fn() => response('OK', 200));
        });
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    // ────────────────────────────────────────────
    //  Safe fields in POST body
    // ────────────────────────────────────────────

    #[Test]
    public function full_cycle_safe_field_in_body_is_not_scanned(): void
    {
        config(['threat-detection.safe_fields' => ['content']]);

        $this->call('POST', '/safe-test', [
            'content' => '<script>alert(1)</script>',
        ]);

        // XSS in safe field should NOT be detected
        $this->assertDatabaseMissing('threat_logs', [
            'type' => '[middleware] XSS Script Tag',
        ]);
    }

    #[Test]
    public function full_cycle_non_safe_field_in_body_is_still_scanned(): void
    {
        config(['threat-detection.safe_fields' => ['content']]);

        $this->call('POST', '/safe-test', [
            'content' => '<script>alert(1)</script>',  // safe — skipped
            'search' => "UNION SELECT * FROM users",    // not safe — scanned
        ]);

        // SQL in non-safe field should be detected
        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] SQL Injection UNION',
        ]);
    }

    #[Test]
    public function full_cycle_multiple_safe_fields_excluded(): void
    {
        config(['threat-detection.safe_fields' => ['content', 'html', 'code']]);

        $this->call('POST', '/safe-test', [
            'content' => '<script>alert(1)</script>',
            'html' => 'DROP TABLE users',
            'code' => "system('ls -la')",
        ]);

        $count = DB::table('threat_logs')->where('type', 'like', '[middleware]%')->count();
        $this->assertEquals(0, $count, 'All fields are safe — no middleware threats should be logged');
    }

    // ────────────────────────────────────────────
    //  Safe fields in query params
    // ────────────────────────────────────────────

    #[Test]
    public function full_cycle_safe_field_in_query_is_not_scanned(): void
    {
        config(['threat-detection.safe_fields' => ['q']]);

        $this->get('/safe-test?q=UNION+SELECT+*+FROM+users');

        $this->assertDatabaseMissing('threat_logs', [
            'type' => '[middleware] SQL Injection UNION',
        ]);
    }

    #[Test]
    public function full_cycle_non_safe_query_field_still_scanned(): void
    {
        config(['threat-detection.safe_fields' => ['content']]);

        $this->get('/safe-test?search=DROP+TABLE+users');

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] SQL DDL Injection',
        ]);
    }

    // ────────────────────────────────────────────
    //  Empty safe_fields (default) scans everything
    // ────────────────────────────────────────────

    #[Test]
    public function full_cycle_empty_safe_fields_scans_all(): void
    {
        config(['threat-detection.safe_fields' => []]);

        $this->call('POST', '/safe-test', [
            'content' => '<script>alert(1)</script>',
        ]);

        // Should be detected when safe_fields is empty
        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] XSS Script Tag',
        ]);
    }

    // ────────────────────────────────────────────
    //  Passive mode preserved
    // ────────────────────────────────────────────

    #[Test]
    public function full_cycle_safe_fields_dont_break_response(): void
    {
        config(['threat-detection.safe_fields' => ['content']]);

        $this->call('POST', '/safe-test', [
            'content' => '<script>alert(1)</script>',
            'name' => 'John',
        ])->assertStatus(200);
    }
}
