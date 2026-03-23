<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use JayAnta\ThreatDetection\Tests\TestCase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use JayAnta\ThreatDetection\Events\ThreatDetected;

/**
 * Phase 5 v1.3.0: Full-cycle tests for 404 probe tracking.
 *
 * Tests detection of reconnaissance probes hitting known vulnerable paths
 * (wp-admin, .env, phpmyadmin, etc.) logged with [probe] type tag.
 */
class Phase5ProbeTrackingTest extends TestCase
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
            'threat-detection.probe_tracking.enabled' => true,
            'cache.default' => 'array',
        ]);

        // Register probe paths as actual routes so middleware runs
        Route::middleware('threat-detect')->group(function () {
            Route::get('/wp-admin', fn() => response('OK', 200));
            Route::get('/wp-login.php', fn() => response('OK', 200));
            Route::get('/.env', fn() => response('OK', 200));
            Route::get('/phpmyadmin', fn() => response('OK', 200));
            Route::get('/actuator/env', fn() => response('OK', 200));
            Route::get('/cgi-bin/test', fn() => response('OK', 200));
            Route::get('/swagger/index.html', fn() => response('OK', 200));
            Route::get('/backup/db.sql', fn() => response('OK', 200));
            Route::get('/test.jsp', fn() => response('OK', 200));
            Route::get('/normal-page', fn() => response('OK', 200));
            Route::get('/wp-admin-dashboard', fn() => response('OK', 200));
            // Probe path WITH malicious payload
            Route::get('/wp-login.php-inject', fn() => response('OK', 200));
        });
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    // ────────────────────────────────────────────
    //  WordPress Probes
    // ────────────────────────────────────────────

    /** @test */
    public function full_cycle_wp_admin_probe_is_detected(): void
    {
        $this->get('/wp-admin');

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[probe] WordPress Admin',
            'threat_level' => 'medium',
        ]);
    }

    /** @test */
    public function full_cycle_wp_login_probe_is_detected(): void
    {
        $this->get('/wp-login.php');

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[probe] WordPress Login',
            'threat_level' => 'medium',
        ]);
    }

    // ────────────────────────────────────────────
    //  Config / Sensitive File Probes
    // ────────────────────────────────────────────

    /** @test */
    public function full_cycle_env_file_probe_is_detected(): void
    {
        $this->get('/.env');

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[probe] Environment File',
            'threat_level' => 'medium',
        ]);
    }

    /** @test */
    public function full_cycle_phpmyadmin_probe_is_detected(): void
    {
        $this->get('/phpmyadmin');

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[probe] phpMyAdmin',
            'threat_level' => 'medium',
        ]);
    }

    // ────────────────────────────────────────────
    //  Technology / Stack Probes
    // ────────────────────────────────────────────

    /** @test */
    public function full_cycle_spring_actuator_probe_is_detected(): void
    {
        $this->get('/actuator/env');

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[probe] Spring Actuator',
        ]);
    }

    /** @test */
    public function full_cycle_cgi_bin_probe_is_detected(): void
    {
        $this->get('/cgi-bin/test');

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[probe] CGI Bin',
        ]);
    }

    /** @test */
    public function full_cycle_swagger_probe_is_detected(): void
    {
        $this->get('/swagger/index.html');

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[probe] Swagger UI',
        ]);
    }

    /** @test */
    public function full_cycle_jsp_probe_is_detected(): void
    {
        $this->get('/test.jsp');

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[probe] JSP Probe',
        ]);
    }

    /** @test */
    public function full_cycle_backup_probe_is_detected(): void
    {
        $this->get('/backup/db.sql');

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[probe] Backup Directory',
        ]);
    }

    // ────────────────────────────────────────────
    //  Probe + Payload: both logged independently
    // ────────────────────────────────────────────

    /** @test */
    public function full_cycle_probe_with_payload_logs_both(): void
    {
        $this->get('/wp-admin?q=UNION+SELECT+*+FROM+users');

        // Probe entry
        $this->assertDatabaseHas('threat_logs', [
            'type' => '[probe] WordPress Admin',
        ]);

        // Payload detection entry
        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] SQL Injection UNION',
        ]);
    }

    // ────────────────────────────────────────────
    //  Config: enabled/disabled
    // ────────────────────────────────────────────

    /** @test */
    public function full_cycle_probe_disabled_produces_no_probe_logs(): void
    {
        config(['threat-detection.probe_tracking.enabled' => false]);

        $this->get('/wp-admin');

        $this->assertDatabaseMissing('threat_logs', [
            'type' => '[probe] WordPress Admin',
        ]);
    }

    // ────────────────────────────────────────────
    //  Deduplication
    // ────────────────────────────────────────────

    /** @test */
    public function full_cycle_probe_uses_deduplication(): void
    {
        $this->get('/wp-admin');
        $this->get('/wp-admin');

        $count = DB::table('threat_logs')
            ->where('type', '[probe] WordPress Admin')
            ->count();

        $this->assertEquals(1, $count, 'Duplicate probe within 5 min should be deduplicated');
    }

    // ────────────────────────────────────────────
    //  Event dispatch
    // ────────────────────────────────────────────

    /** @test */
    public function full_cycle_probe_fires_threat_detected_event(): void
    {
        Event::fake([ThreatDetected::class]);

        $this->get('/wp-admin');

        Event::assertDispatched(ThreatDetected::class);
    }

    // ────────────────────────────────────────────
    //  False positives: normal paths not flagged
    // ────────────────────────────────────────────

    /** @test */
    public function full_cycle_normal_path_not_flagged_as_probe(): void
    {
        $this->get('/normal-page');

        $this->assertDatabaseMissing('threat_logs', [
            'type' => '[probe] WordPress Admin',
        ]);

        $count = DB::table('threat_logs')
            ->where('type', 'like', '[probe]%')
            ->count();

        $this->assertEquals(0, $count);
    }

    // ────────────────────────────────────────────
    //  Passive: all probes return 200
    // ────────────────────────────────────────────

    /** @test */
    public function full_cycle_probe_detection_never_blocks(): void
    {
        $this->get('/wp-admin')->assertStatus(200);
        $this->get('/.env')->assertStatus(200);
        $this->get('/phpmyadmin')->assertStatus(200);
    }
}
