<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use JayAnta\ThreatDetection\Tests\TestCase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Cache;

/**
 * Full-cycle evasion resistance tests.
 *
 * Each test sends a real HTTP request through the threat-detect middleware,
 * which calls ThreatDetectionService::detectAndLogFromRequest(), runs
 * normalization + evasion patterns + confidence scoring, writes to the
 * database, and dispatches the ThreatDetected event.
 *
 * Assertions verify the actual database row — not just pattern matches.
 */
class EvasionResistanceTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();

        // Ensure detection is fully active with zero suppression
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
            'cache.default' => 'array',
        ]);

        // Register a test route behind the middleware
        Route::middleware('threat-detect')->group(function () {
            Route::get('/evasion-test', fn() => response('OK', 200));
            Route::post('/evasion-test', fn() => response('OK', 200));
        });
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    // ────────────────────────────────────────────
    //  SQL Comment Evasion: UNION/**/SELECT
    // ────────────────────────────────────────────

    /** @test */
    public function full_cycle_sql_comment_evasion_is_detected_and_logged(): void
    {
        $response = $this->get('/evasion-test?q=UNION/**/SELECT+*+FROM+users');

        $response->assertStatus(200);

        // Evasion pattern should log "SQL Comment Evasion" (high)
        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] SQL Comment Evasion',
            'threat_level' => 'high',
        ]);

        // Normalization strips /**/ → "UNION SELECT" triggers default SQLi pattern
        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] SQL Injection UNION',
            'threat_level' => 'high',
        ]);

        // Verify the full row structure
        $log = DB::table('threat_logs')
            ->where('type', '[middleware] SQL Comment Evasion')
            ->first();

        $this->assertNotNull($log);
        $this->assertNotNull($log->ip_address);
        $this->assertStringContainsString('/evasion-test', $log->url);
        $this->assertNotNull($log->payload);
        $this->assertNotNull($log->confidence_score);
        $this->assertNotNull($log->confidence_label);
        $this->assertNotNull($log->created_at);
    }

    // ────────────────────────────────────────────
    //  Double URL Encoding: %2527
    // ────────────────────────────────────────────

    /** @test */
    public function full_cycle_double_url_encoding_is_detected_and_logged(): void
    {
        // POST body preserves the literal "%2527" (GET query params get decoded by PHP)
        $response = $this->post('/evasion-test', [
            'input' => '%2527 OR 1%253D1',
        ]);

        $response->assertStatus(200);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] Double URL Encoding',
            'threat_level' => 'high',
        ]);

        $log = DB::table('threat_logs')
            ->where('type', '[middleware] Double URL Encoding')
            ->first();

        $this->assertNotNull($log);
        $this->assertGreaterThan(0, $log->confidence_score);
    }

    // ────────────────────────────────────────────
    //  SQL CHAR Encoding: CHAR(39)
    // ────────────────────────────────────────────

    /** @test */
    public function full_cycle_sql_char_encoding_is_detected_and_logged(): void
    {
        $response = $this->get('/evasion-test?id=1+AND+CHAR(39)');

        $response->assertStatus(200);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] SQL Injection CHAR Encoding',
            'threat_level' => 'high',
        ]);

        $log = DB::table('threat_logs')
            ->where('type', '[middleware] SQL Injection CHAR Encoding')
            ->first();

        $this->assertNotNull($log);
        $this->assertStringContainsString('CHAR', $log->payload);
    }

    // ────────────────────────────────────────────
    //  POST body evasion: comment injection in body
    // ────────────────────────────────────────────

    /** @test */
    public function full_cycle_post_body_sql_comment_evasion_is_detected(): void
    {
        $response = $this->post('/evasion-test', [
            'search' => "admin'/**/UNION/**/SELECT/**/password/**/FROM/**/users--",
        ]);

        $response->assertStatus(200);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] SQL Comment Evasion',
            'threat_level' => 'high',
        ]);

        // After normalization the payload becomes a clean UNION SELECT
        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] SQL Injection UNION',
            'threat_level' => 'high',
        ]);
    }

    // ────────────────────────────────────────────
    //  LFI Protocol Evasion: phar://
    // ────────────────────────────────────────────

    /** @test */
    public function full_cycle_phar_protocol_lfi_is_detected(): void
    {
        $response = $this->get('/evasion-test?file=phar://malicious.phar/exploit');

        $response->assertStatus(200);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] LFI Protocol Usage',
            'threat_level' => 'medium',
        ]);
    }

    /** @test */
    public function full_cycle_expect_protocol_lfi_is_detected(): void
    {
        $response = $this->get('/evasion-test?cmd=expect://id');

        $response->assertStatus(200);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] LFI Protocol Usage',
            'threat_level' => 'medium',
        ]);
    }

    // ────────────────────────────────────────────
    //  Combined evasion: multiple techniques at once
    // ────────────────────────────────────────────

    /** @test */
    public function full_cycle_combined_evasion_techniques_produce_high_confidence(): void
    {
        // Use POST so literal %2527 survives PHP's URL decoding
        $response = $this->call('POST', '/evasion-test', [
            'q' => 'UNION/**/SELECT',
            'token' => '%2527',
            'x' => 'CHAR(39)',
        ]);

        $response->assertStatus(200);

        // All three evasion types should be logged
        $logs = DB::table('threat_logs')->get();
        $types = $logs->pluck('type')->toArray();

        $this->assertContains('[middleware] SQL Comment Evasion', $types);
        $this->assertContains('[middleware] Double URL Encoding', $types);
        $this->assertContains('[middleware] SQL Injection CHAR Encoding', $types);

        // With multiple high-severity hits, confidence should be elevated
        $maxConfidence = $logs->max('confidence_score');
        $this->assertGreaterThanOrEqual(35, $maxConfidence, 'Combined evasion should produce meaningful confidence');
    }

    // ────────────────────────────────────────────
    //  NO false positive: benign double-dash / CSS classes
    // ────────────────────────────────────────────

    /** @test */
    public function full_cycle_benign_double_dash_does_not_trigger_sql_comment(): void
    {
        $response = $this->post('/evasion-test', [
            'class' => 'font--bold text--large',
            'flag' => '--verbose --dry-run',
        ]);

        $response->assertStatus(200);

        $sqlCommentLogs = DB::table('threat_logs')
            ->where('type', 'LIKE', '%SQL Comment Syntax%')
            ->count();

        $this->assertEquals(0, $sqlCommentLogs, 'CSS double-dash and CLI flags should NOT trigger SQL Comment detection');
    }

    // ────────────────────────────────────────────
    //  Normalization end-to-end proof
    // ────────────────────────────────────────────

    /** @test */
    public function full_cycle_normalization_strips_comments_enabling_pattern_match(): void
    {
        // "SELECT/*comment*/FROM" — without normalization, "SELECT FROM" pattern won't match
        $response = $this->get('/evasion-test?q=SELECT/*junk*/password/*more*/FROM/*garbage*/users');

        $response->assertStatus(200);

        // After normalization: "SELECT password FROM users" → triggers SQL SELECT Query
        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] SQL SELECT Query',
        ]);

        // Also triggers evasion detection on the raw payload
        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] SQL Comment Evasion',
            'threat_level' => 'high',
        ]);
    }

    // ────────────────────────────────────────────
    //  Confidence scoring is accurate in full cycle
    // ────────────────────────────────────────────

    /** @test */
    public function full_cycle_confidence_score_and_label_are_populated(): void
    {
        // POST body preserves literal %2527 (GET would decode it)
        $response = $this->post('/evasion-test', ['q' => '%2527']);

        $response->assertStatus(200);

        $log = DB::table('threat_logs')
            ->where('type', '[middleware] Double URL Encoding')
            ->first();

        $this->assertNotNull($log, 'Double URL Encoding should be logged');
        $this->assertGreaterThan(0, $log->confidence_score);
        $this->assertContains($log->confidence_label, ['low', 'medium', 'high', 'very_high']);
    }

    // ────────────────────────────────────────────
    //  Payload is captured correctly
    // ────────────────────────────────────────────

    /** @test */
    public function full_cycle_payload_column_captures_the_malicious_input(): void
    {
        $response = $this->get('/evasion-test?inject=UNION/**/SELECT');

        $response->assertStatus(200);

        $log = DB::table('threat_logs')
            ->where('type', '[middleware] SQL Comment Evasion')
            ->first();

        $this->assertNotNull($log);
        $this->assertStringContainsString('UNION', $log->payload);
        $this->assertStringContainsString('SELECT', $log->payload);
    }

    // ────────────────────────────────────────────
    //  Private IP range detection (full RFC 1918)
    // ────────────────────────────────────────────

    /** @test */
    public function full_cycle_private_ip_172_range_is_detected(): void
    {
        // 172.20.x.x is in the 172.16-31 private range
        $response = $this->get('/evasion-test?ssrf=http://172.20.0.1:8080/admin');

        $response->assertStatus(200);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[custom] Private IP Access',
        ]);
    }

    // ────────────────────────────────────────────
    //  Localhost SSRF with 0.0.0.0
    // ────────────────────────────────────────────

    /** @test */
    public function full_cycle_localhost_ssrf_with_zero_ip_is_detected(): void
    {
        $response = $this->get('/evasion-test?url=http://0.0.0.0:9200/_cat/indices');

        $response->assertStatus(200);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] Localhost SSRF',
        ]);
    }

    // ────────────────────────────────────────────
    //  Event is dispatched during full cycle
    // ────────────────────────────────────────────

    /** @test */
    public function full_cycle_threat_detected_event_is_dispatched(): void
    {
        \Illuminate\Support\Facades\Event::fake([
            \JayAnta\ThreatDetection\Events\ThreatDetected::class,
        ]);

        $this->get('/evasion-test?q=UNION/**/SELECT');

        \Illuminate\Support\Facades\Event::assertDispatched(
            \JayAnta\ThreatDetection\Events\ThreatDetected::class,
            function ($event) {
                return $event->threatLevel === 'high'
                    && $event->ipAddress !== null
                    && !empty($event->threatLog);
            }
        );
    }

    // ────────────────────────────────────────────
    //  Response is never blocked (passive detector)
    // ────────────────────────────────────────────

    /** @test */
    public function full_cycle_response_is_always_200_even_for_attacks(): void
    {
        // The package is a passive detector — it must NEVER block the request
        $attacks = [
            '/evasion-test?q=UNION/**/SELECT+*+FROM+users',
            '/evasion-test?q=%2527+OR+1%253D1',
            '/evasion-test?q=CHAR(39)+AND+1=1',
            '/evasion-test?file=phar://evil.phar',
        ];

        foreach ($attacks as $path) {
            $response = $this->get($path);
            $this->assertEquals(200, $response->getStatusCode(),
                "Passive detector must not block request: {$path}");
        }
    }

    // ────────────────────────────────────────────
    //  Queue mode: job is dispatched, not sync insert
    // ────────────────────────────────────────────

    /** @test */
    public function full_cycle_queue_mode_dispatches_job_instead_of_sync_insert(): void
    {
        \Illuminate\Support\Facades\Queue::fake();

        config(['threat-detection.queue.enabled' => true]);

        $this->get('/evasion-test?q=UNION/**/SELECT');

        \Illuminate\Support\Facades\Queue::assertPushed(
            \JayAnta\ThreatDetection\Jobs\StoreThreatLog::class
        );

        // With queue faked, nothing should be in the DB
        $this->assertEquals(0, DB::table('threat_logs')->count(),
            'When queue is enabled, threats should be dispatched not inserted synchronously');
    }
}
