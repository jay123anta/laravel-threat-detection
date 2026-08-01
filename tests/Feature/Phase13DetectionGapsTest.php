<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Services\ExclusionRuleService;
use JayAnta\ThreatDetection\Services\ProbeDetectorService;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * Regression cover for four gaps where a pattern was configured, matched its
 * input, and still never fired.
 *
 * Every payload here is deliberately bare. The earlier custom-pattern tests all
 * routed their bodies through a helper that appended an email address and a
 * "password" field; those two values happened to satisfy the keyword pre-screen
 * and activate a category, so the tests passed while the same pattern failed on
 * a realistic request. Nothing below carries a value it does not need.
 */
class Phase13DetectionGapsTest extends TestCase
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
            'threat-detection.auth_paths' => [],
            'threat-detection.safe_fields' => [],
            'threat-detection.safe_paths' => [],
            'threat-detection.pattern_validators' => [],
            'threat-detection.notifications.enabled' => false,
            'threat-detection.queue.enabled' => false,
            // Isolate the pattern engine from the separate probe-path tracker.
            'threat-detection.probe_tracking.enabled' => false,
            'cache.default' => 'array',
        ]);

        Route::middleware('threat-detect')->group(function () {
            Route::get('/gaps-test', fn() => response('OK', 200));
            Route::post('/gaps-test', fn() => response('OK', 200));
            Route::get('/deep/path/vendor/phpunit/phpunit/eval-stdin.php', fn() => response('OK', 200));
            Route::get('/actuator/env', fn() => response('OK', 200));
            Route::get('/clean/profile/page', fn() => response('OK', 200));
            Route::get('/.env', fn() => response('OK', 200));
            Route::get('/admin/users', fn() => response('OK', 200));
            Route::post('/zz-raw-cap', fn() => response('OK', 200));
        });

        ThreatDetectionService::flushCaches();
    }

    protected function tearDown(): void
    {
        ThreatDetectionService::flushCaches();
        Cache::flush();
        parent::tearDown();
    }

    // ────────────────────────────────────────────
    //  Custom patterns are no longer category-gated
    // ────────────────────────────────────────────

    #[Test]
    public function custom_pattern_fires_without_any_category_keyword(): void
    {
        config(['threat-detection.custom_patterns' => [
            '/\bREF-\d{6}\b/' => 'Internal Reference Leak',
        ]]);
        ThreatDetectionService::flushCaches();

        // No email, no "password" — nothing that activates a built-in category.
        $this->postJson('/gaps-test', ['ref' => 'REF-123456']);

        $this->assertDatabaseHas('threat_logs', ['type' => '[custom] Internal Reference Leak']);
    }

    #[Test]
    public function custom_pattern_fires_on_a_body_with_no_suspicious_substring(): void
    {
        config(['threat-detection.custom_patterns' => [
            '/\bACME-[A-Z]{4}\b/' => 'Partner Code Leak',
        ]]);
        ThreatDetectionService::flushCaches();

        $this->postJson('/gaps-test', ['code' => 'ACME-WXYZ']);

        $this->assertDatabaseHas('threat_logs', ['type' => '[custom] Partner Code Leak']);
    }

    #[Test]
    public function custom_pattern_in_the_query_string_fires_unaided(): void
    {
        config(['threat-detection.custom_patterns' => [
            '/\bREF-\d{6}\b/' => 'Internal Reference Leak',
        ]]);
        ThreatDetectionService::flushCaches();

        $this->get('/gaps-test?ref=REF-123456');

        $this->assertDatabaseHas('threat_logs', ['type' => '[custom] Internal Reference Leak']);
    }

    // ────────────────────────────────────────────
    //  Shipped regional PII patterns
    // ────────────────────────────────────────────

    #[Test]
    public function pan_number_alone_in_a_body_is_detected(): void
    {
        $this->postJson('/gaps-test', ['pan' => 'ABCDE1234F']);

        $this->assertDatabaseHas('threat_logs', ['type' => '[custom] PAN Number Detected']);
    }

    #[Test]
    public function aadhaar_number_alone_in_a_body_is_detected(): void
    {
        // Checksum-valid Aadhaar; the shipped verhoeff validator must pass it.
        config(['threat-detection.pattern_validators' => ['Aadhaar Number Detected' => 'verhoeff']]);
        ThreatDetectionService::flushCaches();

        $this->postJson('/gaps-test', ['aadhaar' => '234567890124']);

        $this->assertDatabaseHas('threat_logs', ['type' => '[custom] Aadhaar Number Detected']);
    }

    #[Test]
    public function mobile_number_alone_in_a_body_is_detected(): void
    {
        $this->postJson('/gaps-test', ['mobile' => '9876543210']);

        $this->assertDatabaseHas('threat_logs', ['type' => '[custom] Mobile Number Detected']);
    }

    #[Test]
    public function bank_account_number_in_a_labelled_field_is_detected(): void
    {
        $this->postJson('/gaps-test', ['bank_account' => '123456789012']);

        $this->assertDatabaseHas('threat_logs', ['type' => '[custom] Bank Account Number Detected']);
    }

    /**
     * The counterweight to the tests above. v1.2.0 deleted the SQL comment
     * pattern for being the top false-positive source and v1.6.0 added the
     * Verhoeff checksum so order ids and timestamps stop being logged as PII.
     * Ungating the digit-run patterns would have undone that: an ordinary
     * checkout body logged two *high* severity PII threats.
     */
    #[Test]
    public function ordinary_numeric_data_is_never_logged_as_pii(): void
    {
        $this->postJson('/gaps-test', [
            'order_id'    => '1735689600000',   // ms epoch timestamp
            'invoice_no'  => '987654321',       // 9-digit invoice
            'product_sku' => '600123456789',    // 12-digit SKU
            'total_paise' => '4999900',
        ]);

        $this->assertEquals(
            0,
            DB::table('threat_logs')->where('type', 'like', '%Number Detected%')->count(),
            'Timestamps, invoice numbers and SKUs must not be logged as PII'
        );
    }

    // ────────────────────────────────────────────
    //  The request path is scanned
    // ────────────────────────────────────────────

    #[Test]
    public function attack_nested_in_the_url_path_is_detected(): void
    {
        $this->get('/deep/path/vendor/phpunit/phpunit/eval-stdin.php');

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] PHPUnit RCE Probe CVE-2017-9841',
            'threat_level' => 'high',
        ]);
    }

    #[Test]
    public function actuator_probe_in_the_url_path_is_detected(): void
    {
        $this->get('/actuator/env');

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] Spring Boot Actuator Probe',
        ]);
    }

    #[Test]
    public function env_file_probe_in_the_url_path_is_detected(): void
    {
        // "/.env" contains no keyword from the pre-screen list, which is exactly
        // why the path segment must be exempt from it.
        $this->get('/.env');

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[custom] Environment File Access',
        ]);
    }

    #[Test]
    public function a_legitimate_nested_admin_route_is_not_flagged(): void
    {
        // The shipped pattern is deliberately narrow: bare /admin matches,
        // /admin/<anything> does not. Path scanning must not change that.
        $this->get('/admin/users');

        $this->assertDatabaseMissing('threat_logs', [
            'type' => '[custom] Admin Path Access Attempt',
        ]);
    }

    /**
     * Probe tracking (v1.3.0, path list extended in v1.3.1) is the package's
     * first-class answer for known recon paths. Path scanning must complement
     * it, not log a second row for the same request.
     */
    #[Test]
    public function a_tracked_probe_path_is_not_logged_twice(): void
    {
        config(['threat-detection.probe_tracking.enabled' => true]);
        ProbeDetectorService::flushCaches();

        $this->get('/.env');

        $rows = DB::table('threat_logs')->pluck('type');

        $this->assertCount(1, $rows, 'Probe tracker and path scanning must not both fire');
        $this->assertEquals('[probe] Environment File', $rows->first());
    }

    #[Test]
    public function a_path_the_probe_list_misses_is_still_caught_by_the_patterns(): void
    {
        // '/vendor/phpunit/*' only matches at the root, so the probe tracker
        // misses this nested variant. The pattern engine must still catch it.
        config(['threat-detection.probe_tracking.enabled' => true]);
        ProbeDetectorService::flushCaches();

        $this->get('/deep/path/vendor/phpunit/phpunit/eval-stdin.php');

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] PHPUnit RCE Probe CVE-2017-9841',
        ]);
    }

    // ────────────────────────────────────────────
    //  Evasion patterns see the still-encoded request
    // ────────────────────────────────────────────

    #[Test]
    public function single_encoded_crlf_in_the_raw_query_string_is_detected(): void
    {
        // A real attacker sends %0d%0a in the URL; Laravel decodes it to actual
        // control characters before the decoded segments are built, so only the
        // raw segment can still see the literal escape.
        $this->get('/gaps-test?input=value%0d%0aSet-Cookie:+hacked%3dtrue');

        $this->assertDatabaseHas('threat_logs', ['type' => '[middleware] CRLF Injection']);
    }

    #[Test]
    public function single_encoded_null_byte_in_the_raw_query_string_is_detected(): void
    {
        $this->get('/gaps-test?file=image.php%00.jpg');

        $this->assertDatabaseHas('threat_logs', ['type' => '[middleware] Null Byte Injection']);
    }

    /**
     * The raw segment reads the body via getContent(), which materialises the
     * whole stream. Bounding that read is the difference between scanning a
     * request and letting one buffer an arbitrary amount of memory on every
     * hit. Over the cap the raw segment declines; the decoded segments still
     * scan the same request.
     */
    #[Test]
    public function an_oversized_raw_body_is_not_buffered(): void
    {
        $huge = str_repeat('a', 70000) . '%00';

        $this->call('POST', '/zz-raw-cap', [], [], [], [
            'CONTENT_TYPE' => 'text/plain',
            'CONTENT_LENGTH' => (string) strlen($huge),
        ], $huge)->assertStatus(200);

        $this->assertDatabaseMissing('threat_logs', ['type' => '[middleware] Null Byte Injection']);
    }

    #[Test]
    public function a_body_under_the_cap_is_still_scanned_raw(): void
    {
        $body = 'file=image.php%00.jpg';

        $this->call('POST', '/zz-raw-cap', [], [], [], [
            'CONTENT_TYPE' => 'text/plain',
            'CONTENT_LENGTH' => (string) strlen($body),
        ], $body)->assertStatus(200);

        $this->assertDatabaseHas('threat_logs', ['type' => '[middleware] Null Byte Injection']);
    }

    #[Test]
    public function an_evasion_label_is_not_double_counted_across_raw_and_decoded(): void
    {
        // "%25" survives decoding, so both the decoded and raw segments match
        // Double URL Encoding. It must still produce exactly one row.
        $this->get('/gaps-test?q=%2555%254e%2549%254f%254e');

        $count = DB::table('threat_logs')
            ->where('type', '[middleware] Double URL Encoding')
            ->count();

        $this->assertEquals(1, $count);
    }

    // ────────────────────────────────────────────
    //  The fast path still holds
    // ────────────────────────────────────────────

    #[Test]
    public function a_genuinely_clean_request_still_logs_nothing(): void
    {
        $this->get('/clean/profile/page?name=John&city=London&age=30');

        $this->assertEquals(0, DB::table('threat_logs')->count());
    }

    #[Test]
    public function a_clean_post_body_still_logs_nothing(): void
    {
        $this->call('POST', '/gaps-test', [
            'name' => 'Jane Doe',
            'email' => 'jane@example.com',
            'message' => 'Hello this is a normal message about web development',
        ]);

        $this->assertEquals(0, DB::table('threat_logs')->count());
    }

    // ────────────────────────────────────────────
    //  Earlier false-positive fixes stay fixed
    // ────────────────────────────────────────────

    /**
     * v1.3.1 excluded the Authorization header from the headers segment —
     * ordinary authenticated traffic was logging a high-severity token threat
     * per IP every 5 minutes. The 'raw' segment added for encoded-evasion
     * detection carries the query string and body only; it must not put the
     * header back in scope.
     */
    #[Test]
    public function the_authorization_header_is_still_not_scanned(): void
    {
        $jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
            . '.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ'
            . '.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk';

        $this->get('/gaps-test', ['HTTP_AUTHORIZATION' => 'Bearer ' . $jwt]);

        $this->assertDatabaseMissing('threat_logs', ['type' => '[middleware] JWT Token Found']);
        $this->assertDatabaseMissing('threat_logs', ['type' => '[custom] Bearer Token Detected']);
    }

    /**
     * v1.2.0 deleted the SQL Comment Syntax pattern as the top false-positive
     * source (it matched CSS classes and CLI flags). Nothing here revives it.
     */
    #[Test]
    public function css_classes_and_cli_flags_are_still_not_sql_comments(): void
    {
        $this->post('/gaps-test', [
            'class' => 'font--bold text--large',
            'flag' => '--verbose --dry-run',
        ]);

        $this->assertEquals(
            0,
            DB::table('threat_logs')->where('type', 'like', '%SQL Comment Syntax%')->count()
        );
    }

    // ────────────────────────────────────────────
    //  Exclusion rules match exactly
    // ────────────────────────────────────────────

    #[Test]
    public function a_short_rule_label_no_longer_swallows_unrelated_patterns(): void
    {
        DB::table('threat_exclusion_rules')->insert([
            'pattern_label' => 'SQL',
            'is_active' => true,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $service = new ExclusionRuleService();
        $service->clearCache();

        $this->assertFalse(
            $service->isExcluded('[middleware] SQL Injection UNION', 'https://example.com/x'),
            'A rule labelled "SQL" must not disable every SQL pattern'
        );
        $this->assertTrue(
            $service->isExcluded('[middleware] SQL', 'https://example.com/x'),
            'The exact label must still be excluded'
        );
    }
}
