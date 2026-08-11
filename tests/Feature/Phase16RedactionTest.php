<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * Detecting sensitive data must not store it.
 *
 * Observed on a live application: a profile form carrying a name, mobile
 * number, PAN and bank account tripped three PII patterns, and each of the
 * three rows written stored the whole body verbatim. The detector had turned
 * itself into a second, concentrated cleartext copy of exactly the data it
 * exists to warn about — kept for the full retention period and readable by
 * anyone with dashboard or database access.
 */
class Phase16RedactionTest extends TestCase
{
    /**
     * The dashboard routes are registered during boot, gated on this flag, so
     * it has to be set before the provider boots rather than inside a test.
     */
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('threat-detection.dashboard.enabled', true);
        $app['config']->set('threat-detection.dashboard.middleware', ['web']);

        // The 'web' group encrypts cookies, which needs a key.
        $app['config']->set('app.key', 'base64:' . base64_encode(str_repeat('t', 32)));
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();

        config([
            'threat-detection.enabled' => true,
            'threat-detection.detection_mode' => 'balanced',
            'threat-detection.skip_paths' => [],
            'threat-detection.probe_tracking.enabled' => false,
            'threat-detection.api_route_filtering.enabled' => false,
            'threat-detection.notifications.enabled' => false,
            'threat-detection.queue.enabled' => false,
            'cache.default' => 'array',
        ]);

        Route::middleware('threat-detect')->group(function () {
            Route::post('/profile', fn() => response('OK', 200));
            Route::get('/profile', fn() => response('OK', 200));
            Route::post('/search', fn() => response('OK', 200));
        });

        ThreatDetectionService::flushCaches();
    }

    protected function tearDown(): void
    {
        ThreatDetectionService::flushCaches();
        Cache::flush();
        parent::tearDown();
    }

    private function payloads(): string
    {
        return DB::table('threat_logs')->pluck('payload')->implode("\n");
    }

    // ── the leak ────────────────────────────────────────────────────────────

    #[Test]
    public function detected_pii_is_not_written_to_the_payload(): void
    {
        $this->postJson('/profile', [
            'name' => 'Jane Doe',
            'mobile' => '9876543210',
            'pan' => 'ABCDE1234F',
            'bank_account' => '123456789012',
        ]);

        // The alert still happened...
        $this->assertDatabaseHas('threat_logs', ['type' => '[custom] PAN Number Detected']);

        // ...but the values are gone from every row it wrote.
        $payloads = $this->payloads();
        $this->assertStringNotContainsString('ABCDE1234F', $payloads, 'PAN was stored in cleartext');
        $this->assertStringNotContainsString('9876543210', $payloads, 'Mobile was stored in cleartext');
        $this->assertStringNotContainsString('123456789012', $payloads, 'Bank account was stored in cleartext');
        $this->assertStringContainsString('[REDACTED]', $payloads);
    }

    #[Test]
    public function non_sensitive_context_survives_so_the_row_is_still_useful(): void
    {
        $this->postJson('/profile', [
            'name' => 'Jane Doe',
            'pan' => 'ABCDE1234F',
        ]);

        $payload = $this->payloads();

        // The field names and surrounding request shape are what make the alert
        // actionable; only the value itself is masked.
        $this->assertStringContainsString('pan', $payload);
        $this->assertStringContainsString('Jane Doe', $payload);
    }

    #[Test]
    public function pii_in_the_query_string_is_masked_in_the_stored_url(): void
    {
        // The url column is as much of a leak as the payload.
        $this->get('/profile?pan=ABCDE1234F');

        $urls = DB::table('threat_logs')->pluck('url')->implode("\n");

        $this->assertNotEmpty($urls, 'nothing detected — test is not exercising the path');
        $this->assertStringNotContainsString('ABCDE1234F', $urls, 'PAN was stored in the url column');
        $this->assertStringContainsString('[REDACTED]', $urls);
    }

    // ── it must not over-reach ──────────────────────────────────────────────

    #[Test]
    public function an_attack_payload_is_stored_intact(): void
    {
        // Redaction keys off sensitive labels only. An SQL injection payload is
        // evidence, not a secret — masking it would destroy the investigation.
        $this->post('/search', ['q' => "' UNION SELECT password FROM users--"]);

        $this->assertStringContainsString('UNION SELECT', $this->payloads());
    }

    #[Test]
    public function redaction_can_be_turned_off(): void
    {
        config(['threat-detection.redact.enabled' => false]);

        $this->postJson('/profile', ['pan' => 'ABCDE1234F']);

        $this->assertStringContainsString('ABCDE1234F', $this->payloads());
    }

    #[Test]
    public function the_mask_is_configurable(): void
    {
        config(['threat-detection.redact.mask' => '***']);

        $this->postJson('/profile', ['pan' => 'ABCDE1234F']);

        $payload = $this->payloads();
        $this->assertStringContainsString('***', $payload);
        $this->assertStringNotContainsString('ABCDE1234F', $payload);
    }

    #[Test]
    public function a_label_not_listed_as_sensitive_is_left_alone(): void
    {
        config(['threat-detection.redact.labels' => ['Mobile Number Detected']]);
        ThreatDetectionService::flushCaches();

        $this->postJson('/profile', ['pan' => 'ABCDE1234F', 'mobile' => '9876543210']);

        $payload = $this->payloads();
        $this->assertStringNotContainsString('9876543210', $payload, 'listed label should be masked');
        $this->assertStringContainsString('ABCDE1234F', $payload, 'unlisted label should be untouched');
    }

    // ── detection itself is unaffected ──────────────────────────────────────

    #[Test]
    public function redaction_runs_after_detection_so_nothing_is_missed(): void
    {
        $this->postJson('/profile', [
            'mobile' => '9876543210',
            'pan' => 'ABCDE1234F',
            'bank_account' => '123456789012',
        ]);

        foreach (['PAN Number Detected', 'Mobile Number Detected', 'Bank Account Number Detected'] as $label) {
            $this->assertDatabaseHas('threat_logs', ['type' => '[custom] ' . $label]);
        }
    }

    // ── dashboard hardening ─────────────────────────────────────────────────

    /**
     * The dashboard renders attacker-supplied payloads, URLs and user agents to
     * an authenticated admin, and loads three third-party scripts. The headers
     * below are what stop a compromised one from shipping this application's
     * threat data somewhere else, and stop the page being framed.
     */
    #[Test]
    public function the_dashboard_sends_security_headers(): void
    {
        $response = $this->get('/' . config('threat-detection.dashboard.path', 'threat-detection'));

        $response->assertOk();
        $response->assertHeader('X-Frame-Options', 'DENY');
        $response->assertHeader('X-Content-Type-Options', 'nosniff');
        $response->assertHeader('Referrer-Policy', 'no-referrer');

        $csp = $response->headers->get('Content-Security-Policy');
        $this->assertStringContainsString("connect-src 'self'", $csp, 'must block third-party exfiltration');
        $this->assertStringContainsString("frame-ancestors 'none'", $csp);
        $this->assertStringContainsString("default-src 'self'", $csp);
    }

    #[Test]
    public function every_dashboard_script_is_pinned_and_has_an_integrity_hash(): void
    {
        $layout = file_get_contents(__DIR__ . '/../../resources/views/layouts/app.blade.php');

        preg_match_all('/<script[^>]*\ssrc="([^"]+)"[^>]*>/i', $layout, $tags, PREG_SET_ORDER);

        $this->assertNotEmpty($tags, 'no external scripts found — has the layout changed?');

        foreach ($tags as [$tag, $src]) {
            $this->assertStringContainsString('integrity="sha384-', $tag, "Missing SRI hash: {$src}");
            $this->assertStringContainsString('crossorigin=', $tag, "Missing crossorigin: {$src}");
            $this->assertDoesNotMatchRegularExpression(
                '/@\d+(\.x)*\/|@\d+\//',
                $src,
                "Floating version range, cannot be pinned by SRI: {$src}"
            );
        }
    }
}
