<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * Two properties of the deployment that the package depends on and cannot
 * see from inside a request.
 *
 * **Proxy trust.** The whitelist and the `ip` guards key off
 * `$request->ip()`, which honours X-Forwarded-For from any proxy the app
 * trusts. With TrustProxies at `*` that is whoever connects directly, so an
 * app reachable around its proxy lets a client name its own address — a
 * whitelisted one is never scanned, an allowed one opens the dashboard.
 *
 * **Retention.** Off by default, so IP addresses, URLs and user agents are
 * kept indefinitely. In the EU those are personal data, and storage has to be
 * limited (GDPR Art. 5(1)(e)).
 */
class DoctorDeploymentChecksTest extends TestCase
{
    private const PROXY_WARNING = 'trust X-Forwarded-For from any client';

    private const RETENTION_WARNING = 'Retention is off';

    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();

        config([
            'threat-detection.enabled' => true,
            'threat-detection.enabled_environments' => null,
            'threat-detection.custom_patterns' => [],
            'threat-detection.dashboard.enabled' => false,
            'threat-detection.api.enabled' => true,
            'threat-detection.api.middleware' => ['api', 'auth'],
            'threat-detection.whitelisted_ips' => [],
            'trustedproxy.proxies' => null,
            'cache.default' => 'array',
        ]);

        Route::middleware('threat-detect')->get('/doctor-probe', fn () => 'OK');
    }

    protected function tearDown(): void
    {
        if (method_exists(TrustProxies::class, 'flushState')) {
            TrustProxies::flushState();
        }

        parent::tearDown();
    }

    #[Test]
    public function a_whitelist_behind_wildcard_proxy_trust_is_reported(): void
    {
        config(['threat-detection.whitelisted_ips' => ['198.51.100.0/24'], 'trustedproxy.proxies' => '*']);

        $this->artisan('threat-detection:doctor')
            ->expectsOutputToContain(self::PROXY_WARNING)
            ->assertExitCode(0);
    }

    #[Test]
    public function an_ip_guard_behind_wildcard_proxy_trust_is_reported(): void
    {
        config([
            'threat-detection.dashboard.enabled' => true,
            'threat-detection.dashboard.guard' => 'ip',
            'threat-detection.dashboard.allowed_ips' => ['127.0.0.1'],
            'trustedproxy.proxies' => '*',
        ]);

        $this->artisan('threat-detection:doctor')->expectsOutputToContain(self::PROXY_WARNING);
    }

    /** Laravel 11+ sets it in bootstrap/app.php rather than in config. */
    #[Test]
    public function wildcard_trust_set_in_the_application_bootstrap_is_seen(): void
    {
        if (!method_exists(TrustProxies::class, 'at')) {
            $this->markTestSkipped('TrustProxies::at() arrived in Laravel 11.');
        }

        TrustProxies::at('*');
        config(['threat-detection.whitelisted_ips' => ['198.51.100.0/24']]);

        $this->artisan('threat-detection:doctor')->expectsOutputToContain(self::PROXY_WARNING);
    }

    /** Negative control: wildcard trust with no IP decision to subvert says nothing. */
    #[Test]
    public function wildcard_trust_alone_is_not_reported(): void
    {
        config(['trustedproxy.proxies' => '*']);

        $this->artisan('threat-detection:doctor')->doesntExpectOutputToContain(self::PROXY_WARNING);
    }

    /** Negative control: named proxies are what the warning asks for. */
    #[Test]
    public function named_proxies_are_not_reported(): void
    {
        config(['threat-detection.whitelisted_ips' => ['198.51.100.0/24'], 'trustedproxy.proxies' => '10.0.0.5']);

        $this->artisan('threat-detection:doctor')->doesntExpectOutputToContain(self::PROXY_WARNING);
    }

    #[Test]
    public function retention_off_in_production_is_reported(): void
    {
        $this->app['env'] = 'production';
        config(['threat-detection.retention.enabled' => false]);

        $this->artisan('threat-detection:doctor')->expectsOutputToContain(self::RETENTION_WARNING);
    }

    #[Test]
    public function retention_on_in_production_is_not_reported(): void
    {
        $this->app['env'] = 'production';
        config(['threat-detection.retention.enabled' => true]);

        $this->artisan('threat-detection:doctor')->doesntExpectOutputToContain(self::RETENTION_WARNING);
    }

    /** Local development keeps its data as long as it likes. */
    #[Test]
    public function retention_off_outside_production_is_not_reported(): void
    {
        config(['threat-detection.retention.enabled' => false]);

        $this->artisan('threat-detection:doctor')->doesntExpectOutputToContain(self::RETENTION_WARNING);
    }
}
