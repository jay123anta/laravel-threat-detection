<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Events\DdosThresholdExceeded;
use JayAnta\ThreatDetection\Facades\ThreatDetection;

/**
 * Operator-side refusal helpers (#4).
 *
 * The package never blocks — these helpers expose its decisions (static
 * denylist, flood counter) so operators can enforce them in their own
 * middleware. Whitelist wins on overlap, CIDR via IpUtils, entries trimmed
 * at match time, and the DdosThresholdExceeded event is throttled to once
 * per window.
 */
class Phase13OperatorHelpersTest extends TestCase
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
            'threat-detection.blocklisted_ips' => [],
            'threat-detection.api_route_filtering.enabled' => false,
            'threat-detection.content_paths' => [],
            'threat-detection.notifications.enabled' => false,
            'threat-detection.queue.enabled' => false,
            'threat-detection.ddos.threshold' => 3,
            'threat-detection.ddos.window' => 60,
            'cache.default' => 'array',
        ]);
    }

    // ── isBlocklisted / isWhitelisted ──

    #[Test]
    public function blocklisted_ip_matches_exact_entry(): void
    {
        config(['threat-detection.blocklisted_ips' => ['203.0.113.7']]);

        $this->assertTrue(ThreatDetection::isBlocklisted('203.0.113.7'));
        $this->assertFalse(ThreatDetection::isBlocklisted('203.0.113.8'));
    }

    #[Test]
    public function blocklisted_ip_matches_cidr_ranges(): void
    {
        config(['threat-detection.blocklisted_ips' => ['203.0.113.0/24', '2001:db8::/32']]);

        $this->assertTrue(ThreatDetection::isBlocklisted('203.0.113.200'));
        $this->assertTrue(ThreatDetection::isBlocklisted('2001:db8::1'));
        $this->assertFalse(ThreatDetection::isBlocklisted('198.51.100.1'));
        $this->assertFalse(ThreatDetection::isBlocklisted('2001:db9::1'));
    }

    #[Test]
    public function whitelist_wins_on_overlap(): void
    {
        config([
            'threat-detection.blocklisted_ips' => ['203.0.113.0/24'],
            'threat-detection.whitelisted_ips' => ['203.0.113.7'],
        ]);

        $this->assertFalse(ThreatDetection::isBlocklisted('203.0.113.7'));
        $this->assertTrue(ThreatDetection::isBlocklisted('203.0.113.8'));
        $this->assertTrue(ThreatDetection::isWhitelisted('203.0.113.7'));
    }

    #[Test]
    public function untrimmed_entries_from_a_stale_published_config_still_match(): void
    {
        // The shipped config trims on parse, but a stale published copy may
        // hand the helper untrimmed entries — matching must not silently stop.
        config(['threat-detection.blocklisted_ips' => [' 203.0.113.7 ', "\t198.51.100.0/24"]]);

        $this->assertTrue(ThreatDetection::isBlocklisted('203.0.113.7'));
        $this->assertTrue(ThreatDetection::isBlocklisted('198.51.100.42'));
    }

    #[Test]
    public function empty_or_malformed_lists_never_match(): void
    {
        config(['threat-detection.blocklisted_ips' => []]);
        $this->assertFalse(ThreatDetection::isBlocklisted('203.0.113.7'));

        config(['threat-detection.blocklisted_ips' => [null, 42, '', '   ']]);
        $this->assertFalse(ThreatDetection::isBlocklisted('203.0.113.7'));

        $this->assertFalse(ThreatDetection::isBlocklisted(''));
    }

    // ── The core invariant: the package itself never refuses ──

    #[Test]
    public function detection_middleware_never_refuses_a_blocklisted_ip(): void
    {
        config(['threat-detection.blocklisted_ips' => ['203.0.113.7']]);

        Route::middleware('threat-detect')->get('/open-page', fn() => response('OK', 200));

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.7'])
            ->get('/open-page')
            ->assertStatus(200);
    }

    #[Test]
    public function middleware_whitelist_check_trims_stale_entries(): void
    {
        config(['threat-detection.whitelisted_ips' => [' 10.9.9.9 ']]);

        Route::middleware('threat-detect')->get('/scan-me', fn() => response('OK', 200));

        $this->withServerVariables(['REMOTE_ADDR' => '10.9.9.9'])
            ->get('/scan-me?q=' . urlencode('<script>alert(1)</script>'))
            ->assertStatus(200);

        $this->assertSame(0, DB::table('threat_logs')->count());

        $this->withServerVariables(['REMOTE_ADDR' => '10.9.9.10'])
            ->get('/scan-me?q=' . urlencode('<script>alert(1)</script>'))
            ->assertStatus(200);

        $this->assertGreaterThan(0, DB::table('threat_logs')->count());
    }

    // ── The README recipe: enforcement in operator middleware ──

    #[Test]
    public function recipe_middleware_refuses_blocklisted_ip_with_403(): void
    {
        config(['threat-detection.blocklisted_ips' => ['203.0.113.0/24']]);

        Route::middleware([RecipeEnforcementMiddleware::class, 'threat-detect'])
            ->get('/guarded', fn() => response('OK', 200));

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.7'])
            ->get('/guarded')
            ->assertStatus(403);

        $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.1'])
            ->get('/guarded')
            ->assertStatus(200);
    }

    #[Test]
    public function recipe_middleware_refuses_flooding_ip_with_429_and_retry_after(): void
    {
        Cache::put('ddos:203.0.113.9', 10, now()->addSeconds(60));

        Route::middleware([RecipeEnforcementMiddleware::class, 'threat-detect'])
            ->get('/guarded', fn() => response('OK', 200));

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.9'])
            ->get('/guarded')
            ->assertStatus(429)
            ->assertHeader('Retry-After', '60');
    }

    // ── DDoS counter helpers ──

    #[Test]
    public function ddos_request_count_peeks_without_incrementing(): void
    {
        $this->assertSame(0, ThreatDetection::ddosRequestCount('203.0.113.9'));

        Cache::put('ddos:203.0.113.9', 5, now()->addSeconds(60));

        $this->assertSame(5, ThreatDetection::ddosRequestCount('203.0.113.9'));
        $this->assertSame(5, ThreatDetection::ddosRequestCount('203.0.113.9'));
    }

    #[Test]
    public function ddos_threshold_exceeded_flips_only_above_threshold(): void
    {
        Cache::put('ddos:203.0.113.9', 3, now()->addSeconds(60));
        $this->assertFalse(ThreatDetection::isDdosThresholdExceeded('203.0.113.9'));

        Cache::put('ddos:203.0.113.9', 4, now()->addSeconds(60));
        $this->assertTrue(ThreatDetection::isDdosThresholdExceeded('203.0.113.9'));
    }

    #[Test]
    public function ddos_helpers_stay_inert_on_unsupported_cache_driver(): void
    {
        config(['cache.default' => 'null']);

        $this->assertSame(0, ThreatDetection::ddosRequestCount('203.0.113.9'));
        $this->assertFalse(ThreatDetection::isDdosThresholdExceeded('203.0.113.9'));
    }

    // ── DdosThresholdExceeded event ──

    #[Test]
    public function ddos_event_dispatched_once_per_window_with_payload(): void
    {
        Event::fake([DdosThresholdExceeded::class]);

        Cache::put('ddos:203.0.113.9', 3, now()->addSeconds(60));

        $request = \Illuminate\Http\Request::create('/flood', 'GET');
        $request->server->set('REMOTE_ADDR', '203.0.113.9');

        ThreatDetection::detectAndLogFromRequest($request);
        ThreatDetection::detectAndLogFromRequest($request);

        Event::assertDispatchedTimes(DdosThresholdExceeded::class, 1);
        Event::assertDispatched(DdosThresholdExceeded::class, function (DdosThresholdExceeded $event) {
            return $event->ipAddress === '203.0.113.9'
                && $event->requestCount > 3
                && $event->threshold === 3
                && $event->windowSeconds === 60;
        });
    }
}

/**
 * The README's minimal user-side blocking middleware, verbatim in spirit:
 * enforcement lives here, in operator code — the package only answers.
 */
class RecipeEnforcementMiddleware
{
    public function handle($request, \Closure $next)
    {
        $ip = (string) $request->ip();

        if (ThreatDetection::isBlocklisted($ip)) {
            abort(403);
        }

        if (ThreatDetection::isDdosThresholdExceeded($ip)) {
            return response('Too Many Requests', 429, [
                'Retry-After' => (string) config('threat-detection.ddos.window', 60),
            ]);
        }

        return $next($request);
    }
}
