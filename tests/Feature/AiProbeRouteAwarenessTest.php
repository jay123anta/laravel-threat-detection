<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Contracts\Http\Kernel;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Http\Middleware\ThreatDetectionMiddleware;
use JayAnta\ThreatDetection\Services\ProbeDetectorService;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * An AI-infrastructure path the application itself serves is not a probe.
 *
 * The pack's premise is that almost no Laravel app serves these paths, so a
 * request for one is someone hunting for exposed model infrastructure. That
 * is true of `/v1/models` on a shop. It is not true of `/api/tags` on a blog
 * with a tags API, of `/api/chat` on a support widget — and it was never true
 * of the `/api/v1/*` wildcard the pack briefly shipped, which matched every
 * versioned API in the ecosystem and logged each ordinary call as a
 * high-severity probe.
 *
 * So a pack path counts as the application's own when a real route serves
 * it, and is skipped. A fallback route, or a catch-all made of a single
 * parameter (an SPA's `{any}`), does not count: those answer every path, so
 * they say nothing about whether this one is real — and they are exactly the
 * setups where the pack does its work.
 *
 * Only the AI pack is route-aware. The general probe list behaves as it
 * always has.
 */
class AiProbeRouteAwarenessTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();

        config([
            'cache.default' => 'array',
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
            'threat-detection.probe_tracking.ai_infrastructure.enabled' => true,
        ]);

        ThreatDetectionService::flushCaches();
        ProbeDetectorService::flushCaches();
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    /** @return array<int, string> */
    private function probeTypes(): array
    {
        return DB::table('threat_logs')->where('type', 'like', '[probe] %')->pluck('type')->all();
    }

    // ── The application's own endpoints ────────────────────────────────────

    public static function ownEndpoints(): array
    {
        return [
            'a versioned API' => ['/api/v1/orders', '/api/v1/orders'],
            'a versioned API with a parameter' => ['/api/v1/orders/{id}', '/api/v1/orders/42'],
            'a tags API' => ['/api/tags', '/api/tags'],
            'a chat widget' => ['/api/chat', '/api/chat'],
            'a health check' => ['/health_check', '/health_check'],
            'a generic resource router' => ['/api/{resource}', '/api/show'],
        ];
    }

    #[Test]
    #[DataProvider('ownEndpoints')]
    public function a_path_the_application_serves_is_not_a_probe(string $route, string $request): void
    {
        Route::middleware('threat-detect')->get($route, fn () => response('OK'));

        $this->get($request)->assertStatus(200);

        $this->assertSame([], $this->probeTypes(), "the app's own {$request} was logged as a probe");
    }

    // ── What the pack exists to catch ──────────────────────────────────────

    public static function probes(): array
    {
        return [
            'OpenAI-compatible enumeration' => ['/v1/models'],
            'Ollama enumeration' => ['/api/tags'],
            'Langflow CVE path' => ['/api/v1/validate/code'],
            'Gemini model list' => ['/v1beta/models'],
            'Gemini generation' => ['/v1beta/models/gemini-2.0-flash:generateContent'],
            'Anthropic-compatible messages' => ['/v1/messages'],
            'OpenAI Responses API' => ['/v1/responses'],
        ];
    }

    /** A fallback answers every path; it does not make any one of them real. */
    #[Test]
    #[DataProvider('probes')]
    public function a_probe_that_reaches_a_fallback_route_is_logged(string $path): void
    {
        Route::middleware('threat-detect')->group(function () {
            Route::get('/', fn () => response('home'));
            Route::fallback(fn () => response('Not Found', 404));
        });

        $this->get($path);

        $this->assertNotEmpty($this->probeTypes(), "{$path} reached the fallback and was not logged");
    }

    /**
     * Any route marked as a fallback, not just Route::fallback()'s own
     * single-parameter one. Laravel lets an ordinary route be marked this
     * way, and its longer URI would otherwise read as a real endpoint.
     */
    #[Test]
    public function any_route_marked_as_a_fallback_does_not_count_as_serving_a_path(): void
    {
        Route::middleware('threat-detect')->get('/v1/{rest}', fn () => response('Not Found', 404))
            ->where('rest', '.*')
            ->fallback();

        $this->get('/v1/models');

        $this->assertNotEmpty($this->probeTypes(), 'a route marked as a fallback was treated as the app serving /v1/models');
    }

    /** The same for an SPA's catch-all, which answers every path with 200. */
    #[Test]
    #[DataProvider('probes')]
    public function a_probe_that_reaches_a_single_parameter_catch_all_is_logged(string $path): void
    {
        Route::middleware('threat-detect')->get('/{any}', fn () => response('<div id="app"></div>'))->where('any', '.*');

        $this->get($path)->assertStatus(200);

        $this->assertNotEmpty($this->probeTypes(), "{$path} reached the SPA catch-all and was not logged");
    }

    /**
     * The `/api/v1/*` wildcard is gone, not merely route-aware. A 404 under
     * the app's own versioned API — a stale client, a typo, a removed
     * endpoint — is not someone hunting for Langflow. The CVE-specific path
     * stays.
     */
    #[Test]
    public function a_miss_under_a_versioned_api_is_not_a_langflow_probe(): void
    {
        Route::middleware('threat-detect')->group(fn () => Route::fallback(fn () => response('Not Found', 404)));

        $this->get('/api/v1/orders-old');

        $this->assertSame([], $this->probeTypes());
    }

    // ── Global middleware sees unrouted requests too ───────────────────────

    #[Test]
    public function with_global_middleware_an_unrouted_probe_is_logged(): void
    {
        $this->app[Kernel::class]->pushMiddleware(ThreatDetectionMiddleware::class);

        $this->get('/v1/models')->assertStatus(404);

        $this->assertNotEmpty($this->probeTypes());
    }

    /** The path exists and only the method differs: still the app's own. */
    #[Test]
    public function with_global_middleware_a_served_path_under_another_method_is_not_a_probe(): void
    {
        $this->app[Kernel::class]->pushMiddleware(ThreatDetectionMiddleware::class);
        Route::post('/api/chat', fn () => response('OK'));

        $this->get('/api/chat')->assertStatus(405);

        $this->assertSame([], $this->probeTypes());
    }

    /**
     * Route matching can fail for reasons of the app's own — here a route
     * whose constraint is not a valid regex. That failure must not reach the
     * middleware's outer catch, which would skip detection for the whole
     * request; an unknown answer is treated as unserved.
     */
    #[Test]
    public function a_route_table_that_cannot_be_matched_does_not_cost_the_request_its_detection(): void
    {
        $this->app[Kernel::class]->pushMiddleware(ThreatDetectionMiddleware::class);
        Route::get('/broken/{segment}', fn () => response('OK'))->where('segment', '[unclosed');

        $this->get('/v1/models');

        $this->assertNotEmpty($this->probeTypes(), 'a route-matching failure skipped detection for the request');
    }

    // ── The general list is unchanged ──────────────────────────────────────

    #[Test]
    public function the_general_probe_list_is_not_route_aware(): void
    {
        Route::middleware('threat-detect')->get('/wp-admin', fn () => response('OK'));

        $this->get('/wp-admin')->assertStatus(200);

        $this->assertNotEmpty($this->probeTypes(), 'the general probe list changed behaviour');
    }

    /**
     * The result is stored on the request as `threat-detection:probe`, where
     * an application can read it. The general list's shape is unchanged; only
     * pack entries say where they came from.
     */
    #[Test]
    public function the_general_list_result_keeps_its_exact_shape(): void
    {
        $detector = new ProbeDetectorService;

        $this->assertSame(['label' => 'WordPress Admin', 'level' => 'medium'], $detector->detect('/wp-admin'));
        $this->assertSame(
            ['label' => 'OpenAI-Compatible Model Enumeration', 'level' => 'high', 'pack' => ProbeDetectorService::AI_PACK],
            $detector->detect('/v1/models')
        );
    }

    #[Test]
    public function the_pack_is_still_off_by_default(): void
    {
        config(['threat-detection.probe_tracking.ai_infrastructure.enabled' => false]);
        ProbeDetectorService::flushCaches();

        Route::middleware('threat-detect')->group(fn () => Route::fallback(fn () => response('Not Found', 404)));

        $this->get('/v1/models');

        $this->assertSame([], $this->probeTypes());
    }
}
