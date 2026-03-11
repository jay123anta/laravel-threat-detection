<?php

namespace JayAnta\ThreatDetection\Tests\Unit;

use JayAnta\ThreatDetection\Http\Middleware\ThreatDetectionMiddleware;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Tests\TestCase;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

class MiddlewareTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // Mock the service to prevent DB writes in middleware unit tests
        $mock = $this->createMock(ThreatDetectionService::class);
        $mock->method('detectAndLogFromRequest');
        $this->app->instance(ThreatDetectionService::class, $mock);
        $this->app->instance('threat-detection', $mock);
    }

    private function runMiddleware(Request $request, array $configOverrides = []): \Symfony\Component\HttpFoundation\Response
    {
        foreach ($configOverrides as $key => $value) {
            config([$key => $value]);
        }

        $middleware = $this->app->make(ThreatDetectionMiddleware::class);

        return $middleware->handle($request, fn($req) => new Response('OK', 200));
    }

    /** @test */
    public function it_passes_request_through(): void
    {
        $request = Request::create('/test-path', 'GET');

        $response = $this->runMiddleware($request);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('OK', $response->getContent());
    }

    /** @test */
    public function it_skips_when_disabled(): void
    {
        $request = Request::create('/test', 'GET', ['q' => "' UNION SELECT * FROM users"]);

        $response = $this->runMiddleware($request, [
            'threat-detection.enabled' => false,
        ]);

        $this->assertEquals(200, $response->getStatusCode());
    }

    /** @test */
    public function it_skips_whitelisted_ips(): void
    {
        $request = Request::create('/test', 'GET', ['q' => "'; DROP TABLE users;--"]);
        $request->server->set('REMOTE_ADDR', '192.168.1.100');

        $response = $this->runMiddleware($request, [
            'threat-detection.whitelisted_ips' => ['192.168.1.100'],
        ]);

        $this->assertEquals(200, $response->getStatusCode());
    }

    /** @test */
    public function it_skips_paths_matching_skip_patterns(): void
    {
        $request = Request::create('/public/assets/logo.png', 'GET');

        $response = $this->runMiddleware($request, [
            'threat-detection.skip_paths' => ['public/assets/*'],
        ]);

        $this->assertEquals(200, $response->getStatusCode());
    }

    /** @test */
    public function it_sets_content_path_attribute(): void
    {
        $request = Request::create('/admin/posts/edit', 'POST');

        $this->runMiddleware($request, [
            'threat-detection.content_paths' => ['admin/posts/*'],
        ]);

        $this->assertTrue($request->attributes->get('threat-detection:content-path', false));
    }

    /** @test */
    public function it_does_not_set_content_path_for_other_routes(): void
    {
        $request = Request::create('/api/users', 'GET');

        $this->runMiddleware($request, [
            'threat-detection.content_paths' => ['admin/posts/*'],
        ]);

        $this->assertNull($request->attributes->get('threat-detection:content-path'));
    }

    /** @test */
    public function it_only_scans_paths_in_only_paths_whitelist(): void
    {
        // Mock should NOT receive detectAndLogFromRequest for non-matching path
        $mock = $this->createMock(ThreatDetectionService::class);
        $mock->expects($this->never())->method('detectAndLogFromRequest');
        $this->app->instance(ThreatDetectionService::class, $mock);
        $this->app->instance('threat-detection', $mock);

        $request = Request::create('/public/page', 'GET');

        $response = $this->runMiddleware($request, [
            'threat-detection.only_paths' => ['admin/*', 'api/*'],
        ]);

        $this->assertEquals(200, $response->getStatusCode());
    }

    /** @test */
    public function it_scans_matching_path_in_only_paths_whitelist(): void
    {
        // Mock SHOULD receive detectAndLogFromRequest for matching path
        $mock = $this->createMock(ThreatDetectionService::class);
        $mock->expects($this->once())->method('detectAndLogFromRequest');
        $this->app->instance(ThreatDetectionService::class, $mock);
        $this->app->instance('threat-detection', $mock);

        $request = Request::create('/admin/dashboard', 'GET');

        $response = $this->runMiddleware($request, [
            'threat-detection.only_paths' => ['admin/*', 'api/*'],
        ]);

        $this->assertEquals(200, $response->getStatusCode());
    }

    /** @test */
    public function it_scans_all_paths_when_only_paths_is_empty(): void
    {
        // Mock SHOULD receive detectAndLogFromRequest when only_paths is empty (default)
        $mock = $this->createMock(ThreatDetectionService::class);
        $mock->expects($this->once())->method('detectAndLogFromRequest');
        $this->app->instance(ThreatDetectionService::class, $mock);
        $this->app->instance('threat-detection', $mock);

        $request = Request::create('/any/random/path', 'GET');

        $response = $this->runMiddleware($request, [
            'threat-detection.only_paths' => [],
        ]);

        $this->assertEquals(200, $response->getStatusCode());
    }

    /** @test */
    public function skip_paths_still_applies_within_only_paths(): void
    {
        // Path matches only_paths BUT also matches skip_paths — should be skipped
        $mock = $this->createMock(ThreatDetectionService::class);
        $mock->expects($this->never())->method('detectAndLogFromRequest');
        $this->app->instance(ThreatDetectionService::class, $mock);
        $this->app->instance('threat-detection', $mock);

        $request = Request::create('/api/healthcheck', 'GET');

        $response = $this->runMiddleware($request, [
            'threat-detection.only_paths' => ['api/*'],
            'threat-detection.skip_paths' => ['api/healthcheck'],
        ]);

        $this->assertEquals(200, $response->getStatusCode());
    }
}
