<?php

namespace JayAnta\ThreatDetection\Tests\Unit;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use JayAnta\ThreatDetection\Http\Middleware\ThreatDetectionMiddleware;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * `only_paths` scopes scanning to the routes an operator names. It compared
 * them against the path as sent, still percent-encoded, while Laravel's router
 * matches the decoded path — so one request could reach a scoped route while
 * falling outside the scope meant to cover it.
 *
 * Either spelling now brings a path into scope. The lists that *narrow*
 * scanning — skip_paths, content_paths, auth_paths — still compare the raw
 * path, so an encoding can widen what is scanned and never narrow it.
 */
class OnlyPathsDecodingTest extends TestCase
{
    private function expectScans(int $times): void
    {
        $mock = $this->createMock(ThreatDetectionService::class);
        $mock->expects($this->exactly($times))->method('detectAndLogFromRequest');
        $this->app->instance(ThreatDetectionService::class, $mock);
        $this->app->instance('threat-detection', $mock);
    }

    private function handleThrough(string $uri, array $config): void
    {
        config($config);

        $response = $this->app->make(ThreatDetectionMiddleware::class)
            ->handle(Request::create($uri, 'GET'), fn () => new Response('OK', 200));

        $this->assertSame(200, $response->getStatusCode());
    }

    #[Test]
    public function an_encoded_spelling_of_a_scoped_path_is_scanned(): void
    {
        $this->expectScans(1);

        $this->handleThrough('/%61dmin/users', ['threat-detection.only_paths' => ['admin/*']]);
    }

    #[Test]
    public function an_encoded_separator_inside_a_scoped_path_is_scanned(): void
    {
        $this->expectScans(1);

        $this->handleThrough('/admin%2Fusers', ['threat-detection.only_paths' => ['admin/*']]);
    }

    /** Positive control: the plain spelling is still scanned. */
    #[Test]
    public function the_plain_spelling_is_still_scanned(): void
    {
        $this->expectScans(1);

        $this->handleThrough('/admin/users', ['threat-detection.only_paths' => ['admin/*']]);
    }

    /** Negative control: a path outside the scope, in either spelling, is not. */
    #[Test]
    public function a_path_outside_the_scope_is_still_skipped(): void
    {
        $this->expectScans(0);

        $this->handleThrough('/%70ublic/page', ['threat-detection.only_paths' => ['admin/*']]);
    }

    /** Decoding widens scope only: skip_paths still compares the raw path. */
    #[Test]
    public function an_encoded_spelling_does_not_reach_a_skip_entry(): void
    {
        $this->expectScans(1);

        $this->handleThrough('/%68ealth', [
            'threat-detection.only_paths' => [],
            'threat-detection.skip_paths' => ['health'],
        ]);
    }
}
