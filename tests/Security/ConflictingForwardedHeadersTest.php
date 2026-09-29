<?php

namespace JayAnta\ThreatDetection\Tests\Security;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use JayAnta\ThreatDetection\Http\Middleware\ThreatDetectionMiddleware;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Exception\ConflictingHeadersException;

/**
 * Forwarded headers that disagree must not stop the request being recorded.
 *
 * When an application trusts both `Forwarded` and `X-Forwarded-For`, a client
 * can send the two with different addresses, and Symfony's ip() then throws
 * ConflictingHeadersException. ip() was the first call in both the middleware
 * and the detector, so the throw ended detection before anything was
 * written. The address the connection actually came from is used instead —
 * the one fact about the client that no header can change.
 */
class ConflictingForwardedHeadersTest extends TestCase
{
    private const INJECTION = "' UNION SELECT password FROM users--";

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
        ]);

        ThreatDetectionService::flushCaches();

        Request::setTrustedProxies(['10.0.0.9'], Request::HEADER_FORWARDED | Request::HEADER_X_FORWARDED_FOR);
    }

    protected function tearDown(): void
    {
        Request::setTrustedProxies([], 0);
        Cache::flush();
        parent::tearDown();
    }

    private function conflictingRequest(): Request
    {
        $request = Request::create('/search?q=' . urlencode(self::INJECTION), 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.0.9']);
        $request->headers->set('Forwarded', 'for=198.51.100.1');
        $request->headers->set('X-Forwarded-For', '198.51.100.2');

        return $request;
    }

    /** Positive control: the stand-in request really does make ip() throw. */
    #[Test]
    public function symfony_refuses_to_name_the_client(): void
    {
        $this->expectException(ConflictingHeadersException::class);

        $this->conflictingRequest()->ip();
    }

    #[Test]
    public function the_attack_is_recorded_under_the_connecting_address(): void
    {
        $response = $this->app->make(ThreatDetectionMiddleware::class)
            ->handle($this->conflictingRequest(), fn () => new Response('OK', 200));

        $this->assertSame(200, $response->getStatusCode());

        $row = DB::table('threat_logs')->where('type', 'like', '%SQL Injection UNION%')->first();

        $this->assertNotNull($row, 'conflicting forwarded headers stopped the request being recorded');
        $this->assertSame('10.0.0.9', $row->ip_address);
    }
}
