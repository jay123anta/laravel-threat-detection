<?php

namespace JayAnta\ThreatDetection\Tests\Security;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Http\Middleware\ThreatDetectionMiddleware;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Exception\SuspiciousOperationException;

/**
 * A malformed Host header must not stop the request being recorded.
 *
 * The stored URL was built with $request->fullUrl(), and Symfony validates the
 * Host header while building it: an invalid one throws
 * SuspiciousOperationException. That was the first thing detection did, so
 * the throw ended it before anything was written; the middleware swallowed
 * it to stay passive, and an application route that never builds a URL of
 * its own answered normally. The URL is now built from the raw request when
 * Symfony refuses to, and the refused Host is kept, escaped, as evidence.
 */
class MalformedHostTest extends TestCase
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

        Route::middleware('threat-detect')->get('/search', fn () => response('OK'));
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    private function injectionRow(): ?object
    {
        return DB::table('threat_logs')->where('type', 'like', '%SQL Injection UNION%')->first();
    }

    /**
     * Laravel's test client rebuilds HTTP_HOST from the URL it is given, so
     * an invalid Host has to be put on the request directly.
     */
    private function requestWithHost(string $host): Request
    {
        $request = Request::create('/search?q=' . urlencode(self::INJECTION), 'GET');
        $request->headers->set('HOST', $host);
        $request->server->set('HTTP_HOST', $host);

        return $request;
    }

    /** Positive control: the stand-in request really is refused by Symfony. */
    #[Test]
    public function symfony_refuses_to_build_the_url(): void
    {
        $this->expectException(SuspiciousOperationException::class);

        $this->requestWithHost('bad host')->fullUrl();
    }

    #[Test]
    public function the_attack_is_recorded_despite_an_invalid_host(): void
    {
        $response = $this->app->make(ThreatDetectionMiddleware::class)
            ->handle($this->requestWithHost('bad host'), fn () => new Response('OK', 200));

        $this->assertSame(200, $response->getStatusCode());

        $row = $this->injectionRow();

        $this->assertNotNull($row, 'an invalid Host header stopped the request being recorded');
        $this->assertStringContainsString('/search?q=', $row->url);
        $this->assertStringContainsString('bad host', $row->url, 'the refused Host should be kept as evidence');
    }

    /** Positive control: an ordinary Host is stored exactly as before. */
    #[Test]
    public function an_ordinary_host_is_stored_as_before(): void
    {
        $this->get('/search?q=' . urlencode(self::INJECTION))->assertStatus(200);

        $this->assertStringStartsWith('http://localhost/search?q=', (string) $this->injectionRow()?->url);
    }
}
