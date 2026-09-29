<?php

namespace JayAnta\ThreatDetection\Tests\Unit;

use Illuminate\Http\Request;
use JayAnta\ThreatDetection\Http\Middleware\ThreatDetectionMiddleware;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * The application runs once per request, whatever it throws.
 *
 * The early exits — detection off, a whitelisted address, a path outside
 * only_paths or inside skip_paths — returned $next($request) from inside the
 * try that guards detection. When the application threw there, the catch took
 * its exception for a detection failure, logged it as one, and then called
 * $next($request) a second time: the controller ran twice. Laravel's pipeline
 * usually renders exceptions into responses first, but not when no exception
 * handler is bound or rendering itself fails — and a second run of a
 * controller is a second charge, a second email, a second write.
 */
class MiddlewareRunsNextOnceTest extends TestCase
{
    public static function earlyExits(): array
    {
        return [
            'detection disabled' => [['threat-detection.enabled' => false], '/anything'],
            'a whitelisted address' => [['threat-detection.whitelisted_ips' => ['127.0.0.1']], '/anything'],
            'outside only_paths' => [['threat-detection.only_paths' => ['admin/*']], '/public/page'],
            'inside skip_paths' => [['threat-detection.skip_paths' => ['health']], '/health'],
        ];
    }

    #[Test]
    #[DataProvider('earlyExits')]
    public function the_application_runs_once_and_its_exception_is_its_own(array $config, string $uri): void
    {
        // The case's own settings win: `+` keeps the left-hand keys.
        config($config + ['threat-detection.enabled' => true, 'threat-detection.whitelisted_ips' => []]);

        $runs = 0;
        $thrown = null;

        try {
            $this->app->make(ThreatDetectionMiddleware::class)->handle(
                Request::create($uri, 'GET'),
                function () use (&$runs) {
                    $runs++;

                    throw new \DomainException('the application failed');
                }
            );
        } catch (\DomainException $e) {
            $thrown = $e;
        }

        $this->assertSame(1, $runs, 'the application ran more than once');
        $this->assertNotNull($thrown, "the application's exception did not reach its caller");
    }

    /** Positive control: the scanned path was already right. */
    #[Test]
    public function a_scanned_request_runs_the_application_once(): void
    {
        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();
        config(['threat-detection.enabled' => true, 'threat-detection.whitelisted_ips' => [], 'cache.default' => 'array']);

        $runs = 0;

        try {
            $this->app->make(ThreatDetectionMiddleware::class)->handle(
                Request::create('/search', 'GET'),
                function () use (&$runs) {
                    $runs++;

                    throw new \DomainException('the application failed');
                }
            );
        } catch (\DomainException) {
            // Expected.
        }

        $this->assertSame(1, $runs);
    }
}
