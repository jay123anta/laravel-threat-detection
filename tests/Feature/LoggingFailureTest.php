<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Tests\TestCase;
use Monolog\Handler\AbstractProcessingHandler;
use Monolog\Logger;
use Monolog\LogRecord;
use PHPUnit\Framework\Attributes\Test;

/**
 * A log channel that cannot be written must not make the package fail
 * requests, or lose what it detected.
 *
 * An unwritable storage/logs is one of the commonest deployment mistakes, and
 * Monolog throws when it cannot open the file. The per-detection warning ran
 * before the batch was written, so the throw lost the detection; the
 * middleware's catch then logged that — and threw again, out of the catch,
 * failing the application's request with a 500. A passive detector turned
 * into one that broke exactly the requests it detected.
 */
class LoggingFailureTest extends TestCase
{
    private const SQLI = "' UNION SELECT password FROM users--";

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
            'logging.default' => 'unwritable',
            'logging.channels.unwritable' => ['driver' => 'custom', 'via' => UnwritableLogFactory::class],
        ]);

        ThreatDetectionService::flushCaches();

        Route::middleware('threat-detect')->get('/search', fn () => response('OK'));
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    #[Test]
    public function the_request_is_answered_normally(): void
    {
        $this->get('/search?q=' . urlencode(self::SQLI))
            ->assertStatus(200)
            ->assertSee('OK');
    }

    #[Test]
    public function the_detection_is_still_recorded(): void
    {
        $this->get('/search?q=' . urlencode(self::SQLI));

        $this->assertGreaterThan(
            0,
            DB::table('threat_logs')->where('type', 'like', '%SQL Injection UNION%')->count(),
            'an unwritable log lost the detection'
        );
    }

    /** Even when detection itself fails, the middleware's own error log must not fail the request. */
    #[Test]
    public function a_failure_inside_detection_is_still_passive(): void
    {
        Schema::drop('threat_logs');

        $this->get('/search?q=' . urlencode(self::SQLI))
            ->assertStatus(200)
            ->assertSee('OK');
    }
}

/** A log channel whose handler throws on every write, as an unwritable file does. */
class UnwritableLogFactory
{
    public function __invoke(array $config): Logger
    {
        return new Logger('unwritable', [new class extends AbstractProcessingHandler
        {
            protected function write(LogRecord $record): void
            {
                throw new \UnexpectedValueException(
                    'The stream or file "storage/logs/laravel.log" could not be opened in append mode: Permission denied'
                );
            }
        }]);
    }
}
