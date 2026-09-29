<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Queue\SyncQueue;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Jobs\StoreThreatLog;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * With queued writes on, a queue that cannot be reached must not lose the
 * detection.
 *
 * The row was handed to the queue and nowhere else. When the push failed —
 * Redis down, the queue table missing — the exception reached the
 * middleware's catch, which swallows everything to stay passive, and the
 * detection was gone. The synchronous write the package uses without a queue
 * is now the fallback.
 */
class QueueOutageTest extends TestCase
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
            'threat-detection.queue.enabled' => true,
            'threat-detection.queue.connection' => 'unreachable',
            'queue.connections.unreachable' => ['driver' => 'unreachable'],
        ]);

        Queue::extend('unreachable', fn () => new UnreachableQueue);

        ThreatDetectionService::flushCaches();

        Route::middleware('threat-detect')->get('/search', fn () => response('OK'));
    }

    private function injectionsLogged(): int
    {
        return DB::table('threat_logs')->where('type', 'like', '%SQL Injection UNION%')->count();
    }

    #[Test]
    public function the_detection_is_written_directly_when_the_queue_is_down(): void
    {
        $this->get('/search?q=' . urlencode(self::SQLI))->assertStatus(200);

        $this->assertGreaterThan(0, $this->injectionsLogged(), 'the queue outage lost the detection');
    }

    #[Test]
    public function the_alert_is_sent_directly_too(): void
    {
        Http::fake(['*' => Http::response('ok', 200)]);
        config([
            'threat-detection.notifications.enabled' => true,
            'threat-detection.notifications.notify_levels' => ['high'],
            'threat-detection.notifications.slack_webhook' => 'https://hooks.slack.example/services/T/B/X',
        ]);

        $this->get('/search?q=' . urlencode(self::SQLI))->assertStatus(200);

        Http::assertSent(fn ($request) => str_contains($request->url(), 'hooks.slack.example'));
    }

    /** Positive control: a working queue still gets the job, and nothing is written directly. */
    #[Test]
    public function a_working_queue_still_gets_the_job(): void
    {
        Queue::fake();

        $this->get('/search?q=' . urlencode(self::SQLI))->assertStatus(200);

        Queue::assertPushed(StoreThreatLog::class);
        $this->assertSame(0, $this->injectionsLogged());
    }
}

/** A queue whose push fails, as one backed by an unreachable Redis does. */
class UnreachableQueue extends SyncQueue
{
    public function push($job, $data = '', $queue = null)
    {
        throw new \RuntimeException('Connection refused [tcp://127.0.0.1:6379]');
    }
}
