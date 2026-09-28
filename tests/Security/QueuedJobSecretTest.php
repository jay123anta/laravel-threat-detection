<?php

namespace JayAnta\ThreatDetection\Tests\Security;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Jobs\StoreThreatLog;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * A Slack incoming-webhook URL is a credential: anyone holding it can post to
 * the channel. Queued detections carried it inside every job, so on a database
 * or Redis queue it was written to `jobs` for each alerting request — and to
 * `failed_jobs`, which nothing prunes, whenever one failed.
 *
 * The job now reads it from config when it runs. A job queued by an earlier
 * version still carries it, and is still honoured, so nothing in flight at
 * upgrade time is lost.
 */
class QueuedJobSecretTest extends TestCase
{
    private const WEBHOOK = 'https://hooks.slack.example/services/T000/B000/s3cr3tw3bh00k';

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
            'threat-detection.queue.enabled' => true,
            'threat-detection.notifications.enabled' => true,
            'threat-detection.notifications.notify_levels' => ['high'],
            'threat-detection.notifications.slack_webhook' => self::WEBHOOK,
        ]);

        ThreatDetectionService::flushCaches();

        Route::middleware('threat-detect')->get('/search', fn () => response('OK'));
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    private function queuedJob(): StoreThreatLog
    {
        Queue::fake();

        $this->get('/search?q=' . urlencode(self::SQLI))->assertStatus(200);

        $jobs = Queue::pushed(StoreThreatLog::class);
        $this->assertCount(1, $jobs, 'no alerting job was queued, so nothing below means anything');

        return $jobs->first();
    }

    #[Test]
    public function the_webhook_url_is_not_serialised_into_the_job(): void
    {
        $this->assertStringNotContainsString(
            's3cr3tw3bh00k',
            serialize($this->queuedJob()),
            'the Slack webhook URL was written into the queued job payload'
        );
    }

    /** Positive control: the job still alerts, to the configured webhook. */
    #[Test]
    public function the_job_still_posts_to_the_configured_webhook(): void
    {
        $job = $this->queuedJob();
        Http::fake(['*' => Http::response('ok', 200)]);

        $job->handle();

        $this->assertGreaterThan(0, DB::table('threat_logs')->count());
        Http::assertSent(fn ($request) => $request->url() === self::WEBHOOK);
    }

    /** A job that does not alert carries no notification data at all. */
    #[Test]
    public function a_job_with_nothing_to_alert_sends_nothing(): void
    {
        config(['threat-detection.notifications.enabled' => false]);
        $job = $this->queuedJob();
        Http::fake();

        $job->handle();

        Http::assertNothingSent();
    }
}
