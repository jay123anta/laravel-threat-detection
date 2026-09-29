<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use JayAnta\ThreatDetection\Jobs\StoreThreatLog;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * A queued write that succeeded must not be retried.
 *
 * The job logs a failed notification from its catch. With the log
 * unwritable, that call threw out of the catch, the job failed after its
 * insert had already gone through — and the queue retried it, writing the
 * same rows again, up to three times.
 */
class StoreJobLoggingTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();

        config(['threat-detection.notifications.slack_webhook' => 'https://hooks.slack.example/services/T/B/X']);

        // Every log call throws, as it does when Monolog cannot open its file.
        Log::swap(new class
        {
            public function __call(string $method, array $arguments): never
            {
                throw new \UnexpectedValueException('The stream or file "storage/logs/laravel.log" could not be opened in append mode');
            }
        });
    }

    /** Positive control: the log really cannot be written here. */
    #[Test]
    public function the_log_really_throws(): void
    {
        $this->expectException(\UnexpectedValueException::class);

        Log::error('anything');
    }

    #[Test]
    public function a_failed_alert_with_an_unwritable_log_does_not_fail_the_job(): void
    {
        Http::fake(fn () => throw new ConnectionException('timed out'));

        $job = new StoreThreatLog(
            [[
                'ip_address' => '203.0.113.1', 'url' => 'https://example.com/x', 'user_agent' => 'PHPUnit',
                'type' => '[middleware] XSS Script Tag', 'payload' => 'x', 'threat_level' => 'high',
                'confidence_score' => 50, 'confidence_label' => 'high', 'user_id' => null,
                'created_at' => now(), 'updated_at' => now(),
            ]],
            ['alert_data' => ['ip_address' => '203.0.113.1']]
        );

        $job->handle();

        $this->assertSame(1, DB::table('threat_logs')->count());
    }
}
