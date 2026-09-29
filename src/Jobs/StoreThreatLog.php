<?php

namespace JayAnta\ThreatDetection\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Notifications\Messages\SlackMessage;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Notification;
use JayAnta\ThreatDetection\Notifications\ThreatAlertSlack;
use JayAnta\ThreatDetection\Support\LogsQuietly;

class StoreThreatLog implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, LogsQuietly, Queueable, SerializesModels;

    public int $tries = 3;

    public array $backoff = [10, 30];

    public function __construct(
        protected array $logData,
        protected ?array $notificationData = null,
    ) {}

    public function handle(): void
    {
        try {
            DB::table(config('threat-detection.table_name', 'threat_logs'))
                ->insert($this->logData);

            if ($this->notificationData) {
                $this->sendNotification();
            }
        } catch (\Throwable $e) {
            self::logQuietly('error', 'StoreThreatLog job failed: ' . $e->getMessage());
            throw $e;
        }
    }

    private function sendNotification(): void
    {
        try {
            // Read when the job runs, not carried in it: the URL is a
            // credential, and the payload is stored by the queue. A job
            // queued by an earlier version still carries one, and is honoured.
            $webhookUrl = config('threat-detection.notifications.slack_webhook')
                ?: ($this->notificationData['webhook_url'] ?? null);
            if (!$webhookUrl) {
                return;
            }

            $alert = new ThreatAlertSlack($this->notificationData['alert_data']);

            if (class_exists(SlackMessage::class)) {
                Notification::route('slack', $webhookUrl)->notify($alert);
            } else {
                Http::post($webhookUrl, $alert->toWebhookPayload());
            }
        } catch (\Throwable $e) {
            // Quietly: the rows are written, and a log that cannot be opened
            // must not fail the job now — the queue would retry it and write
            // them again.
            self::logQuietly('error', 'StoreThreatLog notification failed: ' . $e->getMessage());
        }
    }
}
