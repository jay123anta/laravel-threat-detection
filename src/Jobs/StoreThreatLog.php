<?php

namespace JayAnta\ThreatDetection\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Notification;
use JayAnta\ThreatDetection\Notifications\ThreatAlertSlack;

class StoreThreatLog implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public int $tries = 3;
    public array $backoff = [10, 30];

    public function __construct(
        protected array $logData,
        protected ?array $notificationData = null,
    ) {
    }

    public function handle(): void
    {
        try {
            DB::table(config('threat-detection.table_name', 'threat_logs'))
                ->insert($this->logData);

            if ($this->notificationData) {
                $this->sendNotification();
            }
        } catch (\Throwable $e) {
            Log::error('StoreThreatLog job failed: ' . $e->getMessage());
            throw $e;
        }
    }

    private function sendNotification(): void
    {
        try {
            $webhookUrl = $this->notificationData['webhook_url'] ?? null;
            if (!$webhookUrl) {
                return;
            }

            $alert = new ThreatAlertSlack($this->notificationData['alert_data']);

            if (class_exists(\Illuminate\Notifications\Messages\SlackMessage::class)) {
                Notification::route('slack', $webhookUrl)->notify($alert);
            } else {
                \Illuminate\Support\Facades\Http::post($webhookUrl, $alert->toWebhookPayload());
            }
        } catch (\Throwable $e) {
            Log::error('StoreThreatLog notification failed: ' . $e->getMessage());
        }
    }
}
