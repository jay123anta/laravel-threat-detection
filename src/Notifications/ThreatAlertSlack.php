<?php

namespace JayAnta\ThreatDetection\Notifications;

use Illuminate\Notifications\Notification;

class ThreatAlertSlack extends Notification
{
    protected array $log;

    public function __construct(array $log)
    {
        $this->log = $log;
    }

    public function via($notifiable): array
    {
        if (class_exists(\Illuminate\Notifications\Messages\SlackMessage::class)) {
            return ['slack'];
        }

        return [];
    }

    /** Laravel 10 Slack format. */
    public function toSlack($notifiable)
    {
        $log = $this->log;
        $sanitizedUrl = $this->sanitizeUrl($log['url'] ?? 'N/A');

        return (new \Illuminate\Notifications\Messages\SlackMessage)
            ->from(config('threat-detection.notifications.slack_username', 'ThreatBot'))
            ->to(config('threat-detection.notifications.slack_channel', '#threat-alerts'))
            ->warning()
            ->content('@here *Threat Detected*')
            ->attachment(function ($attachment) use ($log, $sanitizedUrl) {
                $attachment->fields([
                    'IP'     => $log['ip_address'] ?? 'N/A',
                    'URL'    => $sanitizedUrl,
                    'Type'   => $log['type'] ?? 'Unknown',
                    'Level'  => ucfirst($log['threat_level'] ?? 'low'),
                    'Action' => $log['action_taken'] ?? 'N/A',
                ]);
            });
    }

    /** Raw webhook payload for Laravel 11+. */
    public function toWebhookPayload(): array
    {
        $log = $this->log;
        $sanitizedUrl = $this->sanitizeUrl($log['url'] ?? 'N/A');

        return [
            'username' => config('threat-detection.notifications.slack_username', 'ThreatBot'),
            'channel' => config('threat-detection.notifications.slack_channel', '#threat-alerts'),
            'text' => '@here *Threat Detected*',
            'attachments' => [
                [
                    'color' => 'warning',
                    'fields' => [
                        ['title' => 'IP', 'value' => $log['ip_address'] ?? 'N/A', 'short' => true],
                        ['title' => 'URL', 'value' => $sanitizedUrl, 'short' => true],
                        ['title' => 'Type', 'value' => $log['type'] ?? 'Unknown', 'short' => true],
                        ['title' => 'Level', 'value' => ucfirst($log['threat_level'] ?? 'low'), 'short' => true],
                        ['title' => 'Action', 'value' => $log['action_taken'] ?? 'N/A', 'short' => true],
                    ],
                ],
            ],
        ];
    }

    // Defang URL to prevent Slack auto-linking
    private function sanitizeUrl(string $url): string
    {
        $sanitized = preg_replace('/^https?:\/\//i', 'hxxp://', $url);
        return str_replace('.', '[.]', $sanitized);
    }
}
