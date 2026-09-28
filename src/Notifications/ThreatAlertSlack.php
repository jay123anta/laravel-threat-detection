<?php

namespace JayAnta\ThreatDetection\Notifications;

use Illuminate\Notifications\Messages\SlackMessage;
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
        if (class_exists(SlackMessage::class)) {
            return ['slack'];
        }

        return [];
    }

    /** Laravel 10 Slack format. */
    public function toSlack($notifiable)
    {
        $fields = $this->fieldValues();

        return (new SlackMessage)
            ->from(config('threat-detection.notifications.slack_username', 'ThreatBot'))
            ->to(config('threat-detection.notifications.slack_channel', '#threat-alerts'))
            ->warning()
            ->content('@here *Threat Detected*')
            ->attachment(function ($attachment) use ($fields) {
                $attachment->fields($fields);
            });
    }

    /** Raw webhook payload for Laravel 11+. */
    public function toWebhookPayload(): array
    {
        $fields = [];

        foreach ($this->fieldValues() as $title => $value) {
            $fields[] = ['title' => $title, 'value' => $value, 'short' => true];
        }

        return [
            'username' => config('threat-detection.notifications.slack_username', 'ThreatBot'),
            'channel' => config('threat-detection.notifications.slack_channel', '#threat-alerts'),
            'text' => '@here *Threat Detected*',
            'attachments' => [
                [
                    'color' => 'warning',
                    'fields' => $fields,
                ],
            ],
        ];
    }

    /**
     * The alert's fields, ready for Slack.
     *
     * Slack reads `&`, `<` and `>` as markup in attachment fields: `<!channel>`
     * notifies everyone in the channel, and `<http://…|text>` renders a link
     * whose visible text says anything. The URL is the requester's, path and
     * all, so every value is escaped as Slack's documentation asks — `&`
     * first, so an entity already in the value stays literal.
     *
     * @return array<string, string>
     */
    private function fieldValues(): array
    {
        $log = $this->log;

        $fields = [
            'IP' => (string) ($log['ip_address'] ?? 'N/A'),
            'URL' => $this->sanitizeUrl((string) ($log['url'] ?? 'N/A')),
            'Type' => (string) ($log['type'] ?? 'Unknown'),
            'Level' => ucfirst((string) ($log['threat_level'] ?? 'low')),
            'Action' => (string) ($log['action_taken'] ?? 'N/A'),
        ];

        return array_map(
            static fn (string $value): string => str_replace(['&', '<', '>'], ['&amp;', '&lt;', '&gt;'], $value),
            $fields
        );
    }

    // Defang URL to prevent Slack auto-linking
    private function sanitizeUrl(string $url): string
    {
        $sanitized = preg_replace('/^https?:\/\//i', 'hxxp://', $url);

        return str_replace('.', '[.]', $sanitized);
    }
}
