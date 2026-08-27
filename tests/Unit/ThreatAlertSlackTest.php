<?php

namespace JayAnta\ThreatDetection\Tests\Unit;

use Illuminate\Notifications\Messages\SlackMessage;
use JayAnta\ThreatDetection\Notifications\ThreatAlertSlack;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * The Slack alert had never been executed by any test. Both payload builders
 * and the URL defanging were unverified, on the one code path that leaves the
 * server and lands in a human's chat client.
 */
class ThreatAlertSlackTest extends TestCase
{
    private function alert(array $overrides = []): ThreatAlertSlack
    {
        return new ThreatAlertSlack(array_merge([
            'ip_address' => '203.0.113.10',
            'url' => 'https://evil.example.com/wp-admin',
            'type' => '[middleware] SQL Injection UNION',
            'threat_level' => 'high',
            'action_taken' => 'logged',
            'user_agent' => 'sqlmap/1.7',
        ], $overrides));
    }

    #[Test]
    public function the_webhook_payload_carries_every_field(): void
    {
        $fields = collect($this->alert()->toWebhookPayload()['attachments'][0]['fields'])
            ->pluck('value', 'title');

        $this->assertSame('203.0.113.10', $fields['IP']);
        $this->assertSame('[middleware] SQL Injection UNION', $fields['Type']);
        $this->assertSame('High', $fields['Level']);
        $this->assertSame('logged', $fields['Action']);
    }

    /**
     * A live URL in a Slack message is a link an on-call engineer can click by
     * accident at 3am. Both the scheme and the dots are broken so it cannot
     * auto-link or resolve.
     */
    #[Test]
    public function the_url_is_defanged_so_slack_cannot_linkify_it(): void
    {
        $url = collect($this->alert()->toWebhookPayload()['attachments'][0]['fields'])
            ->firstWhere('title', 'URL')['value'];

        $this->assertStringNotContainsString('https://', $url);
        $this->assertStringStartsWith('hxxp://', $url);
        $this->assertStringNotContainsString('evil.example.com', $url);
        $this->assertStringContainsString('evil[.]example[.]com', $url);
    }

    #[Test]
    public function http_urls_are_defanged_too(): void
    {
        $url = collect($this->alert(['url' => 'http://10.0.0.1/x'])->toWebhookPayload()['attachments'][0]['fields'])
            ->firstWhere('title', 'URL')['value'];

        $this->assertSame('hxxp://10[.]0[.]0[.]1/x', $url);
    }

    #[Test]
    public function missing_fields_fall_back_rather_than_erroring(): void
    {
        $payload = (new ThreatAlertSlack([]))->toWebhookPayload();
        $fields = collect($payload['attachments'][0]['fields'])->pluck('value', 'title');

        $this->assertSame('N/A', $fields['IP']);
        $this->assertSame('Unknown', $fields['Type']);
        $this->assertSame('Low', $fields['Level']);
    }

    #[Test]
    public function the_payload_honours_the_configured_channel_and_username(): void
    {
        config([
            'threat-detection.notifications.slack_channel' => '#soc',
            'threat-detection.notifications.slack_username' => 'Sentry',
        ]);

        $payload = $this->alert()->toWebhookPayload();

        $this->assertSame('#soc', $payload['channel']);
        $this->assertSame('Sentry', $payload['username']);
    }

    /**
     * via() returns the slack channel only when the optional
     * laravel/slack-notification-channel package supplies SlackMessage.
     * It is not installed here, so the notification routes nowhere rather
     * than fataling on a missing class.
     */
    #[Test]
    public function via_is_empty_when_the_slack_channel_package_is_absent(): void
    {
        $expected = class_exists(SlackMessage::class)
            ? ['slack']
            : [];

        $this->assertSame($expected, $this->alert()->via(null));
    }
}
