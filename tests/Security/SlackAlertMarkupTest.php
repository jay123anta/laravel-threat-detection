<?php

namespace JayAnta\ThreatDetection\Tests\Security;

use JayAnta\ThreatDetection\Notifications\ThreatAlertSlack;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * Slack reads `&`, `<` and `>` as markup in attachment fields, and its
 * documentation says values must escape them. The alert did not.
 *
 * The URL is the requester's: the path reaches the alert as sent, so a request
 * for `/<!channel>` notified the whole channel, and `<http://…|Open the
 * dashboard>` rendered as a link whose visible text says anything at all —
 * posted into the room where the people who respond to attacks read. Defanging
 * the URL's own scheme and dots does not reach markup in the middle of it.
 */
class SlackAlertMarkupTest extends TestCase
{
    /** @return array<string, string> */
    private function fields(array $log): array
    {
        $payload = (new ThreatAlertSlack(array_merge([
            'ip_address' => '203.0.113.10',
            'url' => 'https://app.test/search',
            'type' => '[query] SQL Injection UNION',
            'threat_level' => 'high',
            'action_taken' => 'logged',
        ], $log)))->toWebhookPayload();

        return collect($payload['attachments'][0]['fields'])->pluck('value', 'title')->all();
    }

    public static function markupInTheUrl(): array
    {
        return [
            'a channel-wide mention' => ['https://app.test/<!channel>', '&lt;!channel&gt;'],
            'a user mention' => ['https://app.test/<@U024BE7LH>', '&lt;@U024BE7LH&gt;'],
            'a labelled link' => ['https://app.test/<http://2130706433|Open the dashboard>', '&lt;http://2130706433|Open the dashboard&gt;'],
        ];
    }

    #[Test]
    #[DataProvider('markupInTheUrl')]
    public function markup_in_the_url_reaches_slack_as_text(string $url, string $expected): void
    {
        $value = $this->fields(['url' => $url])['URL'];

        $this->assertStringNotContainsString('<', $value);
        $this->assertStringNotContainsString('>', $value);
        $this->assertStringContainsString($expected, $value);
    }

    /** An ampersand is escaped first, so an entity already in the URL stays literal. */
    #[Test]
    public function an_ampersand_is_escaped_too(): void
    {
        $this->assertStringContainsString(
            'a=1&amp;b=&amp;lt;',
            $this->fields(['url' => 'https://app.test/x?a=1&b=&lt;'])['URL']
        );
    }

    /** Every field is escaped, not only the URL: none of them is trusted at this layer. */
    #[Test]
    public function every_field_is_escaped(): void
    {
        $fields = $this->fields([
            'ip_address' => '<!here>',
            'type' => '[query] <!channel>',
            'action_taken' => '<!everyone>',
        ]);

        foreach ($fields as $title => $value) {
            $this->assertStringNotContainsString('<', $value, "the {$title} field carried raw markup");
        }
    }

    /** Positive control: an ordinary alert reads exactly as before. */
    #[Test]
    public function an_ordinary_alert_is_unchanged(): void
    {
        $fields = $this->fields([]);

        $this->assertSame('203.0.113.10', $fields['IP']);
        $this->assertSame('hxxp://app[.]test/search', $fields['URL']);
        $this->assertSame('[query] SQL Injection UNION', $fields['Type']);
        $this->assertSame('High', $fields['Level']);
        $this->assertSame('logged', $fields['Action']);
    }
}
