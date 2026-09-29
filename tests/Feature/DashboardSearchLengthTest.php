<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Support\Facades\DB;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * Searching the dashboard for a long URL must work, and a refused search must
 * not turn into a redirect.
 *
 * The keyword was capped at 255 characters, while stored URLs run to 8 KB —
 * so pasting one into the search box was refused. And the dashboard's fetch
 * sent no Accept header, so Laravel answered the refusal with a redirect to
 * the home page rather than a 422: the JSON parse failed and the table sat
 * unchanged, with nothing on screen to say why. The cap now matches the
 * stored bound, and the dashboard asks for JSON.
 */
class DashboardSearchLengthTest extends TestCase
{
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('threat-detection.dashboard.enabled', true);
        $app['config']->set('threat-detection.dashboard.guard', 'none');
        $app['config']->set('threat-detection.dashboard.middleware', ['web']);
        $app['config']->set('app.key', 'base64:' . base64_encode(random_bytes(32)));
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();

        config(['threat-detection.api.guard' => 'none']);
    }

    #[Test]
    public function a_long_stored_url_can_be_searched_for(): void
    {
        $url = 'https://app.test/search?q=' . str_repeat('a', 2000);

        DB::table('threat_logs')->insert([
            'ip_address' => '203.0.113.9', 'url' => $url, 'user_agent' => 'UA',
            'type' => '[query] SQL Injection UNION', 'payload' => 'x', 'threat_level' => 'high',
            'created_at' => now(), 'updated_at' => now(),
        ]);

        $this->getJson('/api/threat-detection/threats?keyword=' . urlencode($url))
            ->assertStatus(200)
            ->assertJsonPath('data.total', 1);
    }

    /** Still bounded: nothing longer than a stored value can match. */
    #[Test]
    public function a_keyword_longer_than_any_stored_value_is_refused(): void
    {
        $this->getJson('/api/threat-detection/threats?keyword=' . str_repeat('a', 8193))->assertStatus(422);
    }

    #[Test]
    public function the_dashboard_asks_the_api_for_json(): void
    {
        $html = (string) $this->get('/threat-detection')->assertStatus(200)->getContent();

        $this->assertStringContainsString('threatDashboard()', $html, 'this is not the dashboard, so nothing below means anything');

        $this->assertMatchesRegularExpression("/fetch\\(API \\+ path, \\{[^}]*'Accept': 'application\\/json'/s", $html);
    }
}
