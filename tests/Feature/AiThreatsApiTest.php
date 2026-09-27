<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * The API behind the dashboard's split between web attacks and AI-related
 * threats.
 *
 * Every endpoint the dashboard reads takes an optional `category` of `ai` or
 * `traditional`. Without it, each returns exactly what it always did — the
 * contract an existing consumer relies on, and the first thing tested here.
 */
class AiThreatsApiTest extends TestCase
{
    private const API = '/api/threat-detection';

    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();

        config([
            'cache.default' => 'array',
            'threat-detection.api.write_guard' => 'none',
        ]);

        $this->seedRows();
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    /**
     * Three web attacks, two AI-infrastructure probes, one LLM-directed
     * payload — from four addresses, one of them doing both kinds.
     */
    private function seedRows(): void
    {
        $rows = [
            ['10.0.0.1', '[middleware] SQL Injection UNION', 'high'],
            ['10.0.0.1', '[middleware] XSS Script Tag', 'high'],
            ['10.0.0.2', '[probe] WordPress Admin', 'medium'],
            ['10.0.0.3', '[probe] OpenAI-Compatible Model Enumeration', 'high'],
            ['10.0.0.1', '[probe] Ollama Model Enumeration', 'high'],
            ['10.0.0.4', '[custom] LLM Triage Manipulation', 'medium'],
        ];

        foreach ($rows as [$ip, $type, $level]) {
            DB::table('threat_logs')->insert([
                'ip_address' => $ip,
                'url' => 'https://example.com/x',
                'user_agent' => 'curl/8',
                'type' => $type,
                'payload' => 'x',
                'threat_level' => $level,
                'created_at' => now(),
                'updated_at' => now(),
            ]);
        }
    }

    // ── Unchanged without the parameter ────────────────────────────────────

    #[Test]
    public function without_a_category_every_endpoint_counts_everything(): void
    {
        $this->assertSame(6, $this->getJson(self::API . '/stats')->json('data.total_threats'));
        $this->assertSame(6, $this->getJson(self::API . '/threats')->json('data.total'));
        $this->assertSame(6, collect($this->getJson(self::API . '/timeline')->json('data'))->sum('count'));
        $this->assertSame(6, collect($this->getJson(self::API . '/top-ips')->json('data'))->sum('threat_count'));
    }

    /** The stats keys an existing consumer reads are exactly the ones it read before. */
    #[Test]
    public function the_stats_shape_is_unchanged(): void
    {
        $this->assertSame(
            ['total_threats', 'high_severity', 'medium_severity', 'low_severity', 'unique_ips', 'foreign_ips', 'cloud_attacks', 'today', 'last_hour'],
            array_keys($this->getJson(self::API . '/stats')->json('data'))
        );
    }

    // ── The split ──────────────────────────────────────────────────────────

    public static function splits(): array
    {
        return [
            'ai' => ['ai', 3],
            'traditional' => ['traditional', 3],
        ];
    }

    #[Test]
    #[DataProvider('splits')]
    public function each_endpoint_honours_the_category(string $category, int $expected): void
    {
        $this->assertSame($expected, $this->getJson(self::API . "/stats?category={$category}")->json('data.total_threats'));
        $this->assertSame($expected, $this->getJson(self::API . "/threats?category={$category}")->json('data.total'));
        $this->assertSame($expected, collect($this->getJson(self::API . "/timeline?category={$category}")->json('data'))->sum('count'));
        $this->assertSame($expected, collect($this->getJson(self::API . "/top-ips?category={$category}")->json('data'))->sum('threat_count'));
    }

    #[Test]
    public function the_country_breakdown_honours_the_category(): void
    {
        DB::table('threat_logs')->update(['country_code' => 'NL', 'country_name' => 'Netherlands']);

        $sum = fn (string $query) => collect($this->getJson(self::API . '/by-country' . $query)->json('data'))->sum('count');

        $this->assertSame(6, $sum(''));
        $this->assertSame(3, $sum('?category=ai'));
        $this->assertSame(3, $sum('?category=traditional'));
    }

    /** The two halves partition the whole: nothing counted twice, nothing lost. */
    #[Test]
    public function the_halves_add_up_to_the_whole(): void
    {
        $ai = $this->getJson(self::API . '/threats?category=ai&per_page=100')->json('data.data');
        $web = $this->getJson(self::API . '/threats?category=traditional&per_page=100')->json('data.data');

        $this->assertSame([], array_intersect(array_column($ai, 'id'), array_column($web, 'id')));
        $this->assertCount(6, array_merge($ai, $web));
    }

    /** A WordPress probe is reconnaissance, but not AI reconnaissance. */
    #[Test]
    public function an_ordinary_probe_stays_with_the_web_attacks(): void
    {
        $web = array_column($this->getJson(self::API . '/threats?category=traditional')->json('data.data'), 'type');

        $this->assertContains('[probe] WordPress Admin', $web);
    }

    #[Test]
    public function each_row_says_which_ai_family_it_belongs_to(): void
    {
        $rows = collect($this->getJson(self::API . '/threats?per_page=100')->json('data.data'))->keyBy('type');

        $this->assertSame('ai_infrastructure_probe', $rows['[probe] OpenAI-Compatible Model Enumeration']['ai_family']);
        $this->assertSame('llm_injection', $rows['[custom] LLM Triage Manipulation']['ai_family']);
        $this->assertNull($rows['[middleware] SQL Injection UNION']['ai_family']);
    }

    #[Test]
    public function an_unknown_category_is_rejected(): void
    {
        $this->getJson(self::API . '/threats?category=everything')->assertStatus(422);
        $this->getJson(self::API . '/stats?category=everything')->assertStatus(422);
    }

    // ── The AI section's own endpoint ──────────────────────────────────────

    #[Test]
    public function the_ai_endpoint_counts_each_family_separately(): void
    {
        $data = $this->getJson(self::API . '/ai-threats')->assertStatus(200)->json('data');

        $this->assertSame(2, $data['totals']['infrastructure_probes']);
        $this->assertSame(1, $data['totals']['llm_injection']);
        $this->assertSame(3, $data['totals']['unique_ips']);

        $labels = array_column($data['by_type'], 'label');
        $this->assertContains('OpenAI-Compatible Model Enumeration', $labels);
        $this->assertNotContains('SQL Injection UNION', $labels);
        $this->assertNotContains('WordPress Admin', $labels);
    }

    /**
     * "Off" and "nothing found" are different answers, and a dashboard that
     * showed a zero for a switched-off feature would say the second.
     */
    #[Test]
    public function the_ai_endpoint_says_what_is_switched_off(): void
    {
        $data = $this->getJson(self::API . '/ai-threats')->json('data');

        $this->assertSame(
            ['ai_probes' => false, 'llm_injection' => false, 'actor_signals' => false, 'actor_score' => false, 'ai_guard' => false],
            $data['enabled']
        );
        $this->assertNull($data['mutation_chains'], 'an analysis that never ran reported an empty result');
        $this->assertNull($data['payload_clusters']);
        $this->assertNull($data['retry_bursts']);
        $this->assertNull($data['risky_actors']);
    }

    #[Test]
    public function the_ai_endpoint_reports_what_is_switched_on(): void
    {
        config([
            'threat-detection.probe_tracking.ai_infrastructure.enabled' => true,
            'threat-detection.actor_score.enabled' => true,
        ]);

        $data = $this->getJson(self::API . '/ai-threats')->json('data');

        $this->assertTrue($data['enabled']['ai_probes']);
        $this->assertTrue($data['enabled']['actor_score']);
        $this->assertIsArray($data['risky_actors']);
        $this->assertNotEmpty($data['risky_actors']);
    }

    /** Rows logged while a pack was on are still AI-related after it is switched off. */
    #[Test]
    public function history_is_counted_whatever_the_current_switches(): void
    {
        $this->assertSame(2, $this->getJson(self::API . '/ai-threats')->json('data.totals.infrastructure_probes'));
    }

    #[Test]
    public function the_window_is_honoured(): void
    {
        DB::table('threat_logs')->where('type', '[custom] LLM Triage Manipulation')->update(['created_at' => now()->subDays(10)]);

        $this->assertSame(0, $this->getJson(self::API . '/ai-threats?days=7')->json('data.totals.llm_injection'));
        $this->assertSame(1, $this->getJson(self::API . '/ai-threats?days=30')->json('data.totals.llm_injection'));
    }
}
