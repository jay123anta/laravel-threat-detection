<?php

namespace JayAnta\ThreatDetection\Tests\Unit;

use Illuminate\Support\Facades\DB;
use JayAnta\ThreatDetection\Services\ThreatCorrelationService;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * The reporting queries were only ever reached through two API endpoints, which
 * asserted a 200 and the shape of the envelope — not the aggregates themselves.
 * These assert the numbers.
 */
class ThreatCorrelationServiceTest extends TestCase
{
    private ThreatCorrelationService $service;

    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->service = new ThreatCorrelationService;
    }

    private function seedThreat(string $ip, string $type, string $level, $at, string $url = 'https://example.com/login'): void
    {
        DB::table('threat_logs')->insert([
            'ip_address' => $ip,
            'url' => $url,
            'user_agent' => 'PHPUnit',
            'type' => $type,
            'payload' => 'x',
            'threat_level' => $level,
            'action_taken' => 'logged',
            'created_at' => $at,
            'updated_at' => $at,
        ]);
    }

    // ── getIpStatistics ─────────────────────────────────────────────────────

    #[Test]
    public function ip_statistics_count_totals_and_high_severity_separately(): void
    {
        $this->seedThreat('10.0.0.1', '[middleware] XSS Script Tag', 'high', now()->subHours(3));
        $this->seedThreat('10.0.0.1', '[middleware] SQL Injection UNION', 'high', now()->subHours(2));
        $this->seedThreat('10.0.0.1', '[middleware] Directory Traversal', 'medium', now()->subHour());
        $this->seedThreat('10.0.0.2', '[middleware] XSS Script Tag', 'high', now());

        $stats = $this->service->getIpStatistics('10.0.0.1');

        $this->assertSame(3, $stats['total_threats']);
        $this->assertSame(2, $stats['high_threats']);
        $this->assertNotNull($stats['first_seen']);
        $this->assertNotNull($stats['last_seen']);
        $this->assertCount(3, $stats['top_threat_types']);
    }

    #[Test]
    public function ip_statistics_are_zero_for_an_unseen_address(): void
    {
        $this->seedThreat('10.0.0.1', '[middleware] XSS Script Tag', 'high', now());

        $stats = $this->service->getIpStatistics('198.51.100.99');

        $this->assertSame(0, $stats['total_threats']);
        $this->assertSame(0, $stats['high_threats']);
        $this->assertNull($stats['first_seen']);
    }

    // ── detectCoordinatedAttacks ────────────────────────────────────────────

    #[Test]
    public function coordinated_attacks_need_the_minimum_distinct_ip_count(): void
    {
        // Three distinct IPs on one URL — at the threshold.
        foreach (['10.0.0.1', '10.0.0.2', '10.0.0.3'] as $ip) {
            $this->seedThreat($ip, '[middleware] SQL Injection UNION', 'high', now()->subMinutes(5), 'https://example.com/admin');
        }
        // Two distinct IPs on another — below it.
        foreach (['10.0.1.1', '10.0.1.2'] as $ip) {
            $this->seedThreat($ip, '[middleware] XSS Script Tag', 'high', now()->subMinutes(5), 'https://example.com/search');
        }

        $result = $this->service->detectCoordinatedAttacks(15, 3);

        $this->assertCount(1, $result);
        $this->assertSame('https://example.com/admin', $result[0]['url']);
        $this->assertSame(3, (int) $result[0]['unique_ips']);
        $this->assertCount(3, $result[0]['attacking_ips']);
    }

    #[Test]
    public function coordinated_attacks_ignore_rows_outside_the_window(): void
    {
        foreach (['10.0.0.1', '10.0.0.2', '10.0.0.3'] as $ip) {
            $this->seedThreat($ip, '[middleware] SQL Injection UNION', 'high', now()->subHours(3), 'https://example.com/admin');
        }

        $this->assertSame([], $this->service->detectCoordinatedAttacks(15, 3));
    }

    // ── detectAttackCampaigns ───────────────────────────────────────────────

    #[Test]
    public function campaigns_group_by_type_and_need_five_distinct_ips(): void
    {
        for ($i = 1; $i <= 5; $i++) {
            $this->seedThreat("10.0.0.{$i}", '[middleware] SQL Injection UNION', 'high', now()->subHours(2));
        }
        for ($i = 1; $i <= 4; $i++) {
            $this->seedThreat("10.1.0.{$i}", '[middleware] XSS Script Tag', 'high', now()->subHours(2));
        }

        $result = $this->service->detectAttackCampaigns(24);

        $this->assertCount(1, $result);
        $this->assertSame('[middleware] SQL Injection UNION', $result[0]['threat_type']);
        $this->assertSame(5, (int) $result[0]['unique_ips']);
    }

    // ── detectRapidAttacks ──────────────────────────────────────────────────

    #[Test]
    public function rapid_attackers_need_the_minimum_hit_count(): void
    {
        for ($i = 0; $i < 10; $i++) {
            $this->seedThreat('10.0.0.1', "[middleware] Type {$i}", 'high', now()->subMinutes(2));
        }
        $this->seedThreat('10.0.0.2', '[middleware] XSS Script Tag', 'high', now()->subMinutes(2));

        $result = $this->service->detectRapidAttacks(5, 10);

        $this->assertCount(1, $result);
        $this->assertSame('10.0.0.1', $result[0]['ip_address']);
        $this->assertSame(10, (int) $result[0]['threat_count']);
    }

    /**
     * Ten hits sharing one timestamp make the elapsed window zero. The rate
     * calculation divides by it, so it is floored at one minute — without that
     * guard this is a division by zero.
     */
    #[Test]
    public function rapid_attack_rate_survives_a_zero_length_window(): void
    {
        $at = now()->subMinute();
        for ($i = 0; $i < 10; $i++) {
            $this->seedThreat('10.0.0.1', "[middleware] Type {$i}", 'high', $at);
        }

        $result = $this->service->detectRapidAttacks(5, 10);

        $this->assertSame(10.0, (float) $result[0]['attacks_per_minute']);
    }

    // ── getCorrelationSummary ───────────────────────────────────────────────

    #[Test]
    public function summary_counts_each_correlation_kind(): void
    {
        foreach (['10.0.0.1', '10.0.0.2', '10.0.0.3'] as $ip) {
            $this->seedThreat($ip, '[middleware] SQL Injection UNION', 'high', now()->subMinutes(2), 'https://example.com/admin');
        }

        $summary = $this->service->getCorrelationSummary();

        $this->assertArrayHasKey('coordinated_attacks', $summary);
        $this->assertArrayHasKey('active_campaigns', $summary);
        $this->assertArrayHasKey('rapid_attackers', $summary);
        $this->assertSame(1, $summary['coordinated_attacks']);
    }

    #[Test]
    public function summary_is_all_zeros_on_an_empty_table(): void
    {
        $this->assertSame(
            ['coordinated_attacks' => 0, 'active_campaigns' => 0, 'rapid_attackers' => 0],
            $this->service->getCorrelationSummary()
        );
    }
}
