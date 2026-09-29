<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use JayAnta\ThreatDetection\Services\ThreatCorrelationService;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * The correlation reports are read when an attack is under way, and their
 * size must not be the attacker's to choose.
 *
 * Each fetched every address behind its top rows in one query — every
 * distinct IP for each coordinated URL, every IP for each campaign, every
 * actor for each shared payload — and the coordinated report returned them
 * all. A distributed attack from a hundred thousand addresses therefore
 * loaded a hundred thousand rows into PHP and answered with all of them,
 * on the endpoint an operator opens because of that attack. The lists are
 * now samples fetched with a limit; the counts beside them stay exact.
 */
class CorrelationBoundsTest extends TestCase
{
    private const SAMPLE_ADDRESSES = 50;

    private const SAMPLE_CAMPAIGN_ADDRESSES = 10;

    private const SAMPLE_ACTORS = 200;

    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();
        config(['cache.default' => 'array']);
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    private function seedAttackers(int $count): void
    {
        $rows = [];

        for ($i = 0; $i < $count; $i++) {
            $rows[] = [
                'ip_address' => '198.51.' . intdiv($i, 250) . '.' . ($i % 250 + 1),
                'url' => 'https://app.test/login',
                'user_agent' => 'UA',
                'type' => '[body] SQL Injection UNION',
                'payload' => 'x',
                'threat_level' => 'high',
                'created_at' => now()->subMinutes(2),
                'updated_at' => now()->subMinutes(2),
            ];
        }

        foreach (array_chunk($rows, 100) as $chunk) {
            DB::table('threat_logs')->insert($chunk);
        }
    }

    #[Test]
    public function the_coordinated_report_samples_its_addresses_and_counts_them_all(): void
    {
        $this->seedAttackers(300);

        $attack = (new ThreatCorrelationService)->detectCoordinatedAttacks(15, 3)[0];

        $this->assertSame(300, (int) $attack['unique_ips'], 'the count must stay exact');
        $this->assertCount(self::SAMPLE_ADDRESSES, $attack['attacking_ips']);
    }

    #[Test]
    public function the_campaign_report_samples_its_addresses(): void
    {
        $this->seedAttackers(300);

        $campaign = (new ThreatCorrelationService)->detectAttackCampaigns(24)[0];

        $this->assertSame(300, (int) $campaign['unique_ips']);
        $this->assertCount(self::SAMPLE_CAMPAIGN_ADDRESSES, $campaign['sample_ips']);
    }

    /** Positive control: a small attack is listed in full, as before. */
    #[Test]
    public function a_small_coordinated_attack_is_listed_in_full(): void
    {
        $this->seedAttackers(4);

        $attack = (new ThreatCorrelationService)->detectCoordinatedAttacks(15, 3)[0];

        $this->assertCount(4, $attack['attacking_ips']);
    }

    #[Test]
    public function the_cluster_report_samples_its_actors_and_counts_them_all(): void
    {
        (require __DIR__ . '/../../database/migrations/create_threat_actor_signals_table.php.stub')->up();
        config(['threat-detection.actor_signals.enabled' => true]);

        $rows = [];
        for ($i = 0; $i < 250; $i++) {
            foreach (['aaaaaaaaaaaaaaaa', 'bbbbbbbbbbbbbbbb'] as $fingerprint) {
                $rows[] = [
                    'actor_key' => '203.0.' . intdiv($i, 250) . '.' . ($i % 250 + 1),
                    'fingerprint' => $fingerprint,
                    'variant' => substr(sha1($fingerprint . $i), 0, 16),
                    'label' => 'SQL Injection UNION',
                    'context' => 'body',
                    'observed_on' => now()->toDateString(),
                    'created_at' => now()->subMinutes(5),
                ];
            }
        }
        foreach (array_chunk($rows, 100) as $chunk) {
            DB::table('threat_actor_signals')->insert($chunk);
        }

        $clusters = (new ThreatCorrelationService)->detectPayloadClusters(60, 3, 2);

        $this->assertCount(1, $clusters, 'the two shared payloads should form one cluster');
        $this->assertSame(250, $clusters[0]['actor_count'], 'the count must stay exact');
        $this->assertCount(self::SAMPLE_ACTORS, $clusters[0]['actors']);
        $this->assertSame(2, $clusters[0]['fingerprint_count']);
    }
}
