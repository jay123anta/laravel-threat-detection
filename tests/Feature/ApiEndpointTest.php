<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Support\Facades\DB;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

class ApiEndpointTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();

        // These tests cover what the endpoints *do*. Since 1.7.0 the two write
        // endpoints sit behind api.write_guard ('role' by default), so without
        // this they would all assert 403 and stop testing their own subject.
        // The guard itself is covered by WriteGuardTest.
        config(['threat-detection.api.write_guard' => 'none']);
    }

    private function seedThreats(int $count = 5): void
    {
        $rows = [];
        for ($i = 0; $i < $count; $i++) {
            $rows[] = [
                'ip_address' => "10.0.0.{$i}",
                'url' => "https://example.com/test/{$i}",
                'user_agent' => 'PHPUnit/Test',
                'type' => '[test] SQL Injection',
                'payload' => 'SELECT * FROM users',
                'threat_level' => ['high', 'medium', 'low'][$i % 3],
                'action_taken' => 'logged',
                'created_at' => now(),
                'updated_at' => now(),
            ];
        }
        DB::table('threat_logs')->insert($rows);
    }

    #[Test]
    public function stats_endpoint_returns_correct_structure(): void
    {
        $this->seedThreats(3);

        $response = $this->getJson('/api/threat-detection/stats');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'success',
                'data' => [
                    'total_threats',
                    'high_severity',
                    'medium_severity',
                    'low_severity',
                    'unique_ips',
                    'today',
                    'last_hour',
                ],
            ])
            ->assertJson(['success' => true]);

        $this->assertEquals(3, $response->json('data.total_threats'));
    }

    #[Test]
    public function threats_endpoint_returns_paginated_data(): void
    {
        $this->seedThreats(25);

        $response = $this->getJson('/api/threat-detection/threats?per_page=10');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'success',
                'data' => [
                    'data',
                    'current_page',
                    'last_page',
                    'per_page',
                    'total',
                ],
            ]);

        $data = $response->json('data');
        $this->assertCount(10, $data['data']);
        $this->assertEquals(25, $data['total']);
    }

    #[Test]
    public function threats_endpoint_supports_level_filter(): void
    {
        $this->seedThreats(12);

        $response = $this->getJson('/api/threat-detection/threats?level=high');

        $response->assertStatus(200);
        $threats = $response->json('data.data');

        foreach ($threats as $threat) {
            $this->assertEquals('high', $threat['threat_level']);
        }
    }

    #[Test]
    public function stats_returns_zeros_when_empty(): void
    {
        $response = $this->getJson('/api/threat-detection/stats');

        $response->assertStatus(200);
        $data = $response->json('data');
        $this->assertEquals(0, $data['total_threats']);
        $this->assertEquals(0, $data['unique_ips']);
    }

    #[Test]
    public function live_count_endpoint_works(): void
    {
        $this->seedThreats(3);

        $response = $this->getJson('/api/threat-detection/live-count');

        $response->assertStatus(200)
            ->assertJson(['success' => true])
            ->assertJsonStructure(['success', 'data' => ['count']]);

        $this->assertEquals(3, $response->json('data.count'));
    }

    #[Test]
    public function show_endpoint_returns_single_threat(): void
    {
        $this->seedThreats(1);

        $response = $this->getJson('/api/threat-detection/threats/1');

        $response->assertStatus(200)
            ->assertJson(['success' => true])
            ->assertJsonStructure([
                'success',
                'data' => ['id', 'ip_address', 'url', 'type', 'threat_level'],
            ]);
    }

    #[Test]
    public function show_endpoint_returns_404_for_missing_threat(): void
    {
        $response = $this->getJson('/api/threat-detection/threats/999');

        $response->assertStatus(404);
    }

    #[Test]
    public function mark_false_positive_creates_exclusion_rule(): void
    {
        $this->seedThreats(1);

        $response = $this->postJson('/api/threat-detection/threats/1/false-positive', [
            'reason' => 'Not a real threat',
        ]);

        $response->assertStatus(200)
            ->assertJson(['success' => true]);

        $this->assertDatabaseHas('threat_logs', [
            'id' => 1,
            'is_false_positive' => true,
        ]);

        $this->assertDatabaseHas('threat_exclusion_rules', [
            'created_from_threat_id' => 1,
            'reason' => 'Not a real threat',
            'is_active' => true,
        ]);
    }

    #[Test]
    public function mark_false_positive_returns_404_for_missing_threat(): void
    {
        $response = $this->postJson('/api/threat-detection/threats/999/false-positive');

        $response->assertStatus(404);
    }

    #[Test]
    public function exclusion_rules_endpoint_lists_rules(): void
    {
        DB::table('threat_exclusion_rules')->insert([
            'pattern_label' => 'XSS Script Tag',
            'is_active' => true,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $response = $this->getJson('/api/threat-detection/exclusion-rules');

        $response->assertStatus(200)
            ->assertJson(['success' => true]);

        $this->assertCount(1, $response->json('data'));
    }

    #[Test]
    public function delete_exclusion_rule_works(): void
    {
        $id = DB::table('threat_exclusion_rules')->insertGetId([
            'pattern_label' => 'XSS Script Tag',
            'is_active' => true,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $response = $this->deleteJson("/api/threat-detection/exclusion-rules/{$id}");

        $response->assertStatus(200)
            ->assertJson(['success' => true]);

        $this->assertDatabaseMissing('threat_exclusion_rules', ['id' => $id]);
    }

    #[Test]
    public function delete_exclusion_rule_returns_404_for_missing(): void
    {
        $response = $this->deleteJson('/api/threat-detection/exclusion-rules/999');

        $response->assertStatus(404);
    }

    #[Test]
    public function summary_endpoint_returns_correct_structure(): void
    {
        $this->seedThreats(5);

        $response = $this->getJson('/api/threat-detection/summary');

        $response->assertStatus(200)
            ->assertJson(['success' => true])
            ->assertJsonStructure([
                'success',
                'data' => [
                    'byType',
                    'byLevel',
                    'byIP',
                    'byCountry',
                    'byCloudProvider',
                    'byDate',
                ],
            ]);
    }

    #[Test]
    public function by_country_endpoint_returns_data(): void
    {
        DB::table('threat_logs')->insert([
            'ip_address' => '10.0.0.1',
            'url' => 'https://example.com/test',
            'type' => '[test] XSS',
            'threat_level' => 'high',
            'action_taken' => 'logged',
            'country_code' => 'US',
            'country_name' => 'United States',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $response = $this->getJson('/api/threat-detection/by-country');

        $response->assertStatus(200)
            ->assertJson(['success' => true]);

        $data = $response->json('data');
        $this->assertNotEmpty($data);
        $this->assertEquals('US', $data[0]['country_code']);
    }

    #[Test]
    public function by_cloud_provider_endpoint_returns_data(): void
    {
        DB::table('threat_logs')->insert([
            'ip_address' => '10.0.0.1',
            'url' => 'https://example.com/test',
            'type' => '[test] XSS',
            'threat_level' => 'high',
            'action_taken' => 'logged',
            'cloud_provider' => 'AWS',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $response = $this->getJson('/api/threat-detection/by-cloud-provider');

        $response->assertStatus(200)
            ->assertJson(['success' => true]);

        $data = $response->json('data');
        $this->assertNotEmpty($data);
        $this->assertEquals('AWS', $data[0]['cloud_provider']);
    }

    #[Test]
    public function top_ips_endpoint_returns_data_with_limit(): void
    {
        $this->seedThreats(10);

        $response = $this->getJson('/api/threat-detection/top-ips?limit=5');

        $response->assertStatus(200)
            ->assertJson(['success' => true]);

        $data = $response->json('data');
        $this->assertLessThanOrEqual(5, count($data));
    }

    #[Test]
    public function timeline_endpoint_returns_grouped_data(): void
    {
        $this->seedThreats(3);

        $response = $this->getJson('/api/threat-detection/timeline?days=7');

        $response->assertStatus(200)
            ->assertJson(['success' => true])
            ->assertJsonStructure(['success', 'data']);
    }

    #[Test]
    public function ip_stats_endpoint_returns_stats(): void
    {
        $this->seedThreats(3);

        $response = $this->getJson('/api/threat-detection/ip-stats?ip=10.0.0.0');

        $response->assertStatus(200)
            ->assertJson(['success' => true])
            ->assertJsonStructure([
                'success',
                'data' => [
                    'ip_address',
                    'statistics',
                    'recent_threats',
                    'level_breakdown',
                ],
            ]);
    }

    #[Test]
    public function ip_stats_requires_valid_ip(): void
    {
        $response = $this->getJson('/api/threat-detection/ip-stats');

        $response->assertStatus(422);
    }

    #[Test]
    public function correlation_endpoint_returns_data(): void
    {
        $this->seedThreats(5);

        $response = $this->getJson('/api/threat-detection/correlation?type=all');

        $response->assertStatus(200)
            ->assertJson(['success' => true])
            ->assertJsonStructure([
                'success',
                'data',
            ]);
    }

    #[Test]
    public function export_endpoint_returns_csv(): void
    {
        $this->seedThreats(3);

        $response = $this->get('/api/threat-detection/export');

        $response->assertStatus(200);
        $this->assertStringContainsString('text/csv', $response->headers->get('Content-Type'));
        $this->assertStringContainsString('attachment', $response->headers->get('Content-Disposition'));
        $this->assertStringContainsString('ID,Time,"IP Address"', $response->getContent());
    }

    #[Test]
    public function threats_endpoint_supports_false_positive_filter(): void
    {
        $this->seedThreats(5);
        DB::table('threat_logs')->where('id', 1)->update(['is_false_positive' => true]);

        $response = $this->getJson('/api/threat-detection/threats?is_false_positive=true');

        $response->assertStatus(200);
        $threats = $response->json('data.data');
        $this->assertCount(1, $threats);
        $this->assertTrue((bool) $threats[0]['is_false_positive']);
    }

    #[Test]
    public function threats_endpoint_supports_date_filters(): void
    {
        $this->seedThreats(3);
        DB::table('threat_logs')->where('id', 1)->update([
            'created_at' => now()->subDays(10),
        ]);

        $response = $this->getJson('/api/threat-detection/threats?date_from=' . now()->subDay()->toDateString());

        $response->assertStatus(200);
        $this->assertEquals(2, $response->json('data.total'));
    }

    #[Test]
    public function threats_endpoint_validates_per_page(): void
    {
        $response = $this->getJson('/api/threat-detection/threats?per_page=999999');

        $response->assertStatus(422);
    }

    #[Test]
    public function top_ips_validates_limit(): void
    {
        $response = $this->getJson('/api/threat-detection/top-ips?limit=999');

        $response->assertStatus(422);
    }

    #[Test]
    public function timeline_validates_days(): void
    {
        $response = $this->getJson('/api/threat-detection/timeline?days=0');

        $response->assertStatus(422);
    }
}
