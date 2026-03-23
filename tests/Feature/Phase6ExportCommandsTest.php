<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use JayAnta\ThreatDetection\Tests\TestCase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Cache;

/**
 * Phase 6 v1.3.0: Full-cycle tests for fail2ban and blocklist export commands.
 */
class Phase6ExportCommandsTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();
        Cache::flush();
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    private function seedThreats(): void
    {
        $table = config('threat-detection.table_name', 'threat_logs');
        $now = now();

        // IP 10.0.0.1: 5 high threats
        for ($i = 0; $i < 5; $i++) {
            DB::table($table)->insert([
                'ip_address' => '10.0.0.1',
                'url' => 'http://example.com/?q=attack' . $i,
                'user_agent' => 'sqlmap/1.0',
                'type' => '[middleware] SQL Injection UNION',
                'payload' => 'UNION SELECT',
                'threat_level' => 'high',
                'confidence_score' => 90,
                'confidence_label' => 'very_high',
                'created_at' => $now->copy()->subMinutes($i),
                'updated_at' => $now->copy()->subMinutes($i),
            ]);
        }

        // IP 10.0.0.2: 2 medium threats
        for ($i = 0; $i < 2; $i++) {
            DB::table($table)->insert([
                'ip_address' => '10.0.0.2',
                'url' => 'http://example.com/../../etc/passwd',
                'user_agent' => 'Mozilla/5.0',
                'type' => '[middleware] Directory Traversal',
                'payload' => '../../etc/passwd',
                'threat_level' => 'medium',
                'confidence_score' => 60,
                'confidence_label' => 'high',
                'created_at' => $now->copy()->subMinutes($i),
                'updated_at' => $now->copy()->subMinutes($i),
            ]);
        }

        // IP 10.0.0.3: 1 low threat
        DB::table($table)->insert([
            'ip_address' => '10.0.0.3',
            'url' => 'http://example.com/',
            'user_agent' => 'python-requests/2.28',
            'type' => '[user-agent] Python Script',
            'payload' => '',
            'threat_level' => 'low',
            'confidence_score' => 20,
            'confidence_label' => 'low',
            'created_at' => $now,
            'updated_at' => $now,
        ]);

        // IP 10.0.0.4: 3 high threats from 48 hours ago (outside default 24h window)
        for ($i = 0; $i < 3; $i++) {
            DB::table($table)->insert([
                'ip_address' => '10.0.0.4',
                'url' => 'http://example.com/?cmd=system',
                'user_agent' => 'Mozilla/5.0',
                'type' => '[middleware] RCE Shell Function',
                'payload' => "system('ls')",
                'threat_level' => 'high',
                'confidence_score' => 85,
                'confidence_label' => 'very_high',
                'created_at' => $now->copy()->subHours(48),
                'updated_at' => $now->copy()->subHours(48),
            ]);
        }
    }

    // ────────────────────────────────────────────
    //  Fail2ban Export
    // ────────────────────────────────────────────

    /** @test */
    public function fail2ban_export_outputs_ips_in_fail2ban_format(): void
    {
        $this->seedThreats();

        $this->artisan('threat-detection:export-fail2ban')
            ->expectsOutputToContain('fail2ban-client set threat-detection banip 10.0.0.1')
            ->assertExitCode(0);
    }

    /** @test */
    public function fail2ban_export_plain_format_outputs_one_ip_per_line(): void
    {
        $this->seedThreats();

        $this->artisan('threat-detection:export-fail2ban', ['--format' => 'plain'])
            ->expectsOutputToContain('10.0.0.1')
            ->expectsOutputToContain('10.0.0.2')
            ->assertExitCode(0);
    }

    /** @test */
    public function fail2ban_export_filters_by_level(): void
    {
        $this->seedThreats();

        $this->artisan('threat-detection:export-fail2ban', ['--level' => 'high', '--format' => 'plain'])
            ->expectsOutputToContain('10.0.0.1')
            ->doesntExpectOutputToContain('10.0.0.2')
            ->assertExitCode(0);
    }

    /** @test */
    public function fail2ban_export_filters_by_min_hits(): void
    {
        $this->seedThreats();

        $this->artisan('threat-detection:export-fail2ban', ['--min-hits' => '3', '--format' => 'plain'])
            ->expectsOutputToContain('10.0.0.1')
            ->doesntExpectOutputToContain('10.0.0.2')
            ->doesntExpectOutputToContain('10.0.0.3')
            ->assertExitCode(0);
    }

    /** @test */
    public function fail2ban_export_filters_by_since(): void
    {
        $this->seedThreats();

        // Default 24h should exclude 10.0.0.4 (48h old)
        $this->artisan('threat-detection:export-fail2ban', ['--format' => 'plain'])
            ->doesntExpectOutputToContain('10.0.0.4')
            ->assertExitCode(0);
    }

    /** @test */
    public function fail2ban_export_wider_since_includes_old_ips(): void
    {
        $this->seedThreats();

        $this->artisan('threat-detection:export-fail2ban', ['--since' => '7d', '--format' => 'plain'])
            ->expectsOutputToContain('10.0.0.4')
            ->assertExitCode(0);
    }

    /** @test */
    public function fail2ban_export_no_results_shows_message(): void
    {
        // Empty DB
        $this->artisan('threat-detection:export-fail2ban')
            ->expectsOutputToContain('No IPs match')
            ->assertExitCode(0);
    }

    /** @test */
    public function fail2ban_export_custom_jail_name(): void
    {
        $this->seedThreats();

        $this->artisan('threat-detection:export-fail2ban', ['--jail' => 'my-app'])
            ->expectsOutputToContain('fail2ban-client set my-app banip')
            ->assertExitCode(0);
    }

    // ────────────────────────────────────────────
    //  Blocklist Export
    // ────────────────────────────────────────────

    /** @test */
    public function blocklist_export_plain_format(): void
    {
        $this->seedThreats();

        $this->artisan('threat-detection:export-blocklist', ['--format' => 'plain'])
            ->expectsOutputToContain('10.0.0.1')
            ->assertExitCode(0);
    }

    /** @test */
    public function blocklist_export_nginx_format(): void
    {
        $this->seedThreats();

        $this->artisan('threat-detection:export-blocklist', ['--format' => 'nginx'])
            ->expectsOutputToContain('deny 10.0.0.1;')
            ->assertExitCode(0);
    }

    /** @test */
    public function blocklist_export_apache_format(): void
    {
        $this->seedThreats();

        $this->artisan('threat-detection:export-blocklist', ['--format' => 'apache'])
            ->expectsOutputToContain('Deny from 10.0.0.1')
            ->assertExitCode(0);
    }

    /** @test */
    public function blocklist_export_csv_format(): void
    {
        $this->seedThreats();

        $this->artisan('threat-detection:export-blocklist', ['--format' => 'csv'])
            ->expectsOutputToContain('ip_address,hits,last_seen,threat_level')
            ->expectsOutputToContain('10.0.0.1,5')
            ->assertExitCode(0);
    }

    /** @test */
    public function blocklist_export_filters_by_level_and_min_hits(): void
    {
        $this->seedThreats();

        $this->artisan('threat-detection:export-blocklist', [
            '--level' => 'high',
            '--min-hits' => '3',
            '--format' => 'plain',
        ])
            ->expectsOutputToContain('10.0.0.1')
            ->doesntExpectOutputToContain('10.0.0.2')
            ->doesntExpectOutputToContain('10.0.0.3')
            ->assertExitCode(0);
    }
}
