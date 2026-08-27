<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Schema;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * The three commands that shipped without any test: purge, stats and enrich.
 *
 * purge deletes rows and cascades into threat_exclusion_rules; stats is the
 * first thing most operators run; enrich sends every IP it looks up to a third
 * party over the network. All three were reachable from a user's terminal with
 * nothing asserting they worked.
 */
class MaintenanceCommandsTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        config(['cache.default' => 'array']);
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    private function seedThreat(array $overrides = []): int
    {
        return DB::table('threat_logs')->insertGetId(array_merge([
            'ip_address' => '203.0.113.10',
            'url' => 'https://example.com/x',
            'user_agent' => 'PHPUnit',
            'type' => '[middleware] XSS Script Tag',
            'payload' => 'test',
            'threat_level' => 'high',
            'action_taken' => 'logged',
            'created_at' => now(),
            'updated_at' => now(),
        ], $overrides));
    }

    // ── threat-detection:purge ──────────────────────────────────────────────

    #[Test]
    public function purge_deletes_rows_older_than_the_days_option_and_keeps_newer(): void
    {
        $old = $this->seedThreat(['created_at' => now()->subDays(40)]);
        $recent = $this->seedThreat(['created_at' => now()->subDays(5)]);

        $this->artisan('threat-detection:purge', ['--days' => 30])
            ->expectsConfirmation('Are you sure you want to proceed?', 'yes')
            ->assertExitCode(0);

        $this->assertDatabaseMissing('threat_logs', ['id' => $old]);
        $this->assertDatabaseHas('threat_logs', ['id' => $recent]);
    }

    #[Test]
    public function purge_reports_when_there_is_nothing_to_delete(): void
    {
        $this->seedThreat(['created_at' => now()]);

        $this->artisan('threat-detection:purge', ['--days' => 30])
            ->expectsOutputToContain('No threat logs found older than 30 days')
            ->assertExitCode(0);

        $this->assertSame(1, DB::table('threat_logs')->count());
    }

    /**
     * The cascade. An exclusion rule points at the threat it was created from;
     * once that row is purged the rule is orphaned and must go with it.
     */
    #[Test]
    public function purge_removes_exclusion_rules_orphaned_by_the_delete(): void
    {
        $this->createExclusionRulesTable();

        $old = $this->seedThreat(['created_at' => now()->subDays(40)]);
        $kept = $this->seedThreat(['created_at' => now()]);

        DB::table('threat_exclusion_rules')->insert([
            ['pattern_label' => 'Orphan', 'created_from_threat_id' => $old, 'is_active' => true, 'created_at' => now(), 'updated_at' => now()],
            ['pattern_label' => 'Kept', 'created_from_threat_id' => $kept, 'is_active' => true, 'created_at' => now(), 'updated_at' => now()],
            ['pattern_label' => 'Manual', 'created_from_threat_id' => null, 'is_active' => true, 'created_at' => now(), 'updated_at' => now()],
        ]);

        $this->artisan('threat-detection:purge', ['--days' => 30])
            ->expectsConfirmation('Are you sure you want to proceed?', 'yes')
            ->assertExitCode(0);

        $this->assertDatabaseMissing('threat_exclusion_rules', ['pattern_label' => 'Orphan']);
        $this->assertDatabaseHas('threat_exclusion_rules', ['pattern_label' => 'Kept']);
        // A hand-written rule has no source threat and must never be collected.
        $this->assertDatabaseHas('threat_exclusion_rules', ['pattern_label' => 'Manual']);
    }

    #[Test]
    public function purge_survives_a_missing_exclusion_rules_table(): void
    {
        Schema::dropIfExists('threat_exclusion_rules');
        $this->seedThreat(['created_at' => now()->subDays(40)]);

        $this->artisan('threat-detection:purge', ['--days' => 30])
            ->expectsConfirmation('Are you sure you want to proceed?', 'yes')
            ->assertExitCode(0);

        $this->assertSame(0, DB::table('threat_logs')->count());
    }

    // ── threat-detection:stats ──────────────────────────────────────────────

    #[Test]
    public function stats_reports_totals_by_severity(): void
    {
        $this->seedThreat(['threat_level' => 'high', 'ip_address' => '203.0.113.1']);
        $this->seedThreat(['threat_level' => 'medium', 'ip_address' => '203.0.113.2']);
        $this->seedThreat(['threat_level' => 'low', 'ip_address' => '203.0.113.2']);

        $this->artisan('threat-detection:stats')
            ->expectsOutputToContain('Threat Detection Stats')
            ->assertExitCode(0);
    }

    #[Test]
    public function stats_runs_against_an_empty_table(): void
    {
        $this->artisan('threat-detection:stats')->assertExitCode(0);
    }

    #[Test]
    public function stats_fails_with_a_migration_hint_when_the_table_is_missing(): void
    {
        Schema::dropIfExists('threat_logs');

        $this->artisan('threat-detection:stats')
            ->expectsOutputToContain('vendor:publish --tag=threat-detection-migrations')
            ->assertExitCode(1);
    }

    // ── threat-detection:enrich ─────────────────────────────────────────────

    #[Test]
    public function enrich_maps_provider_fields_onto_the_row(): void
    {
        Http::fake(['*' => Http::response([
            'countryCode' => 'US', 'country' => 'United States',
            'city' => 'Ashburn', 'isp' => 'Amazon', 'org' => 'AWS EC2',
        ])]);

        $id = $this->seedThreat(['ip_address' => '8.8.8.8']);

        $this->artisan('threat-detection:enrich', ['--days' => 7])->assertExitCode(0);

        $row = DB::table('threat_logs')->find($id);
        $this->assertSame('US', $row->country_code);
        $this->assertSame('Ashburn', $row->city);
        $this->assertSame('AWS', $row->cloud_provider);
        $this->assertTrue((bool) $row->is_cloud_ip);
    }

    /**
     * home_country defaults to 'IN'. The flag must key off it rather than
     * assuming any particular home country.
     */
    #[Test]
    public function enrich_flags_foreign_only_when_the_country_differs_from_home(): void
    {
        config(['threat-detection.home_country' => 'US']);

        Http::fake(['*' => Http::response([
            'countryCode' => 'US', 'country' => 'United States', 'city' => 'Ashburn',
            'isp' => 'Level 3', 'org' => 'Level 3',
        ])]);

        $id = $this->seedThreat(['ip_address' => '8.8.4.4']);

        $this->artisan('threat-detection:enrich', ['--days' => 7])->assertExitCode(0);

        $this->assertFalse((bool) DB::table('threat_logs')->find($id)->is_foreign);
    }

    /**
     * The SSRF guard. A private address must never leave the server — the
     * provider cannot resolve it, and asking would disclose internal
     * addressing. Http::preventStrayRequests() in TestCase would fail this
     * test if the guard let one through unfaked.
     */
    #[Test]
    public function enrich_never_sends_a_private_address_to_the_provider(): void
    {
        Http::fake();

        $id = $this->seedThreat(['ip_address' => '192.168.1.50']);

        $this->artisan('threat-detection:enrich', ['--days' => 7])->assertExitCode(0);

        Http::assertNothingSent();
        $this->assertNull(DB::table('threat_logs')->find($id)->country_code);
    }

    #[Test]
    public function enrich_never_sends_a_malformed_address_to_the_provider(): void
    {
        Http::fake();

        $this->seedThreat(['ip_address' => 'not-an-ip']);

        $this->artisan('threat-detection:enrich', ['--days' => 7])->assertExitCode(0);

        Http::assertNothingSent();
    }

    #[Test]
    public function enrich_reports_the_provider_it_is_about_to_contact(): void
    {
        Http::fake(['*' => Http::response(['countryCode' => 'US'])]);
        $this->seedThreat(['ip_address' => '8.8.8.8']);

        $this->artisan('threat-detection:enrich', ['--days' => 7])
            ->expectsOutputToContain('Provider:')
            ->expectsOutputToContain('sent to this third party')
            ->assertExitCode(0);
    }

    #[Test]
    public function enrich_does_nothing_when_there_is_no_unenriched_row(): void
    {
        Http::fake();

        $this->seedThreat(['ip_address' => '8.8.8.8', 'country_code' => 'US']);

        $this->artisan('threat-detection:enrich', ['--days' => 7])
            ->expectsOutputToContain('No IPs to enrich')
            ->assertExitCode(0);

        Http::assertNothingSent();
    }

    #[Test]
    public function enrich_tolerates_a_provider_error_without_failing(): void
    {
        Http::fake(['*' => Http::response('upstream down', 500)]);

        $id = $this->seedThreat(['ip_address' => '8.8.8.8']);

        $this->artisan('threat-detection:enrich', ['--days' => 7])->assertExitCode(0);

        // Geo lookup is best-effort; a failed one leaves the row unenriched
        // rather than aborting the run.
        $this->assertNull(DB::table('threat_logs')->find($id)->country_code);
    }
}
