<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * Reading the threat log and switching a detection off are different
 * privileges. Before this, the shipped `['api', 'auth:sanctum']` with
 * guard => 'none' meant any authenticated user of the host application could
 * silence a detection type for everyone, with no authorization check.
 */
class WriteGuardTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();

        DB::table('threat_logs')->insert([
            'ip_address' => '10.0.0.1',
            'url' => 'https://example.com/x',
            'type' => '[middleware] XSS Script Tag',
            'threat_level' => 'high',
            'action_taken' => 'logged',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        DB::table('threat_exclusion_rules')->insert([
            'id' => 1,
            'pattern_label' => 'XSS Script Tag',
            'is_active' => true,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    private function prefix(): string
    {
        return '/' . ltrim(config('threat-detection.api.prefix', 'api/threat-detection'), '/');
    }

    // ── the default protects the write endpoints ────────────────────────────

    #[Test]
    public function marking_a_false_positive_is_denied_by_default(): void
    {
        // Default write_guard is 'role'; no authenticated user here.
        $this->postJson($this->prefix() . '/threats/1/false-positive')
            ->assertStatus(403);

        $this->assertDatabaseHas('threat_logs', ['id' => 1, 'is_false_positive' => false]);
    }

    #[Test]
    public function deleting_an_exclusion_rule_is_denied_by_default(): void
    {
        $this->deleteJson($this->prefix() . '/exclusion-rules/1')
            ->assertStatus(403);

        $this->assertDatabaseHas('threat_exclusion_rules', ['id' => 1]);
    }

    /**
     * The point of a separate write_guard: an existing install that upgrades
     * keeps its dashboard and its read API working. Only the two endpoints
     * that disable detections tighten up.
     */
    #[Test]
    public function reading_is_unaffected_by_the_write_guard(): void
    {
        $this->getJson($this->prefix() . '/threats')->assertOk();
        $this->getJson($this->prefix() . '/stats')->assertOk();
        $this->getJson($this->prefix() . '/exclusion-rules')->assertOk();
    }

    // ── the escape hatches work ─────────────────────────────────────────────

    #[Test]
    public function write_guard_none_restores_the_previous_behaviour(): void
    {
        config(['threat-detection.api.write_guard' => 'none']);

        $this->postJson($this->prefix() . '/threats/1/false-positive')
            ->assertOk();

        $this->assertDatabaseHas('threat_logs', ['id' => 1, 'is_false_positive' => true]);
    }

    #[Test]
    public function an_ip_write_guard_allows_a_listed_address(): void
    {
        config([
            'threat-detection.api.write_guard' => 'ip',
            'threat-detection.api.allowed_ips' => ['127.0.0.1'],
        ]);

        $this->postJson($this->prefix() . '/threats/1/false-positive')
            ->assertOk();
    }

    #[Test]
    public function an_ip_write_guard_denies_an_unlisted_address(): void
    {
        config([
            'threat-detection.api.write_guard' => 'ip',
            'threat-detection.api.allowed_ips' => ['203.0.113.5'],
        ]);

        $this->postJson($this->prefix() . '/threats/1/false-positive')
            ->assertStatus(403);
    }

    #[Test]
    public function an_unrecognised_write_guard_fails_closed(): void
    {
        config(['threat-detection.api.write_guard' => 'sure-why-not']);

        $this->postJson($this->prefix() . '/threats/1/false-positive')
            ->assertStatus(403);
    }

    // ── the doctor reports it ───────────────────────────────────────────────

    #[Test]
    public function the_doctor_reports_an_open_write_guard(): void
    {
        config(['threat-detection.api.write_guard' => 'none']);

        $this->artisan('threat-detection:doctor')
            ->expectsOutputToContain('Any authenticated user can disable a detection');
    }

    #[Test]
    public function the_doctor_passes_on_the_default(): void
    {
        $this->artisan('threat-detection:doctor')
            ->expectsOutputToContain('Disabling a detection requires elevated access');
    }
}
