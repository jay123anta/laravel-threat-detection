<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * The doctor exists because every failure it checks for was observed on a real
 * application and none of them surfaced as an error a user would notice — the
 * dashboard simply stayed empty, which reads as "no attacks" rather than
 * "nothing is being recorded".
 */
class Phase15DoctorCommandTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config([
            'threat-detection.enabled' => true,
            'threat-detection.enabled_environments' => null,
            'threat-detection.custom_patterns' => [],
            'threat-detection.dashboard.enabled' => false,
            'threat-detection.api.enabled' => true,
            'threat-detection.api.middleware' => ['api', 'auth'],
            'cache.default' => 'array',
        ]);

        // The middleware check looks for a route or group carrying it.
        Route::middleware('threat-detect')->get('/doctor-probe', fn() => 'OK');
    }

    private function healthySchema(): void
    {
        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();
    }

    // ── healthy install ─────────────────────────────────────────────────────

    /**
     * Asserts no *failures* rather than a literal "All checks passed", because
     * some checks are properties of the environment the suite happens to run
     * in. The framework-support check warns on Laravel 10 and 11, which this
     * package still supports and CI still tests, so an exact-summary assertion
     * would pass on the Laravel 12/13 legs and fail on the others.
     */
    #[Test]
    public function a_healthy_install_reports_no_failures(): void
    {
        $this->healthySchema();

        $this->artisan('threat-detection:doctor')->assertExitCode(0);
    }

    #[Test]
    public function it_reports_on_the_framework_version(): void
    {
        $this->healthySchema();

        $major = (int) $this->app->version();
        $expected = in_array($major, [9, 10, 11], true)
            ? 'no longer receives security patches'
            : 'is a supported release';

        $this->artisan('threat-detection:doctor')
            ->expectsOutputToContain($expected)
            ->assertExitCode(0);
    }

    // ── the failure that discarded 100% of detections on a live app ─────────

    #[Test]
    public function a_table_missing_confidence_columns_fails_loudly(): void
    {
        Schema::create('threat_logs', function (Blueprint $table) {
            // The pre-v1.2.0 shape, as found on a live Laravel 10 app.
            $table->id();
            $table->string('ip_address');
            $table->text('url');
            $table->text('user_agent')->nullable();
            $table->text('type');
            $table->text('payload')->nullable();
            $table->string('threat_level')->default('medium');
            $table->string('action_taken')->default('logged');
            $table->unsignedBigInteger('user_id')->nullable();
            $table->timestamps();
        });
        $this->createExclusionRulesTable();

        $this->artisan('threat-detection:doctor')
            ->expectsOutputToContain('EVERY threat is being discarded')
            ->assertExitCode(1);
    }

    #[Test]
    public function a_missing_table_fails(): void
    {
        $this->artisan('threat-detection:doctor')
            ->expectsOutputToContain('does not exist')
            ->assertExitCode(1);
    }

    // ── the drift that resurrected a fixed false positive ───────────────────

    #[Test]
    public function a_custom_pattern_shadowing_a_built_in_is_reported(): void
    {
        $this->healthySchema();

        // The real case: a config published before v1.3.1 keeps its own copy of
        // Localhost SSRF, without the (?<!\d) guard, so Chrome/120.0.0.0 in a
        // user-agent is logged as SSRF on nearly every request.
        config(['threat-detection.custom_patterns' => [
            '/(localhost|127\.0\.0\.1|0\.0\.0\.0)/i' => 'Localhost SSRF',
        ]]);

        $this->artisan('threat-detection:doctor')
            ->expectsOutputToContain('shadow a built-in: Localhost SSRF')
            ->assertExitCode(0);   // a warning, not a failure
    }

    #[Test]
    public function an_identical_custom_pattern_is_not_reported_as_shadowing(): void
    {
        $this->healthySchema();

        $service = app(\JayAnta\ThreatDetection\Services\ThreatDetectionService::class);
        $regex = array_search('Localhost SSRF', $service->getDefaultThreatPatterns(), true);

        config(['threat-detection.custom_patterns' => [$regex => 'Localhost SSRF']]);

        $this->artisan('threat-detection:doctor')
            ->expectsOutputToContain('No custom pattern shadows a built-in')
            ->assertExitCode(0);
    }

    // ── wiring ──────────────────────────────────────────────────────────────

    #[Test]
    public function detection_disabled_is_reported_as_a_failure(): void
    {
        $this->healthySchema();
        config(['threat-detection.enabled' => false]);

        $this->artisan('threat-detection:doctor')
            ->expectsOutputToContain('Detection is disabled')
            ->assertExitCode(1);
    }

    #[Test]
    public function an_excluded_environment_is_reported_as_a_failure(): void
    {
        $this->healthySchema();
        config(['threat-detection.enabled_environments' => ['production']]);

        $this->artisan('threat-detection:doctor')
            ->expectsOutputToContain('Detection is off in this environment')
            ->assertExitCode(1);
    }

    // ── exposure ────────────────────────────────────────────────────────────

    #[Test]
    public function an_unauthenticated_api_surface_is_reported(): void
    {
        $this->healthySchema();
        config(['threat-detection.api.middleware' => ['api'], 'threat-detection.api.guard' => 'none']);

        $this->artisan('threat-detection:doctor')
            ->expectsOutputToContain('your threat data is public')
            ->assertExitCode(0);   // warning outside production
    }

    #[Test]
    public function a_cache_driver_without_atomic_increment_is_reported(): void
    {
        $this->healthySchema();
        config(['cache.default' => 'file']);

        $this->artisan('threat-detection:doctor')
            ->expectsOutputToContain('DDoS detection is off')
            ->assertExitCode(0);
    }
}
