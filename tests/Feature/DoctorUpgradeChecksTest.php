<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Schema;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * What `threat-detection:doctor` says about an upgrade to 1.9.
 *
 * Two gaps it could not see before. Its drift check compared top-level config
 * keys, so a published file missing an option added *inside* a block it
 * already had — probe_tracking.ai_infrastructure — was reported as current.
 * And none of the opt-in features was checked at all, though each can be
 * switched on and still do nothing, silently, by design.
 */
class DoctorUpgradeChecksTest extends TestCase
{
    private string $published;

    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();
        $this->published = config_path('threat-detection.php');
    }

    protected function tearDown(): void
    {
        if (is_file($this->published)) {
            unlink($this->published);
        }

        parent::tearDown();
    }

    /** Write a published config: the package's own file, reshaped by $edit. */
    private function publish(callable $edit): void
    {
        $config = $edit(require __DIR__ . '/../../config/threat-detection.php');

        file_put_contents($this->published, '<?php return ' . var_export($config, true) . ';');
    }

    private function doctor(): string
    {
        Artisan::call('threat-detection:doctor');

        return Artisan::output();
    }

    // ── Config drift at any depth ──────────────────────────────────────────

    #[Test]
    public function an_option_missing_inside_a_published_block_is_reported(): void
    {
        $this->publish(function (array $config) {
            unset($config['probe_tracking']['ai_infrastructure']);

            return $config;
        });

        $output = $this->doctor();

        $this->assertStringContainsString('probe_tracking.ai_infrastructure', $output);
        $this->assertStringNotContainsString('Published config matches this version', $output);
    }

    /** Data the operator trimmed — probe paths, patterns — is their content, not drift. */
    #[Test]
    public function trimmed_data_is_not_reported_as_missing_options(): void
    {
        $this->publish(function (array $config) {
            unset($config['probe_tracking']['paths']['/wp-admin']);
            array_pop($config['llm_log_safety']['patterns']);

            return $config;
        });

        $output = $this->doctor();

        $this->assertStringContainsString('Published config matches this version', $output);
        $this->assertStringNotContainsString('/wp-admin', $output);
    }

    #[Test]
    public function a_current_published_config_still_passes(): void
    {
        $this->publish(fn (array $config) => $config);

        $this->assertStringContainsString('Published config matches this version', $this->doctor());
    }

    // ── The opt-in features ────────────────────────────────────────────────

    #[Test]
    public function actor_signals_without_their_table_fail(): void
    {
        config(['threat-detection.actor_signals.enabled' => true]);

        $output = $this->doctor();

        $this->assertMatchesRegularExpression('/FAIL.*Actor signals are on but .*table does not exist/', $output);
    }

    #[Test]
    public function actor_signals_with_their_table_pass(): void
    {
        config(['threat-detection.actor_signals.enabled' => true]);
        (require __DIR__ . '/../../database/migrations/create_threat_actor_signals_table.php.stub')->up();

        $output = $this->doctor();

        $this->assertMatchesRegularExpression('/PASS.*Actor signals are recorded/', $output);
        Schema::dropIfExists('threat_actor_signals');
    }

    #[Test]
    public function actor_scoring_without_signals_is_a_warning(): void
    {
        config(['threat-detection.actor_score.enabled' => true]);

        $this->assertMatchesRegularExpression('/WARN.*Actor scoring is on without actor signals/', $this->doctor());
    }

    #[Test]
    public function the_ai_pack_with_probe_tracking_off_is_a_warning(): void
    {
        config([
            'threat-detection.probe_tracking.enabled' => false,
            'threat-detection.probe_tracking.ai_infrastructure.enabled' => true,
        ]);

        $this->assertMatchesRegularExpression('/WARN.*probe pack is on but probe tracking is off/', $this->doctor());
    }

    /** ai-guard is not a dependency of this package, so here it is genuinely absent. */
    #[Test]
    public function the_ai_guard_integration_without_ai_guard_is_a_warning(): void
    {
        config(['threat-detection.ai_guard.enabled' => true]);

        $this->assertMatchesRegularExpression('/WARN.*ai-guard integration is on but ai-guard is not installed/', $this->doctor());
    }

    /** Off means silent: nothing about features nobody enabled. */
    #[Test]
    public function features_that_are_off_are_not_mentioned(): void
    {
        $output = $this->doctor();

        foreach (['Actor signals', 'Actor scoring', 'probe pack', 'ai-guard'] as $phrase) {
            $this->assertStringNotContainsString($phrase, $output);
        }
    }
}
