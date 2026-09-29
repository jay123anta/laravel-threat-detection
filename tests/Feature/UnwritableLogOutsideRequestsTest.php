<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Facades\DB;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * An unwritable log must not turn a completed operation into a failure.
 *
 * Deleting an exclusion rule logs an audit line after the delete; a throw
 * there answered 500 for a rule that was gone. And the provider warns about
 * an unusable retention period while booting the console, so with the log
 * unwritable too, every artisan command — the scheduler and the queue worker
 * among them — died at boot.
 */
class UnwritableLogOutsideRequestsTest extends TestCase
{
    private bool $retentionTypo = false;

    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        if ($this->retentionTypo) {
            $app['config']->set('threat-detection.retention', ['enabled' => true, 'days' => 'ninety']);
        }

        // Every log call throws, as it does when Monolog cannot open its file.
        $app->instance('log', new class
        {
            public function __call(string $method, array $arguments): never
            {
                throw new \UnexpectedValueException('The stream or file "storage/logs/laravel.log" could not be opened in append mode');
            }
        });

        $app->make(Kernel::class);
    }

    #[Test]
    public function deleting_a_rule_reports_the_delete(): void
    {
        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();
        config(['threat-detection.api.write_guard' => 'none', 'threat-detection.api.guard' => 'none', 'cache.default' => 'array']);

        $id = DB::table('threat_exclusion_rules')->insertGetId([
            'pattern_label' => 'SQL Injection UNION', 'path_pattern' => 'search',
            'is_active' => true, 'created_at' => now(), 'updated_at' => now(),
        ]);

        $this->deleteJson("/api/threat-detection/exclusion-rules/{$id}")->assertStatus(200);

        $this->assertSame(0, DB::table('threat_exclusion_rules')->count());
    }

    /** The "no authentication" nudge is a courtesy; failing to write it must not fail the read. */
    #[Test]
    public function an_unguarded_api_still_answers(): void
    {
        $this->createThreatLogsTable();
        config(['threat-detection.api.guard' => 'none', 'cache.default' => 'array']);

        $this->getJson('/api/threat-detection/stats')->assertStatus(200);
    }

    /** Positive control: a guard that denies still denies. */
    #[Test]
    public function a_denying_guard_still_denies(): void
    {
        config(['threat-detection.api.write_guard' => 'nonsense', 'cache.default' => 'array']);

        $this->deleteJson('/api/threat-detection/exclusion-rules/1')->assertStatus(403);
    }

    #[Test]
    public function artisan_still_boots_with_a_retention_typo(): void
    {
        $this->retentionTypo = true;
        $this->refreshApplication();

        $this->assertSame(0, $this->app->make(Kernel::class)->call('list'));
    }
}
