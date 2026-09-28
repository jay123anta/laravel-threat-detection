<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * A retention period that is not a number of days must not become "delete
 * everything".
 *
 * The purge deletes rows older than now() minus --days, and --days was cast
 * with (int). A negative value put the cutoff in the future, so every row was
 * older than it; a non-numeric value cast to 0, which is the documented way to
 * delete every row. The scheduler passes THREAT_DETECTION_RETENTION_DAYS
 * straight through, so a typo in .env — "ninety", "-1" — wiped the log every
 * night at 02:00, silently. `--days=0` by hand still deletes everything, as
 * the 1.8.0 upgrade guide tells people to.
 */
class RetentionDaysValidationTest extends TestCase
{
    private array $retentionOverride = [];

    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        if ($this->retentionOverride !== []) {
            $app['config']->set('threat-detection.retention', $this->retentionOverride);
        }

        // Bind the real Schedule before boot, as artisan does; see
        // ScheduledRetentionTest for why this ordering matters.
        $app->make(Kernel::class);
    }

    private function withRetention(array $retention): void
    {
        $this->retentionOverride = $retention;
        $this->refreshApplication();
    }

    private function purgeEvents(): array
    {
        return array_values(array_filter(
            $this->app->make(Schedule::class)->events(),
            fn ($event) => str_contains($event->command ?? '', 'threat-detection:purge')
        ));
    }

    private function seedRecentAndOld(): void
    {
        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();

        foreach (['recent' => now()->subMinute(), 'old' => now()->subDays(100)] as $name => $at) {
            DB::table('threat_logs')->insert([
                'ip_address' => '203.0.113.9',
                'url' => "https://example.com/{$name}",
                'user_agent' => 'curl/8',
                'type' => '[query] SQL Injection UNION',
                'payload' => 'x',
                'threat_level' => 'high',
                'created_at' => $at,
                'updated_at' => $at,
            ]);
        }
    }

    public static function invalidDays(): array
    {
        return [
            'negative' => ['-5'],
            'words' => ['ninety'],
            'a fraction' => ['7.5'],
            'empty' => [''],
        ];
    }

    #[Test]
    #[DataProvider('invalidDays')]
    public function the_purge_refuses_a_period_that_is_not_a_number_of_days(string $days): void
    {
        $this->seedRecentAndOld();

        $this->artisan('threat-detection:purge', ['--days' => $days, '--no-interaction' => true])
            ->assertExitCode(1);

        $this->assertSame(2, DB::table('threat_logs')->count(), "--days={$days} deleted rows");
    }

    /** Positive control: an ordinary period deletes only what is older. */
    #[Test]
    public function an_ordinary_period_deletes_only_older_rows(): void
    {
        $this->seedRecentAndOld();

        $this->artisan('threat-detection:purge', ['--days' => '30', '--no-interaction' => true])
            ->assertExitCode(0);

        $this->assertSame(['https://example.com/recent'], DB::table('threat_logs')->pluck('url')->all());
    }

    /** The documented way to delete every row keeps working. */
    #[Test]
    public function zero_by_hand_still_deletes_everything(): void
    {
        $this->seedRecentAndOld();

        $this->artisan('threat-detection:purge', ['--days' => '0', '--no-interaction' => true])
            ->assertExitCode(0);

        $this->assertSame(0, DB::table('threat_logs')->count());
    }

    public static function invalidScheduledDays(): array
    {
        return [
            'words' => ['ninety'],
            'negative' => [-1],
            'zero' => [0],
            'a fraction' => ['7.5'],
        ];
    }

    /** Nightly, zero means "delete everything every night", which nobody means. */
    #[Test]
    #[DataProvider('invalidScheduledDays')]
    public function no_purge_is_scheduled_for_a_period_that_is_not_a_number_of_days(int|string $days): void
    {
        $this->withRetention(['enabled' => true, 'days' => $days]);

        $this->assertSame([], $this->purgeEvents(), 'a purge was scheduled with days=' . var_export($days, true));
    }

    /** Positive control: .env values arrive as strings, and "90" is fine. */
    #[Test]
    public function a_numeric_string_period_is_scheduled(): void
    {
        $this->withRetention(['enabled' => true, 'days' => '90']);

        $events = $this->purgeEvents();

        $this->assertCount(1, $events);
        $this->assertStringContainsString('--days=90', $events[0]->command);
    }

    #[Test]
    public function doctor_reports_an_unusable_retention_period(): void
    {
        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();
        config(['threat-detection.retention' => ['enabled' => true, 'days' => 'ninety']]);

        $this->artisan('threat-detection:doctor')
            ->expectsOutputToContain('Retention is on but its period is not a number of days')
            ->assertExitCode(1);
    }

    /** Actor signals have their own period, cast the same way. */
    #[Test]
    public function a_non_numeric_signal_period_does_not_wipe_the_signals(): void
    {
        $this->seedRecentAndOld();
        Schema::create('threat_actor_signals', function (Blueprint $table) {
            $table->id();
            $table->string('actor_key', 100);
            $table->timestamp('created_at')->nullable();
        });
        DB::table('threat_actor_signals')->insert(['actor_key' => '203.0.113.9', 'created_at' => now()->subMinute()]);
        config(['threat-detection.actor_signals.retention_days' => 'seven']);

        $this->artisan('threat-detection:purge', ['--days' => '30', '--no-interaction' => true]);

        $this->assertSame(1, DB::table('threat_actor_signals')->count(), 'retention_days=seven deleted every signal');
    }
}
