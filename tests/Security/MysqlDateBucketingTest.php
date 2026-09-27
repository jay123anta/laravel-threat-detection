<?php

namespace JayAnta\ThreatDetection\Tests\Security;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * Per-day buckets on MySQL, the other branch of ThreatLogController::day().
 *
 * SQLite needs DATE() and everything else CAST(... AS DATE). The SQLite side
 * is covered by tests/Feature/DateBucketingTest.php; this is the side most
 * production installs run. Skipped unless THREAT_DETECTION_MYSQL=1.
 */
class MysqlDateBucketingTest extends TestCase
{
    private const API = '/api/threat-detection';

    protected function setUp(): void
    {
        parent::setUp();

        if (env('THREAT_DETECTION_MYSQL') !== '1') {
            $this->markTestSkipped('Set THREAT_DETECTION_MYSQL=1 and point the connection at a scratch database to run these.');
        }

        try {
            DB::connection('mysql_scratch')->select('SELECT 1');
        } catch (\Throwable $e) {
            $this->markTestSkipped('No MySQL/MariaDB server answered: ' . $e->getMessage());
        }

        Schema::dropIfExists('threat_logs');
        Schema::dropIfExists('threat_exclusion_rules');
        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();
        config(['cache.default' => 'array']);

        foreach ([now()->subDays(2), now()->subDays(2), now()] as $at) {
            DB::table('threat_logs')->insert([
                'ip_address' => '10.0.0.1',
                'url' => 'https://example.com/x',
                'user_agent' => 'curl/8',
                'type' => '[middleware] SQL Injection UNION',
                'payload' => 'x',
                'threat_level' => 'high',
                'created_at' => $at,
                'updated_at' => $at,
            ]);
        }
    }

    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('database.default', 'mysql_scratch');
        $app['config']->set('database.connections.mysql_scratch', [
            'driver' => 'mysql',
            'host' => env('THREAT_DETECTION_MYSQL_HOST', '127.0.0.1'),
            'port' => env('THREAT_DETECTION_MYSQL_PORT', '3306'),
            'database' => env('THREAT_DETECTION_MYSQL_DATABASE', 'threat_detection_test'),
            'username' => env('THREAT_DETECTION_MYSQL_USERNAME', 'root'),
            'password' => env('THREAT_DETECTION_MYSQL_PASSWORD', ''),
            'charset' => 'utf8mb4',
            'collation' => 'utf8mb4_unicode_ci',
            'prefix' => '',
            'strict' => true,
            'engine' => null,
        ]);
    }

    protected function tearDown(): void
    {
        if (env('THREAT_DETECTION_MYSQL') === '1') {
            try {
                Schema::dropIfExists('threat_logs');
                Schema::dropIfExists('threat_exclusion_rules');
            } catch (\Throwable $e) {
                // The skip path never built them.
            }
        }

        Cache::flush();
        parent::tearDown();
    }

    #[Test]
    public function the_timeline_buckets_by_calendar_day(): void
    {
        $rows = collect($this->getJson(self::API . '/timeline?days=7')->assertStatus(200)->json('data'));

        $this->assertSame(
            [now()->subDays(2)->toDateString() => 2, now()->toDateString() => 1],
            $rows->mapWithKeys(fn ($row) => [(string) $row['date'] => (int) $row['count']])->sortKeys()->all()
        );

        foreach ($rows as $row) {
            $this->assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2}$/', (string) $row['date']);
        }
    }

    #[Test]
    public function the_summary_buckets_by_calendar_day(): void
    {
        $byDate = collect($this->getJson(self::API . '/summary')->assertStatus(200)->json('data.byDate'));

        $this->assertSame(
            [now()->subDays(2)->toDateString() => 2, now()->toDateString() => 1],
            $byDate->mapWithKeys(fn ($row) => [(string) $row['date'] => (int) $row['count']])->sortKeys()->all()
        );
    }
}
