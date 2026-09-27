<?php

namespace JayAnta\ThreatDetection\Tests\Security;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * The actor-signals migration and its queries, on a real strict-mode server.
 *
 * SQLite accepts almost any schema and almost any GROUP BY, so passing there
 * says little about the engine most installs actually run. Three things can
 * only fail on MySQL:
 *
 *   - index names, which are capped at 64 characters;
 *   - a real DATE column, rather than SQLite's advisory typing;
 *   - grouped queries under ONLY_FULL_GROUP_BY, which is on by default in
 *     MySQL 5.7+ and rejects selected columns that are not grouped or
 *     aggregated.
 *
 * The mutation-chain and cluster queries are exactly that shape, so they are
 * run here against the shipped schema rather than a hand-built table.
 *
 * Skipped unless THREAT_DETECTION_MYSQL=1, like the other file in this
 * directory, so a plain `composer test` is unaffected.
 */
class MysqlActorSignalsTest extends TestCase
{
    private const TABLE = 'threat_actor_signals';

    protected function setUp(): void
    {
        parent::setUp();

        $this->skipUnlessMysqlIsReachable();

        config(['threat-detection.actor_signals.table' => self::TABLE]);
        Schema::dropIfExists(self::TABLE);
        $this->migration()->up();
    }

    protected function tearDown(): void
    {
        if (env('THREAT_DETECTION_MYSQL') === '1') {
            try {
                Schema::dropIfExists(self::TABLE);
            } catch (\Throwable $e) {
                // The skip path never created it.
            }
        }

        parent::tearDown();
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

    private function skipUnlessMysqlIsReachable(): void
    {
        if (env('THREAT_DETECTION_MYSQL') !== '1') {
            $this->markTestSkipped('Set THREAT_DETECTION_MYSQL=1 and point the connection at a scratch database to run these.');
        }

        try {
            DB::connection('mysql_scratch')->select('SELECT 1');
        } catch (\Throwable $e) {
            $this->markTestSkipped('No MySQL/MariaDB server answered: ' . $e->getMessage());
        }
    }

    private function migration(): object
    {
        return require __DIR__ . '/../../database/migrations/create_threat_actor_signals_table.php.stub';
    }

    private function seedSignal(string $actor, string $fingerprint, string $variant): void
    {
        DB::table(self::TABLE)->insert([
            'actor_key' => $actor,
            'fingerprint' => $fingerprint,
            'variant' => $variant,
            'label' => 'SQL Injection UNION',
            'context' => 'query',
            'observed_on' => now()->toDateString(),
            'created_at' => now(),
        ]);
    }

    #[Test]
    public function the_shipped_migration_runs_on_a_strict_mode_server(): void
    {
        $this->assertTrue(Schema::hasTable(self::TABLE));

        foreach (['actor_key', 'fingerprint', 'variant', 'label', 'context', 'observed_on', 'created_at'] as $column) {
            $this->assertTrue(Schema::hasColumn(self::TABLE, $column), "missing column {$column}");
        }
    }

    /**
     * MySQL rejects an identifier over 64 characters outright. Laravel's
     * generated names are long — table plus every column plus "index" — which
     * is why the migration names these explicitly.
     */
    #[Test]
    public function every_index_name_is_within_the_mysql_identifier_limit(): void
    {
        $names = collect(DB::select('SHOW INDEX FROM ' . self::TABLE))
            ->pluck('Key_name')
            ->unique()
            ->values();

        $this->assertNotEmpty($names);

        foreach ($names as $name) {
            $this->assertLessThanOrEqual(64, strlen((string) $name), "index name too long: {$name}");
        }

        foreach (['tas_actor_fp_time', 'tas_fingerprint_time', 'tas_observed_on'] as $expected) {
            $this->assertContains($expected, $names->all(), "the {$expected} index was not created");
        }
    }

    /**
     * ONLY_FULL_GROUP_BY is on by default from MySQL 5.7 and rejects a
     * selected column that is neither grouped nor aggregated. Both detection
     * queries select alongside a GROUP BY, so this is where they would break.
     */
    #[Test]
    public function the_mutation_chain_query_runs_under_only_full_group_by(): void
    {
        for ($i = 1; $i <= 3; $i++) {
            $this->seedSignal('203.0.113.5', 'fp-union', "variant-{$i}");
        }

        $chains = DB::table(self::TABLE)
            ->select(
                'actor_key',
                'fingerprint',
                'label',
                DB::raw('COUNT(DISTINCT variant) as variant_count'),
                DB::raw('MIN(created_at) as first_seen'),
                DB::raw('MAX(created_at) as last_seen')
            )
            ->where('created_at', '>=', now()->subHour())
            ->groupBy('actor_key', 'fingerprint', 'label')
            ->havingRaw('COUNT(DISTINCT variant) >= ?', [2])
            ->get();

        $this->assertCount(1, $chains);
        $this->assertSame(3, (int) $chains[0]->variant_count);
    }

    #[Test]
    public function the_cluster_query_runs_under_only_full_group_by(): void
    {
        foreach (['198.51.100.1', '198.51.100.2', '198.51.100.3'] as $actor) {
            $this->seedSignal($actor, 'fp-shared', 'v-shared');
        }

        $clusters = DB::table(self::TABLE)
            ->select('fingerprint', 'label', DB::raw('COUNT(DISTINCT actor_key) as actor_count'))
            ->where('created_at', '>=', now()->subHour())
            ->groupBy('fingerprint', 'label')
            ->havingRaw('COUNT(DISTINCT actor_key) >= ?', [3])
            ->get();

        $this->assertCount(1, $clusters);
        $this->assertSame(3, (int) $clusters[0]->actor_count);
    }

    /**
     * The date-only column exists so daily rollups never need DATE(created_at),
     * which is not portable. Confirm it groups natively.
     */
    #[Test]
    public function the_date_column_groups_without_a_date_function(): void
    {
        $this->seedSignal('203.0.113.6', 'fp-a', 'v-a');
        $this->seedSignal('203.0.113.7', 'fp-b', 'v-b');

        $daily = DB::table(self::TABLE)
            ->select('observed_on', DB::raw('COUNT(*) as total'))
            ->groupBy('observed_on')
            ->get();

        $this->assertCount(1, $daily);
        $this->assertSame(2, (int) $daily[0]->total);
    }

    /**
     * Column widths are advisory on SQLite and enforced here. The recorder
     * truncates before writing; this confirms the widths it truncates to are
     * the widths the table actually has.
     */
    #[Test]
    public function the_recorders_truncation_widths_match_the_real_columns(): void
    {
        $this->seedSignal(str_repeat('a', 100), str_repeat('f', 32), str_repeat('v', 32));

        $row = DB::table(self::TABLE)->first();

        $this->assertSame(100, strlen($row->actor_key));
        $this->assertSame(32, strlen($row->fingerprint));
        $this->assertSame(32, strlen($row->variant));
    }

    #[Test]
    public function the_migration_drops_cleanly(): void
    {
        $this->migration()->down();

        $this->assertFalse(Schema::hasTable(self::TABLE));
    }
}
