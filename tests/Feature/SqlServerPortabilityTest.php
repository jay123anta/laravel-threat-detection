<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * The README lists SQL Server among the supported databases, and SQL Server
 * has no DATE() function. `/stats` and `threat-detection:stats` counted
 * today's rows with DATE(created_at), so on SQL Server the dashboard's
 * headline cards and the stats command failed outright. The controller
 * already had a helper that writes CAST(created_at AS DATE) for every driver
 * but SQLite; these two queries did not use it.
 *
 * No SQL Server runs here, so the queries are generated in pretend mode on a
 * sqlsrv connection: Laravel builds and logs the real SQL without connecting.
 */
class SqlServerPortabilityTest extends TestCase
{
    private const CONNECTION = 'sqlsrv_pretend';

    protected function setUp(): void
    {
        parent::setUp();

        config([
            'database.connections.' . self::CONNECTION => [
                'driver' => 'sqlsrv',
                'host' => '127.0.0.1',
                'database' => 'threat_detection',
                'username' => 'nobody',
                'password' => '',
                'prefix' => '',
            ],
            'database.default' => self::CONNECTION,
            'threat-detection.api.guard' => 'none',
        ]);

        // Pretend mode still quotes bound values, which needs a PDO, and
        // there is no sqlsrv driver here. A SQLite PDO does the quoting; the
        // connection — and so the grammar and the driver name the code
        // branches on — stays SQL Server's.
        DB::connection(self::CONNECTION)
            ->setPdo(new \PDO('sqlite::memory:'))
            ->setReadPdo(new \PDO('sqlite::memory:'));
    }

    /** @return string every statement the callback would have run */
    private function sqlOf(callable $callback): string
    {
        $queries = DB::connection(self::CONNECTION)->pretend(function () use ($callback) {
            try {
                $callback();
            } catch (\Throwable) {
                // Pretend mode returns no rows, so code that reads a result
                // may fail after its query is built. The query is what counts.
            }
        });

        return implode("\n", array_column($queries, 'query'));
    }

    #[Test]
    public function the_stats_endpoint_uses_no_date_function(): void
    {
        $sql = $this->sqlOf(fn () => $this->getJson('/api/threat-detection/stats'));

        $this->assertStringContainsString('as today', $sql, 'the stats query was not generated, so this proves nothing');
        $this->assertStringNotContainsString('DATE(created_at)', $sql);
    }

    #[Test]
    public function the_stats_command_uses_no_date_function(): void
    {
        $sql = $this->sqlOf(fn () => Artisan::call('threat-detection:stats'));

        $this->assertStringContainsString('as today', $sql, 'the stats query was not generated, so this proves nothing');
        $this->assertStringNotContainsString('DATE(created_at)', $sql);
    }

    /** Positive control: the timeline already used the portable form. */
    #[Test]
    public function the_timeline_already_casts(): void
    {
        $sql = $this->sqlOf(fn () => $this->getJson('/api/threat-detection/timeline'));

        $this->assertStringContainsString('CAST(created_at AS DATE)', $sql);
    }
}
