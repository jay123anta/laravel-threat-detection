<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\ServiceProvider;
use JayAnta\ThreatDetection\Tests\TestCase;
use JayAnta\ThreatDetection\ThreatDetectionServiceProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * Runs the shipped migration stub for real.
 *
 * Every other test that touches threat_actor_signals builds the table by hand,
 * which is fast but proves nothing about the file operators actually publish.
 * A stub that does not run is a broken install on first upgrade, and it is the
 * kind of break that only shows up on someone else's machine.
 *
 * So this executes the stub itself, up and down, and then writes and reads a
 * row through it.
 */
class ActorSignalsMigrationTest extends TestCase
{
    private const TABLE = 'threat_actor_signals';

    private function stub(): object
    {
        config(['threat-detection.actor_signals.table' => self::TABLE]);

        return require __DIR__ . '/../../database/migrations/create_threat_actor_signals_table.php.stub';
    }

    protected function tearDown(): void
    {
        Schema::dropIfExists(self::TABLE);
        parent::tearDown();
    }

    #[Test]
    public function the_published_stub_creates_and_drops_the_table(): void
    {
        $migration = $this->stub();

        $this->assertFalse(Schema::hasTable(self::TABLE), 'the table existed before the migration ran');

        $migration->up();
        $this->assertTrue(Schema::hasTable(self::TABLE), 'the migration did not create the table');

        $migration->down();
        $this->assertFalse(Schema::hasTable(self::TABLE), 'the migration did not drop the table');
    }

    #[Test]
    public function the_created_table_has_every_column_the_recorder_writes(): void
    {
        $this->stub()->up();

        // Exactly the keys ActorSignalRecorder::pendingRows() inserts.
        foreach (['id', 'actor_key', 'fingerprint', 'variant', 'label', 'context', 'observed_on', 'created_at'] as $column) {
            $this->assertTrue(
                Schema::hasColumn(self::TABLE, $column),
                "the migration does not create the '{$column}' column, which the recorder writes"
            );
        }
    }

    /**
     * A write and a read through the real schema, using the same shapes the
     * recorder and the correlation queries use.
     */
    #[Test]
    public function a_row_written_through_the_real_schema_reads_back(): void
    {
        $this->stub()->up();

        DB::table(self::TABLE)->insert([
            'actor_key' => '203.0.113.5',
            'fingerprint' => str_repeat('a', 16),
            'variant' => str_repeat('b', 16),
            'label' => 'SQL Injection UNION',
            'context' => 'query',
            'observed_on' => now()->toDateString(),
            'created_at' => now(),
        ]);

        $row = DB::table(self::TABLE)->first();

        $this->assertSame('203.0.113.5', $row->actor_key);
        $this->assertSame(str_repeat('b', 16), $row->variant);
        $this->assertSame(now()->toDateString(), (string) $row->observed_on);
    }

    /**
     * The grouped queries both detections use, run against the real indexes.
     * A mistyped index or column name would pass every hand-built-table test
     * and fail here.
     */
    #[Test]
    public function the_detection_queries_run_against_the_real_schema(): void
    {
        $this->stub()->up();

        for ($i = 1; $i <= 3; $i++) {
            DB::table(self::TABLE)->insert([
                'actor_key' => '203.0.113.6',
                'fingerprint' => 'fp',
                'variant' => "v{$i}",
                'label' => 'SQL Injection UNION',
                'context' => 'query',
                'observed_on' => now()->toDateString(),
                'created_at' => now(),
            ]);
        }

        $variants = DB::table(self::TABLE)
            ->select('actor_key', DB::raw('COUNT(DISTINCT variant) as variant_count'))
            ->groupBy('actor_key', 'fingerprint', 'label')
            ->havingRaw('COUNT(DISTINCT variant) >= ?', [2])
            ->get();

        $this->assertCount(1, $variants);
        $this->assertSame(3, (int) $variants[0]->variant_count);

        $daily = DB::table(self::TABLE)
            ->select('observed_on', DB::raw('COUNT(*) as total'))
            ->groupBy('observed_on')
            ->get();

        $this->assertCount(1, $daily, 'the date-only column did not group as expected');
    }

    /**
     * The table name is configurable, so the stub must honour it rather than
     * hard-coding the default.
     */
    #[Test]
    public function the_stub_honours_a_renamed_table(): void
    {
        config(['threat-detection.actor_signals.table' => 'custom_signals']);

        $migration = require __DIR__ . '/../../database/migrations/create_threat_actor_signals_table.php.stub';
        $migration->up();

        $this->assertTrue(Schema::hasTable('custom_signals'));
        $this->assertFalse(Schema::hasTable(self::TABLE));

        $migration->down();
        Schema::dropIfExists('custom_signals');
    }

    /**
     * The provider publishes it. A stub that exists but is never offered to
     * the operator is the same as no stub at all.
     */
    #[Test]
    public function the_provider_offers_the_stub_for_publishing(): void
    {
        $paths = ServiceProvider::pathsToPublish(
            ThreatDetectionServiceProvider::class,
            'threat-detection-migrations'
        );

        $sources = implode('|', array_keys($paths));

        $this->assertStringContainsString(
            'create_threat_actor_signals_table',
            $sources,
            'the actor-signals migration is not published, so operators can never run it'
        );
    }
}
