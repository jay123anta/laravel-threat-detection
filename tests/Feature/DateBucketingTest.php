<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * Per-day buckets on SQLite — the default database for a new Laravel app.
 *
 * The timeline and the summary grouped by CAST(created_at AS DATE). SQLite
 * has no DATE type: the cast takes NUMERIC affinity and returns the leading
 * number, so every row of 2026 landed in one bucket called 2026. The
 * dashboard's chart then called .substring() on a number and never drew.
 * Found by executing the dashboard's own JavaScript against real API output;
 * no PHP test had looked at what the dates actually were.
 */
class DateBucketingTest extends TestCase
{
    private const API = '/api/threat-detection';

    protected function setUp(): void
    {
        parent::setUp();

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

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    #[Test]
    public function the_timeline_buckets_by_calendar_day(): void
    {
        $rows = collect($this->getJson(self::API . '/timeline?days=7')->assertStatus(200)->json('data'));

        $this->assertSame(
            [now()->subDays(2)->toDateString() => 2, now()->toDateString() => 1],
            $rows->mapWithKeys(fn ($row) => [$row['date'] => $row['count']])->sortKeys()->all(),
            'the timeline did not return one bucket per calendar day'
        );
    }

    /** The dashboard formats these with string methods; a number breaks the chart. */
    #[Test]
    public function timeline_dates_are_iso_date_strings(): void
    {
        foreach ($this->getJson(self::API . '/timeline?days=7')->json('data') as $row) {
            $this->assertIsString($row['date']);
            $this->assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2}$/', $row['date']);
        }
    }

    #[Test]
    public function the_summary_buckets_by_calendar_day(): void
    {
        $byDate = collect($this->getJson(self::API . '/summary')->assertStatus(200)->json('data.byDate'));

        $this->assertSame(
            [now()->subDays(2)->toDateString() => 2, now()->toDateString() => 1],
            $byDate->mapWithKeys(fn ($row) => [$row['date'] => $row['count']])->sortKeys()->all()
        );
    }
}
