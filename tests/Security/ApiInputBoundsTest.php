<?php

namespace JayAnta\ThreatDetection\Tests\Security;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * Free-text inputs to the API had no shape or size.
 *
 * `keyword` went into three LIKE clauses at any length, over the two TEXT
 * columns every search already scans in full, and an array in its place
 * answered 500. `reason` was written to the database as given, at any length
 * and of any type. Neither is reachable without passing the API's guard, so
 * this is hygiene rather than a hole — but every other parameter here is
 * validated, and these now are too.
 */
class ApiInputBoundsTest extends TestCase
{
    private const API = '/api/threat-detection';

    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();

        config([
            'cache.default' => 'array',
            'threat-detection.api.guard' => 'none',
            'threat-detection.api.write_guard' => 'none',
        ]);

        DB::table('threat_logs')->insert([
            'ip_address' => '203.0.113.9',
            'url' => 'https://app.test/search?q=union',
            'user_agent' => 'Mozilla/5.0',
            'type' => '[query] SQL Injection UNION',
            'payload' => 'x',
            'threat_level' => 'high',
            'confidence_score' => 90,
            'confidence_label' => 'very_high',
            'action_taken' => 'logged',
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    #[Test]
    public function an_ordinary_keyword_still_filters(): void
    {
        $this->getJson(self::API . '/threats?keyword=UNION')
            ->assertStatus(200)
            ->assertJsonPath('data.total', 1);
    }

    #[Test]
    public function an_over_long_keyword_is_refused(): void
    {
        $this->getJson(self::API . '/threats?keyword=' . str_repeat('a', 256))->assertStatus(422);
    }

    #[Test]
    public function an_array_keyword_is_refused_rather_than_failing(): void
    {
        $this->getJson(self::API . '/threats?keyword[]=a')->assertStatus(422);
    }

    #[Test]
    public function the_export_refuses_an_array_keyword_too(): void
    {
        $this->get(self::API . '/export?keyword[]=a', ['Accept' => 'application/json'])->assertStatus(422);
    }

    #[Test]
    public function an_ordinary_reason_is_still_stored(): void
    {
        $this->postJson(self::API . '/threats/1/false-positive', ['reason' => 'staff search'])->assertStatus(200);

        $this->assertSame('staff search', DB::table('threat_exclusion_rules')->value('reason'));
    }

    #[Test]
    public function an_over_long_reason_is_refused(): void
    {
        $this->postJson(self::API . '/threats/1/false-positive', ['reason' => str_repeat('a', 1001)])->assertStatus(422);

        $this->assertSame(0, DB::table('threat_exclusion_rules')->count());
        $this->assertFalse((bool) DB::table('threat_logs')->where('id', 1)->value('is_false_positive'));
    }

    #[Test]
    public function a_reason_that_is_not_text_is_refused(): void
    {
        $this->postJson(self::API . '/threats/1/false-positive', ['reason' => ['a' => 'b']])->assertStatus(422);

        $this->assertSame(0, DB::table('threat_exclusion_rules')->count());
    }
}
