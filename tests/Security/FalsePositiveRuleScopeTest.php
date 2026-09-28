<?php

namespace JayAnta\ThreatDetection\Tests\Security;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Services\ExclusionRuleService;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * A rule built from a row must never reach further than that row's path.
 *
 * 1.9.0 made those rules match their path exactly rather than as a glob. One
 * shape escaped: a row with no path to speak of. The path was stored as
 * `$path ?: null`, and a rule with a null path is the operator's spelling for
 * "every path" — so marking a detection on the site root as noise, the most
 * common place for one, silenced that label on every route. `/0` did the same,
 * since '0' is falsy, and so did any URL parse_url() gave up on.
 *
 * A row-derived rule now always carries a path, the root included, and one
 * whose path cannot be stored exactly is refused rather than widened.
 */
class FalsePositiveRuleScopeTest extends TestCase
{
    private const LABEL = 'SQL Injection UNION';

    private const TYPE = '[query] ' . self::LABEL;

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
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    private function service(): ExclusionRuleService
    {
        return new ExclusionRuleService;
    }

    private function rowAt(string $url): int
    {
        return DB::table('threat_logs')->insertGetId([
            'ip_address' => '203.0.113.9',
            'url' => $url,
            'user_agent' => 'curl/8',
            'type' => self::TYPE,
            'payload' => 'x',
            'threat_level' => 'high',
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    public static function pathlessRows(): array
    {
        return [
            'root with a query' => ['https://app.test/?q=x', 'https://app.test/?q=other'],
            'root without a slash' => ['https://app.test?q=x', 'https://app.test/?q=other'],
            'a path that is falsy' => ['https://app.test/0?q=x', 'https://app.test/0?q=other'],
        ];
    }

    #[Test]
    #[DataProvider('pathlessRows')]
    public function a_rule_from_such_a_row_does_not_reach_other_paths(string $rowUrl, string $ownPath): void
    {
        $this->assertNotNull($this->service()->createFromThreat($this->rowAt($rowUrl)));

        $this->assertFalse(
            $this->service()->isExcluded(self::TYPE, 'https://app.test/orders/42?q=1'),
            "one false-positive click on {$rowUrl} silenced the label on every path"
        );
    }

    /** Positive control: the rule still silences the path it was made from. */
    #[Test]
    #[DataProvider('pathlessRows')]
    public function a_rule_from_such_a_row_still_covers_its_own_path(string $rowUrl, string $ownPath): void
    {
        $this->assertNotNull($this->service()->createFromThreat($this->rowAt($rowUrl)));

        $this->assertTrue($this->service()->isExcluded(self::TYPE, $ownPath));
    }

    /**
     * Rules already written by earlier versions from a root row carry a null
     * path. They are fixed where they are read, as the glob rules were, so no
     * migration is needed and none is missed.
     */
    #[Test]
    public function an_existing_row_derived_rule_with_no_path_covers_only_the_root(): void
    {
        DB::table('threat_exclusion_rules')->insert([
            'pattern_label' => self::LABEL,
            'path_pattern' => null,
            'created_from_threat_id' => 7,
            'is_active' => true,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->assertFalse($this->service()->isExcluded(self::TYPE, 'https://app.test/orders/42?q=1'));
        $this->assertTrue($this->service()->isExcluded(self::TYPE, 'https://app.test/?q=1'));
    }

    /** A label-wide rule the operator wrote on purpose keeps meaning every path. */
    #[Test]
    public function an_operator_written_rule_with_no_path_still_covers_every_path(): void
    {
        DB::table('threat_exclusion_rules')->insert([
            'pattern_label' => self::LABEL,
            'path_pattern' => null,
            'created_from_threat_id' => null,
            'is_active' => true,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->assertTrue($this->service()->isExcluded(self::TYPE, 'https://app.test/orders/42?q=1'));
    }

    public static function unscopableRows(): array
    {
        return [
            'a URL parse_url() rejects' => ['http:///orders?q=x'],
            'a path longer than the column' => ['https://app.test/' . str_repeat('a', 300) . '?q=x'],
        ];
    }

    /** Refused, not widened: no rule, and nothing that says one was made. */
    #[Test]
    #[DataProvider('unscopableRows')]
    public function a_row_whose_path_cannot_be_stored_exactly_gets_no_rule(string $rowUrl): void
    {
        $this->assertNull($this->service()->createFromThreat($this->rowAt($rowUrl)));
        $this->assertSame(0, DB::table('threat_exclusion_rules')->count());
    }

    #[Test]
    #[DataProvider('unscopableRows')]
    public function the_api_refuses_such_a_row_and_leaves_it_unmarked(string $rowUrl): void
    {
        $id = $this->rowAt($rowUrl);

        $this->postJson("/api/threat-detection/threats/{$id}/false-positive")
            ->assertStatus(422)
            ->assertJson(['success' => false]);

        $this->assertSame(0, DB::table('threat_exclusion_rules')->count());
        $this->assertFalse((bool) DB::table('threat_logs')->where('id', $id)->value('is_false_positive'));
    }

    /** Positive control for the API: an ordinary row is still marked and ruled. */
    #[Test]
    public function the_api_still_marks_an_ordinary_row(): void
    {
        $id = $this->rowAt('https://app.test/?q=x');

        $this->postJson("/api/threat-detection/threats/{$id}/false-positive")->assertStatus(200);

        $this->assertTrue((bool) DB::table('threat_logs')->where('id', $id)->value('is_false_positive'));
        $this->assertSame(1, DB::table('threat_exclusion_rules')->where('created_from_threat_id', $id)->count());
    }

    /** Through the pipeline: after a click on a root row, the attack elsewhere is still logged. */
    #[Test]
    public function an_attack_elsewhere_is_still_logged_after_a_click_on_the_root(): void
    {
        config([
            'threat-detection.enabled' => true,
            'threat-detection.detection_mode' => 'strict',
            'threat-detection.min_confidence' => 0,
            'threat-detection.skip_paths' => [],
            'threat-detection.only_paths' => [],
            'threat-detection.whitelisted_ips' => [],
            'threat-detection.api_route_filtering.enabled' => false,
            'threat-detection.content_paths' => [],
            'threat-detection.notifications.enabled' => false,
            'threat-detection.queue.enabled' => false,
        ]);
        ThreatDetectionService::flushCaches();

        $this->service()->createFromThreat($this->rowAt('https://app.test/?q=x'));

        Route::middleware('threat-detect')->get('/search', fn () => response('OK'));
        $this->get('/search?q=' . urlencode("' UNION SELECT password FROM users--"))->assertStatus(200);

        $this->assertTrue(
            DB::table('threat_logs')->where('url', 'like', '%/search%')->where('type', 'like', '%' . self::LABEL)->exists(),
            'one false-positive click on the site root silenced this injection site-wide'
        );
    }
}
