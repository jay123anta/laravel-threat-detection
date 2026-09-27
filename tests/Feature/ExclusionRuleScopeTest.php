<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Services\ExclusionRuleService;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * How far a false-positive click reaches.
 *
 * Marking a row as a false positive creates an exclusion rule from that row's
 * label and URL path. The path was matched with fnmatch(), so it was a glob —
 * and the path is whatever the requester sent. A request for `/*` carrying an
 * injection, marked as noise by an operator clearing a busy dashboard, became
 * a permanent rule silencing that injection label on every path of the site.
 *
 * Exclusions are the part of a detection system that quietly ratchets: across
 * nine years of SigmaHQ rules, exclusions were added 5.4 times for every one
 * removed and 64.1% of path exclusions were satisfiable by an unprivileged
 * attacker (arXiv:2608.31062). A rule whose scope the attacker chose is the
 * worst case of both.
 *
 * A rule built from a logged row now matches that row's path exactly. Rules
 * an operator writes by hand keep glob matching — there, the pattern is theirs.
 */
class ExclusionRuleScopeTest extends TestCase
{
    private const LABEL = 'SQL Injection UNION';

    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();
        config(['cache.default' => 'array']);
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

    private function ruleFromRowAt(string $url): void
    {
        $id = DB::table('threat_logs')->insertGetId([
            'ip_address' => '203.0.113.9',
            'url' => $url,
            'user_agent' => 'curl/8',
            'type' => '[query] ' . self::LABEL,
            'payload' => 'x',
            'threat_level' => 'high',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->assertNotNull($this->service()->createFromThreat($id));
    }

    public static function attackerShapedPaths(): array
    {
        return [
            'star' => ['https://app.test/*?q=x', 'orders/42'],
            'star inside' => ['https://app.test/a*?q=x', 'admin/users'],
            'character class' => ['https://app.test/[a-z]*?q=x', 'search'],
            'escaped star' => ['https://app.test/foo\\bar?q=x', 'foobar'],
        ];
    }

    #[Test]
    #[DataProvider('attackerShapedPaths')]
    public function a_rule_from_a_row_does_not_reach_paths_it_never_saw(string $rowUrl, string $elsewhere): void
    {
        $this->ruleFromRowAt($rowUrl);

        $this->assertFalse(
            $this->service()->isExcluded('[query] ' . self::LABEL, "https://app.test/{$elsewhere}?q=1"),
            "a rule created from {$rowUrl} also silenced /{$elsewhere}"
        );
    }

    /** The rule still does what the operator meant: silence that row's own path. */
    #[Test]
    #[DataProvider('attackerShapedPaths')]
    public function a_rule_from_a_row_still_covers_its_own_path(string $rowUrl, string $elsewhere): void
    {
        $this->ruleFromRowAt($rowUrl);

        $this->assertTrue($this->service()->isExcluded('[query] ' . self::LABEL, $rowUrl));
    }

    #[Test]
    public function an_ordinary_path_behaves_exactly_as_before(): void
    {
        $this->ruleFromRowAt('https://app.test/api/search?q=x');

        $this->assertTrue($this->service()->isExcluded('[query] ' . self::LABEL, 'https://app.test/api/search?q=other'));
        $this->assertFalse($this->service()->isExcluded('[query] ' . self::LABEL, 'https://app.test/api/searches?q=other'));
    }

    /** A pattern the operator wrote themselves is still a pattern. */
    #[Test]
    public function an_operator_written_rule_keeps_glob_matching(): void
    {
        DB::table('threat_exclusion_rules')->insert([
            'pattern_label' => self::LABEL,
            'path_pattern' => 'admin/*',
            'created_from_threat_id' => null,
            'is_active' => true,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->assertTrue($this->service()->isExcluded('[query] ' . self::LABEL, 'https://app.test/admin/users'));
    }

    /** Through the pipeline: after the click, the attack elsewhere is still logged. */
    #[Test]
    public function an_attack_elsewhere_is_still_logged_after_the_click(): void
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

        $this->ruleFromRowAt('https://app.test/*?q=x');

        Route::middleware('threat-detect')->get('/search', fn () => response('OK'));
        $this->get('/search?q=' . urlencode("' UNION SELECT password FROM users--"))->assertStatus(200);

        $this->assertTrue(
            DB::table('threat_logs')->where('url', 'like', '%/search%')->where('type', 'like', '%' . self::LABEL)->exists(),
            'one false-positive click on a /* row silenced this injection site-wide'
        );
    }
}
