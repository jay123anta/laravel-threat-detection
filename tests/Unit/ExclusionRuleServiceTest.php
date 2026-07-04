<?php

namespace JayAnta\ThreatDetection\Tests\Unit;

use JayAnta\ThreatDetection\Services\ExclusionRuleService;
use PHPUnit\Framework\Attributes\Test;
use JayAnta\ThreatDetection\Tests\TestCase;
use Illuminate\Support\Facades\DB;

class ExclusionRuleServiceTest extends TestCase
{
    private ExclusionRuleService $service;

    protected function setUp(): void
    {
        parent::setUp();
        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();
        $this->service = new ExclusionRuleService();
    }

    #[Test]
    public function it_returns_empty_when_no_rules_exist(): void
    {
        $rules = $this->service->getActiveRules();

        $this->assertIsArray($rules);
        $this->assertEmpty($rules);
    }

    #[Test]
    public function it_creates_rule_from_threat(): void
    {
        $threatId = DB::table('threat_logs')->insertGetId([
            'ip_address' => '10.0.0.1',
            'url' => 'https://example.com/test/page',
            'type' => '[query] XSS Script Tag',
            'threat_level' => 'high',
            'action_taken' => 'logged',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $rule = $this->service->createFromThreat($threatId, 1, 'Not a real attack');

        $this->assertNotNull($rule);
        $this->assertEquals('XSS Script Tag', $rule->pattern_label);
        $this->assertEquals('test/page', $rule->path_pattern);
        $this->assertEquals($threatId, $rule->created_from_threat_id);
        $this->assertEquals('Not a real attack', $rule->reason);
        $this->assertTrue((bool) $rule->is_active);
    }

    #[Test]
    public function it_returns_null_for_nonexistent_threat(): void
    {
        $rule = $this->service->createFromThreat(999);

        $this->assertNull($rule);
    }

    #[Test]
    public function it_checks_exclusion_by_label(): void
    {
        DB::table('threat_exclusion_rules')->insert([
            'pattern_label' => 'XSS Script Tag',
            'is_active' => true,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->service->clearCache();

        $this->assertTrue($this->service->isExcluded('[query] XSS Script Tag', 'https://example.com/any'));
        $this->assertFalse($this->service->isExcluded('[query] SQL Injection', 'https://example.com/any'));
    }

    #[Test]
    public function it_checks_exclusion_by_path_pattern(): void
    {
        DB::table('threat_exclusion_rules')->insert([
            'pattern_label' => 'XSS Script Tag',
            'path_pattern' => 'blog/*',
            'is_active' => true,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->service->clearCache();

        $this->assertTrue($this->service->isExcluded('[query] XSS Script Tag', 'https://example.com/blog/post-1'));
        $this->assertFalse($this->service->isExcluded('[query] XSS Script Tag', 'https://example.com/admin/users'));
    }

    #[Test]
    public function inactive_rules_are_ignored(): void
    {
        DB::table('threat_exclusion_rules')->insert([
            'pattern_label' => 'XSS Script Tag',
            'is_active' => false,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->service->clearCache();

        $this->assertFalse($this->service->isExcluded('[query] XSS Script Tag', 'https://example.com/any'));
    }

    #[Test]
    public function it_deletes_a_rule(): void
    {
        $id = DB::table('threat_exclusion_rules')->insertGetId([
            'pattern_label' => 'XSS Script Tag',
            'is_active' => true,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->assertTrue($this->service->delete($id));
        $this->assertFalse($this->service->delete($id)); // already deleted
    }

    #[Test]
    public function all_returns_all_rules(): void
    {
        DB::table('threat_exclusion_rules')->insert([
            ['pattern_label' => 'Rule 1', 'is_active' => true, 'created_at' => now(), 'updated_at' => now()],
            ['pattern_label' => 'Rule 2', 'is_active' => false, 'created_at' => now(), 'updated_at' => now()],
        ]);

        $rules = $this->service->all();

        $this->assertCount(2, $rules);
    }
}
