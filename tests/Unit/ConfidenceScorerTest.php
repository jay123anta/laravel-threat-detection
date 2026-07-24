<?php

namespace JayAnta\ThreatDetection\Tests\Unit;

use JayAnta\ThreatDetection\Services\ConfidenceScorer;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

class ConfidenceScorerTest extends TestCase
{
    private ConfidenceScorer $scorer;

    protected function setUp(): void
    {
        parent::setUp();
        $this->scorer = new ConfidenceScorer();
    }

    #[Test]
    public function it_returns_zero_for_empty_matches(): void
    {
        $result = $this->scorer->calculate([]);

        $this->assertEquals(0, $result['score']);
        $this->assertEquals('low', $result['label']);
    }

    #[Test]
    public function single_match_gets_base_score(): void
    {
        $matches = [['XSS Script Tag', 'high', 'query']];
        $result = $this->scorer->calculate($matches);

        // Base 20 + high severity 15 = 35
        $this->assertEquals(35, $result['score']);
        $this->assertEquals('medium', $result['label']);
    }

    #[Test]
    public function multiple_matches_increase_score(): void
    {
        $matches = [
            ['XSS Script Tag', 'high', 'query'],
            ['SQL Injection', 'high', 'query'],
            ['Directory Traversal', 'medium', 'body'],
        ];
        $result = $this->scorer->calculate($matches);

        // Base 20 + 2 extra * 15 = 50, + high severity 15 = 65
        $this->assertEquals(65, $result['score']);
        $this->assertEquals('high', $result['label']);
    }

    #[Test]
    public function extra_matches_capped_at_three(): void
    {
        $matches = [
            ['XSS', 'high', 'query'],
            ['SQLi', 'high', 'query'],
            ['Traversal', 'medium', 'body'],
            ['RCE', 'high', 'body'],
            ['SSRF', 'medium', 'body'],
        ];
        $result = $this->scorer->calculate($matches);

        // Base 20 + 3 extra max * 15 = 65, + high severity 15 = 80
        $this->assertEquals(80, $result['score']);
        $this->assertEquals('very_high', $result['label']);
    }

    #[Test]
    public function context_weight_adds_bonus(): void
    {
        $matches = [['XSS Script Tag', 'medium', 'query']];
        $contextWeights = ['XSS Script Tag' => 1.5];

        $result = $this->scorer->calculate($matches, $contextWeights);

        // Base 20 + context bonus 10 = 30
        $this->assertEquals(30, $result['score']);
        $this->assertEquals('medium', $result['label']);
    }

    #[Test]
    public function attack_tool_ua_adds_bonus(): void
    {
        $matches = [['XSS Script Tag', 'medium', 'query']];
        $result = $this->scorer->calculate($matches, [], true);

        // Base 20 + attack tool 25 = 45
        $this->assertEquals(45, $result['score']);
        $this->assertEquals('medium', $result['label']);
    }

    #[Test]
    public function strict_mode_adds_bonus(): void
    {
        $matches = [['XSS Script Tag', 'medium', 'query']];

        $balanced = $this->scorer->calculate($matches, [], false, 'balanced');
        $strict = $this->scorer->calculate($matches, [], false, 'strict');

        $this->assertEquals($balanced['score'] + 10, $strict['score']);
    }

    #[Test]
    public function relaxed_mode_subtracts_penalty(): void
    {
        $matches = [['XSS Script Tag', 'medium', 'query']];

        $balanced = $this->scorer->calculate($matches, [], false, 'balanced');
        $relaxed = $this->scorer->calculate($matches, [], false, 'relaxed');

        $this->assertEquals($balanced['score'] - 10, $relaxed['score']);
    }

    #[Test]
    public function score_is_clamped_to_100(): void
    {
        $matches = [
            ['XSS', 'high', 'query'],
            ['SQLi', 'high', 'query'],
            ['Traversal', 'high', 'body'],
            ['RCE', 'high', 'body'],
        ];
        $contextWeights = ['XSS' => 1.5];

        $result = $this->scorer->calculate($matches, $contextWeights, true, 'strict');

        $this->assertLessThanOrEqual(100, $result['score']);
    }

    #[Test]
    public function score_is_clamped_to_zero(): void
    {
        $matches = [['Minor', 'low', 'body']];
        $result = $this->scorer->calculate($matches, [], false, 'relaxed');

        $this->assertGreaterThanOrEqual(0, $result['score']);
    }

    #[Test]
    public function it_detects_attack_tool_user_agents(): void
    {
        $this->assertTrue($this->scorer->isAttackToolUserAgent('sqlmap/1.5'));
        $this->assertTrue($this->scorer->isAttackToolUserAgent('Mozilla/5.0 Nikto'));
        $this->assertTrue($this->scorer->isAttackToolUserAgent('Nmap Scripting Engine'));
        $this->assertFalse($this->scorer->isAttackToolUserAgent('Mozilla/5.0 (Windows NT 10.0)'));
        $this->assertFalse($this->scorer->isAttackToolUserAgent(''));
    }

    #[Test]
    public function score_to_label_mapping_is_correct(): void
    {
        $this->assertEquals('low', $this->scorer->scoreToLabel(0));
        $this->assertEquals('low', $this->scorer->scoreToLabel(25));
        $this->assertEquals('medium', $this->scorer->scoreToLabel(26));
        $this->assertEquals('medium', $this->scorer->scoreToLabel(50));
        $this->assertEquals('high', $this->scorer->scoreToLabel(51));
        $this->assertEquals('high', $this->scorer->scoreToLabel(75));
        $this->assertEquals('very_high', $this->scorer->scoreToLabel(76));
        $this->assertEquals('very_high', $this->scorer->scoreToLabel(100));
    }
}
