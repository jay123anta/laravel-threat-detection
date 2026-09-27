<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * The dashboard shows web attacks and AI-related threats in separate
 * sections, so an operator can tell them apart at a glance.
 *
 * The sections are rendered client-side from the API, so what can be pinned
 * here is the structure and the wiring: each section exists, each asks the
 * API for its own category, and the AI section's wording does not claim more
 * than the evidence supports. The data behind them is tested in
 * AiThreatsApiTest.
 */
class DashboardSectionsTest extends TestCase
{
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('threat-detection.dashboard.enabled', true);
        $app['config']->set('threat-detection.dashboard.guard', 'none');
        $app['config']->set('threat-detection.dashboard.middleware', ['web']);
        $app['config']->set('app.key', 'base64:' . base64_encode(random_bytes(32)));
    }

    private function html(): string
    {
        $response = $this->get('/threat-detection');
        $response->assertStatus(200);

        return (string) $response->getContent();
    }

    #[Test]
    public function web_attacks_and_ai_related_threats_have_their_own_sections(): void
    {
        $html = $this->html();

        foreach (['health', 'web', 'ai', 'adaptive', 'actors', 'volume'] as $section) {
            $this->assertStringContainsString("data-section=\"{$section}\"", $html, "the {$section} section is missing");
        }

        $this->assertStringContainsString('>Web attacks<', $html);
        $this->assertStringContainsString('>AI-related threats<', $html);

        // The web section comes first and the AI section is not nested in it.
        $this->assertLessThan(strpos($html, 'data-section="ai"'), strpos($html, 'data-section="web"'));
    }

    /** Each section asks for its own half, so no row is shown in both. */
    #[Test]
    public function each_section_requests_its_own_category(): void
    {
        $html = $this->html();

        $this->assertStringContainsString('/stats?category=traditional', $html);
        $this->assertStringContainsString("category: 'traditional'", $html, 'the web table does not filter to traditional threats');
        $this->assertStringContainsString('/timeline?days=7&category=traditional', $html);
        $this->assertStringContainsString('/threats?category=ai', $html);
        $this->assertStringContainsString('/ai-threats', $html);
    }

    #[Test]
    public function the_ai_panels_are_separate_from_each_other(): void
    {
        $html = $this->html();

        $this->assertStringContainsString('data-panel="ai-infrastructure"', $html);
        $this->assertStringContainsString('data-panel="llm-directed"', $html);
        $this->assertStringContainsString('data-panel="mutation-chains"', $html);
        $this->assertStringContainsString('data-panel="payload-clusters"', $html);
        $this->assertStringContainsString('data-panel="retry-bursts"', $html);
    }

    /**
     * The wording is part of the feature. "AI-related" means what was
     * targeted; adaptive behaviour is explicitly not evidence of AI; and the
     * dashboard never calls anyone an "AI attacker". Research on both counts:
     * the largest campaigns against LLM endpoints were ordinary scanners, and
     * a three-month honeypot deployment found 8 possible AI agents in 8.1 million
     * interactions (arXiv:2410.13919).
     */
    #[Test]
    public function the_dashboard_does_not_claim_more_than_the_evidence(): void
    {
        $html = $this->html();

        $this->assertStringContainsString('not who attacked', $html);
        $this->assertStringContainsString('not evidence of AI', $html);
        $this->assertStringNotContainsStringIgnoringCase('AI attacker', $html);
        $this->assertStringNotContainsStringIgnoringCase('AI-powered attack', $html);
    }

    /** A switched-off feature must read as off, never as a reassuring zero. */
    #[Test]
    public function switched_off_features_are_labelled_off(): void
    {
        $html = $this->html();

        $this->assertStringContainsString("return 'off';", $html);
        $this->assertStringContainsString('THREAT_DETECTION_AI_PROBES=true', $html);
        $this->assertStringContainsString('THREAT_DETECTION_LLM_INJECTION=true', $html);
        $this->assertStringContainsString('THREAT_DETECTION_ACTOR_SIGNALS=true', $html);
        $this->assertStringContainsString('THREAT_DETECTION_ACTOR_SCORE=true', $html);
    }

    /** The false-positive click says what it will create before it creates it. */
    #[Test]
    public function the_false_positive_dialog_states_the_exclusion_scope(): void
    {
        $html = $this->html();

        $this->assertStringContainsString('This creates a permanent exclusion', $html);
        $this->assertStringContainsString('will no longer be logged on', $html);
    }
}
