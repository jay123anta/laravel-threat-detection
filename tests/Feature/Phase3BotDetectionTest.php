<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Cache;

/**
 * Phase 3 v1.3.0: Full-cycle tests for expanded bot/scanner detection.
 *
 * Tests new security scanners, AI scrapers, headless browsers,
 * and aggressive crawlers added to user-agent detection.
 */
class Phase3BotDetectionTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();

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
            'cache.default' => 'array',
        ]);

        Route::middleware('threat-detect')->group(function () {
            Route::get('/bot-test', fn() => response('OK', 200));
        });
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    // ────────────────────────────────────────────
    //  New Security Scanners
    // ────────────────────────────────────────────

    #[Test]
    public function full_cycle_feroxbuster_scanner_is_detected(): void
    {
        $this->get('/bot-test', ['HTTP_USER_AGENT' => 'feroxbuster/2.10.0']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[user-agent] FeroxBuster',
            'threat_level' => 'high',
        ]);
    }

    #[Test]
    public function full_cycle_ffuf_fuzzer_is_detected(): void
    {
        $this->get('/bot-test', ['HTTP_USER_AGENT' => 'Fuzz Faster U Fool v2.0.0-dev (ffuf)']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[user-agent] FFUF Fuzzer',
            'threat_level' => 'high',
        ]);
    }

    #[Test]
    public function full_cycle_xsstrike_is_detected(): void
    {
        $this->get('/bot-test', ['HTTP_USER_AGENT' => 'XSStrike/3.1.5']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[user-agent] XSStrike Tool',
            'threat_level' => 'high',
        ]);
    }

    #[Test]
    public function full_cycle_netsparker_is_detected(): void
    {
        $this->get('/bot-test', ['HTTP_USER_AGENT' => 'Netsparker/5.8']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[user-agent] Netsparker Scanner',
            'threat_level' => 'high',
        ]);
    }

    #[Test]
    public function full_cycle_commix_is_detected(): void
    {
        $this->get('/bot-test', ['HTTP_USER_AGENT' => 'commix/v3.5']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[user-agent] Commix Tool',
            'threat_level' => 'high',
        ]);
    }

    #[Test]
    public function full_cycle_dalfox_is_detected(): void
    {
        $this->get('/bot-test', ['HTTP_USER_AGENT' => 'dalfox/v2.9.0']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[user-agent] Dalfox XSS Scanner',
            'threat_level' => 'high',
        ]);
    }

    // ────────────────────────────────────────────
    //  AI Scrapers
    // ────────────────────────────────────────────

    #[Test]
    public function full_cycle_gptbot_is_detected(): void
    {
        $this->get('/bot-test', ['HTTP_USER_AGENT' => 'Mozilla/5.0 AppleWebKit/537.36 (compatible; GPTBot/1.0)']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[user-agent] GPTBot AI Scraper',
            'threat_level' => 'low',
        ]);
    }

    #[Test]
    public function full_cycle_claudebot_is_detected(): void
    {
        $this->get('/bot-test', ['HTTP_USER_AGENT' => 'ClaudeBot/1.0']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[user-agent] ClaudeBot AI Scraper',
            'threat_level' => 'low',
        ]);
    }

    #[Test]
    public function full_cycle_bytespider_is_detected(): void
    {
        $this->get('/bot-test', ['HTTP_USER_AGENT' => 'Mozilla/5.0 (compatible; Bytespider)']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[user-agent] ByteSpider Crawler',
            'threat_level' => 'low',
        ]);
    }

    // ────────────────────────────────────────────
    //  Headless Browsers / Automation
    // ────────────────────────────────────────────

    #[Test]
    public function full_cycle_headless_chrome_is_detected(): void
    {
        $this->get('/bot-test', ['HTTP_USER_AGENT' => 'Mozilla/5.0 HeadlessChrome/120.0.0.0']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[user-agent] Headless Chrome',
            'threat_level' => 'medium',
        ]);
    }

    #[Test]
    public function full_cycle_puppeteer_is_detected(): void
    {
        $this->get('/bot-test', ['HTTP_USER_AGENT' => 'Mozilla/5.0 (puppeteer)']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[user-agent] Puppeteer Automation',
            'threat_level' => 'medium',
        ]);
    }

    #[Test]
    public function full_cycle_selenium_is_detected(): void
    {
        $this->get('/bot-test', ['HTTP_USER_AGENT' => 'selenium/4.8.0']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[user-agent] Selenium WebDriver',
            'threat_level' => 'medium',
        ]);
    }

    #[Test]
    public function full_cycle_playwright_is_detected(): void
    {
        $this->get('/bot-test', ['HTTP_USER_AGENT' => 'Playwright/1.40.0']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[user-agent] Playwright Automation',
            'threat_level' => 'medium',
        ]);
    }

    // ────────────────────────────────────────────
    //  Aggressive Crawlers
    // ────────────────────────────────────────────

    #[Test]
    public function full_cycle_ahrefsbot_is_detected(): void
    {
        $this->get('/bot-test', ['HTTP_USER_AGENT' => 'Mozilla/5.0 (compatible; AhrefsBot/7.0)']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[user-agent] Ahrefs Bot',
            'threat_level' => 'low',
        ]);
    }

    #[Test]
    public function full_cycle_semrushbot_is_detected(): void
    {
        $this->get('/bot-test', ['HTTP_USER_AGENT' => 'Mozilla/5.0 (compatible; SemrushBot/7~bl)']);

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[user-agent] SEMRush Bot',
            'threat_level' => 'low',
        ]);
    }

    // ────────────────────────────────────────────
    //  Passive + false positive
    // ────────────────────────────────────────────

    #[Test]
    public function full_cycle_all_bots_return_200(): void
    {
        $this->get('/bot-test', ['HTTP_USER_AGENT' => 'feroxbuster/2.10'])->assertStatus(200);
        $this->get('/bot-test', ['HTTP_USER_AGENT' => 'GPTBot/1.0'])->assertStatus(200);
        $this->get('/bot-test', ['HTTP_USER_AGENT' => 'HeadlessChrome/120'])->assertStatus(200);
    }

    #[Test]
    public function full_cycle_normal_chrome_browser_not_flagged(): void
    {
        $this->get('/bot-test', ['HTTP_USER_AGENT' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36']);

        $this->assertDatabaseMissing('threat_logs', [
            'type' => '[user-agent] Headless Chrome',
        ]);
    }

    #[Test]
    public function full_cycle_normal_firefox_not_flagged(): void
    {
        $this->get('/bot-test', ['HTTP_USER_AGENT' => 'Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0']);

        $count = DB::table('threat_logs')->where('type', 'like', '[user-agent]%')->count();
        $this->assertEquals(0, $count);
    }
}
