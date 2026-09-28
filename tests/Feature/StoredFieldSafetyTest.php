<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * What lands in the fields this package stores as sent.
 *
 * The consequence that matters most — a strict MySQL connection rejecting a
 * non-UTF-8 User-Agent and taking every detection in the request down with
 * it — can only be observed on MySQL, and is covered in
 * tests/Security/MysqlHostileBytesTest.php. SQLite stores whatever it is
 * given, which makes it the right place to check *what* is written.
 */
class StoredFieldSafetyTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();

        config([
            'cache.default' => 'array',
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

        Route::middleware('threat-detect')->get('/search', fn () => response('OK'));
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    private function storedUserAgent(string $userAgent): string
    {
        $this->withHeaders(['User-Agent' => $userAgent])
            ->get('/search?q=' . urlencode("' UNION SELECT password FROM users--"))
            ->assertStatus(200);

        $stored = DB::table('threat_logs')->value('user_agent');
        $this->assertNotNull($stored, 'nothing was logged, so this proves nothing');

        return (string) $stored;
    }

    #[Test]
    public function an_ordinary_user_agent_is_stored_exactly_as_sent(): void
    {
        $ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36';

        $this->assertSame($ua, $this->storedUserAgent($ua));
    }

    /** Non-ASCII that *is* UTF-8 is someone's legitimate browser, not an attack. */
    #[Test]
    public function valid_non_ascii_survives_untouched(): void
    {
        $ua = 'Mozilla/5.0 (Linux; Android 14; Pixel) Ünïcödé-Browser/1.0 日本語';

        $this->assertSame($ua, $this->storedUserAgent($ua));
    }

    #[Test]
    public function invalid_utf8_is_replaced_and_the_row_is_valid_utf8(): void
    {
        $stored = $this->storedUserAgent("Mozilla/5.0 \xFF\xFE tail");

        $this->assertTrue(mb_check_encoding($stored, 'UTF-8'), 'the stored value is still not UTF-8');
        $this->assertStringStartsWith('Mozilla/5.0 ', $stored);
        $this->assertStringEndsWith(' tail', $stored, 'bytes after the bad sequence were lost');
    }

    public static function controlSequences(): array
    {
        return [
            'escape (clear screen)' => ["\x1b[2J", "\x1b", '\x1B'],
            'bell' => ["\x07", "\x07", '\x07'],
            'null byte' => ["\x00", "\x00", '\x00'],
            'delete' => ["\x7f", "\x7f", '\x7F'],
            'C1 CSI, honoured as ESC [ by some terminals' => ["\u{9B}2J", "\u{9B}", '\u009B'],
            'right-to-left override' => ["\u{202E}gnp.exe", "\u{202E}", '\u202E'],
            'left-to-right embedding' => ["\u{202A}x", "\u{202A}", '\u202A'],
            'right-to-left isolate' => ["\u{2067}x", "\u{2067}", '\u2067'],
            'pop directional isolate' => ["x\u{2069}", "\u{2069}", '\u2069'],
        ];
    }

    #[Test]
    #[DataProvider('controlSequences')]
    public function control_characters_become_visible_text(string $sequence, string $raw, string $visible): void
    {
        $stored = $this->storedUserAgent("Mozilla/5.0 {$sequence} end");

        $this->assertStringNotContainsString($raw, $stored, 'the control character was stored raw');
        $this->assertStringContainsString($visible, $stored, 'the evidence that it was there was lost');
        $this->assertStringEndsWith(' end', $stored);
    }

    /** Tab is whitespace, not a control sequence, and is left alone. */
    /** Right-to-left letters are text, not controls, and are stored as sent. */
    #[Test]
    public function right_to_left_text_is_left_alone(): void
    {
        $ua = 'Mozilla/5.0 متصفح عربي דפדפן';

        $this->assertSame($ua, $this->storedUserAgent($ua));
    }

    #[Test]
    public function a_tab_is_left_alone(): void
    {
        $this->assertSame("Mozilla/5.0\tBrowser", $this->storedUserAgent("Mozilla/5.0\tBrowser"));
    }

    /** Sanitising for storage must not change what is detected. */
    #[Test]
    public function the_attack_tool_is_still_recognised_through_a_hostile_user_agent(): void
    {
        $this->withHeaders(['User-Agent' => "sqlmap/1.8 \x1b[2J\xFF"])
            ->get('/search?q=' . urlencode("' UNION SELECT password FROM users--"))
            ->assertStatus(200);

        $types = DB::table('threat_logs')->pluck('type')->implode(' | ');

        $this->assertStringContainsString('SQL Injection', $types);
        $this->assertStringContainsStringIgnoringCase('sqlmap', $types, 'the scanner was no longer identified from its User-Agent');
    }
}
