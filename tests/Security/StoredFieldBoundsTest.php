<?php

namespace JayAnta\ThreatDetection\Tests\Security;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * The URL and User-Agent are stored as sent, and until now at any length.
 *
 * Both columns are TEXT, which on MySQL holds 65,535 bytes. A strict
 * connection — Laravel's default — rejects a longer value, and every detection
 * in a request goes out in one INSERT, so a header past that size cost the
 * request all of its detections. Escaping makes it easier to reach: a control
 * byte is stored as four visible characters.
 *
 * nginx and Apache refuse headers that long by default, but the limit is the
 * server's, not this package's: Go-based servers such as FrankenPHP accept a
 * megabyte, and operators raise nginx's buffers for large cookies. The stored
 * copy is therefore bounded here. Detection still reads the whole value.
 *
 * SQLite stores any length, so these tests assert the bound itself; the
 * failure it prevents is shown on a real server in MysqlHostileBytesTest.
 */
class StoredFieldBoundsTest extends TestCase
{
    private const INJECTION = "' UNION SELECT password FROM users--";

    /** Generous: the bound plus room for the truncation marker. */
    private const CEILING = 8192 + 64;

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

    private function injectionRow(): ?object
    {
        return DB::table('threat_logs')->where('type', 'like', '%SQL Injection%')->first();
    }

    /** Positive control: ordinary values are stored exactly as sent. */
    #[Test]
    public function ordinary_values_are_stored_unchanged(): void
    {
        $this->withHeaders(['User-Agent' => 'Mozilla/5.0 (X11; Linux x86_64)'])
            ->get('/search?q=' . urlencode(self::INJECTION))
            ->assertStatus(200);

        $row = $this->injectionRow();

        $this->assertNotNull($row, 'the injection was not logged, so nothing below means anything');
        $this->assertSame('Mozilla/5.0 (X11; Linux x86_64)', $row->user_agent);
        $this->assertStringNotContainsString('[truncated]', $row->url);
    }

    #[Test]
    public function an_oversized_user_agent_is_stored_bounded_and_marked(): void
    {
        $this->withHeaders(['User-Agent' => 'Mozilla/5.0 ' . str_repeat('a', 100000)])
            ->get('/search?q=' . urlencode(self::INJECTION))
            ->assertStatus(200);

        $row = $this->injectionRow();

        $this->assertNotNull($row);
        $this->assertLessThanOrEqual(self::CEILING, strlen($row->user_agent));
        $this->assertStringStartsWith('Mozilla/5.0 aaaa', $row->user_agent);
        $this->assertStringEndsWith('[truncated]', $row->user_agent, 'a cut value must say it was cut');
    }

    #[Test]
    public function an_oversized_url_is_stored_bounded_and_marked(): void
    {
        $this->get('/search?q=' . urlencode(self::INJECTION) . '&pad=' . str_repeat('a', 100000))
            ->assertStatus(200);

        $row = $this->injectionRow();

        $this->assertNotNull($row);
        $this->assertLessThanOrEqual(self::CEILING, strlen($row->url));
        $this->assertStringContainsString('/search?', $row->url);
        $this->assertStringEndsWith('[truncated]', $row->url);
    }

    /** The bound is applied to what is stored, after escaping has grown it. */
    #[Test]
    public function the_bound_holds_after_escaping_expands_the_value(): void
    {
        $this->withHeaders(['User-Agent' => 'Mozilla/5.0 ' . str_repeat("\x01", 20000)])
            ->get('/search?q=' . urlencode(self::INJECTION))
            ->assertStatus(200);

        $row = $this->injectionRow();

        $this->assertNotNull($row);
        $this->assertLessThanOrEqual(self::CEILING, strlen($row->user_agent));
        $this->assertTrue(mb_check_encoding($row->user_agent, 'UTF-8'));
    }

    /** A cut never leaves half a character behind for a strict server to reject. */
    #[Test]
    public function a_cut_through_multibyte_text_stays_valid_utf8(): void
    {
        $this->withHeaders(['User-Agent' => 'Mozilla/5.0 ' . str_repeat('€', 40000)])
            ->get('/search?q=' . urlencode(self::INJECTION))
            ->assertStatus(200);

        $row = $this->injectionRow();

        $this->assertNotNull($row);
        $this->assertLessThanOrEqual(self::CEILING, strlen($row->user_agent));
        $this->assertTrue(mb_check_encoding($row->user_agent, 'UTF-8'));
    }

    /** Bounding the stored copy must not bound what detection reads. */
    #[Test]
    public function detection_still_reads_the_whole_user_agent(): void
    {
        $this->withHeaders(['User-Agent' => 'Mozilla/5.0 ' . str_repeat('a', 20000) . ' sqlmap/1.7'])
            ->get('/search')
            ->assertStatus(200);

        $this->assertTrue(
            DB::table('threat_logs')->where('type', 'like', '%SQLMap Scanner%')->exists(),
            'the scanner name past the storage bound was not seen by detection'
        );
    }

    /** The flood row is written on its own path, and is bounded on it too. */
    #[Test]
    public function the_flood_row_is_bounded_too(): void
    {
        config(['threat-detection.ddos.threshold' => 2, 'threat-detection.ddos.window' => 60]);

        foreach (range(1, 5) as $ignored) {
            $this->withHeaders(['User-Agent' => 'Mozilla/5.0 ' . str_repeat('a', 100000)])
                ->get('/search?pad=' . str_repeat('b', 100000));
        }

        $row = DB::table('threat_logs')->where('type', '[ddos] Excessive Requests')->first();

        $this->assertNotNull($row, 'no flood row was written, so this proves nothing');
        $this->assertLessThanOrEqual(self::CEILING, strlen($row->user_agent));
        $this->assertLessThanOrEqual(self::CEILING, strlen($row->url));
    }
}
