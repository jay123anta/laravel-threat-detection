<?php

namespace JayAnta\ThreatDetection\Tests\Security;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * Attacker-chosen bytes in the fields stored verbatim, on a strict server.
 *
 * SQLite stores any bytes you give it, so the default suite cannot see this.
 * A strict MySQL connection — Laravel's default — rejects a string that is
 * not valid UTF-8 for a utf8mb4 column, and the whole INSERT fails. Every
 * detection in a request is written in one batched statement, so one bad
 * byte in a header that is stored as-is would cost the request *all* of its
 * detections: append \xFF to the User-Agent and the attack beside it is never
 * logged.
 *
 * Skipped unless THREAT_DETECTION_MYSQL=1, like the other files here.
 */
class MysqlHostileBytesTest extends TestCase
{
    private const INJECTION = "' UNION SELECT password FROM users--";

    protected function setUp(): void
    {
        parent::setUp();

        if (env('THREAT_DETECTION_MYSQL') !== '1') {
            $this->markTestSkipped('Set THREAT_DETECTION_MYSQL=1 and point the connection at a scratch database to run these.');
        }

        try {
            DB::connection('mysql_scratch')->select('SELECT 1');
        } catch (\Throwable $e) {
            $this->markTestSkipped('No MySQL/MariaDB server answered: ' . $e->getMessage());
        }

        Schema::dropIfExists('threat_logs');
        Schema::dropIfExists('threat_exclusion_rules');
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

    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('database.default', 'mysql_scratch');
        $app['config']->set('database.connections.mysql_scratch', [
            'driver' => 'mysql',
            'host' => env('THREAT_DETECTION_MYSQL_HOST', '127.0.0.1'),
            'port' => env('THREAT_DETECTION_MYSQL_PORT', '3306'),
            'database' => env('THREAT_DETECTION_MYSQL_DATABASE', 'threat_detection_test'),
            'username' => env('THREAT_DETECTION_MYSQL_USERNAME', 'root'),
            'password' => env('THREAT_DETECTION_MYSQL_PASSWORD', ''),
            'charset' => 'utf8mb4',
            'collation' => 'utf8mb4_unicode_ci',
            'prefix' => '',
            'strict' => true,
            'engine' => null,
        ]);
    }

    protected function tearDown(): void
    {
        if (env('THREAT_DETECTION_MYSQL') === '1') {
            try {
                Schema::dropIfExists('threat_logs');
                Schema::dropIfExists('threat_exclusion_rules');
            } catch (\Throwable $e) {
                // The skip path never built them.
            }
        }

        Cache::flush();
        parent::tearDown();
    }

    private function injectionsLogged(): int
    {
        return DB::table('threat_logs')->where('type', 'like', '%SQL Injection%')->count();
    }

    /** Positive control: the same request, clean User-Agent, is logged. */
    #[Test]
    public function the_injection_is_logged_with_an_ordinary_user_agent(): void
    {
        $this->withHeaders(['User-Agent' => 'Mozilla/5.0'])
            ->get('/search?q=' . urlencode(self::INJECTION))
            ->assertStatus(200);

        $this->assertGreaterThan(0, $this->injectionsLogged());
    }

    #[Test]
    public function an_invalid_utf8_user_agent_does_not_cost_the_request_its_detections(): void
    {
        $this->withHeaders(['User-Agent' => "Mozilla/5.0 \xFF\xFE"])
            ->get('/search?q=' . urlencode(self::INJECTION))
            ->assertStatus(200);

        $this->assertGreaterThan(0, $this->injectionsLogged(), 'one invalid byte in the User-Agent made the attack beside it unloggable');
    }

    /**
     * Terminal control sequences are stored for a human to read later — in a
     * shell, a log tail, an export opened in a pager. Stored raw, an escape
     * sequence rewrites what that human sees.
     */
    #[Test]
    public function terminal_control_sequences_are_not_stored_raw(): void
    {
        $this->withHeaders(['User-Agent' => "Mozilla/5.0 \x1b[2J\x1b[1;1Hall clear\x07"])
            ->get('/search?q=' . urlencode(self::INJECTION))
            ->assertStatus(200);

        $stored = (string) DB::table('threat_logs')->value('user_agent');

        $this->assertNotSame('', $stored, 'nothing was stored, so this proves nothing');
        $this->assertStringNotContainsString("\x1b", $stored);
        $this->assertStringNotContainsString("\x07", $stored);
        $this->assertStringContainsString('Mozilla/5.0', $stored, 'the printable part of the header should survive');
    }

    /**
     * TEXT holds 65,535 bytes. A longer User-Agent failed the batched INSERT
     * on a strict server and took the attack beside it down with it — a
     * header size nginx refuses by default but Go-based servers accept.
     */
    #[Test]
    public function an_oversized_user_agent_does_not_cost_the_request_its_detections(): void
    {
        $this->withHeaders(['User-Agent' => 'Mozilla/5.0 ' . str_repeat('a', 70000)])
            ->get('/search?q=' . urlencode(self::INJECTION))
            ->assertStatus(200);

        $this->assertGreaterThan(0, $this->injectionsLogged(), 'an oversized User-Agent made the attack beside it unloggable');
    }

    /** Escaping grows a control byte to four characters, so a smaller header reaches the limit. */
    #[Test]
    public function a_user_agent_that_escaping_pushes_past_the_column_does_not_either(): void
    {
        $this->withHeaders(['User-Agent' => 'Mozilla/5.0 ' . str_repeat("\x01", 20000)])
            ->get('/search?q=' . urlencode(self::INJECTION))
            ->assertStatus(200);

        $this->assertGreaterThan(0, $this->injectionsLogged(), 'a 20 KB User-Agent, escaped past 64 KB, made the attack unloggable');
    }

    #[Test]
    public function an_oversized_url_does_not_cost_the_request_its_detections(): void
    {
        $this->get('/search?q=' . urlencode(self::INJECTION) . '&pad=' . str_repeat('a', 70000))
            ->assertStatus(200);

        $this->assertGreaterThan(0, $this->injectionsLogged(), 'an oversized URL made its own attack unloggable');
    }
}
