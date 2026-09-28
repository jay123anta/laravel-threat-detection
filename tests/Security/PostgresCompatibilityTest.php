<?php

namespace JayAnta\ThreatDetection\Tests\Security;

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use JayAnta\ThreatDetection\Services\ExclusionRuleService;
use JayAnta\ThreatDetection\Services\ThreatCorrelationService;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * The package on PostgreSQL.
 *
 * The package claims to be database-agnostic, and until this file nothing ran
 * it on PostgreSQL. SQLite — the suite's default — accepts invalid UTF-8,
 * compares a boolean to an integer without complaint, and casts a timestamp
 * to a DATE by returning the year; each of those hid a real bug in this
 * package. PostgreSQL is stricter than both SQLite and MySQL on types and on
 * encoding, so it is where the next one would surface.
 *
 * Skipped unless THREAT_DETECTION_PGSQL=1.
 */
class PostgresCompatibilityTest extends TestCase
{
    private const API = '/api/threat-detection';

    private const SIGNALS = 'threat_actor_signals';

    protected function setUp(): void
    {
        parent::setUp();

        if (env('THREAT_DETECTION_PGSQL') !== '1') {
            $this->markTestSkipped('Set THREAT_DETECTION_PGSQL=1 and point the connection at a scratch PostgreSQL database to run these.');
        }

        try {
            DB::connection('pgsql_scratch')->select('SELECT 1');
        } catch (\Throwable $e) {
            $this->markTestSkipped('No PostgreSQL server answered: ' . $e->getMessage());
        }

        foreach (['threat_logs', 'threat_exclusion_rules', self::SIGNALS] as $table) {
            Schema::dropIfExists($table);
        }

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();

        config([
            'cache.default' => 'array',
            'threat-detection.api.write_guard' => 'none',
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
    }

    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('database.default', 'pgsql_scratch');
        $app['config']->set('database.connections.pgsql_scratch', [
            'driver' => 'pgsql',
            'host' => env('THREAT_DETECTION_PGSQL_HOST', '127.0.0.1'),
            'port' => env('THREAT_DETECTION_PGSQL_PORT', '5432'),
            'database' => env('THREAT_DETECTION_PGSQL_DATABASE', 'threat_detection_test'),
            'username' => env('THREAT_DETECTION_PGSQL_USERNAME', 'postgres'),
            'password' => env('THREAT_DETECTION_PGSQL_PASSWORD', ''),
            'charset' => 'utf8',
            'prefix' => '',
            'search_path' => 'public',
            'sslmode' => 'prefer',
        ]);
    }

    protected function tearDown(): void
    {
        if (env('THREAT_DETECTION_PGSQL') === '1') {
            try {
                foreach (['threat_logs', 'threat_exclusion_rules', self::SIGNALS] as $table) {
                    Schema::dropIfExists($table);
                }
            } catch (\Throwable $e) {
                // The skip path never built them.
            }
        }

        Cache::flush();
        parent::tearDown();
    }

    /** Rows across two days, both kinds, one foreign and one cloud. */
    private function seedRows(): void
    {
        $rows = [
            ['10.0.0.1', '[middleware] SQL Injection UNION', 'high', now()->subDays(2), true, 'aws'],
            ['10.0.0.1', '[probe] OpenAI-Compatible Model Enumeration', 'high', now()->subDays(2), false, null],
            ['10.0.0.2', '[probe] WordPress Admin', 'medium', now(), false, null],
            ['10.0.0.3', '[custom] LLM Triage Manipulation', 'medium', now(), true, null],
        ];

        foreach ($rows as [$ip, $type, $level, $at, $foreign, $cloud]) {
            DB::table('threat_logs')->insert([
                'ip_address' => $ip,
                'url' => 'https://example.com/search?q=1',
                'user_agent' => 'curl/8',
                'type' => $type,
                'payload' => 'x',
                'threat_level' => $level,
                'is_foreign' => $foreign,
                'cloud_provider' => $cloud,
                'is_cloud_ip' => $cloud !== null,
                'country_code' => 'NL',
                'country_name' => 'Netherlands',
                'created_at' => $at,
                'updated_at' => $at,
            ]);
        }
    }

    // ── Every read endpoint answers ────────────────────────────────────────

    public static function readEndpoints(): array
    {
        return [
            'threats' => ['/threats'],
            'threats, ai' => ['/threats?category=ai'],
            'threat by id' => ['/threats/1'],
            'stats' => ['/stats'],
            'stats, traditional' => ['/stats?category=traditional'],
            'summary' => ['/summary'],
            'live count' => ['/live-count'],
            'by country' => ['/by-country?category=ai'],
            'by cloud provider' => ['/by-cloud-provider'],
            'top ips' => ['/top-ips?category=traditional'],
            'timeline' => ['/timeline?days=7'],
            'ip stats' => ['/ip-stats?ip=10.0.0.1'],
            'correlation, all' => ['/correlation?type=all'],
            'ai threats' => ['/ai-threats'],
            'export' => ['/export'],
            'exclusion rules' => ['/exclusion-rules'],
        ];
    }

    #[Test]
    #[DataProvider('readEndpoints')]
    public function every_read_endpoint_answers(string $endpoint): void
    {
        $this->seedRows();

        $response = $this->get(self::API . $endpoint);

        $this->assertSame(200, $response->status(), "{$endpoint} failed on PostgreSQL: " . substr((string) $response->getContent(), 0, 300));
    }

    /** The one this file was written to check: `is_foreign = 1` against a boolean column. */
    #[Test]
    public function stats_counts_booleans_correctly(): void
    {
        $this->seedRows();

        $stats = $this->getJson(self::API . '/stats')->assertStatus(200)->json('data');

        $this->assertSame(4, $stats['total_threats']);
        $this->assertSame(2, $stats['foreign_ips']);
        $this->assertSame(1, $stats['cloud_attacks']);
    }

    #[Test]
    public function the_timeline_buckets_by_calendar_day(): void
    {
        $this->seedRows();

        $rows = collect($this->getJson(self::API . '/timeline?days=7')->assertStatus(200)->json('data'));

        $this->assertSame(
            [now()->subDays(2)->toDateString() => 2, now()->toDateString() => 2],
            $rows->groupBy('date')->map(fn ($day) => $day->sum('count'))->sortKeys()->all()
        );
    }

    #[Test]
    public function the_ai_split_partitions_the_rows(): void
    {
        $this->seedRows();

        $this->assertSame(2, $this->getJson(self::API . '/stats?category=ai')->json('data.total_threats'));
        $this->assertSame(2, $this->getJson(self::API . '/stats?category=traditional')->json('data.total_threats'));
    }

    // ── Writes ─────────────────────────────────────────────────────────────

    /** PostgreSQL rejects invalid UTF-8 just as strict MySQL does. */
    #[Test]
    public function an_invalid_utf8_user_agent_does_not_cost_the_request_its_detections(): void
    {
        Route::middleware('threat-detect')->get('/search', fn () => response('OK'));

        $this->withHeaders(['User-Agent' => "Mozilla/5.0 \xFF\xFE \x1b[2J"])
            ->get('/search?q=' . urlencode("' UNION SELECT password FROM users--"))
            ->assertStatus(200);

        $this->assertTrue(
            DB::table('threat_logs')->where('type', 'like', '%SQL Injection%')->exists(),
            'one invalid byte in the User-Agent made the attack unloggable on PostgreSQL'
        );
    }

    #[Test]
    public function marking_a_false_positive_creates_a_working_exclusion(): void
    {
        $this->seedRows();

        $this->postJson(self::API . '/threats/1/false-positive')->assertStatus(200);

        $service = new ExclusionRuleService;
        $this->assertTrue($service->isExcluded('[middleware] SQL Injection UNION', 'https://example.com/search'));
        $this->assertFalse($service->isExcluded('[middleware] SQL Injection UNION', 'https://example.com/other'));
    }

    #[Test]
    public function the_purge_command_runs(): void
    {
        $this->seedRows();
        DB::table('threat_logs')->update(['created_at' => now()->subDays(100)]);

        $this->assertSame(0, Artisan::call('threat-detection:purge', ['--days' => 30, '--no-interaction' => true]));
        $this->assertSame(0, DB::table('threat_logs')->count());
    }

    // ── Actor signals: the migration and the grouped queries ───────────────

    #[Test]
    public function the_actor_signal_analyses_run(): void
    {
        config([
            'threat-detection.actor_signals.enabled' => true,
            'threat-detection.actor_signals.table' => self::SIGNALS,
            'threat-detection.actor_score.enabled' => true,
        ]);
        (require __DIR__ . '/../../database/migrations/create_threat_actor_signals_table.php.stub')->up();

        Route::middleware('threat-detect')->get('/search', fn () => response('OK'));
        foreach (['a', 'b', 'c', 'd', 'e', 'f'] as $column) {
            $this->get('/search?q=' . urlencode("' UNION SELECT {$column} FROM users--"))->assertStatus(200);
        }
        foreach (["' UNION/**/SELECT a FROM users--", "' Union Select a From users--", "' UNION%20SELECT a FROM users--", "' UNION\tSELECT a FROM users--"] as $variant) {
            $this->get('/search?q=' . urlencode($variant))->assertStatus(200);
        }

        $correlation = new ThreatCorrelationService;

        $this->assertNotEmpty($correlation->detectRetryBursts(60, 5));
        $this->assertIsArray($correlation->detectMutationChains(60, 2));
        $this->assertIsArray($correlation->detectPayloadClusters(60, 2, 1));

        $this->getJson(self::API . '/correlation?type=all')->assertStatus(200);
        $this->getJson(self::API . '/ai-threats')->assertStatus(200);
    }
}
