<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Cache\ArrayStore;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * A cache outage must not blind the detector.
 *
 * Three cache calls sat on the request path unguarded — the exclusion rules,
 * the dedup check and the dedup mark. With the cache unreachable (Redis
 * restarting, a network partition) the first of them threw, the middleware's
 * catch swallowed it to stay passive, and no request was recorded until the
 * cache came back: an outage, or an attacker who could cause one, switched
 * detection off. The DDoS counter already survived exactly this.
 *
 * Without a cache the detector now does what it can: rules are read from the
 * database, and without dedup a repeated attack is recorded more than once,
 * which is the safe direction.
 */
class CacheOutageTest extends TestCase
{
    private const SQLI = "' UNION SELECT password FROM users--";

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
        ]);

        ThreatDetectionService::flushCaches();

        Route::middleware('threat-detect')->get('/search', fn () => response('OK'));
    }

    private function breakTheCache(): void
    {
        Cache::extend('unreachable', fn () => Cache::repository(new UnreachableStore));
        config(['cache.default' => 'unreachable', 'cache.stores.unreachable' => ['driver' => 'unreachable']]);
    }

    private function injectionsLogged(): int
    {
        return DB::table('threat_logs')->where('type', 'like', '%SQL Injection UNION%')->count();
    }

    #[Test]
    public function an_attack_is_still_recorded_while_the_cache_is_down(): void
    {
        $this->breakTheCache();

        $this->get('/search?q=' . urlencode(self::SQLI))->assertStatus(200);

        $this->assertGreaterThan(0, $this->injectionsLogged(), 'the cache outage switched detection off');
    }

    /** Exclusion rules still apply without a cache: they are read from the database. */
    #[Test]
    public function exclusion_rules_still_apply_while_the_cache_is_down(): void
    {
        DB::table('threat_exclusion_rules')->insert([
            'pattern_label' => 'SQL Injection UNION',
            'path_pattern' => 'search',
            'created_from_threat_id' => null,
            'is_active' => true,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        $this->breakTheCache();

        $this->get('/search?q=' . urlencode(self::SQLI))->assertStatus(200);

        $this->assertSame(0, $this->injectionsLogged(), 'an exclusion rule was ignored because the cache was down');
    }

    /**
     * The dedup mark is written after the row and before the alert, so an
     * unguarded failure there kept the row and lost the alert.
     */
    #[Test]
    public function the_alert_is_still_sent_while_the_cache_is_down(): void
    {
        Http::fake(['*' => Http::response('ok', 200)]);
        config([
            'threat-detection.notifications.enabled' => true,
            'threat-detection.notifications.notify_levels' => ['high'],
            'threat-detection.notifications.slack_webhook' => 'https://hooks.slack.example/services/T/B/X',
        ]);
        $this->breakTheCache();

        $this->get('/search?q=' . urlencode(self::SQLI))->assertStatus(200);

        Http::assertSent(fn ($request) => str_contains($request->url(), 'hooks.slack.example'));
    }

    /** Positive control: the stand-in really is unreachable. */
    #[Test]
    public function the_stand_in_cache_throws(): void
    {
        $this->breakTheCache();

        $this->expectException(\RuntimeException::class);

        Cache::get('anything');
    }
}

/** A cache store whose every operation fails, as an unreachable Redis does. */
class UnreachableStore extends ArrayStore
{
    public function get($key)
    {
        throw new \RuntimeException('Connection refused [tcp://127.0.0.1:6379]');
    }

    public function put($key, $value, $seconds)
    {
        throw new \RuntimeException('Connection refused [tcp://127.0.0.1:6379]');
    }

    public function increment($key, $value = 1)
    {
        throw new \RuntimeException('Connection refused [tcp://127.0.0.1:6379]');
    }

    public function forget($key)
    {
        throw new \RuntimeException('Connection refused [tcp://127.0.0.1:6379]');
    }
}
