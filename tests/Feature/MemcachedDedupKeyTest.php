<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Cache\ArrayStore;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * Memcached's text protocol refuses a key that contains whitespace or runs
 * past 250 bytes, and the client reports it only as a failed call.
 *
 * The five-minute dedup mark was keyed `threat_logged:{ip}:{type}`, and every
 * type contains a space — "[query] SQL Injection UNION". On memcached, one of
 * the two drivers `doctor` recommends, every read and write of the mark
 * failed, dedup never engaged, and each attacking request wrote its own row
 * and sent its own alert.
 *
 * No memcached server runs here. The `memcached` driver name is bound to an
 * array store that enforces the protocol's key rules, which is the part that
 * matters.
 */
class MemcachedDedupKeyTest extends TestCase
{
    private const SQLI = "' UNION SELECT password FROM users--";

    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();

        Cache::extend('memcached', fn () => Cache::repository(new MemcachedKeyRulesStore));

        config([
            'cache.default' => 'memcached',
            'cache.stores.memcached' => ['driver' => 'memcached'],
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
            'threat-detection.ddos.threshold' => 100000,
        ]);

        ThreatDetectionService::flushCaches();

        Route::middleware('threat-detect')->get('/search', fn () => response('OK'));
    }

    private function rows(): int
    {
        return DB::table('threat_logs')->where('type', 'like', '%SQL Injection UNION%')->count();
    }

    #[Test]
    public function a_repeated_attack_is_recorded_once_per_window_on_memcached(): void
    {
        foreach (range(1, 5) as $ignored) {
            $this->get('/search?q=' . urlencode(self::SQLI))->assertStatus(200);
        }

        $this->assertSame(1, $this->rows(), 'dedup never engaged on memcached: one row per request');
    }

    /** Positive control: the store really does refuse a key with a space. */
    #[Test]
    public function the_stand_in_refuses_what_memcached_refuses(): void
    {
        $this->assertFalse(Cache::put('has a space', true, 60));
        $this->assertTrue(Cache::put('no_space', true, 60));
    }

    /** Other stores keep the readable key they have always had. */
    #[Test]
    public function other_stores_keep_the_readable_key(): void
    {
        config(['cache.default' => 'array']);

        $this->get('/search?q=' . urlencode(self::SQLI))->assertStatus(200);

        $this->assertTrue(Cache::has('threat_logged:127.0.0.1:[middleware] SQL Injection UNION'));
    }
}

/** An array store with memcached's key rules: no whitespace or controls, at most 250 bytes. */
class MemcachedKeyRulesStore extends ArrayStore
{
    private function acceptable($key): bool
    {
        return strlen((string) $key) <= 250 && !preg_match('/[\x00-\x20\x7F]/', (string) $key);
    }

    public function get($key)
    {
        return $this->acceptable($key) ? parent::get($key) : null;
    }

    public function put($key, $value, $seconds)
    {
        return $this->acceptable($key) && parent::put($key, $value, $seconds);
    }

    public function increment($key, $value = 1)
    {
        return $this->acceptable($key) ? parent::increment($key, $value) : false;
    }

    public function forget($key)
    {
        return $this->acceptable($key) && parent::forget($key);
    }
}
