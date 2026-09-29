<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * Who was signed in is metadata; it must not cost the row.
 *
 * Auth::id() is asked once per detecting request, and it runs the
 * application's guard — its user provider, its database. A guard that threw
 * sent the exception to the middleware's catch and the detection was lost,
 * the same way a cache, a queue, a listener or a log could lose it. The row is
 * now written with user_id null instead.
 */
class AuthFailureDuringDetectionTest extends TestCase
{
    private const SQLI = "' UNION SELECT password FROM users--";

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

    #[Test]
    public function a_failing_guard_does_not_lose_the_detection(): void
    {
        Auth::extend('failing', fn () => new FailingGuard);
        config(['auth.guards.failing' => ['driver' => 'failing'], 'auth.defaults.guard' => 'failing']);

        $this->get('/search?q=' . urlencode(self::SQLI))->assertStatus(200);

        $row = DB::table('threat_logs')->where('type', 'like', '%SQL Injection UNION%')->first();

        $this->assertNotNull($row, 'a failing auth guard lost the detection');
        $this->assertNull($row->user_id);
    }
}

/** A guard whose user lookup fails, as one does when its provider's database is down. */
class FailingGuard implements Guard
{
    public function check()
    {
        return $this->user() !== null;
    }

    public function guest()
    {
        return !$this->check();
    }

    public function user()
    {
        throw new \RuntimeException('SQLSTATE[HY000] [2002] Connection refused (users)');
    }

    public function id()
    {
        return $this->user()?->getAuthIdentifier();
    }

    public function validate(array $credentials = [])
    {
        return false;
    }

    public function hasUser()
    {
        return false;
    }

    public function setUser(Authenticatable $user)
    {
        return $this;
    }
}
