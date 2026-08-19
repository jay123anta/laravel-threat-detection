<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * Phase 7 v1.3.0: Full-cycle tests for dashboard auth guard.
 *
 * Tests four guard modes (none, auth, role, ip) for dashboard
 * and API routes. Uses minimal middleware to avoid encryption issues.
 */
class DashboardAuthGuardTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config([
            'cache.default' => 'array',
            'app.key' => 'base64:' . base64_encode(str_repeat('a', 32)),
        ]);

        // Register test routes with only the auth middleware (no full web stack)
        Route::middleware(['threat-dashboard-auth:dashboard'])
            ->get('/test-dashboard', fn () => response('Dashboard OK', 200));

        Route::middleware(['threat-dashboard-auth:api'])
            ->get('/test-api-endpoint', fn () => response('API OK', 200));
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    // ────────────────────────────────────────────
    //  Guard: none (default)
    // ────────────────────────────────────────────

    #[Test]
    public function dashboard_accessible_when_guard_is_none(): void
    {
        config(['threat-detection.dashboard.guard' => 'none']);

        $this->get('/test-dashboard')->assertStatus(200);
    }

    #[Test]
    public function dashboard_logs_warning_when_guard_is_none(): void
    {
        config(['threat-detection.dashboard.guard' => 'none']);

        Log::spy();

        $this->get('/test-dashboard');

        Log::shouldHaveReceived('warning')
            ->withArgs(fn ($msg) => str_contains($msg, 'without authentication'))
            ->once();
    }

    #[Test]
    public function api_accessible_when_guard_is_none(): void
    {
        config(['threat-detection.api.guard' => 'none']);

        $this->get('/test-api-endpoint')->assertStatus(200);
    }

    // ────────────────────────────────────────────
    //  Guard: auth
    // ────────────────────────────────────────────

    #[Test]
    public function dashboard_blocked_when_guard_is_auth_and_not_logged_in(): void
    {
        config(['threat-detection.dashboard.guard' => 'auth']);

        $this->get('/test-dashboard')->assertStatus(403);
    }

    #[Test]
    public function dashboard_accessible_when_guard_is_auth_and_logged_in(): void
    {
        config(['threat-detection.dashboard.guard' => 'auth']);

        $user = new User;
        $user->id = 1;

        $this->actingAs($user)
            ->get('/test-dashboard')
            ->assertStatus(200);
    }

    #[Test]
    public function api_blocked_when_guard_is_auth_and_not_logged_in(): void
    {
        config(['threat-detection.api.guard' => 'auth']);

        $this->get('/test-api-endpoint')->assertStatus(403);
    }

    #[Test]
    public function api_accessible_when_guard_is_auth_and_logged_in(): void
    {
        config(['threat-detection.api.guard' => 'auth']);

        $user = new User;
        $user->id = 1;

        $this->actingAs($user)
            ->get('/test-api-endpoint')
            ->assertStatus(200);
    }

    // ────────────────────────────────────────────
    //  Guard: ip
    // ────────────────────────────────────────────

    #[Test]
    public function dashboard_blocked_when_guard_is_ip_and_wrong_ip(): void
    {
        config([
            'threat-detection.dashboard.guard' => 'ip',
            'threat-detection.dashboard.allowed_ips' => ['192.168.1.100'],
        ]);

        // Test request comes from 127.0.0.1, not 192.168.1.100
        $this->get('/test-dashboard')->assertStatus(403);
    }

    #[Test]
    public function dashboard_accessible_when_guard_is_ip_and_correct_ip(): void
    {
        config([
            'threat-detection.dashboard.guard' => 'ip',
            'threat-detection.dashboard.allowed_ips' => ['127.0.0.1'],
        ]);

        $this->get('/test-dashboard')->assertStatus(200);
    }

    #[Test]
    public function api_blocked_when_guard_is_ip_and_wrong_ip(): void
    {
        config([
            'threat-detection.api.guard' => 'ip',
            'threat-detection.api.allowed_ips' => ['10.0.0.1'],
        ]);

        $this->get('/test-api-endpoint')->assertStatus(403);
    }

    // ────────────────────────────────────────────
    //  Guard: role
    // ────────────────────────────────────────────

    #[Test]
    public function dashboard_blocked_when_guard_is_role_and_not_logged_in(): void
    {
        config(['threat-detection.dashboard.guard' => 'role']);

        $this->get('/test-dashboard')->assertStatus(403);
    }

    #[Test]
    public function dashboard_accessible_when_guard_is_role_and_user_has_role(): void
    {
        config([
            'threat-detection.dashboard.guard' => 'role',
            'threat-detection.dashboard.role' => 'admin',
        ]);

        // Create a user mock with hasRole method
        $user = new class extends User
        {
            public $id = 1;

            public function hasRole(string $role): bool
            {
                return $role === 'admin';
            }
        };

        $this->actingAs($user)
            ->get('/test-dashboard')
            ->assertStatus(200);
    }

    #[Test]
    public function dashboard_blocked_when_guard_is_role_and_user_lacks_role(): void
    {
        config([
            'threat-detection.dashboard.guard' => 'role',
            'threat-detection.dashboard.role' => 'admin',
        ]);

        $user = new class extends User
        {
            public $id = 2;

            public function hasRole(string $role): bool
            {
                return false;
            }
        };

        $this->actingAs($user)
            ->get('/test-dashboard')
            ->assertStatus(403);
    }

    #[Test]
    public function ip_guard_with_empty_allowlist_denies_access(): void
    {
        config([
            'threat-detection.dashboard.guard' => 'ip',
            'threat-detection.dashboard.allowed_ips' => [],
        ]);

        $this->get('/test-dashboard')->assertForbidden();
    }
}
