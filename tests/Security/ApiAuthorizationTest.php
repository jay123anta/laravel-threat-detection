<?php

namespace JayAnta\ThreatDetection\Tests\Security;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * TD-007 — authorization on the threat-log API.
 *
 * Fifteen endpoints serve the collected attack log: which paths were probed,
 * which IPs, which payload types, and a full CSV of the lot. An endpoint that
 * escapes the middleware group is a complete disclosure of the security
 * posture of the application, to anyone.
 *
 * Each route is enumerated from the router rather than listed by hand, so an
 * endpoint added later is covered without editing this file.
 */
class ApiAuthorizationTest extends TestCase
{
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        // The guard has to exist before the provider registers routes.
        $app['config']->set('threat-detection.api.enabled', true);
        $app['config']->set('threat-detection.api.guard', 'role');
        $app['config']->set('threat-detection.api.role', 'admin');
        $app['config']->set('threat-detection.enabled', false);
        $app['config']->set('app.key', 'base64:' . base64_encode(random_bytes(32)));
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();
        config(['cache.default' => 'array']);
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    /**
     * Every route the package registers under the API prefix, taken from the
     * router at runtime.
     *
     * @return array<int, array{0: string, 1: string}> method, uri
     */
    private function packageApiRoutes(): array
    {
        $prefix = trim(config('threat-detection.api.prefix', 'api/threat-detection'), '/');
        $routes = [];

        foreach (Route::getRoutes() as $route) {
            if (!str_starts_with($route->uri(), $prefix)) {
                continue;
            }
            foreach ($route->methods() as $method) {
                if (in_array($method, ['HEAD', 'OPTIONS'], true)) {
                    continue;
                }
                $routes[] = [$method, $route->uri()];
            }
        }

        return $routes;
    }

    /** Substitute a concrete id for any route parameter. */
    private function concrete(string $uri): string
    {
        return '/' . preg_replace('/\{[^}]+\}/', '1', $uri);
    }

    #[Test]
    public function the_package_registers_exactly_the_endpoints_this_file_reasons_about(): void
    {
        $routes = $this->packageApiRoutes();

        $this->assertCount(15, $routes, 'the API surface changed: ' . json_encode($routes));
    }

    /**
     * The core assertion. Not one of the fifteen may answer an anonymous
     * caller once a guard is configured.
     */
    #[Test]
    public function no_endpoint_answers_an_unauthenticated_caller_when_a_guard_is_configured(): void
    {
        $reachable = [];

        foreach ($this->packageApiRoutes() as [$method, $uri]) {
            $response = $this->json($method, $this->concrete($uri));

            if ($response->getStatusCode() < 400) {
                $reachable[] = "{$method} {$uri} -> {$response->getStatusCode()}";
            }
        }

        $this->assertSame([], $reachable, 'endpoints reachable anonymously: ' . implode(', ', $reachable));
    }

    /**
     * ...and not to a user who is authenticated but does not hold the role.
     * "Logged in" is not "allowed to read the security log": on most
     * applications every customer is logged in.
     */
    #[Test]
    public function no_endpoint_answers_an_authenticated_user_without_the_role(): void
    {
        Auth::login(new ApiUser(['customer']));

        $reachable = [];

        foreach ($this->packageApiRoutes() as [$method, $uri]) {
            $response = $this->json($method, $this->concrete($uri));

            if ($response->getStatusCode() < 400) {
                $reachable[] = "{$method} {$uri} -> {$response->getStatusCode()}";
            }
        }

        $this->assertSame([], $reachable, 'endpoints reachable by a low-privilege user: ' . implode(', ', $reachable));
    }

    /**
     * A user model with no hasRole() at all cannot be checked, so it must be
     * refused rather than waved through.
     */
    #[Test]
    public function no_endpoint_answers_a_user_model_that_cannot_be_asked_about_roles(): void
    {
        Auth::login(new ApiUserWithoutRoles);

        $reachable = [];

        foreach ($this->packageApiRoutes() as [$method, $uri]) {
            if ($this->json($method, $this->concrete($uri))->getStatusCode() < 400) {
                $reachable[] = "{$method} {$uri}";
            }
        }

        $this->assertSame([], $reachable, 'reachable with an unqueryable user model: ' . implode(', ', $reachable));
    }

    /**
     * The negative control. With the role held, the read endpoints answer —
     * otherwise the three tests above would pass on a broken API.
     */
    #[Test]
    public function a_user_holding_the_role_can_read_the_log(): void
    {
        Auth::login(new ApiUser(['admin']));

        $this->getJson('/api/threat-detection/stats')->assertStatus(200);
        $this->getJson('/api/threat-detection/threats')->assertStatus(200);
    }

    // ── the write endpoints ────────────────────────────────────────────────

    /**
     * @return array<string, array{0: string, 1: string}>
     */
    public static function writeEndpoints(): array
    {
        return [
            'mark false positive' => ['POST', '/api/threat-detection/threats/1/false-positive'],
            'delete exclusion rule' => ['DELETE', '/api/threat-detection/exclusion-rules/1'],
        ];
    }

    /**
     * Writing here is not editing a record — it switches a detection off for
     * everyone. It is gated behind api.write_guard, which defaults to 'role'
     * independently of api.guard.
     */
    #[Test]
    #[DataProvider('writeEndpoints')]
    public function a_write_endpoint_refuses_a_reader_who_lacks_the_write_role(string $method, string $uri): void
    {
        Auth::login(new ApiUser(['customer']));

        $this->json($method, $uri)->assertStatus(403);
    }

    /*
     * TD-008 lives in CsrfOnWriteEndpointsTest. It was here first, driven
     * with Auth::login() inside the plain `api` group — which authenticates
     * without a session at all, so it demonstrated the missing middleware
     * but not the attack, and no session-aware fix could have made it pass.
     * Moved rather than kept, so there is one place that tests it and that
     * place uses real sessions.
     */

    // ── guard 'none' is the shipped default, and it is not "open" ──────────

    /**
     * api.guard defaults to 'none', which sounds alarming but is not the whole
     * story: api.middleware defaults to ['api', 'auth:sanctum'], so the
     * default posture is authenticated-but-unroled rather than public. Pinned
     * because a change to either default silently changes the other's meaning.
     */
    #[Test]
    public function the_shipped_defaults_put_the_api_behind_authentication(): void
    {
        $shipped = require __DIR__ . '/../../config/threat-detection.php';

        $this->assertSame('none', $shipped['api']['guard'], 'api.guard default changed');
        $this->assertContains('auth:sanctum', $shipped['api']['middleware'], 'the API default is no longer authenticated');
        $this->assertSame('role', $shipped['api']['write_guard'], 'api.write_guard no longer defaults to role');
    }
}
