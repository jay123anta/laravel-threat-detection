<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * The README, UPGRADING.md and the v1.8.0 security advisory all offer
 * `THREAT_DETECTION_API=false` as the way to take the REST endpoints away
 * entirely. For an operator who cannot upgrade yet, it is the workaround that
 * closes the read path to stored credentials — so it has to actually work, and
 * until now nothing had run it.
 *
 * Routes are registered while the provider boots, which is why the setting is
 * applied in getEnvironmentSetUp() rather than in a test body, and why this
 * needs a class of its own.
 */
class ApiDisabledTest extends TestCase
{
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('threat-detection.api.enabled', false);
    }

    /** @return string[] */
    private function registeredApiUris(): array
    {
        $prefix = trim((string) config('threat-detection.api.prefix', 'api/threat-detection'), '/');

        $uris = [];
        foreach (Route::getRoutes() as $route) {
            if (str_starts_with($route->uri(), $prefix)) {
                $uris[] = $route->uri();
            }
        }

        return $uris;
    }

    #[Test]
    public function disabling_the_api_registers_none_of_its_routes(): void
    {
        $this->assertSame(
            [],
            $this->registeredApiUris(),
            'api.enabled=false left REST routes registered, so the documented workaround does not close the read path'
        );
    }

    /**
     * And from the outside: the endpoint that returns a full row, payload
     * included, is simply not there.
     */
    #[Test]
    public function the_endpoint_that_returns_a_stored_payload_is_gone(): void
    {
        $this->createThreatLogsTable();

        $this->getJson('/api/threat-detection/threats/1')->assertStatus(404);
        $this->getJson('/api/threat-detection/threats')->assertStatus(404);
    }
}
