<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * An id that is not a number is a route that does not exist.
 *
 * The {id} routes had no constraint and the controller types the parameter
 * as int, so `/threats/abc` reached the action and failed with a TypeError
 * before its own error handling ran: a 500, and an error in the log for every
 * probe of the API. The router now answers 404.
 */
class RouteIdConstraintTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();

        config(['threat-detection.api.guard' => 'none', 'threat-detection.api.write_guard' => 'none']);
    }

    public static function routes(): array
    {
        return [
            'show' => ['GET', '/api/threat-detection/threats/%s'],
            'mark false positive' => ['POST', '/api/threat-detection/threats/%s/false-positive'],
            'delete exclusion rule' => ['DELETE', '/api/threat-detection/exclusion-rules/%s'],
        ];
    }

    #[Test]
    #[DataProvider('routes')]
    public function a_non_numeric_id_is_not_found(string $method, string $uri): void
    {
        $this->json($method, sprintf($uri, 'abc'))->assertStatus(404);
    }

    /** Positive control: a numeric id still reaches the action, which reports its own 404. */
    #[Test]
    #[DataProvider('routes')]
    public function a_numeric_id_still_reaches_the_action(string $method, string $uri): void
    {
        $this->json($method, sprintf($uri, '999'))
            ->assertStatus(404)
            ->assertJson(['success' => false]);
    }
}
