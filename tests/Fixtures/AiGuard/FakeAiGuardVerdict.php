<?php

namespace JayAnta\ThreatDetection\Tests\Fixtures\AiGuard;

/**
 * Stands in for an ai-guard interop event.
 *
 * Deliberately not named after anything in ai-guard's namespace: the contract
 * is the set of public properties, not the class, and this test double proves
 * the listener reads it that way.
 */
final class FakeAiGuardVerdict
{
    public function __construct(
        public readonly string $schema,
        public readonly ?string $status,
        public readonly ?string $category,
        public readonly ?string $identity,
        public readonly string $ip,
    ) {}
}
