<?php

namespace JayAnta\ThreatDetection\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

/**
 * Dispatched when a client crosses the configured DDoS request threshold.
 *
 * Throttled to once per IP per dedup window (same throttle as the threat-log
 * row), so a flood cannot drown listeners in duplicate dispatches. Listeners
 * run inside the detection middleware's fail-open try/catch — never abort()
 * from a listener; to refuse over-threshold clients, consult
 * ThreatDetection::isDdosThresholdExceeded($ip) from your own middleware.
 */
class DdosThresholdExceeded
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public readonly string $ipAddress,
        public readonly int $requestCount,
        public readonly int $threshold,
        public readonly int $windowSeconds,
    ) {
    }
}
