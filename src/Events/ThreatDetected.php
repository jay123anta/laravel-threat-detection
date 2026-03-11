<?php

namespace JayAnta\ThreatDetection\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class ThreatDetected
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public readonly array $threatLog,
        public readonly ?string $ipAddress = null,
        public readonly ?string $threatLevel = null,
    ) {
    }
}
