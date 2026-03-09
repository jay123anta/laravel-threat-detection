<?php

namespace JayAnta\ThreatDetection\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static void detectAndLogFromRequest(\Illuminate\Http\Request $request)
 * @method static array detectThreatPatterns(string $payload, string $source = 'default', bool $isAuthPath = false)
 * @method static array detectThreatPatternsWithContext(array $segments, string $source = 'default', bool $isAuthPath = false)
 * @method static array getDefaultThreatPatterns()
 * @method static array getIpStatistics(string $ip)
 * @method static array detectCoordinatedAttacks(int $timeWindowMinutes = 15, int $minIpCount = 3)
 * @method static array detectAttackCampaigns(int $hoursBack = 24)
 * @method static array detectRapidAttacks(int $minutesBack = 5, int $minThreshold = 10)
 * @method static array getCorrelationSummary()
 *
 * @see \JayAnta\ThreatDetection\Services\ThreatDetectionService
 */
class ThreatDetection extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'threat-detection';
    }
}
