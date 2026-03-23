<?php

namespace JayAnta\ThreatDetection\Services;

class ProbeDetectorService
{
    /**
     * Check if a request URI matches a known probe path.
     *
     * @return array{label: string, level: string}|null
     */
    public function detect(string $uri): ?array
    {
        if (!config('threat-detection.probe_tracking.enabled', true)) {
            return null;
        }

        $paths = config('threat-detection.probe_tracking.paths', []);
        $uri = '/' . ltrim($uri, '/');

        foreach ($paths as $pattern => $label) {
            if (fnmatch($pattern, $uri, FNM_CASEFOLD)) {
                return [
                    'label' => $label,
                    'level' => config('threat-detection.probe_tracking.default_level', 'medium'),
                ];
            }
        }

        return null;
    }
}
