<?php

namespace JayAnta\ThreatDetection\Services;

class ProbeDetectorService
{
    /** @var array|null Exact paths for O(1) lookup */
    private static ?array $exactPaths = null;

    /** @var array|null Wildcard paths that need fnmatch */
    private static ?array $wildcardPaths = null;

    /**
     * Check if a request URI matches a known probe path.
     * Uses hash lookup for exact paths, fnmatch only for wildcards.
     *
     * @return array{label: string, level: string}|null
     */
    public function detect(string $uri): ?array
    {
        if (!config('threat-detection.probe_tracking.enabled', true)) {
            return null;
        }

        $this->buildPathIndex();

        $uri = '/' . ltrim($uri, '/');
        $uriLower = strtolower($uri);
        $level = config('threat-detection.probe_tracking.default_level', 'medium');

        // O(1) hash lookup for exact paths
        if (isset(self::$exactPaths[$uriLower])) {
            return ['label' => self::$exactPaths[$uriLower], 'level' => $level];
        }

        // fnmatch only for wildcard patterns
        foreach (self::$wildcardPaths as $pattern => $label) {
            if (fnmatch($pattern, $uri, FNM_CASEFOLD)) {
                return ['label' => $label, 'level' => $level];
            }
        }

        return null;
    }

    /**
     * Split paths into exact (hash) and wildcard (fnmatch) groups.
     * Cached as static for process lifetime.
     */
    private function buildPathIndex(): void
    {
        if (self::$exactPaths !== null) {
            return;
        }

        self::$exactPaths = [];
        self::$wildcardPaths = [];

        foreach (config('threat-detection.probe_tracking.paths', []) as $pattern => $label) {
            if (str_contains($pattern, '*') || str_contains($pattern, '?')) {
                self::$wildcardPaths[$pattern] = $label;
            } else {
                self::$exactPaths[strtolower($pattern)] = $label;
            }
        }
    }
}
