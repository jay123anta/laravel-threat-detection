<?php

namespace JayAnta\ThreatDetection\Services;

use JayAnta\ThreatDetection\Support\LogsQuietly;

class ProbeDetectorService
{
    use LogsQuietly;

    /** @var array<string, array{label: string, level: string|null}>|null Exact paths for O(1) lookup */
    private static ?array $exactPaths = null;

    /** @var array<string, array{label: string, level: string|null, pack?: string}>|null Wildcard paths that need fnmatch */
    private static ?array $wildcardPaths = null;

    /** Marks entries that came from the AI-infrastructure pack. */
    public const AI_PACK = 'ai_infrastructure';

    /**
     * @param  array{label: string, level: string|null, pack?: string}  $entry
     * @return array{label: string, level: string, pack?: string}
     */
    private function result(array $entry, string $default): array
    {
        $result = ['label' => $entry['label'], 'level' => $entry['level'] ?? $default];

        // Only for pack entries, so the general list's result keeps the exact
        // shape it has always had.
        if (isset($entry['pack'])) {
            $result['pack'] = $entry['pack'];
        }

        return $result;
    }

    /**
     * Check if a request URI matches a known probe path.
     * Uses hash lookup for exact paths, fnmatch only for wildcards.
     *
     * `pack` is present only on entries from the AI-infrastructure pack.
     *
     * @return array{label: string, level: string, pack?: string}|null
     */
    public function detect(string $uri): ?array
    {
        if (!config('threat-detection.probe_tracking.enabled', true)) {
            return null;
        }

        $this->buildPathIndex();

        $uri = '/' . ltrim($uri, '/');
        $uriLower = strtolower($uri);
        $default = self::level(config('threat-detection.probe_tracking.default_level', 'medium'), 'default_level') ?? 'medium';

        // O(1) hash lookup for exact paths
        if (isset(self::$exactPaths[$uriLower])) {
            return $this->result(self::$exactPaths[$uriLower], $default);
        }

        // fnmatch only for wildcard patterns
        foreach (self::$wildcardPaths as $pattern => $entry) {
            if (fnmatch($pattern, $uri, FNM_CASEFOLD)) {
                return $this->result($entry, $default);
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

        foreach ($this->configuredPaths() as $pattern => $definition) {
            $entry = $this->normaliseDefinition($definition);

            if ($entry === null) {
                continue;
            }

            if (str_contains($pattern, '*') || str_contains($pattern, '?')) {
                self::$wildcardPaths[$pattern] = $entry;
            } else {
                self::$exactPaths[strtolower($pattern)] = $entry;
            }
        }
    }

    /**
     * The shipped path list, plus the AI-infrastructure pack when it is turned on.
     *
     * The pack is opt-in and off by default, like every other capability added
     * after 1.8.0: switching it on is the only thing that changes what an
     * existing install reports.
     *
     * A path appearing in both lists keeps its entry from `paths`, so an
     * operator who has already classified one of these endpoints for their own
     * app is not overridden by the pack.
     *
     * @return array<string, mixed>
     */
    private function configuredPaths(): array
    {
        $paths = (array) config('threat-detection.probe_tracking.paths', []);

        if (!config('threat-detection.probe_tracking.ai_infrastructure.enabled', false)) {
            return $paths;
        }

        $packLevel = self::level(config('threat-detection.probe_tracking.ai_infrastructure.level'), 'ai_infrastructure.level');
        $pack = [];

        foreach ((array) config('threat-detection.probe_tracking.ai_infrastructure.paths', []) as $pattern => $definition) {
            $entry = $this->normaliseDefinition($definition);

            if ($entry === null) {
                continue;
            }

            // A level on the individual entry wins; otherwise the pack-wide
            // level; otherwise the global default, applied at lookup time.
            $pack[$pattern] = ['label' => $entry['label'], 'level' => $entry['level'] ?? $packLevel, 'pack' => self::AI_PACK];
        }

        // Union, not array_merge: `+` keeps the LEFT side on a key collision,
        // so an operator's own entry for a path wins over the pack's.
        return $paths + $pack;
    }

    /**
     * Accept either spelling of a path definition:
     *
     *     '/wp-admin' => 'WordPress Admin'
     *     '/api/pull' => ['label' => 'Ollama Model Pull', 'level' => 'high']
     *
     * The string form has shipped since 1.3.0 and stays the common case; the
     * array form exists because a single `default_level` cannot be right for
     * both a WordPress login page and an endpoint that is only ever reached by
     * someone exploiting a known RCE.
     *
     * @return array{label: string, level: string|null, pack?: string}|null
     */
    private function normaliseDefinition(mixed $definition): ?array
    {
        if (is_string($definition)) {
            $label = trim($definition);

            return $label === '' ? null : ['label' => $label, 'level' => null];
        }

        if (!is_array($definition)) {
            return null;
        }

        $label = isset($definition['label']) && is_string($definition['label'])
            ? trim($definition['label'])
            : '';

        if ($label === '') {
            return null;
        }

        $normalised = ['label' => $label, 'level' => self::level($definition['level'] ?? null, "'{$label}'")];

        if (isset($definition['pack']) && is_string($definition['pack'])) {
            $normalised['pack'] = $definition['pack'];
        }

        return $normalised;
    }

    /**
     * Drop the memoised path index so a runtime change to
     * probe_tracking.paths takes effect (tests, Octane reloads).
     */
    /** @var array<string, true> Unusable levels already reported */
    private static array $levelWarned = [];

    /**
     * A severity the rest of the package reads — high, medium or low, in
     * lower case — or null so the caller falls back to the next one along.
     *
     * Everything downstream speaks those three words, and on PostgreSQL and
     * SQLite compares them case-sensitively: a probe stored as 'High' or
     * 'hgih' was recorded but counted as nothing and never alerted.
     */
    private static function level(mixed $configured, string $where): ?string
    {
        if ($configured === null || (is_string($configured) && trim($configured) === '')) {
            return null;
        }

        $level = is_string($configured) ? strtolower(trim($configured)) : '';

        if (in_array($level, ['high', 'medium', 'low'], true)) {
            return $level;
        }

        $shown = is_scalar($configured) ? (string) $configured : get_debug_type($configured);

        if (!isset(self::$levelWarned[$where . '|' . $shown])) {
            self::$levelWarned[$where . '|' . $shown] = true;
            self::logQuietly('warning', "Threat detection: probe level '{$shown}' for {$where} is not high, medium or low; using the fallback.");
        }

        return null;
    }

    public static function flushCaches(): void
    {
        self::$exactPaths = null;
        self::$wildcardPaths = null;
        self::$levelWarned = [];
    }
}
