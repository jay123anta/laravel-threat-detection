<?php

namespace JayAnta\ThreatDetection\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Schema;
use JayAnta\ThreatDetection\Http\Middleware\ThreatDetectionMiddleware;

/**
 * Checks that threat detection is actually working, not merely installed.
 *
 * Every check here corresponds to a way this package has been observed to fail
 * silently on a real application: a table that predates a migration, a config
 * published two versions ago that shadows the pattern fixes shipped since, a
 * middleware that was never wired into a group. None of them raise an error a
 * user would notice — the dashboard just stays empty, which reads as "no
 * attacks" rather than "nothing is being recorded".
 */
class DoctorCommand extends Command
{
    protected $signature = 'threat-detection:doctor';

    protected $description = 'Check that threat detection is installed, wired up and recording';

    /** Columns the detection writer inserts. Missing any one discards every threat. */
    private const WRITE_COLUMNS = [
        'ip_address', 'url', 'user_agent', 'type', 'payload', 'threat_level',
        'confidence_score', 'confidence_label', 'user_id', 'created_at', 'updated_at',
    ];

    /** Columns the dashboard and API select. Missing any one breaks those, not detection. */
    private const READ_COLUMNS = [
        'is_false_positive', 'action_taken', 'country_code', 'country_name',
        'cloud_provider', 'is_cloud_ip', 'is_foreign',
    ];

    private int $failures = 0;
    private int $warnings = 0;

    public function handle(): int
    {
        $this->newLine();
        $this->line('  <fg=white;options=bold>Threat Detection — health check</>');
        $this->newLine();

        $this->checkEnabled();
        $this->checkWriteSchema();
        $this->checkReadSchema();
        $this->checkExclusionTable();
        $this->checkMiddleware();
        $this->checkConfigDrift();
        $this->checkShadowedPatterns();
        $this->checkCacheDriver();
        $this->checkDashboardExposure();

        return $this->summarise();
    }

    // ── checks ──────────────────────────────────────────────────────────────

    private function checkEnabled(): void
    {
        if (!config('threat-detection.enabled', true)) {
            $this->fail('Detection is disabled', 'Set THREAT_DETECTION_ENABLED=true in your .env.');

            return;
        }

        $envs = config('threat-detection.enabled_environments');
        $current = $this->laravel->environment();

        if (!empty($envs) && !in_array($current, $envs, true)) {
            $this->fail(
                "Detection is off in this environment ('{$current}')",
                "Add '{$current}' to enabled_environments, or set it to null to run everywhere."
            );

            return;
        }

        $this->pass('Detection is enabled for this environment');
    }

    private function checkWriteSchema(): void
    {
        $table = config('threat-detection.table_name', 'threat_logs');

        if (!$this->tableExists($table)) {
            $this->fail(
                "The '{$table}' table does not exist — nothing can be recorded",
                $this->migrateHint()
            );

            return;
        }

        $missing = array_diff(self::WRITE_COLUMNS, Schema::getColumnListing($table));

        if ($missing !== []) {
            $this->fail(
                "'{$table}' is missing " . implode(', ', $missing) . ' — EVERY threat is being discarded',
                $this->migrateHint()
            );

            return;
        }

        $this->pass("'{$table}' has every column the writer needs");
    }

    private function checkReadSchema(): void
    {
        $table = config('threat-detection.table_name', 'threat_logs');

        if (!$this->tableExists($table)) {
            return;
        }

        $missing = array_diff(self::READ_COLUMNS, Schema::getColumnListing($table));

        if ($missing !== []) {
            $this->warn2(
                "'{$table}' is missing " . implode(', ', $missing) . ' — the dashboard and API will error',
                $this->migrateHint()
            );

            return;
        }

        $this->pass('Dashboard and API columns are present');
    }

    private function checkExclusionTable(): void
    {
        if (!$this->tableExists('threat_exclusion_rules')) {
            $this->warn2(
                "No 'threat_exclusion_rules' table — marking a threat as a false positive will fail",
                $this->migrateHint()
            );

            return;
        }

        $this->pass('False-positive exclusion rules table is present');
    }

    private function checkMiddleware(): void
    {
        if (!$this->middlewareIsActive()) {
            $this->fail(
                'The detection middleware is not applied to any route — no request is being scanned',
                "Add \\JayAnta\\ThreatDetection\\Http\\Middleware\\ThreatDetectionMiddleware::class to your 'web'"
                . " and 'api' middleware groups, or apply the 'threat-detect' alias to specific routes."
            );

            return;
        }

        $this->pass('Detection middleware is wired up');
    }

    /**
     * mergeConfigFrom merges top-level keys only, and a published file wins
     * outright for every key it defines. A config published before a feature
     * existed silently keeps the old behaviour for that key.
     */
    private function checkConfigDrift(): void
    {
        $published = config_path('threat-detection.php');

        if (!file_exists($published)) {
            $this->pass('Using package config defaults (nothing published)');

            return;
        }

        $theirs = @include $published;
        $ours = @include __DIR__ . '/../../../config/threat-detection.php';

        if (!is_array($theirs) || !is_array($ours)) {
            $this->warn2('Could not read the published config for comparison', 'Check ' . $published . ' returns an array.');

            return;
        }

        $missing = array_diff(array_keys($ours), array_keys($theirs));
        $obsolete = array_diff(array_keys($theirs), array_keys($ours));

        if ($missing === [] && $obsolete === []) {
            $this->pass('Published config matches this version');

            return;
        }

        if ($missing !== []) {
            $this->warn2(
                'Published config predates ' . count($missing) . ' option(s): ' . implode(', ', $missing),
                'Those run on package defaults. Re-publish with --force after backing up, or hand-merge.'
            );
        }

        if ($obsolete !== []) {
            $this->warn2(
                'Published config defines ' . count($obsolete) . ' option(s) this version ignores: ' . implode(', ', $obsolete),
                'Harmless, but a sign the file is old — see the note above.'
            );
        }
    }

    /**
     * The specific, dangerous form of config drift: a published custom pattern
     * whose label matches a built-in one. The published copy wins, so pattern
     * fixes shipped since publication never take effect. This is how the
     * v1.3.1 "Chrome/120.0.0.0 logged as SSRF" false positive came back on a
     * live app long after it was fixed.
     */
    private function checkShadowedPatterns(): void
    {
        $service = $this->laravel->make(\JayAnta\ThreatDetection\Services\ThreatDetectionService::class);

        $builtIn = array_flip($service->getDefaultThreatPatterns());
        $shadowed = [];

        foreach ((array) config('threat-detection.custom_patterns', []) as $regex => $entry) {
            $label = is_array($entry) ? ($entry['label'] ?? null) : $entry;

            if (is_string($label) && isset($builtIn[$label]) && $regex !== $builtIn[$label]) {
                $shadowed[] = $label;
            }
        }

        if ($shadowed === []) {
            $this->pass('No custom pattern shadows a built-in one');

            return;
        }

        $this->warn2(
            count($shadowed) . ' custom pattern(s) shadow a built-in: ' . implode(', ', array_unique($shadowed)),
            'Your copy runs instead of the maintained one, so later fixes to it never reach you. '
            . 'Delete these from custom_patterns unless you meant to override them.'
        );
    }

    private function checkCacheDriver(): void
    {
        $driver = config('cache.default');

        if (in_array($driver, ['file', 'database', 'null'], true)) {
            $this->warn2(
                "DDoS detection is off — cache driver '{$driver}' has no atomic increment",
                'Switch CACHE_DRIVER to redis or memcached. Pattern detection is unaffected.'
            );

            return;
        }

        $this->pass("Cache driver '{$driver}' supports DDoS counting");
    }

    private function checkDashboardExposure(): void
    {
        foreach (['dashboard', 'api'] as $surface) {
            if (!config("threat-detection.{$surface}.enabled", $surface === 'api')) {
                continue;
            }

            $guard = config("threat-detection.{$surface}.guard", 'none');
            $middleware = (array) config("threat-detection.{$surface}.middleware", []);

            $authed = $guard !== 'none' || array_filter(
                $middleware,
                fn($m) => is_string($m) && str_starts_with($m, 'auth')
            );

            if ($authed) {
                $this->pass(ucfirst($surface) . ' is behind authentication');

                continue;
            }

            $message = ucfirst($surface) . ' is enabled with no authentication — your threat data is public';
            $fix = "Set THREAT_DETECTION_" . strtoupper($surface) . "_GUARD to auth, role or ip,"
                . " or add an auth middleware to threat-detection.{$surface}.middleware.";

            $this->laravel->environment('production')
                ? $this->fail($message, $fix)
                : $this->warn2($message, $fix);
        }
    }

    // ── output ──────────────────────────────────────────────────────────────

    private function pass(string $title): void
    {
        $this->line("  <fg=green>PASS</>  {$title}");
    }

    private function warn2(string $title, string $fix): void
    {
        $this->warnings++;
        $this->line("  <fg=yellow>WARN</>  {$title}");
        $this->line("        <fg=gray>{$fix}</>");
    }

    private function fail(string $title, string $fix): void
    {
        $this->failures++;
        $this->line("  <fg=red>FAIL</>  {$title}");
        $this->line("        <fg=gray>{$fix}</>");
    }

    private function summarise(): int
    {
        $this->newLine();

        if ($this->failures > 0) {
            $this->line("  <fg=red;options=bold>{$this->failures} failure(s)</> and {$this->warnings} warning(s). "
                . 'Detection is not working correctly.');
            $this->newLine();

            return self::FAILURE;
        }

        if ($this->warnings > 0) {
            $this->line("  <fg=yellow;options=bold>{$this->warnings} warning(s)</>, no failures. Detection is recording.");
            $this->newLine();

            return self::SUCCESS;
        }

        $this->line('  <fg=green;options=bold>All checks passed.</>');
        $this->newLine();

        return self::SUCCESS;
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    private function migrateHint(): string
    {
        return 'Run: php artisan vendor:publish --tag=threat-detection-migrations && php artisan migrate';
    }

    private function tableExists(string $table): bool
    {
        try {
            return Schema::hasTable($table);
        } catch (\Throwable $e) {
            return false;
        }
    }

    private function middlewareIsActive(): bool
    {
        $needles = [ThreatDetectionMiddleware::class, 'threat-detect'];

        try {
            $kernel = $this->laravel->make(\Illuminate\Contracts\Http\Kernel::class);

            if (method_exists($kernel, 'getGlobalMiddleware')) {
                foreach ($kernel->getGlobalMiddleware() as $m) {
                    if (in_array($m, $needles, true)) {
                        return true;
                    }
                }
            }

            if (method_exists($kernel, 'getMiddlewareGroups')) {
                foreach ($kernel->getMiddlewareGroups() as $group) {
                    foreach ((array) $group as $m) {
                        if (in_array($m, $needles, true)) {
                            return true;
                        }
                    }
                }
            }
        } catch (\Throwable $e) {
            // Fall through to the route scan.
        }

        try {
            foreach ($this->laravel->make('router')->getRoutes() as $route) {
                foreach ($route->gatherMiddleware() as $m) {
                    if (is_string($m) && (in_array($m, $needles, true) || str_starts_with($m, 'threat-detect'))) {
                        return true;
                    }
                }
            }
        } catch (\Throwable $e) {
            // Nothing else to try.
        }

        return false;
    }
}
