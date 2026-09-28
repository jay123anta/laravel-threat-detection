<?php

namespace JayAnta\ThreatDetection\Console\Commands;

use Composer\InstalledVersions;
use Illuminate\Console\Command;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Support\Facades\Schema;
use JayAnta\ThreatDetection\Http\Middleware\ThreatDetectionMiddleware;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;

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

        $this->checkFrameworkSupport();
        $this->checkEnabled();
        $this->checkWriteSchema();
        $this->checkReadSchema();
        $this->checkExclusionTable();
        $this->checkMiddleware();
        $this->checkConfigDrift();
        $this->checkOptInFeatures();
        $this->checkShadowedPatterns();
        $this->checkCacheDriver();
        $this->checkHttpClient();
        $this->checkDashboardExposure();
        $this->checkProxyTrust();
        $this->checkRetention();

        return $this->summarise();
    }

    // ── checks ──────────────────────────────────────────────────────────────

    /**
     * Laravel majors that no longer receive security patches.
     *
     * Under-reporting is the safe direction here: a major missing from this
     * list is simply not flagged. Extend it as releases age.
     */
    private const EOL_LARAVEL_MAJORS = [9, 10, 11];

    /**
     * An intrusion detector that notices the framework underneath it is
     * unpatched and says nothing is failing at its job.
     *
     * This package still supports and tests Laravel 10 and 11, because the
     * people stuck on an old framework are the ones who need detection most,
     * and dropping them would reduce protection rather than add any. But
     * running detection on an unpatched framework is treating the symptom:
     * upgrading closes whole classes of vulnerability that no amount of
     * request scanning can.
     */
    private function checkFrameworkSupport(): void
    {
        $version = $this->laravel->version();
        $major = (int) $version;

        if (in_array($major, self::EOL_LARAVEL_MAJORS, true)) {
            $this->reportWarning(
                "Laravel {$version} no longer receives security patches",
                'This package runs fine on it and is tested against it, but the framework '
                . 'beneath it is unpatched. Upgrading is worth more than anything this '
                . 'package can detect for you. Check with: composer audit'
            );

            return;
        }

        $this->reportPass("Laravel {$version} is a supported release");
    }

    private function checkEnabled(): void
    {
        if (!config('threat-detection.enabled', true)) {
            $this->reportFailure('Detection is disabled', 'Set THREAT_DETECTION_ENABLED=true in your .env.');

            return;
        }

        $envs = config('threat-detection.enabled_environments');
        $current = $this->laravel->environment();

        if (!empty($envs) && !in_array($current, $envs, true)) {
            $this->reportFailure(
                "Detection is off in this environment ('{$current}')",
                "Add '{$current}' to enabled_environments, or set it to null to run everywhere."
            );

            return;
        }

        $this->reportPass('Detection is enabled for this environment');
    }

    private function checkWriteSchema(): void
    {
        $table = config('threat-detection.table_name', 'threat_logs');

        if (!$this->tableExists($table)) {
            $this->reportFailure(
                "The '{$table}' table does not exist — nothing can be recorded",
                $this->migrateHint()
            );

            return;
        }

        $missing = $this->missingColumns($table, self::WRITE_COLUMNS);

        if ($missing !== []) {
            $this->reportFailure(
                "'{$table}' is missing " . implode(', ', $missing) . ' — EVERY threat is being discarded',
                $this->migrateHint()
            );

            return;
        }

        $this->reportPass("'{$table}' has every column the writer needs");
    }

    private function checkReadSchema(): void
    {
        $table = config('threat-detection.table_name', 'threat_logs');

        if (!$this->tableExists($table)) {
            return;
        }

        $missing = $this->missingColumns($table, self::READ_COLUMNS);

        if ($missing !== []) {
            $this->reportWarning(
                "'{$table}' is missing " . implode(', ', $missing) . ' — the dashboard and API will error',
                $this->migrateHint()
            );

            return;
        }

        $this->reportPass('Dashboard and API columns are present');
    }

    private function checkExclusionTable(): void
    {
        if (!$this->tableExists('threat_exclusion_rules')) {
            $this->reportWarning(
                "No 'threat_exclusion_rules' table — marking a threat as a false positive will fail",
                $this->migrateHint()
            );

            return;
        }

        $this->reportPass('False-positive exclusion rules table is present');
    }

    private function checkMiddleware(): void
    {
        if (!$this->middlewareIsActive()) {
            $this->reportFailure(
                'The detection middleware is not applied to any route — no request is being scanned',
                "Add \\JayAnta\\ThreatDetection\\Http\\Middleware\\ThreatDetectionMiddleware::class to your 'web'"
                . " and 'api' middleware groups, or apply the 'threat-detect' alias to specific routes."
            );

            return;
        }

        $this->reportPass('Detection middleware is wired up');
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
            $this->reportPass('Using package config defaults (nothing published)');

            return;
        }

        $theirs = @include $published;
        $ours = @include __DIR__ . '/../../../config/threat-detection.php';

        if (!is_array($theirs) || !is_array($ours)) {
            $this->reportWarning('Could not read the published config for comparison', 'Check ' . $published . ' returns an array.');

            return;
        }

        $missing = $this->missingOptions($ours, $theirs);
        $obsolete = array_diff(array_keys($theirs), array_keys($ours));

        if ($missing === [] && $obsolete === []) {
            $this->reportPass('Published config matches this version');

            return;
        }

        if ($missing !== []) {
            $this->reportWarning(
                'Published config predates ' . count($missing) . ' option(s): ' . implode(', ', $missing),
                'Those run on package defaults. Re-publish with --force after backing up, or hand-merge.'
            );
        }

        if ($obsolete !== []) {
            $this->reportWarning(
                'Published config defines ' . count($obsolete) . ' option(s) this version ignores: ' . implode(', ', $obsolete),
                'Harmless, but a sign the file is old — see the note above.'
            );
        }
    }

    /**
     * Options this version defines that the published file lacks, at any
     * depth.
     *
     * Top-level keys alone missed the case that matters most: an option added
     * *inside* a block the published file already has. That is how
     * probe_tracking.ai_infrastructure went missing on every install with a
     * published config — and this check, comparing top-level keys, reported
     * the file as current.
     *
     * Recurses only into blocks of named options. A map of data — probe
     * paths, patterns, labels — is the operator's content, and a missing
     * entry there is a choice, not drift.
     *
     * @param  array<mixed>  $ours
     * @param  array<mixed>  $theirs
     * @return array<int, string>
     */
    private function missingOptions(array $ours, array $theirs, string $prefix = ''): array
    {
        $missing = [];

        foreach ($ours as $key => $value) {
            $path = $prefix === '' ? (string) $key : "{$prefix}.{$key}";

            if (!array_key_exists($key, $theirs)) {
                $missing[] = $path;

                continue;
            }

            if (is_array($value) && is_array($theirs[$key]) && $this->isOptionBlock($value)) {
                array_push($missing, ...$this->missingOptions($value, $theirs[$key], $path));
            }
        }

        return $missing;
    }

    /** @param  array<mixed>  $block */
    private function isOptionBlock(array $block): bool
    {
        if ($block === [] || array_is_list($block)) {
            return false;
        }

        foreach (array_keys($block) as $key) {
            if (!is_string($key) || !preg_match('/^[a-z][a-z0-9_]*$/', $key)) {
                return false;
            }
        }

        return true;
    }

    /**
     * The opt-in features, checked only when switched on. Each can be on and
     * still do nothing — a missing table, a missing dependency — and none of
     * them fails loudly on its own, by design, because they must never cost
     * the application anything.
     */
    private function checkOptInFeatures(): void
    {
        if (config('threat-detection.actor_signals.enabled', false)) {
            $table = (string) config('threat-detection.actor_signals.table', 'threat_actor_signals');

            $this->tableExists($table)
                ? $this->reportPass("Actor signals are recorded to '{$table}'")
                : $this->reportFailure("Actor signals are on but the '{$table}' table does not exist — nothing is recorded", $this->migrateHint());
        }

        if (config('threat-detection.actor_score.enabled', false) && !config('threat-detection.actor_signals.enabled', false)) {
            $this->reportWarning(
                'Actor scoring is on without actor signals — the mutation and cadence terms stay at zero',
                'Set THREAT_DETECTION_ACTOR_SIGNALS=true and run the package migrations.'
            );
        }

        if (config('threat-detection.probe_tracking.ai_infrastructure.enabled', false)) {
            config('threat-detection.probe_tracking.enabled', true)
                ? $this->reportPass('AI-infrastructure probe pack is on')
                : $this->reportWarning(
                    'The AI-infrastructure probe pack is on but probe tracking is off, so it never runs',
                    'Set THREAT_DETECTION_PROBE_TRACKING=true, or turn the pack off.'
                );
        }

        if (config('threat-detection.ai_guard.enabled', false)) {
            $this->checkAiGuardPresence();
        }
    }

    /**
     * Asked of Composer, never of ai-guard: no ai-guard class is loaded or
     * class_exists()'d anywhere in this package (see AiGuardContract).
     */
    private function checkAiGuardPresence(): void
    {
        $package = 'jayanta/laravel-ai-guard';

        if (!class_exists(InstalledVersions::class) || !InstalledVersions::isInstalled($package)) {
            $this->reportWarning(
                'The ai-guard integration is on but ai-guard is not installed — it will never receive a verdict',
                'composer require jayanta/laravel-ai-guard:^3.1, or set THREAT_DETECTION_AI_GUARD=false.'
            );

            return;
        }

        $version = ltrim((string) InstalledVersions::getPrettyVersion($package), 'vV');

        if (preg_match('/^\d+\.\d+/', $version) && version_compare($version, '3.1.0', '<')) {
            $this->reportWarning(
                "ai-guard {$version} is installed, but the verdict convention this reads arrived in 3.1.0",
                'composer require jayanta/laravel-ai-guard:^3.1'
            );

            return;
        }

        $this->reportPass("ai-guard is installed ({$version}) and its verdicts are read");
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
        $service = $this->laravel->make(ThreatDetectionService::class);

        $builtIn = array_flip($service->getDefaultThreatPatterns());
        $shadowed = [];

        foreach ((array) config('threat-detection.custom_patterns', []) as $regex => $entry) {
            $label = is_array($entry) ? ($entry['label'] ?? null) : $entry;

            if (is_string($label) && isset($builtIn[$label]) && $regex !== $builtIn[$label]) {
                $shadowed[] = $label;
            }
        }

        if ($shadowed === []) {
            $this->reportPass('No custom pattern shadows a built-in one');

            return;
        }

        $this->reportWarning(
            count($shadowed) . ' custom pattern(s) shadow a built-in: ' . implode(', ', array_unique($shadowed)),
            'Your copy runs instead of the maintained one, so later fixes to it never reach you. '
            . 'Delete these from custom_patterns unless you meant to override them.'
        );
    }

    /**
     * Laravel's HTTP client wraps Guzzle, which is a suggest rather than a
     * requirement — detection makes no outbound request. Without it the geo
     * lookup and the Slack webhook fallback both fail inside best-effort
     * catches, so enrichment quietly does nothing and alerts quietly go
     * nowhere.
     */
    private function checkHttpClient(): void
    {
        if (!class_exists('GuzzleHttp\Client')) {
            $this->reportWarning(
                'No HTTP client — geo enrichment and Slack webhook alerts will do nothing',
                'Run: composer require guzzlehttp/guzzle. Detection itself is unaffected.'
            );

            return;
        }

        $this->reportPass('HTTP client available for enrichment and alerts');
    }

    private function checkCacheDriver(): void
    {
        $driver = config('cache.default');

        if (in_array($driver, ['file', 'database', 'null'], true)) {
            $this->reportWarning(
                "DDoS detection is off — cache driver '{$driver}' has no atomic increment",
                'Switch CACHE_DRIVER to redis or memcached. Pattern detection is unaffected.'
            );

            return;
        }

        $this->reportPass("Cache driver '{$driver}' supports DDoS counting");
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
                fn ($m) => is_string($m) && str_starts_with($m, 'auth')
            );

            if ($authed) {
                $this->reportPass(ucfirst($surface) . ' is behind authentication');

                continue;
            }

            $message = ucfirst($surface) . ' is enabled with no authentication — your threat data is public';
            $fix = 'Set THREAT_DETECTION_' . strtoupper($surface) . '_GUARD to auth, role or ip,'
                . " or add an auth middleware to threat-detection.{$surface}.middleware.";

            $this->laravel->environment('production')
                ? $this->reportFailure($message, $fix)
                : $this->reportWarning($message, $fix);
        }

        $this->checkWriteGuard();
    }

    /**
     * Marking a false positive and deleting an exclusion rule both switch a
     * detection off for everyone. Reading the log and disabling it are
     * different privileges.
     */
    private function checkWriteGuard(): void
    {
        if (!config('threat-detection.api.enabled', true)) {
            return;
        }

        if (config('threat-detection.api.write_guard', 'role') === 'none') {
            $this->reportWarning(
                'Any authenticated user can disable a detection (write_guard is none)',
                'Set THREAT_DETECTION_API_WRITE_GUARD to role, auth or ip.'
            );

            return;
        }

        $this->reportPass('Disabling a detection requires elevated access');
    }

    /**
     * The whitelist and the `ip` guards key off $request->ip(), which honours
     * X-Forwarded-For from any proxy the app trusts. TrustProxies at '*'
     * trusts whoever connects directly, so if the app can be reached without
     * passing through the proxy, a client names its own address: a
     * whitelisted one is never scanned, an allowed one opens the dashboard.
     *
     * Only reported when an IP decision exists to subvert. Whether the origin
     * is reachable around the proxy is not something this command can see, so
     * this is a warning, never a failure.
     */
    private function checkProxyTrust(): void
    {
        $decisions = [];

        if (!empty(config('threat-detection.whitelisted_ips', []))) {
            $decisions[] = 'whitelisted_ips';
        }

        foreach (['dashboard' => false, 'api' => true] as $surface => $enabledByDefault) {
            if (config("threat-detection.{$surface}.enabled", $enabledByDefault)
                && config("threat-detection.{$surface}.guard") === 'ip') {
                $decisions[] = "{$surface}.guard=ip";
            }
        }

        if (config('threat-detection.api.enabled', true) && config('threat-detection.api.write_guard', 'role') === 'ip') {
            $decisions[] = 'api.write_guard=ip';
        }

        if ($decisions === [] || !$this->trustsEveryProxy()) {
            return;
        }

        $this->reportWarning(
            'IP decisions trust X-Forwarded-For from any client (TrustProxies is *): ' . implode(', ', $decisions),
            'Make sure the app is reachable only through your proxy, or list the proxy addresses in TrustProxies.'
        );
    }

    /**
     * Whether TrustProxies is set to trust any caller.
     *
     * Read the way the framework reads it: from each TrustProxies middleware
     * in the kernel's global stack, which covers Laravel 11+'s
     * bootstrap/app.php (applied when the kernel is built) and Laravel 10's
     * app subclass alike, then config('trustedproxy.proxies'). Anything that
     * cannot be read is treated as not a wildcard: this check may miss a
     * case, never invent one.
     */
    private function trustsEveryProxy(): bool
    {
        $candidates = [config('trustedproxy.proxies')];

        try {
            foreach ($this->globalMiddleware() as $middleware) {
                if (is_a($middleware, TrustProxies::class, true)) {
                    $candidates[] = (new \ReflectionMethod($middleware, 'proxies'))
                        ->invoke($this->laravel->make($middleware));
                }
            }
        } catch (\Throwable) {
            // Unreadable: fall through with what was collected.
        }

        foreach ($candidates as $proxies) {
            foreach ((array) $proxies as $proxy) {
                if ($proxy === '*' || $proxy === '**') {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Retention is off by default, so threat_logs keeps every IP address, URL
     * and user agent indefinitely. In the EU those are personal data, and
     * storage has to be limited (GDPR Art. 5(1)(e)). Reported in production
     * only: a development database may keep what it likes.
     */
    private function checkRetention(): void
    {
        if (!$this->laravel->environment('production') || config('threat-detection.retention.enabled', false)) {
            return;
        }

        $this->reportWarning(
            'Retention is off: threat_logs keeps IP addresses, URLs and user agents indefinitely',
            'Set THREAT_DETECTION_RETENTION=true and THREAT_DETECTION_RETENTION_DAYS, and run the scheduler. '
            . 'IP addresses are personal data under GDPR, which requires a storage limit.'
        );
    }

    // ── output ──────────────────────────────────────────────────────────────

    /*
     * Named report* deliberately. Illuminate\Console\Command already defines
     * public warn() and, since Laravel 11, public fail() — and PHP will not
     * let a subclass narrow an inherited method's visibility, so a private
     * fail() here is a fatal error on Laravel 11+ rather than a warning.
     * Prefixing keeps every reporter clear of that namespace for good.
     */

    private function reportPass(string $title): void
    {
        $this->line("  <fg=green>PASS</>  {$title}");
    }

    private function reportWarning(string $title, string $fix): void
    {
        $this->warnings++;
        $this->line("  <fg=yellow>WARN</>  {$title}");
        $this->line("        <fg=gray>{$fix}</>");
    }

    private function reportFailure(string $title, string $fix): void
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

    /**
     * Columns from $wanted that the table does not have.
     *
     * Uses hasColumn() per column rather than getColumnListing(), which the
     * schema builder has been reshaping across recent Laravel versions
     * (getColumns() is the newer form). hasColumn() has been stable since
     * forever and this package supports Laravel 10 through 13. It costs one
     * query per column, which is nothing for a diagnostic run by hand.
     *
     * @param  string[]  $wanted
     * @return string[]
     */
    private function missingColumns(string $table, array $wanted): array
    {
        $missing = [];

        foreach ($wanted as $column) {
            try {
                if (!Schema::hasColumn($table, $column)) {
                    $missing[] = $column;
                }
            } catch (\Throwable $e) {
                // Cannot inspect the column: report it rather than claim it is
                // present, since claiming present is the dangerous direction.
                $missing[] = $column;
            }
        }

        return $missing;
    }

    private function tableExists(string $table): bool
    {
        try {
            return Schema::hasTable($table);
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * The HTTP kernel's global middleware, or none when it cannot say.
     *
     * @return array<int, mixed>
     */
    private function globalMiddleware(): array
    {
        try {
            $kernel = $this->laravel->make(Kernel::class);

            return method_exists($kernel, 'getGlobalMiddleware') ? $kernel->getGlobalMiddleware() : [];
        } catch (\Throwable) {
            return [];
        }
    }

    private function middlewareIsActive(): bool
    {
        $needles = [ThreatDetectionMiddleware::class, 'threat-detect'];

        foreach ($this->globalMiddleware() as $m) {
            if (in_array($m, $needles, true)) {
                return true;
            }
        }

        try {
            $kernel = $this->laravel->make(Kernel::class);

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
