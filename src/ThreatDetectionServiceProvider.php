<?php

namespace JayAnta\ThreatDetection;

use Illuminate\Support\ServiceProvider;
use Illuminate\Routing\Router;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Services\ConfidenceScorer;
use JayAnta\ThreatDetection\Services\ExclusionRuleService;
use JayAnta\ThreatDetection\Http\Middleware\ThreatDetectionMiddleware;
use JayAnta\ThreatDetection\Console\Commands\EnrichThreatLogsCommand;
use JayAnta\ThreatDetection\Console\Commands\ThreatStatsCommand;
use JayAnta\ThreatDetection\Console\Commands\PurgeThreatLogsCommand;

class ThreatDetectionServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../config/threat-detection.php',
            'threat-detection'
        );

        $this->app->singleton(ConfidenceScorer::class, fn() => new ConfidenceScorer());
        $this->app->singleton(ExclusionRuleService::class, fn() => new ExclusionRuleService());

        $this->app->singleton('threat-detection', function ($app) {
            return new ThreatDetectionService(
                $app->make(ConfidenceScorer::class),
                $app->make(ExclusionRuleService::class)
            );
        });

        $this->app->singleton(ThreatDetectionService::class, function ($app) {
            return $app->make('threat-detection');
        });
    }

    public function boot(): void
    {
        $this->registerPublishes();
        $this->registerMiddleware();
        $this->registerRoutes();
        $this->registerCommands();
        $this->registerViews();
    }

    protected function registerPublishes(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/threat-detection.php' => config_path('threat-detection.php'),
            ], 'threat-detection-config');

            $this->publishes([
                __DIR__ . '/../database/migrations/create_threat_logs_table.php.stub' => database_path('migrations/' . date('Y_m_d_His') . '_create_threat_logs_table.php'),
                __DIR__ . '/../database/migrations/add_confidence_to_threat_logs_table.php.stub' => database_path('migrations/' . date('Y_m_d_His', time() + 1) . '_add_confidence_to_threat_logs_table.php'),
                __DIR__ . '/../database/migrations/create_threat_exclusion_rules_table.php.stub' => database_path('migrations/' . date('Y_m_d_His', time() + 2) . '_create_threat_exclusion_rules_table.php'),
            ], 'threat-detection-migrations');

            if (is_dir(__DIR__ . '/../resources/views')) {
                $this->publishes([
                    __DIR__ . '/../resources/views' => resource_path('views/vendor/threat-detection'),
                ], 'threat-detection-views');
            }
        }
    }

    protected function registerMiddleware(): void
    {
        /** @var Router $router */
        $router = $this->app->make(Router::class);
        $router->aliasMiddleware('threat-detect', ThreatDetectionMiddleware::class);
    }

    protected function registerRoutes(): void
    {
        if (config('threat-detection.api.enabled', true)) {
            $middleware = config('threat-detection.api.middleware', ['api', 'auth:sanctum']);

            // Fall back to ['api'] when Sanctum is not installed
            if (!class_exists(\Laravel\Sanctum\SanctumServiceProvider::class)) {
                $middleware = array_values(array_filter($middleware, fn($m) => $m !== 'auth:sanctum'));
            }

            config(['threat-detection.api.middleware' => $middleware]);
            $this->loadRoutesFrom(__DIR__ . '/../routes/api.php');
        }

        if (config('threat-detection.dashboard.enabled', false)
            && file_exists(__DIR__ . '/../routes/web.php')) {
            $this->loadRoutesFrom(__DIR__ . '/../routes/web.php');
        }
    }

    protected function registerCommands(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([
                EnrichThreatLogsCommand::class,
                ThreatStatsCommand::class,
                PurgeThreatLogsCommand::class,
            ]);
        }
    }

    protected function registerViews(): void
    {
        if (is_dir(__DIR__ . '/../resources/views')) {
            $this->loadViewsFrom(__DIR__ . '/../resources/views', 'threat-detection');
        }
    }
}
