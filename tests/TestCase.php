<?php

namespace JayAnta\ThreatDetection\Tests;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Schema;
use JayAnta\ThreatDetection\Services\ProbeDetectorService;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\ThreatDetectionServiceProvider;
use Orchestra\Testbench\TestCase as OrchestraTestCase;

abstract class TestCase extends OrchestraTestCase
{
    protected function getPackageProviders($app): array
    {
        return [ThreatDetectionServiceProvider::class];
    }

    /**
     * Pattern and probe-path caches live for the whole process, so one file's
     * config overrides would otherwise leak into the next.
     */
    protected function setUp(): void
    {
        parent::setUp();

        ThreatDetectionService::flushCaches();
        ProbeDetectorService::flushCaches();

        // No test may reach the network. threat-detection:enrich calls a
        // third-party geo API, and an unfaked test of it would hit that API
        // for real — slow, rate-limited, and leaking the IPs under test.
        // Any stray request now fails the test that made it.
        Http::preventStrayRequests();
    }

    protected function tearDown(): void
    {
        ThreatDetectionService::flushCaches();
        ProbeDetectorService::flushCaches();

        parent::tearDown();
    }

    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);

        $app['config']->set('threat-detection.enabled', true);
        $app['config']->set('threat-detection.enabled_environments', null);
        $app['config']->set('threat-detection.table_name', 'threat_logs');
        $app['config']->set('threat-detection.whitelisted_ips', []);
        $app['config']->set('threat-detection.dashboard.enabled', false);
        $app['config']->set('threat-detection.api.enabled', true);
        $app['config']->set('threat-detection.api.middleware', ['api']);
    }

    protected function createExclusionRulesTable(): void
    {
        Schema::create('threat_exclusion_rules', function (Blueprint $table) {
            $table->id();
            $table->string('pattern_label');
            $table->string('path_pattern')->nullable();
            $table->string('source_context')->nullable();
            $table->unsignedBigInteger('created_from_threat_id')->nullable();
            $table->unsignedBigInteger('created_by_user_id')->nullable();
            $table->text('reason')->nullable();
            $table->boolean('is_active')->default(true)->index();
            $table->timestamps();
        });
    }

    protected function createThreatLogsTable(): void
    {
        Schema::create(config('threat-detection.table_name', 'threat_logs'), function (Blueprint $table) {
            $table->id();
            $table->string('ip_address')->index();
            $table->text('url');
            $table->text('user_agent')->nullable();
            $table->text('type');
            $table->text('payload')->nullable();
            $table->string('threat_level')->default('medium')->index();
            $table->unsignedTinyInteger('confidence_score')->default(0)->index();
            $table->string('confidence_label', 20)->default('low');
            $table->boolean('is_false_positive')->default(false)->index();
            $table->string('action_taken')->default('logged');
            $table->unsignedBigInteger('user_id')->nullable()->index();
            $table->string('country_code', 5)->nullable()->index();
            $table->string('country_name', 100)->nullable();
            $table->string('city', 100)->nullable();
            $table->string('isp', 255)->nullable();
            $table->string('cloud_provider', 50)->nullable()->index();
            $table->boolean('is_foreign')->default(false)->index();
            $table->boolean('is_cloud_ip')->default(false)->index();
            $table->timestamps();
        });
    }
}
