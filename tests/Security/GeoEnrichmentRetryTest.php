<?php

namespace JayAnta\ThreatDetection\Tests\Security;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * A failed lookup must not be remembered.
 *
 * Each address's geo result was cached for seven days through
 * Cache::remember(), and a failed lookup returns a result too — every field
 * null — so the failure was cached like an answer. When every lookup failed,
 * the command said to fix the provider and run it again; the rerun read the
 * cached failures, sent nothing, and reported the same total failure for a
 * week, whatever was changed. `--force` did not help: it re-applies what the
 * cache holds.
 *
 * Successful lookups are still cached, which is what keeps a rerun inside the
 * provider's rate limit.
 */
class GeoEnrichmentRetryTest extends TestCase
{
    private const IP = '8.8.8.8';

    private bool $providerWorks = false;

    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();
        config(['cache.default' => 'array']);
        Cache::flush();

        DB::table('threat_logs')->insert([
            'ip_address' => self::IP, 'url' => 'https://example.com/x', 'user_agent' => 'UA',
            'type' => '[middleware] XSS Script Tag', 'payload' => 'x', 'threat_level' => 'high',
            'confidence_score' => 90, 'confidence_label' => 'very_high', 'action_taken' => 'logged',
            'created_at' => now(), 'updated_at' => now(),
        ]);

        Http::fake(fn () => $this->providerWorks
            ? Http::response(['countryCode' => 'US', 'country' => 'United States', 'city' => 'Mountain View', 'isp' => 'Google LLC'])
            : Http::response('forbidden', 403));
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    #[Test]
    public function a_rerun_after_a_failure_asks_the_provider_again(): void
    {
        $this->artisan('threat-detection:enrich')->assertExitCode(1);

        $this->assertFalse(Cache::has('threat_ip_geo:' . self::IP), 'a failed lookup was cached');

        $this->providerWorks = true;

        $this->artisan('threat-detection:enrich')->assertExitCode(0);

        $this->assertSame(
            'US',
            DB::table('threat_logs')->value('country_code'),
            'the rerun used the cached failure instead of asking again'
        );
    }

    /** A failure cached by an earlier version is not an answer either. */
    #[Test]
    public function a_failure_cached_before_the_upgrade_is_asked_again(): void
    {
        Cache::put('threat_ip_geo:' . self::IP, [
            'country_code' => null, 'country_name' => null, 'city' => null, 'isp' => null,
            'cloud_provider' => null, 'is_foreign' => false, 'is_cloud_ip' => false,
        ], now()->addDays(7));
        $this->providerWorks = true;

        $this->artisan('threat-detection:enrich')->assertExitCode(0);

        $this->assertSame('US', DB::table('threat_logs')->value('country_code'));
    }

    /** Positive control: an answer is still cached, and a forced rerun reuses it. */
    #[Test]
    public function a_successful_answer_is_still_reused(): void
    {
        $this->providerWorks = true;
        $this->artisan('threat-detection:enrich')->assertExitCode(0);

        $this->providerWorks = false;
        $this->artisan('threat-detection:enrich', ['--force' => true])->assertExitCode(0);

        $this->assertSame('US', DB::table('threat_logs')->value('country_code'));
        Http::assertSentCount(1);
    }
}
