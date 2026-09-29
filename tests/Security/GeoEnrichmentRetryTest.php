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

    /**
     * The pause between lookups is a rate limit on requests, so it belongs
     * after a request. It ran after every address — private ones never sent,
     * and cached ones never asked — so a table of internal traffic took 1.4 s
     * per row to enrich nothing.
     */
    #[Test]
    public function addresses_that_are_never_sent_are_not_rate_limited(): void
    {
        DB::table('threat_logs')->delete();

        foreach (['10.0.0.1', '10.0.0.2', '192.168.1.3', '172.16.0.4'] as $private) {
            DB::table('threat_logs')->insert([
                'ip_address' => $private, 'url' => 'https://example.com/x', 'user_agent' => 'UA',
                'type' => '[middleware] XSS Script Tag', 'payload' => 'x', 'threat_level' => 'high',
                'confidence_score' => 90, 'confidence_label' => 'very_high', 'action_taken' => 'logged',
                'created_at' => now(), 'updated_at' => now(),
            ]);
        }

        $started = microtime(true);
        $this->artisan('threat-detection:enrich')->assertExitCode(0);
        $elapsed = microtime(true) - $started;

        Http::assertNothingSent();
        $this->assertLessThan(2.0, $elapsed, "four private addresses took {$elapsed}s to enrich nothing");
    }

    /**
     * The counterpart: requests that are sent are still paced. ip-api.com's
     * free tier allows 45 a minute and blocks the address that exceeds it.
     */
    #[Test]
    public function requests_that_are_sent_are_still_rate_limited(): void
    {
        DB::table('threat_logs')->insert([
            'ip_address' => '1.1.1.1', 'url' => 'https://example.com/x', 'user_agent' => 'UA',
            'type' => '[middleware] XSS Script Tag', 'payload' => 'x', 'threat_level' => 'high',
            'confidence_score' => 90, 'confidence_label' => 'very_high', 'action_taken' => 'logged',
            'created_at' => now(), 'updated_at' => now(),
        ]);
        $this->providerWorks = true;

        $started = microtime(true);
        $this->artisan('threat-detection:enrich')->assertExitCode(0);

        Http::assertSentCount(2);
        $this->assertGreaterThanOrEqual(2.5, microtime(true) - $started, 'two lookups were sent without the pause between them');
    }

    /**
     * `--force` rewrites rows that are already enriched. With the provider
     * down, each lookup came back empty and the update wrote that emptiness
     * over the country, city, ISP and is_foreign the row already had: the
     * failure was reported, after the data was gone.
     */
    #[Test]
    public function a_forced_run_against_a_failing_provider_keeps_what_rows_already_had(): void
    {
        DB::table('threat_logs')->update([
            'country_code' => 'DE',
            'country_name' => 'Germany',
            'city' => 'Berlin',
            'isp' => 'Hetzner Online',
            'is_foreign' => true,
            // Known from the ISP, not from any address prefix, so a failed
            // lookup cannot re-derive it.
            'cloud_provider' => 'Hetzner',
            'is_cloud_ip' => true,
        ]);

        $this->artisan('threat-detection:enrich', ['--force' => true])->assertExitCode(1);

        $row = DB::table('threat_logs')->first();

        $this->assertSame('DE', $row->country_code, 'a failed forced lookup erased the country');
        $this->assertSame('Germany', $row->country_name);
        $this->assertSame('Berlin', $row->city);
        $this->assertSame('Hetzner Online', $row->isp);
        $this->assertTrue((bool) $row->is_foreign);
        $this->assertSame('Hetzner', $row->cloud_provider);
        $this->assertTrue((bool) $row->is_cloud_ip, 'a failed forced lookup reset is_cloud_ip');
    }

    /** What a failed lookup still knows — a cloud range by prefix — is still written. */
    #[Test]
    public function a_failed_lookup_still_records_a_cloud_range_known_by_prefix(): void
    {
        DB::table('threat_logs')->update(['ip_address' => '54.1.2.3']);

        $this->artisan('threat-detection:enrich')->assertExitCode(1);

        $row = DB::table('threat_logs')->first();

        $this->assertSame('AWS', $row->cloud_provider);
        $this->assertTrue((bool) $row->is_cloud_ip);
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
