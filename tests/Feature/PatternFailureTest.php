<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * A detection regex that *fails* must never read as a request that is clean.
 *
 * PHP stops catastrophic backtracking with pcre.backtrack_limit; when the
 * limit trips, preg_match() returns false. Treated as "no match" — which it
 * was, silently, until this — the resource limit meant to stop a denial of
 * service instead turns the attacker's input into an invisible bypass: craft
 * something that makes one pattern blow up and that pattern stops existing
 * for your request.
 *
 * This is the oldest lesson in regex-based detection. Backtracking in NIDS
 * rule matching made inspection up to 1.5 million times slower and let 4.0
 * kbps perpetually disable an unmodified Snort (Smith, Estan and Jha, ACSAC
 * 2006). The SoK on ReDoS (arXiv:2406.11618) lists PHP's backtrack and
 * recursion limits as the language's defence — which is exactly why a PHP
 * detector has to notice when they fire.
 *
 * The v1.8.0 audit fixed one pattern that failed this way. This fixes the
 * failure mode: any pattern, shipped or custom, present or future.
 *
 * Failures are forced deterministically with a custom pattern of the classic
 * exponential shape, so no shipped pattern needs to be vulnerable for the
 * test to mean something.
 */
class PatternFailureTest extends TestCase
{
    /** Exponential on a run of a's that ends in a non-match. */
    private const CATASTROPHIC = '/(a+)+$/';

    private function catastrophicInput(): string
    {
        return str_repeat('a', 40) . 'b';
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();

        config([
            'cache.default' => 'array',
            'threat-detection.enabled' => true,
            'threat-detection.detection_mode' => 'strict',
            'threat-detection.min_confidence' => 0,
            'threat-detection.skip_paths' => [],
            'threat-detection.only_paths' => [],
            'threat-detection.whitelisted_ips' => [],
            'threat-detection.api_route_filtering.enabled' => false,
            'threat-detection.content_paths' => [],
            'threat-detection.notifications.enabled' => false,
            'threat-detection.queue.enabled' => false,
            'threat-detection.custom_patterns' => [
                self::CATASTROPHIC => ['label' => 'Operator Rule With A Bad Regex', 'level' => 'high'],
            ],
        ]);

        ThreatDetectionService::flushCaches();

        // Positive control: the forcing mechanism actually forces a failure
        // on this machine, or every assertion below proves nothing.
        $this->assertFalse(@preg_match(self::CATASTROPHIC, $this->catastrophicInput()), 'the test input no longer makes the pattern fail');
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    /** @return array<int, string> labels found by the path the middleware uses */
    private function detect(string $payload): array
    {
        return array_column(
            app(ThreatDetectionService::class)->detectThreatPatternsWithContext(['query' => $payload], 'middleware'),
            'label'
        );
    }

    private function labels(): array
    {
        return $this->detect($this->catastrophicInput());
    }

    #[Test]
    public function a_pattern_that_fails_to_evaluate_is_reported_not_ignored(): void
    {
        $labels = $this->labels();

        $this->assertContains('Pattern Evaluation Failure', $labels);
    }

    #[Test]
    public function the_failure_is_logged_once_naming_the_pattern(): void
    {
        Log::spy();

        $this->labels();
        $this->labels();

        Log::shouldHaveReceived('warning')
            ->withArgs(fn (string $message) => str_contains($message, 'Operator Rule With A Bad Regex')
                && str_contains($message, 'Backtrack limit'))
            ->once();
    }

    /** Through the whole pipeline, into threat_logs. */
    #[Test]
    public function a_request_that_breaks_a_pattern_lands_in_the_log(): void
    {
        Route::middleware('threat-detect')->get('/search', fn () => response('OK'));

        $this->get('/search?q=' . $this->catastrophicInput())->assertStatus(200);

        $this->assertTrue(
            DB::table('threat_logs')->where('type', 'like', '%Pattern Evaluation Failure')->exists(),
            'the request that made a detection pattern fail was not logged'
        );
    }

    /**
     * An attacker who fills the per-request detection cap with noise must not
     * also be able to hide the failure behind it.
     */
    #[Test]
    public function the_failure_survives_a_full_detection_cap(): void
    {
        // A medium match ahead of the failing pattern fills a cap of one but
        // does not end the scan (only a cap full of high-severity matches
        // does), so the failure happens and then meets the cap.
        config([
            'threat-detection.max_detections_per_request' => 1,
            'threat-detection.custom_patterns' => [
                '/aaaa/' => ['label' => 'Cheap Noise', 'level' => 'medium'],
                self::CATASTROPHIC => ['label' => 'Operator Rule With A Bad Regex', 'level' => 'high'],
            ],
        ]);
        ThreatDetectionService::flushCaches();

        $labels = $this->detect($this->catastrophicInput());

        $this->assertContains('Cheap Noise', $labels, 'the noise did not fill the cap, so this proves nothing');
        $this->assertContains('Pattern Evaluation Failure', $labels, 'the cap trimmed the failure out of the report');
    }

    /**
     * The failure record is per scan. The service is a singleton — under
     * Octane, for the life of the worker — so a record that outlived its scan
     * would flag every clean request after the first bad one.
     */
    #[Test]
    public function a_failure_does_not_leak_into_the_next_scan(): void
    {
        $this->assertContains('Pattern Evaluation Failure', $this->labels());

        $this->assertNotContains(
            'Pattern Evaluation Failure',
            $this->detect('hello world, a perfectly ordinary comment'),
            'a clean request was reported because an earlier one failed'
        );

        // And the single-payload API, which keeps its own record.
        $service = app(ThreatDetectionService::class);
        $this->assertContains('Pattern Evaluation Failure', array_column($service->detectThreatPatterns($this->catastrophicInput()), 0));
        $this->assertNotContains(
            'Pattern Evaluation Failure',
            array_column($service->detectThreatPatterns('hello world, a perfectly ordinary comment'), 0),
            'the single-payload API leaked a failure into the next scan'
        );
    }

    /** flushCaches() resets warn-once state; a missed flag here was a v1.8.0 finding. */
    #[Test]
    public function flushing_caches_rearms_the_warning(): void
    {
        Log::spy();

        $this->labels();
        ThreatDetectionService::flushCaches();
        $this->labels();

        Log::shouldHaveReceived('warning')
            ->withArgs(fn (string $message) => str_contains($message, 'Operator Rule With A Bad Regex'))
            ->twice();
    }

    #[Test]
    public function clean_traffic_reports_nothing_new(): void
    {
        $labels = $this->detect('hello world, a perfectly ordinary comment');

        $this->assertNotContains('Pattern Evaluation Failure', $labels);
    }

    /** A validator-backed pattern takes a different code path; it must fail loud too. */
    #[Test]
    public function a_failing_validated_pattern_is_reported_too(): void
    {
        config(['threat-detection.custom_patterns' => [
            self::CATASTROPHIC => ['label' => 'Validated Bad Regex', 'level' => 'high', 'validator' => 'luhn'],
        ]]);
        ThreatDetectionService::flushCaches();

        $this->assertContains('Pattern Evaluation Failure', $this->labels());
    }

    /** The legacy single-payload API takes its own path through patternMatches(). */
    #[Test]
    public function the_single_payload_api_reports_the_failure_too(): void
    {
        $found = app(ThreatDetectionService::class)->detectThreatPatterns($this->catastrophicInput());

        $this->assertContains('Pattern Evaluation Failure', array_column($found, 0));
    }

    /**
     * Normalisation runs regexes too, and one that fails returns null. Before
     * this, a null there emptied the payload, so every pattern saw an empty
     * string. Forcing it needs JIT off and a tiny backtrack limit — rare, but
     * hardened hosts do disable JIT, and the guard costs nothing.
     *
     * Asserted on normalisation's own output rather than on what detection
     * reports: with the engine crippled every pattern fails as well, so
     * "something was reported" would hold whether or not the payload had
     * survived, and the test would prove nothing about the guard.
     */
    #[Test]
    public function a_failing_normalisation_step_never_empties_the_payload(): void
    {
        // Only a process that *starts* with JIT off can force this: a pattern
        // compiled with JIT stays cached that way whatever pcre.jit says
        // later, and normalisation's patterns are compiled long before this
        // runs. CI runs this file with -d pcre.jit=0 and fails on a skip.
        if (filter_var(ini_get('pcre.jit'), FILTER_VALIDATE_BOOLEAN)) {
            $this->markTestSkipped('Needs a process started with -d pcre.jit=0.');
        }

        $service = app(ThreatDetectionService::class);
        $normalize = new \ReflectionMethod($service, 'normalizeForDetection');

        $jit = ini_get('pcre.jit');
        $limit = ini_get('pcre.backtrack_limit');

        try {
            ini_set('pcre.jit', '0');
            ini_set('pcre.backtrack_limit', '1');

            // Positive control on the mechanism itself, checked directly:
            // normalisation's own calls overwrite preg_last_error(), so it
            // cannot be read after the fact.
            $engineFails = preg_replace('/\s+/', ' ', 'a   b') === null;

            $normalized = $normalize->invoke($service, "' UNION/**/SELECT   password FROM users--");
        } finally {
            ini_set('pcre.jit', (string) $jit);
            ini_set('pcre.backtrack_limit', (string) $limit);
        }

        $this->assertTrue($engineFails, 'these settings no longer make PCRE fail, so this test proves nothing about the guard');
        $this->assertStringContainsString('UNION', (string) $normalized, 'a failed normalisation step emptied the payload');
    }
}
