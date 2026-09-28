<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;
use ReflectionClass;

/**
 * 158 regular expressions run against attacker-controlled request bytes on
 * every request. That is the package's largest and least visible attack
 * surface, and none of it had a test.
 *
 * Two distinct failure modes are checked, because in PHP they are not the
 * same thing:
 *
 *   Time.    A catastrophically backtracking pattern burns CPU. PHP bounds
 *            this with pcre.backtrack_limit (1,000,000 by default), so the
 *            worst case is milliseconds rather than a hung worker — but that
 *            default is an ini setting an operator can raise, and a pattern
 *            that only behaves because of it is still a liability.
 *
 *   Silence. When the backtrack limit *is* hit, preg_match() returns false,
 *            not a match — and the package calls it as `(bool) @preg_match()`
 *            (ThreatDetectionService::patternMatches(), line ~1183). A bailed
 *            match is therefore indistinguishable from a clean payload. This
 *            is the more serious mode: an attacker who can push a pattern
 *            past the limit turns that detection off, cheaply and silently.
 *
 * So every assertion here checks preg_last_error() as well as the clock.
 *
 * Runtime for the whole file is around a second: the inputs are large but the
 * matches either succeed immediately or bail at the backtrack limit. It is
 * grouped 'redos' so it can be excluded if that ever stops being true.
 */
#[Group('redos')]
class RegexSafetyTest extends TestCase
{
    /** Per (pattern, input) budget. */
    private const BUDGET_MS = 50.0;

    /**
     * Wall-clock and resident-memory budgets measure the interpreter as well
     * as the code, and a coverage driver changes both by a large factor: every
     * PHP line is instrumented, and the allocator takes bigger chunks.
     *
     * Left unscaled these assertions flake — they did, once, in a full run
     * under Xdebug, which is worse than useless because a suite that fails
     * intermittently stops being read. CI's `test` job runs `coverage: none`
     * and gets the strict budgets; only the `coverage` job is given slack, and
     * even then a catastrophic regression still fails.
     *
     * Deliberately generous rather than tuned: the point of these numbers is
     * to catch an order-of-magnitude change, not to police a few per cent.
     */
    private static function timeBudget(float $ms): float
    {
        return $ms * (self::instrumented() ? 40.0 : 1.0);
    }

    private static function memoryBudget(int $bytes): int
    {
        return $bytes * (self::instrumented() ? 4 : 1);
    }

    private static function instrumented(): bool
    {
        return extension_loaded('xdebug') || extension_loaded('pcov');
    }

    /** detectThreatPatternsWithContext() substr()s every segment to this. */
    private const SCAN_CAP = 8000;

    /** ThreatDetectionService::MAX_RAW_BODY_BYTES. */
    private const RAW_BODY_CAP = 65536;

    /** @var array<string, string>|null bait name => 1 MB subject */
    private static ?array $largeBait = null;

    /** @var array<string, string>|null bait name => 8 KB subject */
    private static ?array $cappedBait = null;

    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();

        config([
            'threat-detection.enabled' => true,
            'threat-detection.detection_mode' => 'strict',
            'threat-detection.min_confidence' => 0,
            'threat-detection.skip_paths' => [],
            'threat-detection.api_route_filtering.enabled' => false,
            'threat-detection.notifications.enabled' => false,
            'cache.default' => 'array',
        ]);

        Route::middleware('threat-detect')->group(function () {
            Route::get('/redos', fn () => response('OK', 200));
            Route::post('/redos', fn () => response('OK', 200));
        });
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    // ── the pattern inventory ───────────────────────────────────────────────

    /**
     * Every regex the package will run: the shipped defaults, the shipped
     * custom_patterns, and the evasion patterns. Read from source rather than
     * transcribed, so a pattern added later is covered without touching this
     * file.
     *
     * @return array<string, array{0: string, 1: string, 2: string}>
     */
    public static function everyPattern(): array
    {
        $rc = new ReflectionClass(ThreatDetectionService::class);
        $instance = $rc->newInstanceWithoutConstructor();

        $defaults = $rc->getMethod('getDefaultThreatPatterns')->invoke($instance);

        $evasionMethod = $rc->getMethod('getEvasionPatterns');
        $evasionMethod->setAccessible(true);
        $evasion = $evasionMethod->invoke($instance);

        $config = require __DIR__ . '/../../config/threat-detection.php';
        $custom = [];
        foreach ($config['custom_patterns'] as $regex => $entry) {
            $custom[$regex] = is_array($entry) ? $entry['label'] : $entry;
        }

        // The LLM pack only joins the custom patterns when its switch is on,
        // so reading custom_patterns alone never saw it. Added in 1.9.0 and
        // covered from the start.
        $llm = [];
        foreach ($config['llm_log_safety']['patterns'] as $regex => $entry) {
            $llm[$regex] = is_array($entry) ? $entry['label'] : $entry;
        }

        $cases = [];
        foreach ([['default', $defaults], ['custom', $custom], ['evasion', $evasion], ['llm', $llm]] as [$origin, $set]) {
            foreach ($set as $regex => $label) {
                // Several regexes can share a label (the LLM pack has three
                // role-marker patterns). Keyed by label alone, all but the
                // last were silently dropped and never tested.
                $key = "{$origin}: {$label}";
                for ($n = 2; isset($cases[$key]); $n++) {
                    $key = "{$origin}: {$label} #{$n}";
                }
                $cases[$key] = [$regex, $label, $origin];
            }
        }

        return $cases;
    }

    /**
     * Backtracking bait. Long runs of a single character are what turn a
     * nested or adjacent quantifier quadratic; the last few carry a literal
     * the pattern will latch onto, followed by input that never satisfies the
     * rest of it — the classic shape.
     *
     * @return array<string, string>
     */
    private static function bait(int $size): array
    {
        return [
            'letters' => str_repeat('a', $size),
            'spaces' => str_repeat(' ', $size),
            'digits' => str_repeat('9', $size),
            'quotes' => str_repeat("'", $size),
            'open-parens' => str_repeat('(', $size),
            'close-parens' => str_repeat(')', $size),
            'angles' => str_repeat('<', $size),
            'slashes' => str_repeat('/', $size),
            'backslashes' => str_repeat('\\', $size),
            'braces' => str_repeat('{', $size),
            'dollar-braces' => str_repeat('${', intdiv($size, 2)),
            'pipes' => str_repeat('|', $size),
            'percents' => str_repeat('%', $size),
            'ampersands' => str_repeat('&#', intdiv($size, 2)),
            'mixed-meta' => str_repeat('a1\' <(/\\%{$', intdiv($size, 11)),
            // Literal-then-never-terminated: the shape that makes .*? and
            // [^>]* walk the whole subject and then backtrack over it.
            'unclosed-script' => '<script>' . str_repeat('a', max(0, $size - 8)),
            'unclosed-tag' => '<img ' . str_repeat('a', max(0, $size - 5)),
            'keyword-then-space' => 'union' . str_repeat(' ', max(0, $size - 6)) . 'x',
            'entity-run' => str_repeat('&#x41;', intdiv($size, 6)),
            'double-encoded' => str_repeat('%25', intdiv($size, 3)),
            'sql-comment-run' => str_repeat('/*x*/', intdiv($size, 5)),
        ];
    }

    private static function largeBait(): array
    {
        return self::$largeBait ??= self::bait(1024 * 1024);
    }

    private static function cappedBait(): array
    {
        return self::$cappedBait ??= self::bait(self::SCAN_CAP);
    }

    public static function tearDownAfterClass(): void
    {
        self::$largeBait = null;
        self::$cappedBait = null;
    }

    // ── time budget ─────────────────────────────────────────────────────────

    #[Test]
    #[DataProvider('everyPattern')]
    public function the_pattern_completes_within_the_time_budget_on_a_one_megabyte_adversarial_input(
        string $regex,
        string $label,
        string $origin
    ): void {
        $overruns = [];

        foreach (self::largeBait() as $name => $subject) {
            $started = hrtime(true);
            @preg_match($regex, $subject);
            $elapsed = (hrtime(true) - $started) / 1e6;

            if ($elapsed > self::timeBudget(self::BUDGET_MS)) {
                $overruns[] = sprintf('%s: %.1fms', $name, $elapsed);
            }
        }

        $this->assertSame(
            [],
            $overruns,
            "'{$label}' ({$regex}) exceeded the {$this->budget()} budget on a 1MB input: " . implode(', ', $overruns)
        );
    }

    #[Test]
    #[DataProvider('everyPattern')]
    public function the_pattern_completes_within_the_time_budget_at_the_size_the_package_scans(
        string $regex,
        string $label,
        string $origin
    ): void {
        $overruns = [];

        foreach (self::cappedBait() as $name => $subject) {
            $started = hrtime(true);
            @preg_match($regex, $subject);
            $elapsed = (hrtime(true) - $started) / 1e6;

            if ($elapsed > self::timeBudget(self::BUDGET_MS)) {
                $overruns[] = sprintf('%s: %.1fms', $name, $elapsed);
            }
        }

        $this->assertSame([], $overruns, "'{$label}' ({$regex}) exceeded the budget at the 8000-byte scan cap");
    }

    // ── silent abandonment ──────────────────────────────────────────────────

    /**
     * The one that matters. A pattern that exhausts the backtrack limit
     * returns false, and patternMatches() reads false as "no threat here".
     *
     * The package caps every segment at 8000 bytes before matching, so this
     * asserts the property at the size an attacker can actually reach.
     */
    #[Test]
    #[DataProvider('everyPattern')]
    public function the_pattern_never_abandons_a_match_at_the_size_the_package_scans(
        string $regex,
        string $label,
        string $origin
    ): void {
        $abandoned = [];

        foreach (self::cappedBait() as $name => $subject) {
            @preg_match($regex, $subject);

            if (preg_last_error() !== PREG_NO_ERROR) {
                $abandoned[] = $name . ' (' . preg_last_error_msg() . ')';
            }
        }

        $this->assertSame(
            [],
            $abandoned,
            "'{$label}' ({$regex}) gave up mid-match — the caller reads that as 'no threat': " . implode(', ', $abandoned)
        );
    }

    /**
     * At 1MB the picture is different, and worth recording rather than
     * asserting away: several patterns do bail. The package never feeds them
     * 1MB — every segment is truncated to 8000 bytes first — so this documents
     * the margin that truncation is buying, and fails if a pattern ever gets
     * so fragile that it bails at a size the cap does not protect.
     */
    #[Test]
    public function the_eight_kilobyte_scan_cap_is_what_keeps_the_fragile_patterns_working(): void
    {
        $bailsAtOneMegabyte = [];
        $bailsAtTheCap = [];

        foreach (self::everyPattern() as [$regex, $label]) {
            foreach (self::largeBait() as $subject) {
                @preg_match($regex, $subject);
                if (preg_last_error() !== PREG_NO_ERROR) {
                    $bailsAtOneMegabyte[$label] = true;
                    break;
                }
            }
            foreach (self::cappedBait() as $subject) {
                @preg_match($regex, $subject);
                if (preg_last_error() !== PREG_NO_ERROR) {
                    $bailsAtTheCap[$label] = true;
                    break;
                }
            }
        }

        // The cap is load-bearing: some patterns really do fall over above it.
        $this->assertNotEmpty(
            $bailsAtOneMegabyte,
            'no pattern bails at 1MB any more — if the patterns were hardened, tighten this test'
        );

        // And nothing falls over below it.
        $this->assertSame([], array_keys($bailsAtTheCap));
    }

    // ── the regexes the package builds at runtime ──────────────────────────

    /**
     * The sweep above reads the pattern *lists*. It therefore missed the
     * regexes the package assembles on the fly, and the redaction pass —
     * added to fix the credential leak — turned out to have exactly the defect
     * this file exists to catch: an alternation inside a quantifier that
     * exhausted the PCRE JIT stack above about 8 KB.
     *
     * That mattered more than an ordinary bail. Redaction fails closed, so a
     * regex that gave up blanked the whole row: the secret was removed, and so
     * was every piece of evidence beside it.
     *
     * Driven through the real service so the regex under test is the one the
     * package actually builds, not a copy of it.
     */
    #[Test]
    public function the_redaction_pass_never_gives_up_on_a_hostile_payload(): void
    {
        $rc = new ReflectionClass(ThreatDetectionService::class);
        $method = $rc->getMethod('redactSensitiveFields');
        $method->setAccessible(true);
        $service = app(ThreatDetectionService::class);

        $bait = [
            'quotes' => str_repeat('"', 100000),
            'backslashes' => str_repeat('\\', 100000),
            'escaped quotes' => str_repeat('\\"', 50000),
            'unterminated json string' => '{"password":"' . str_repeat('a', 100000),
            'unterminated with backslashes' => '{"password":"' . str_repeat('\\', 100000),
            'unterminated assignment' => 'password=' . str_repeat('a', 100000),
            'many credential keys' => str_repeat('{"password":"x"}', 6000),
            'many assignments' => str_repeat('password=x&', 9000),
            'equals run' => str_repeat('=', 100000),
            'ampersand run' => str_repeat('&', 100000),
            'a real query string' => 'q=' . str_repeat('a', 50000) . '&password=' . str_repeat('s', 50000),
        ];

        $failures = [];

        foreach ($bait as $name => $subject) {
            $started = hrtime(true);
            $result = $method->invoke($service, $subject);
            $elapsed = (hrtime(true) - $started) / 1e6;

            if ($elapsed > self::timeBudget(self::BUDGET_MS)) {
                $failures[] = sprintf('%s took %.1fms', $name, $elapsed);
            }

            // Blanking is what a bail looks like from the outside: the method
            // returns the bare mask instead of the text it was given.
            if ($result === '[REDACTED]' && !str_starts_with($subject, 'password=')) {
                $failures[] = "{$name} was blanked wholesale — the regex gave up";
            }
        }

        $this->assertSame([], $failures, implode('; ', $failures));
    }

    /**
     * The same for the structured pass, which is what actually handles request
     * bodies. It is not a regex, but it does recurse, so a deeply nested body
     * must not exhaust the stack.
     */
    #[Test]
    public function the_structured_redaction_pass_survives_a_deeply_nested_body(): void
    {
        $deep = 'bottom';
        for ($i = 0; $i < 200; $i++) {
            $deep = ['nest' => $deep];
        }

        $response = $this->call('POST', '/redos', [], [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_ACCEPT' => 'application/json',
        ], json_encode(['password' => 'secret-value', 'data' => $deep, 'q' => "' UNION SELECT x FROM y"]));

        $response->assertStatus(200);
        $this->assertStringNotContainsString('secret-value', (string) DB::table('threat_logs')->value('payload'));
    }

    // ── memory ──────────────────────────────────────────────────────────────

    /**
     * @return array<string, array{0: int}>
     */
    public static function bodySizes(): array
    {
        return [
            'just under the raw-body cap' => [self::RAW_BODY_CAP - 1],
            'exactly the raw-body cap' => [self::RAW_BODY_CAP],
            'one byte over the raw-body cap' => [self::RAW_BODY_CAP + 1],
            'four times the raw-body cap' => [self::RAW_BODY_CAP * 4],
            'two megabytes' => [2 * 1024 * 1024],
        ];
    }

    #[Test]
    #[DataProvider('bodySizes')]
    public function a_large_request_body_does_not_blow_the_memory_limit(int $size): void
    {
        // Attack-shaped so the payload cannot be discarded by the pre-screen.
        $body = "' UNION SELECT password FROM users--" . str_repeat("a' OR 1=1 (", intdiv($size, 11));

        $before = memory_get_usage(true);

        $response = $this->call('POST', '/redos', [], [], [], [
            'CONTENT_TYPE' => 'application/x-www-form-urlencoded',
        ], 'field=' . urlencode($body));

        $growth = memory_get_usage(true) - $before;

        $response->assertStatus(200);

        // Generous, but it catches the failure that matters: retaining a
        // multiple of the body rather than a bounded slice of it.
        $this->assertLessThan(
            self::memoryBudget(32 * 1024 * 1024),
            $growth,
            sprintf('a %d-byte body grew resident memory by %.1f MB', $size, $growth / 1048576)
        );
    }

    #[Test]
    public function a_two_megabyte_json_body_is_scanned_without_exhausting_memory(): void
    {
        $payload = str_repeat("<script>alert(1)</script> ' UNION SELECT ", 51200);
        $json = json_encode(['field' => $payload]);
        $this->assertGreaterThan(2 * 1024 * 1024, strlen($json));

        $before = memory_get_usage(true);

        $response = $this->call('POST', '/redos', [], [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_ACCEPT' => 'application/json',
        ], $json);

        $response->assertStatus(200);
        $this->assertLessThan(self::memoryBudget(64 * 1024 * 1024), memory_get_usage(true) - $before);

        // It was still scanned: truncation must not mean abandonment.
        $this->assertGreaterThan(0, DB::table('threat_logs')->count());
    }

    /**
     * The whole scan, not one pattern. A single request must not turn into a
     * measurable pause however hostile its body is.
     */
    #[Test]
    public function a_full_scan_of_a_maximally_hostile_body_stays_well_under_a_second(): void
    {
        $hostile = implode(' ', [
            "' UNION SELECT password FROM users--",
            '<script>' . str_repeat('a', 2000),
            str_repeat('(', 2000),
            str_repeat('${', 500),
            str_repeat('%25', 500),
            str_repeat('a1\' <(/\\%{$', 200),
        ]);

        $started = hrtime(true);
        $this->post('/redos', ['field' => $hostile])->assertStatus(200);
        $elapsed = (hrtime(true) - $started) / 1e6;

        $this->assertLessThan(self::timeBudget(1000.0), $elapsed, sprintf('one hostile request took %.0fms end to end', $elapsed));
    }

    // ── the bug this phase found ────────────────────────────────────────────

    /**
     * BUG 2 (fixed) — LDAP injection detection used to be switched off by 1.5 KB of padding.
     *
     * The pattern is /[)(|*\\].*\(.*=/s (ThreatDetectionService, in
     * getDefaultThreatPatterns()). Two greedy .* with /s, separated by
     * literals, over a subject made of the class's own characters: the
     * backtracking is quadratic.
     *
     * Measured against the real pattern: an LDAP injection payload still
     * matches with up to ~1,400 trailing '(' characters, and stops matching at
     * ~1,600 — preg_match() returns false with PREG_BACKTRACK_LIMIT_ERROR, and
     * patternMatches() casts that to "no match".
     *
     * So an attacker appends about 1,500 open parens and the detection is
     * gone. It is not a denial of service — the bail is fast — it is an
     * evasion, and the cheapest one in the package.
     *
     * Fixed by rewriting the pattern with negated classes and possessive quantifiers, which cannot backtrack. Same acceptance set, no bail.
     */
    #[Test]
    public function an_ldap_injection_padded_with_open_parens_is_still_detected(): void
    {
        $payload = '*)(uid=*))(|(uid=*' . str_repeat('(', 2000);

        $this->post('/redos', ['filter' => $payload])->assertStatus(200);

        $this->assertDatabaseHas('threat_logs', ['type' => '[middleware] LDAP Injection']);
    }

    /** The same payload unpadded, to show the detection genuinely works. */
    #[Test]
    public function an_unpadded_ldap_injection_is_detected(): void
    {
        $this->post('/redos', ['filter' => '*)(uid=*))(|(uid=*'])->assertStatus(200);

        $this->assertDatabaseHas('threat_logs', ['type' => '[middleware] LDAP Injection']);
    }

    /**
     * Padding suppresses the LDAP pattern, but the request is not invisible —
     * the payload still trips other patterns. Worth pinning: it is the
     * difference between "one detection lost" and "an undetected attack", and
     * a future pattern change could quietly turn one into the other.
     */
    #[Test]
    public function a_padded_ldap_injection_is_at_least_still_logged_by_some_pattern(): void
    {
        $payload = '*)(uid=*))(|(uid=*' . str_repeat('(', 2000);

        $this->post('/redos', ['filter' => $payload])->assertStatus(200);

        $this->assertGreaterThan(
            0,
            DB::table('threat_logs')->count(),
            'a padded LDAP injection produced no detection of any kind'
        );
    }

    private function budget(): string
    {
        return self::BUDGET_MS . 'ms';
    }
}
