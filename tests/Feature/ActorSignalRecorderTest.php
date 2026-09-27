<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * Actor signals (1.9.0, opt-in) — substrate, not a detection.
 *
 * threat_logs keeps one row per IP per type per five minutes, which is what
 * stops a flood becoming a write per request. It also means twenty distinct
 * encodings of one injection collapse into a single row, and those nineteen
 * suppressed attempts are the evidence that somebody is iterating on a payload
 * until it lands.
 *
 * This table holds that evidence. Everything below is about two claims:
 *
 *   1. It records what threat_logs cannot — the same attack in many encodings
 *      produces many signal rows and one log row. That is the entire reason
 *      the table exists, and `a_mutation_chain_is_recorded_even_though_the_log_shows_one_row`
 *      is the test that proves it.
 *   2. It is off by default and bounded when on: clean traffic writes nothing,
 *      repeats write nothing, and one actor cannot write without limit.
 */
class ActorSignalRecorderTest extends TestCase
{
    private const SIGNALS = 'threat_actor_signals';

    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();
        $this->createSignalsTable();

        config([
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
            'threat-detection.probe_tracking.enabled' => false,
            'cache.default' => 'array',
        ]);

        Route::middleware('threat-detect')->group(function () {
            Route::get('/search', fn () => response('OK', 200));
            Route::post('/submit', fn () => response('OK', 200));
        });
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    private function createSignalsTable(): void
    {
        Schema::create(self::SIGNALS, function (Blueprint $table) {
            $table->id();
            $table->string('actor_key', 100);
            $table->string('fingerprint', 32);
            $table->string('variant', 32);
            $table->string('label', 100);
            $table->string('context', 20);
            $table->date('observed_on');
            $table->timestamp('created_at')->nullable();
        });
    }

    private function enable(): void
    {
        config(['threat-detection.actor_signals.enabled' => true]);
    }

    private function signalCount(): int
    {
        return DB::table(self::SIGNALS)->count();
    }

    private function logCount(): int
    {
        return DB::table('threat_logs')->count();
    }

    /** Distinct payloads that all decode to the same UNION injection. */
    private function mutations(): array
    {
        return [
            "' UNION SELECT password FROM users--",
            "' UNION/**/SELECT password FROM users--",
            "' UNION%20SELECT password FROM users--",
            "' UNI" . 'ON SELECT password FROM users--',
            "' union select password from users--",
        ];
    }

    // ── off by default ─────────────────────────────────────────────────────

    #[Test]
    public function nothing_is_recorded_until_the_feature_is_turned_on(): void
    {
        $this->get('/search?q=' . urlencode("' UNION SELECT password FROM users--"))->assertStatus(200);

        $this->assertGreaterThan(0, $this->logCount(), 'the attack was not detected, so this proves nothing');
        $this->assertSame(0, $this->signalCount());
    }

    #[Test]
    public function a_missing_table_is_reported_once_rather_than_breaking_the_request(): void
    {
        $this->enable();
        Schema::drop(self::SIGNALS);

        Log::spy();

        $this->get('/search?q=' . urlencode("' UNION SELECT password FROM users--"))->assertStatus(200);

        $this->assertGreaterThan(0, $this->logCount(), 'ordinary logging stopped when the signals table was missing');
        // Log::warning is also how an ordinary detection is reported, so the
        // assertion has to name this message rather than count calls.
        Log::shouldHaveReceived('warning')
            ->withArgs(fn ($message) => str_contains((string) $message, 'does not exist'))
            ->once();
        Log::shouldNotHaveReceived('error');
    }

    // ── the reason the table exists ────────────────────────────────────────

    /**
     * The claim the whole increment rests on. Five distinct payloads that all
     * normalise to the same UNION injection: threat_logs deduplicates them to
     * a single row, and the signals table keeps all five.
     */
    #[Test]
    public function a_mutation_chain_is_recorded_even_though_the_log_shows_one_row(): void
    {
        $this->enable();

        foreach ($this->mutations() as $payload) {
            $this->get('/search?q=' . urlencode($payload))->assertStatus(200);
        }

        $unionRows = DB::table('threat_logs')->where('type', 'like', '%SQL Injection UNION%')->count();
        $this->assertSame(1, $unionRows, 'threat_logs did not deduplicate, so the comparison is meaningless');

        // Count VARIANTS, not fingerprints. Normalisation is what makes the
        // mutations converge, so they share a fingerprint by design — that
        // convergence is the detection, and the surface forms are the count.
        $variants = DB::table(self::SIGNALS)
            ->where('label', 'SQL Injection UNION')
            ->distinct()
            ->count('variant');

        $fingerprints = DB::table(self::SIGNALS)
            ->where('label', 'SQL Injection UNION')
            ->distinct()
            ->count('fingerprint');

        $this->assertGreaterThanOrEqual(
            4,
            $variants,
            "threat_logs kept 1 row and the signals table kept only {$variants} variants"
        );

        $this->assertLessThan(
            $variants,
            $fingerprints,
            'the variants did not converge on a shared fingerprint, so this is not a mutation chain'
        );
    }

    /**
     * Two encodings of the same attack must share a fingerprint — that is the
     * semantic-over-syntactic property the whole design rests on. If they
     * differed, the table would just be a slower copy of the request log.
     */
    #[Test]
    public function two_encodings_of_one_payload_share_a_fingerprint(): void
    {
        $this->enable();

        $plain = '<script>alert(1)</script>';
        $encoded = '&lt;script&gt;alert(1)&lt;/script&gt;';

        $this->post('/submit', ['a' => $plain])->assertStatus(200);
        $first = DB::table(self::SIGNALS)->orderByDesc('id')->value('fingerprint');

        DB::table(self::SIGNALS)->delete();
        Cache::flush();

        $this->post('/submit', ['a' => $encoded])->assertStatus(200);
        $second = DB::table(self::SIGNALS)->orderByDesc('id')->value('fingerprint');

        $this->assertNotNull($first);
        $this->assertNotNull($second);
        $this->assertSame($second, $first, 'the same attack in two encodings produced two fingerprints');
    }

    /**
     * The split between the two hashes, stated as a property.
     *
     * Re-spacing a payload is a surface mutation — it is one of the cheapest
     * ways to move a signature — so it must produce a new *variant*. It is not
     * a new attack, so it must not produce a new *fingerprint*. Collapsing
     * whitespace in both, or in neither, loses one half of the signal.
     */
    #[Test]
    public function respacing_a_payload_is_a_new_variant_but_not_a_new_fingerprint(): void
    {
        $this->enable();

        $this->get('/search?q=' . urlencode("' UNION SELECT password FROM users--"))->assertStatus(200);
        $this->get('/search?q=' . urlencode("' UNION    SELECT   password FROM users--"))->assertStatus(200);

        $rows = DB::table(self::SIGNALS)->where('label', 'SQL Injection UNION')->get();

        $this->assertGreaterThanOrEqual(2, $rows->count(), 'the re-spaced payload was not recorded at all');
        $this->assertSame(
            1,
            $rows->pluck('fingerprint')->unique()->count(),
            're-spacing produced a different fingerprint, so the same attack looks like two'
        );
        $this->assertSame(
            2,
            $rows->pluck('variant')->unique()->count(),
            're-spacing did not produce a different variant, so a whitespace bypass loop would be invisible'
        );
    }

    /**
     * Case is the other cheap surface mutation, and it behaves like
     * whitespace: a new variant, the same fingerprint.
     *
     * This one was wrong until an end-to-end run caught it. Every per-feature
     * test used a single casing, so "UNION SELECT" and "Union Select" quietly
     * produced two fingerprints, and a chain that should have counted as one
     * split into two shorter ones — each below the reporting threshold.
     */
    #[Test]
    public function changing_case_is_a_new_variant_but_not_a_new_fingerprint(): void
    {
        $this->enable();

        $this->get('/search?q=' . urlencode("' UNION SELECT password FROM users--"))->assertStatus(200);
        $this->get('/search?q=' . urlencode("' Union Select password From users--"))->assertStatus(200);

        $rows = DB::table(self::SIGNALS)->where('label', 'SQL Injection UNION')->get();

        $this->assertGreaterThanOrEqual(2, $rows->count(), 'the re-cased payload was not recorded at all');
        $this->assertSame(
            1,
            $rows->pluck('fingerprint')->unique()->count(),
            're-casing produced a different fingerprint, so one mutation chain splits into several short ones'
        );
        $this->assertSame(
            2,
            $rows->pluck('variant')->unique()->count(),
            're-casing did not produce a different variant, so a case-alternating bypass loop would be invisible'
        );
    }

    /**
     * Recorded above the confidence floor, which returns before anything is
     * written to threat_logs. A low-scoring attempt is still an attempt.
     */
    #[Test]
    public function an_attempt_below_the_confidence_floor_is_still_recorded(): void
    {
        $this->enable();
        config(['threat-detection.min_confidence' => 100]);

        $this->get('/search?q=' . urlencode("' UNION SELECT password FROM users--"))->assertStatus(200);

        $this->assertSame(0, $this->logCount(), 'the floor did not suppress the log row, so this proves nothing');
        $this->assertGreaterThan(0, $this->signalCount(), 'the signal was lost to the confidence floor');
    }

    // ── bounded ────────────────────────────────────────────────────────────

    #[Test]
    public function clean_traffic_writes_nothing(): void
    {
        $this->enable();

        $this->get('/search?q=' . urlencode('how do I reset my password'))->assertStatus(200);
        $this->post('/submit', ['body' => 'Thanks for your help yesterday.'])->assertStatus(200);

        $this->assertSame(0, $this->signalCount());
    }

    #[Test]
    public function repeating_one_payload_adds_nothing_after_the_first(): void
    {
        $this->enable();

        $payload = "' UNION SELECT password FROM users--";

        $this->get('/search?q=' . urlencode($payload))->assertStatus(200);
        $afterFirst = $this->signalCount();

        $this->assertGreaterThan(0, $afterFirst, 'the first request recorded nothing');

        for ($i = 0; $i < 4; $i++) {
            $this->get('/search?q=' . urlencode($payload))->assertStatus(200);
        }

        // One request may legitimately trip several labels; what must not
        // happen is the count growing as the same payload is resent.
        $this->assertSame(
            $afterFirst,
            $this->signalCount(),
            'a repeated payload kept adding rows, so the table grows with volume rather than with variety'
        );
    }

    #[Test]
    public function one_actor_cannot_write_past_the_ceiling(): void
    {
        $this->enable();
        config(['threat-detection.actor_signals.max_per_actor_per_window' => 3]);

        Log::spy();

        foreach ($this->mutations() as $payload) {
            $this->get('/search?q=' . urlencode($payload))->assertStatus(200);
        }

        $this->assertLessThanOrEqual(3, $this->signalCount(), 'the per-actor ceiling did not hold');
        Log::shouldHaveReceived('warning')
            ->withArgs(fn ($message) => str_contains((string) $message, 'ceiling'))
            ->once();
    }

    // ── shape of what is stored ────────────────────────────────────────────

    #[Test]
    public function a_row_stores_a_hash_and_never_the_payload(): void
    {
        $this->enable();

        $secret = "' UNION SELECT password FROM users-- hunter2";
        $this->get('/search?q=' . urlencode($secret))->assertStatus(200);

        $row = DB::table(self::SIGNALS)->first();
        $this->assertNotNull($row, 'nothing was recorded');

        $this->assertMatchesRegularExpression('/^[0-9a-f]{16}$/', $row->fingerprint);
        $this->assertSame('query', $row->context);
        $this->assertSame(now()->toDateString(), (string) $row->observed_on);

        // The label is a detection name and legitimately contains attack
        // vocabulary, so the check is for the payload text itself — the part
        // that could carry a credential.
        foreach ((array) $row as $column => $value) {
            $this->assertStringNotContainsStringIgnoringCase('hunter2', (string) $value, "column {$column} stored the payload");
            $this->assertStringNotContainsStringIgnoringCase('password FROM users', (string) $value, "column {$column} stored the payload");
            $this->assertStringNotContainsStringIgnoringCase('SELECT', (string) $value, "column {$column} stored the payload");
        }
    }

    // ── retention ──────────────────────────────────────────────────────────

    #[Test]
    public function purge_removes_signals_on_their_own_shorter_retention(): void
    {
        $this->enable();
        config(['threat-detection.actor_signals.retention_days' => 7]);

        $insert = function (string $when) {
            DB::table(self::SIGNALS)->insert([
                'actor_key' => '203.0.113.5',
                'fingerprint' => substr(hash('sha256', $when), 0, 16),
                'variant' => substr(hash('sha256', 'v' . $when), 0, 16),
                'label' => 'SQL Injection UNION',
                'context' => 'query',
                'observed_on' => $when,
                'created_at' => $when,
            ]);
        };

        $insert(now()->subDays(30)->toDateTimeString());
        $insert(now()->subDay()->toDateTimeString());

        // --days is generous for threat_logs; signals keep their own window.
        Artisan::call('threat-detection:purge', ['--days' => 365, '--no-interaction' => true]);

        $this->assertSame(1, $this->signalCount(), 'signals were not purged on their own retention');
    }
}
