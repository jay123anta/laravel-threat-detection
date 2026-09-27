<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Integration\AiGuardContract;
use JayAnta\ThreatDetection\Integration\AiGuardVerdictListener;
use JayAnta\ThreatDetection\Services\ActorAttributionStore;
use JayAnta\ThreatDetection\Services\ActorRiskScorer;
use JayAnta\ThreatDetection\Tests\Fixtures\AiGuard\FakeAiGuardMiddleware;
use JayAnta\ThreatDetection\Tests\Fixtures\AiGuard\FakeAiGuardMiddlewareWithGarbage;
use JayAnta\ThreatDetection\Tests\Fixtures\AiGuard\FakeAiGuardVerdict;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * Reading bot identity from `jayanta/laravel-ai-guard`, without depending on it.
 *
 * Two things are under test, and the second is the interesting one.
 *
 * **That the integration works.** A verdict reaches the actor score through
 * either channel — the interop events or the request attribute — and is
 * ignored when it is malformed, unknown, or from a schema we do not recognise.
 *
 * **That it cannot be used as a bypass.** The obvious version of this feature
 * exempts verified crawlers from scoring, and the obvious version is wrong.
 * Impersonating a crawler is a deliberate, measured technique — Imperva found
 * 16.3% of 1,000 sites subject to Googlebot impersonation, and one published
 * audit found 107 of 799 requests carrying Googlebot's name were genuine —
 * and the reason it is worth doing is precisely that sites extend trust to
 * crawlers. Research on bot defences puts the security boundary at environment
 * authenticity and shows accumulated trust signals are imitable
 * (arXiv:2607.18659), while identity-based classification catches 8–18% of
 * bots (arXiv:2603.28546).
 *
 * So verification damps a score and never clears one,
 * `a_verified_crawler_that_reached_exploitation_gets_no_discount` is the test
 * that keeps it that way, and no identity verdict of any kind can raise a
 * score for an actor this package detected nothing from.
 */
class AiGuardIntegrationTest extends TestCase
{
    private const IP = '203.0.113.77';

    /**
     * The listeners are registered while the provider boots, so the switch has
     * to be on *before* that — setting it in setUp() would be too late, and
     * every event test below would pass or fail for the wrong reason.
     */
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('threat-detection.ai_guard.enabled', true);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();

        config([
            'cache.default' => 'array',
            'threat-detection.actor_score.enabled' => true,
            'threat-detection.ai_guard.enabled' => true,
        ]);
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    /** One medium detection: enough to score, nowhere near the ceiling. */
    private function detection(string $level = 'medium', string $type = 'SQL Injection UNION'): void
    {
        DB::table('threat_logs')->insert([
            'ip_address' => self::IP,
            'url' => 'https://example.com/search',
            'user_agent' => 'Mozilla/5.0 (compatible; Googlebot/2.1)',
            'type' => $type,
            'payload' => 'x',
            'threat_level' => $level,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    private function verdict(?string $status, ?string $category = 'search_engines', ?string $identity = 'Googlebot'): void
    {
        app(ActorAttributionStore::class)->remember(self::IP, [
            'status' => $status,
            'category' => $category,
            'identity' => $identity,
        ]);
    }

    private function score(): array
    {
        return app(ActorRiskScorer::class)->score(self::IP);
    }

    // ── The output shape ───────────────────────────────────────────────────

    /**
     * With the integration off, the score is byte-identical to 1.14.0's. Every
     * feature in this line is opt-in, and an install that did not opt in must
     * not see a new key appear in a structure it may be reading.
     */
    #[Test]
    public function the_score_shape_is_unchanged_when_the_integration_is_off(): void
    {
        config(['threat-detection.ai_guard.enabled' => false]);
        $this->detection();

        $this->assertSame(
            ['peak', 'persistence', 'diversity', 'progression', 'mutation', 'cadence'],
            array_keys($this->score()['components'])
        );
    }

    #[Test]
    public function the_terms_appear_only_once_the_integration_is_enabled(): void
    {
        $this->detection();

        $components = $this->score()['components'];

        $this->assertArrayHasKey('impersonation', $components);
        $this->assertArrayHasKey('attribution', $components);
    }

    /** Including for an actor with nothing to score, so the shape is stable either way. */
    #[Test]
    public function an_actor_with_no_detections_reports_the_terms_as_zero(): void
    {
        $this->verdict(ActorAttributionStore::STATUS_SPOOFED, 'search_engines');

        $score = $this->score();

        $this->assertSame(0, $score['score'], 'an identity verdict alone produced a score');
        $this->assertSame(0.0, $score['components']['impersonation']);
        $this->assertSame(0.0, $score['components']['attribution']);
    }

    // ── Impersonation raises ───────────────────────────────────────────────

    #[Test]
    public function a_spoofed_identity_raises_the_actor_score(): void
    {
        $this->detection();
        $before = $this->score();

        $this->verdict(ActorAttributionStore::STATUS_SPOOFED);
        $after = $this->score();

        $this->assertGreaterThan($before['score'], $after['score'], 'impersonation did not raise the score');
        $this->assertSame(0.25, $after['components']['impersonation']);
    }

    #[Test]
    public function the_impersonation_bonus_is_configurable(): void
    {
        config(['threat-detection.ai_guard.spoofed_bonus' => 0.4]);
        $this->detection();
        $this->verdict(ActorAttributionStore::STATUS_SPOOFED);

        $this->assertSame(0.4, $this->score()['components']['impersonation']);
    }

    // ── Verification damps, and only damps ─────────────────────────────────

    #[Test]
    public function a_verified_crawler_is_ranked_lower(): void
    {
        $this->detection();
        $before = $this->score();

        $this->verdict(ActorAttributionStore::STATUS_VERIFIED, 'search_engines');
        $after = $this->score();

        $this->assertLessThan($before['score'], $after['score'], 'verification did not damp the score');
        $this->assertSame(-0.25, $after['components']['attribution']);
    }

    /**
     * The whitelist-evasion guard, and the reason this feature discounts
     * rather than exempts. An actor with a high-severity non-probe detection
     * has reached the exploitation stage; whatever its papers say, it does not
     * get the benefit of the doubt.
     */
    #[Test]
    public function a_verified_crawler_that_reached_exploitation_gets_no_discount(): void
    {
        $this->detection('high');
        $this->verdict(ActorAttributionStore::STATUS_VERIFIED, 'search_engines');

        $score = $this->score();

        $this->assertTrue($score['reached_exploit']);
        $this->assertSame(0.0, $score['components']['attribution'], 'a verified identity discounted an exploitation attempt');
    }

    /**
     * Verification confirms *who* a client is, not that it is welcome. A
     * confirmed data harvester is still a data harvester.
     */
    #[Test]
    public function verification_only_discounts_the_configured_categories(): void
    {
        $this->detection();
        $this->verdict(ActorAttributionStore::STATUS_VERIFIED, 'data_harvesters');

        $this->assertSame(0.0, $this->score()['components']['attribution']);
    }

    #[Test]
    public function a_discount_can_never_push_a_score_below_zero(): void
    {
        config(['threat-detection.ai_guard.verified_discount' => 5.0]);
        $this->detection('low');
        $this->verdict(ActorAttributionStore::STATUS_VERIFIED, 'search_engines');

        $this->assertSame(0, $this->score()['score']);
    }

    /** ai-guard's verification is off by default, so this is the common case. */
    #[Test]
    public function an_unverified_or_unknown_status_changes_nothing(): void
    {
        $this->detection();
        $baseline = $this->score()['score'];

        foreach ([null, 'unverified', 'something_added_in_a_later_version'] as $status) {
            Cache::flush();
            $this->verdict($status, 'search_engines');

            $this->assertSame($baseline, $this->score()['score'], "status '{$status}' moved the score");
        }
    }

    // ── The store ──────────────────────────────────────────────────────────

    /**
     * Impersonation is not a state a client drifts out of. Letting a later
     * clean verdict clear the record would hand an attacker the erasure for
     * the price of one well-formed request.
     */
    #[Test]
    public function a_spoofed_verdict_is_not_overwritten_by_a_later_verified_one(): void
    {
        $store = app(ActorAttributionStore::class);

        $store->remember(self::IP, ['status' => 'spoofed', 'category' => 'search_engines']);
        $store->remember(self::IP, ['status' => 'verified', 'category' => 'search_engines']);

        $this->assertSame('spoofed', $store->forActor(self::IP)['status']);
    }

    /**
     * Two gates, tested separately. Checking both with the switch off the
     * whole time would pass if either one alone were deleted, because each
     * hides the other.
     */
    #[Test]
    public function the_store_writes_nothing_while_the_integration_is_off(): void
    {
        $store = app(ActorAttributionStore::class);

        config(['threat-detection.ai_guard.enabled' => false]);
        $store->remember(self::IP, ['status' => 'spoofed', 'category' => 'search_engines']);

        config(['threat-detection.ai_guard.enabled' => true]);
        $this->assertNull($store->forActor(self::IP), 'a verdict was written while the integration was off');
    }

    #[Test]
    public function the_store_reports_nothing_while_the_integration_is_off(): void
    {
        $store = app(ActorAttributionStore::class);
        $store->remember(self::IP, ['status' => 'spoofed', 'category' => 'search_engines']);

        config(['threat-detection.ai_guard.enabled' => false]);
        $this->assertNull($store->forActor(self::IP), 'a stored verdict was read while the integration was off');
    }

    #[Test]
    public function a_verdict_that_claims_nothing_is_not_stored(): void
    {
        $store = app(ActorAttributionStore::class);
        $store->remember(self::IP, ['status' => null, 'category' => null, 'identity' => 'ignored']);

        $this->assertNull($store->forActor(self::IP));
    }

    /** A verdict describes the actor for one score window, not forever. */
    #[Test]
    public function a_verdict_expires_after_its_ttl(): void
    {
        config(['threat-detection.ai_guard.ttl_minutes' => 60]);

        $store = app(ActorAttributionStore::class);
        $store->remember(self::IP, ['status' => 'spoofed', 'category' => 'search_engines']);

        $this->travel(59)->minutes();
        $this->assertNotNull($store->forActor(self::IP), 'the verdict expired early');

        $this->travel(2)->minutes();
        $this->assertNull($store->forActor(self::IP), 'the verdict outlived its TTL');
    }

    // ── The two channels ───────────────────────────────────────────────────

    /**
     * The event channel, driven exactly as ai-guard drives it: dispatched
     * under a class-name string this package never imports, carrying an object
     * whose *properties* are the contract.
     */
    #[Test]
    public function an_interop_event_reaches_the_score(): void
    {
        $this->detection();

        Event::dispatch(AiGuardContract::EVENT_SPOOFED_BOT, [new FakeAiGuardVerdict(
            schema: AiGuardContract::SCHEMA,
            status: 'spoofed',
            category: 'search_engines',
            identity: 'Googlebot',
            ip: self::IP,
        )]);

        $this->assertSame('spoofed', app(ActorAttributionStore::class)->forActor(self::IP)['status']);
        $this->assertGreaterThan(0.0, $this->score()['components']['impersonation']);
    }

    /** A future ai-guard.verdict/2 must be ignored, not guessed at. */
    #[Test]
    public function a_payload_from_an_unrecognised_schema_is_ignored(): void
    {
        Event::dispatch(AiGuardContract::EVENT_SPOOFED_BOT, [new FakeAiGuardVerdict(
            schema: 'ai-guard.verdict/2',
            status: 'spoofed',
            category: 'search_engines',
            identity: 'Googlebot',
            ip: self::IP,
        )]);

        $this->assertNull(app(ActorAttributionStore::class)->forActor(self::IP));
    }

    #[Test]
    public function a_payload_missing_the_fields_entirely_is_ignored(): void
    {
        app(AiGuardVerdictListener::class)->handle(new \stdClass);

        $this->assertNull(app(ActorAttributionStore::class)->forActor(self::IP));
    }

    /**
     * The event channel runs this package's code inside another package's
     * dispatch loop. Whatever arrives, nothing may escape back into it.
     */
    #[Test]
    public function a_non_object_payload_never_reaches_the_dispatcher_as_an_error(): void
    {
        foreach (['a string', 42, null, ['schema' => AiGuardContract::SCHEMA]] as $payload) {
            Event::dispatch(AiGuardContract::EVENT_BOT_CLASSIFIED, [$payload]);
        }

        $this->assertNull(app(ActorAttributionStore::class)->forActor(self::IP));
    }

    #[Test]
    public function an_event_that_throws_on_read_never_reaches_the_dispatcher(): void
    {
        $hostile = new class
        {
            public function __isset(string $name): bool
            {
                throw new \RuntimeException("reading {$name} blew up");
            }

            public function __get(string $name): mixed
            {
                throw new \RuntimeException("reading {$name} blew up");
            }
        };

        Event::dispatch(AiGuardContract::EVENT_SPOOFED_BOT, [$hostile]);

        $this->assertNull(app(ActorAttributionStore::class)->forActor(self::IP));
    }

    /**
     * A well-formed verdict with no address to attach it to is ignored
     * *quietly*. The listener's catch-all would contain the TypeError that
     * passing it through causes — but then every such event writes an error
     * line into the operator's log for input that was not an error, and a log
     * that cries wolf stops being read.
     */
    #[Test]
    public function a_payload_without_an_ip_is_ignored_quietly(): void
    {
        Log::spy();

        $event = new \stdClass;
        $event->schema = AiGuardContract::SCHEMA;
        $event->status = 'spoofed';
        $event->category = 'search_engines';

        app(AiGuardVerdictListener::class)->handle($event);

        $this->assertNull(app(ActorAttributionStore::class)->forActor(self::IP));
        Log::shouldNotHaveReceived('error');
    }

    /**
     * The attribute channel, which is the one that still works when ai-guard's
     * own interop events are switched off.
     */
    #[Test]
    public function the_request_attribute_reaches_the_store_through_the_middleware(): void
    {
        config([
            'threat-detection.enabled' => true,
            'threat-detection.skip_paths' => [],
            'threat-detection.only_paths' => [],
            'threat-detection.whitelisted_ips' => [],
        ]);

        // ai-guard's middleware running first, leaving its verdict behind —
        // the ordering in which the attribute channel is the one that works.
        Route::middleware([FakeAiGuardMiddleware::class, 'threat-detect'])
            ->get('/agent-page', fn () => response('OK'));

        $this->get('/agent-page')->assertStatus(200);

        $stored = app(ActorAttributionStore::class)->forActor('127.0.0.1');

        $this->assertNotNull($stored, 'the middleware never read the ai-guard attribute');
        $this->assertSame('verified', $stored['status']);
        $this->assertSame('ai_agents', $stored['category']);
        $this->assertSame('chatgpt.com', $stored['identity']);
    }

    /**
     * Two layers stand between another package's malformed data and a lost
     * detection, and each is tested on its own — tested together, removing
     * either would pass, because the other still holds.
     *
     * This is the inner one: the listener does not throw on a field of the
     * wrong type.
     */
    #[Test]
    public function the_listener_does_not_throw_on_a_wrongly_typed_field(): void
    {
        $request = Request::create('/probe-me', 'GET');
        $request->server->set('REMOTE_ADDR', self::IP);
        $request->attributes->set(AiGuardContract::REQUEST_ATTRIBUTE, [
            'schema' => AiGuardContract::SCHEMA,
            'bot' => new \stdClass,
            'verification' => ['status' => 'spoofed', 'method' => 'reverse_dns'],
        ]);

        app(AiGuardVerdictListener::class)->ingestRequest($request);

        // The well-formed half is still used.
        $this->assertSame('spoofed', app(ActorAttributionStore::class)->forActor(self::IP)['status']);
    }

    /**
     * And the outer one, which is the property that actually matters: however
     * the integration fails, the request keeps its detection.
     *
     * Found by mutation testing. The first version only asserted a 200, which
     * held — the middleware's outer catch saw to that — while the attack in
     * the same request went unlogged, because the integration shared a try
     * block with detection and a throw skipped straight past it.
     */
    #[Test]
    public function a_failing_integration_never_costs_the_request_its_detection(): void
    {
        config([
            'threat-detection.enabled' => true,
            'threat-detection.detection_mode' => 'strict',
            'threat-detection.min_confidence' => 0,
            'threat-detection.skip_paths' => [],
            'threat-detection.only_paths' => [],
            'threat-detection.whitelisted_ips' => [],
            'threat-detection.api_route_filtering.enabled' => false,
            'threat-detection.notifications.enabled' => false,
            'threat-detection.queue.enabled' => false,
        ]);

        $this->app->instance(AiGuardVerdictListener::class, new class(app(ActorAttributionStore::class)) extends AiGuardVerdictListener
        {
            public function ingestRequest(Request $request): void
            {
                throw new \RuntimeException('simulated integration failure');
            }
        });

        Route::middleware([FakeAiGuardMiddlewareWithGarbage::class, 'threat-detect'])
            ->get('/search-guarded', fn () => response('OK'));

        $this->get('/search-guarded?q=' . urlencode("' UNION SELECT password FROM users--"))
            ->assertStatus(200);

        $this->assertGreaterThan(
            0,
            DB::table('threat_logs')->where('type', 'like', '%SQL Injection%')->count(),
            'the integration failed and took the request\'s detection down with it'
        );
    }

    #[Test]
    public function a_request_without_the_attribute_stores_nothing(): void
    {
        $request = Request::create('/probe-me', 'GET');
        $request->server->set('REMOTE_ADDR', self::IP);

        app(AiGuardVerdictListener::class)->ingestRequest($request);

        $this->assertNull(app(ActorAttributionStore::class)->forActor(self::IP));
    }

    #[Test]
    public function a_malformed_request_attribute_is_ignored(): void
    {
        $malformed = [
            'not-an-array',
            ['schema' => 'wrong'],
            ['bot' => 'not-an-array'],
            // Everything valid except the schema. The only case here the
            // schema check alone stands between and a stored verdict — the
            // others are also empty, so the store would discard them anyway
            // and they cannot tell whether the check exists.
            [
                'schema' => 'ai-guard.verdict/2',
                'bot' => ['category' => 'search_engines', 'token' => 'Googlebot', 'identity' => 'Googlebot'],
                'verification' => ['status' => 'spoofed', 'method' => 'reverse_dns'],
            ],
        ];

        foreach ($malformed as $attribute) {
            $request = Request::create('/probe-me', 'GET');
            $request->server->set('REMOTE_ADDR', self::IP);
            $request->attributes->set(AiGuardContract::REQUEST_ATTRIBUTE, $attribute);

            app(AiGuardVerdictListener::class)->ingestRequest($request);

            $this->assertNull(app(ActorAttributionStore::class)->forActor(self::IP));
        }
    }

    // ── The contract itself ────────────────────────────────────────────────

    /**
     * Every other test in this file builds its payloads *from* these
     * constants, so a typo here would change both sides at once and the whole
     * file would stay green while the real integration silently stopped
     * working. This pins them to the literal values in ai-guard's canonical
     * fixture, tests/Fixtures/interop/verdict-v1.json at v3.1.0.
     */
    #[Test]
    public function the_contract_matches_ai_guards_published_fixture(): void
    {
        $this->assertSame('ai-guard.verdict/1', AiGuardContract::SCHEMA);
        $this->assertSame('ai_guard.verdict', AiGuardContract::REQUEST_ATTRIBUTE);

        $this->assertSame('JayAnta\AiGuard\Events\BotClassified', AiGuardContract::EVENT_BOT_CLASSIFIED);
        $this->assertSame('JayAnta\AiGuard\Events\AgentVerified', AiGuardContract::EVENT_AGENT_VERIFIED);
        $this->assertSame('JayAnta\AiGuard\Events\SpoofedBotDetected', AiGuardContract::EVENT_SPOOFED_BOT);

        $this->assertSame('verified', AiGuardContract::STATUS_VERIFIED);
        $this->assertSame('spoofed', AiGuardContract::STATUS_SPOOFED);

        $this->assertSame(
            [AiGuardContract::EVENT_BOT_CLASSIFIED, AiGuardContract::EVENT_AGENT_VERIFIED, AiGuardContract::EVENT_SPOOFED_BOT],
            AiGuardContract::events()
        );
    }

    /**
     * All three events are listened for, not just the one the other tests
     * happen to dispatch. BotClassified is the one that fires for every
     * recognised bot, so missing it would lose most verdicts.
     */
    #[Test]
    public function every_contract_event_has_a_listener(): void
    {
        foreach (AiGuardContract::events() as $event) {
            $this->assertTrue(Event::hasListeners($event), "nothing listens for {$event}");
        }
    }

    // ── Isolation ──────────────────────────────────────────────────────────

    /**
     * The constraint the whole design exists to satisfy: ai-guard's namespace
     * appears in exactly one file, as strings, and is imported nowhere.
     *
     * Without this test the coupling would creep back one convenient `use`
     * statement at a time, and the failure mode — a fatal error for every
     * install that does not have ai-guard — only shows up on someone else's
     * machine.
     */
    #[Test]
    public function ai_guards_namespace_appears_in_exactly_one_source_file(): void
    {
        $offenders = [];

        foreach ($this->sourceFiles() as $file) {
            $contents = (string) file_get_contents($file);

            if (str_contains($contents, 'JayAnta\\AiGuard') && basename($file) !== 'AiGuardContract.php') {
                $offenders[] = $file;
            }
        }

        $this->assertSame([], $offenders, 'ai-guard class names leaked outside the contract file');
    }

    #[Test]
    public function no_source_file_imports_anything_from_ai_guard(): void
    {
        foreach ($this->sourceFiles() as $file) {
            $this->assertDoesNotMatchRegularExpression(
                '/^use\s+JayAnta\\\\AiGuard/m',
                (string) file_get_contents($file),
                basename($file) . ' imports from ai-guard, which is not installable as a dependency'
            );
        }
    }

    /** ai-guard must not be reachable as a Composer dependency, in either direction. */
    #[Test]
    public function the_package_does_not_require_ai_guard(): void
    {
        $composer = json_decode((string) file_get_contents(__DIR__ . '/../../composer.json'), true);

        $declared = array_merge(
            array_keys($composer['require'] ?? []),
            array_keys($composer['require-dev'] ?? []),
        );

        $this->assertNotContains('jayanta/laravel-ai-guard', $declared);
    }

    /**
     * And the classes are genuinely never loaded. If anything called
     * class_exists() or type-hinted one of them, this would be the symptom.
     */
    #[Test]
    public function no_ai_guard_class_is_ever_loaded(): void
    {
        $this->detection();

        Event::dispatch(AiGuardContract::EVENT_BOT_CLASSIFIED, [new FakeAiGuardVerdict(
            schema: AiGuardContract::SCHEMA,
            status: 'verified',
            category: 'search_engines',
            identity: 'Googlebot',
            ip: self::IP,
        )]);

        $this->score();

        $loaded = array_filter(
            get_declared_classes(),
            fn (string $class) => str_starts_with($class, 'JayAnta\\AiGuard')
        );

        $this->assertSame([], array_values($loaded));
    }

    /** @return array<int, string> */
    private function sourceFiles(): array
    {
        $files = [];
        $directory = new \RecursiveDirectoryIterator(__DIR__ . '/../../src');

        foreach (new \RecursiveIteratorIterator($directory) as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                $files[] = $file->getPathname();
            }
        }

        $this->assertNotEmpty($files, 'no source files were scanned, so the isolation tests prove nothing');

        return $files;
    }
}
