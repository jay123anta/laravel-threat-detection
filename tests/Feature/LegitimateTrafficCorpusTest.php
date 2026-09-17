<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * Legitimate traffic that looks like an attack.
 *
 * This is the failure mode operators actually hit. A missed attack is
 * invisible; a false positive arrives as a page of alerts about a customer
 * writing a support ticket, and it is what makes people uninstall.
 *
 * ProductionFlowTest already drives a plausible application's ordinary
 * traffic. This file is the harder half: content that a signature engine
 * genuinely cannot distinguish from an attack without being told — code
 * samples, SQL tutorials, pasted stack traces, relative file paths, and
 * identifiers shaped like PII.
 *
 * It is organised around an honest distinction:
 *
 *   Clean by design — the package already separates these from attacks, and a
 *   regression would be a real defect. Asserted as clean.
 *
 *   Noise floor — the package flags these with no configuration, and given a
 *   signature engine it is right to. Pinned in one list so that any change is
 *   a decision rather than an accident, and each is then shown to be
 *   silenced by the mitigation the README prescribes — *without* the
 *   mitigation blinding the detector to a real attack alongside it.
 *
 * All of this runs in `balanced`, the shipped default. Existing files mostly
 * run `strict`, which is not what an operator gets out of the box.
 */
class LegitimateTrafficCorpusTest extends TestCase
{
    private const BROWSER = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
        . '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();

        config([
            'threat-detection.enabled' => true,
            // The shipped default, deliberately. Not strict.
            'threat-detection.detection_mode' => 'balanced',
            'threat-detection.min_confidence' => 0,
            'threat-detection.whitelisted_ips' => [],
            'threat-detection.notifications.enabled' => false,
            'threat-detection.queue.enabled' => false,
            'cache.default' => 'array',
        ]);

        $this->registerRoutes();
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    private function registerRoutes(): void
    {
        Route::middleware('threat-detect')->group(function () {
            foreach ([
                'search', 'blog/posts', 'docs/submit', 'files/download',
                'orders', 'profile', 'support/tickets', 'api/v1/orders',
            ] as $uri) {
                Route::get('/' . $uri, fn () => response('OK', 200));
                Route::post('/' . $uri, fn () => response('OK', 200));
            }
        });
    }

    private function browser(): array
    {
        return ['HTTP_USER_AGENT' => self::BROWSER];
    }

    /** @return string[] sorted "Label/level" strings for everything logged */
    private function logged(): array
    {
        $out = DB::table('threat_logs')
            ->get(['type', 'threat_level'])
            ->map(fn ($r) => preg_replace('/^\[[a-z-]+\] /', '', $r->type) . '/' . $r->threat_level)
            ->all();
        sort($out);

        return $out;
    }

    private function assertNothingLogged(string $because): void
    {
        $this->assertSame([], $this->logged(), $because);
    }

    // ── clean by design ─────────────────────────────────────────────────────

    /**
     * Identifiers that happen to be shaped like Indian PII, in fields that
     * have nothing to do with PII. Before v1.7.0 the PII patterns were gated
     * behind credential keywords they never contained, and a later fix moved
     * them to a 'pii' category keyed on field names — which is what keeps an
     * order id from being read as a bank account.
     *
     * @return array<string, array{0: array<string, string>}>
     */
    public static function identifiersShapedLikePii(): array
    {
        return [
            'a SKU shaped like a PAN' => [['sku' => 'ABCDE1234F', 'qty' => '2']],
            'a coupon code shaped like a PAN' => [['coupon' => 'SAVE12345X']],
            'a twelve-digit order number' => [['order_id' => '202601150001']],
            'a ten-digit reference starting with 9' => [['reference' => '9876543210']],
            'an epoch timestamp in milliseconds' => [['placed_at' => '1735689600000']],
            'a fourteen-digit tracking number' => [['tracking' => '12345678901234']],
            'an IFSC-shaped product code' => [['product' => 'HDFC0AB1234']],
            'a nine-digit invoice number' => [['invoice_no' => '987654321']],
        ];
    }

    #[Test]
    #[DataProvider('identifiersShapedLikePii')]
    public function an_identifier_shaped_like_pii_in_an_unrelated_field_is_not_logged_as_pii(array $body): void
    {
        $this->postJson('/orders', $body)->assertStatus(200);

        $this->assertNothingLogged('an ordinary order field was logged as personal data');
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function harmlessSearchQueries(): array
    {
        return [
            'union as an English noun' => ['credit union near me'],
            'union in a brand name' => ['western union transfer fees'],
            'a question about entities' => ['Marks &amp; Spencer gift card'],
            'a question about a config file' => ['where is the .env file stored'],
            'a question about two manifests' => ['composer.json vs package.json'],
            'a question about a dotfile' => ['should I commit the .git directory'],
            'an ordinary product search' => ['waterproof running shoes size 9'],
            'a search with an apostrophe' => ["men's winter jacket"],
            'a search with a hyphen pair' => ['low-cost -- best value'],
            'a version number' => ['upgrade to 8.4.0 from 8.1.25'],
            'an email address' => ['invoice for jane.doe@example.com'],
            'a percentage' => ['30% off winter sale'],
        ];
    }

    #[Test]
    #[DataProvider('harmlessSearchQueries')]
    public function an_ordinary_search_query_is_not_logged(string $query): void
    {
        $this->get('/search?q=' . urlencode($query), $this->browser())->assertStatus(200);

        $this->assertNothingLogged("an ordinary search for '{$query}' was logged as a threat");
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function harmlessProse(): array
    {
        return [
            'a sentence with a semicolon' => ['The build failed; I retried it and it passed.'],
            'a sentence with an ampersand' => ['Sales & marketing both signed off.'],
            'a CSS rule' => ['Target it with .card > .title { color: red; }'],
            'a markdown heading' => ['## Release notes for 1.7.2'],
            'a shell prompt in prose' => ['Run the migration and then restart the queue worker.'],
            'a currency amount' => ['The total came to $1,299.00 including tax.'],
            'a normal user agent pasted by a customer' => ['My browser reports Mozilla/5.0 and it still fails'],
        ];
    }

    #[Test]
    #[DataProvider('harmlessProse')]
    public function ordinary_prose_in_a_support_ticket_is_not_logged(string $body): void
    {
        $this->post('/support/tickets', ['body' => $body], $this->browser())->assertStatus(200);

        $this->assertNothingLogged("ordinary prose was logged as a threat: {$body}");
    }

    // ── the noise floor, pinned ─────────────────────────────────────────────

    /**
     * Attack-shaped legitimate content, under the shipped default config with
     * no tuning whatsoever.
     *
     * Everything in this list is a false positive in the sense that no attack
     * occurred — and every one of them is also a correct signature match. A
     * blog post that contains <script>window.dataLayer=[]</script> is, byte
     * for byte, a stored-XSS payload; nothing but application context can
     * separate them, and the package's answer is safe_fields / safe_paths /
     * content_paths.
     *
     * Pinned as one explicit expectation so a change to any pattern shows up
     * here as a decision to make rather than as noise an operator discovers in
     * production.
     */
    #[Test]
    public function the_untuned_noise_floor_on_attack_shaped_legitimate_content(): void
    {
        $browser = $this->browser();

        $observed = [];

        $corpus = [
            'sql tutorial in a search box' => fn () => $this->get('/search?q=' . urlencode('how to write a UNION SELECT in postgres'), $browser),
            'javascript snippet in a blog post' => fn () => $this->post('/blog/posts', [
                'title' => 'Adding analytics',
                'body' => "Paste this into your layout:\n<script>window.dataLayer=[];</script>\nThen deploy.",
            ], $browser),
            'php snippet in a blog post' => fn () => $this->post('/blog/posts', [
                'title' => 'Shell out safely',
                'body' => 'Never call system("rm -rf /tmp/x") on user input.',
            ], $browser),
            'an html attribute tip in a blog post' => fn () => $this->post('/blog/posts', [
                'body' => 'Use <img src=logo.png onerror="this.src=fallback.png"> for a graceful fallback.',
            ], $browser),
            'a traversal explainer in documentation' => fn () => $this->post('/docs/submit', [
                'body' => 'A path like ../../etc/passwd is the classic traversal payload.',
            ], $browser),
            'a legitimate relative file path' => fn () => $this->get('/files/download?path=' . urlencode('reports/2026/../2025/q4.pdf'), $browser),
            'a pasted sql error in a support ticket' => fn () => $this->post('/support/tickets', [
                'body' => 'I get SQLSTATE[42S02]: Base table not found: SELECT * FROM users WHERE id = 1',
            ], $browser),
            'a blade syntax question in a search box' => fn () => $this->get('/search?q=' . urlencode('what does {{ }} mean in blade'), $browser),
            'a placeholder syntax question' => fn () => $this->get('/search?q=' . urlencode('${price} placeholder syntax'), $browser),
            'a markdown link through a redirector' => fn () => $this->post('/blog/posts', [
                'body' => 'See [the docs](https://example.com/redirect?url=https://example.com/next)',
            ], $browser),
            'a windows path in a blog post' => fn () => $this->post('/blog/posts', [
                'body' => 'On Windows the config lives at C:\\inetpub\\web.config',
            ], $browser),
            'a profile form collecting genuine indian pii' => fn () => $this->postJson('/profile', [
                'name' => 'Priya Sharma', 'mobile' => '9876543210', 'pan' => 'ABCDE1234F',
            ]),
        ];

        foreach ($corpus as $name => $send) {
            DB::table('threat_logs')->delete();
            Cache::flush();
            $send();
            $observed[$name] = $this->logged();
        }

        // assertSame is order-sensitive on associative arrays, and the corpus
        // above and the expectation below now live in two places. Sort both by
        // case so adding a case mid-list reads as what it is, rather than as a
        // noise-floor change that did not happen.
        $expected = self::untunedNoiseFloor();
        ksort($expected);
        ksort($observed);

        $this->assertSame($expected, $observed, 'the untuned noise floor changed — confirm this is intended');
    }

    /**
     * The measured floor, as one source of truth.
     *
     * Extracted from the assertion above because the README publishes a subset
     * of it, and a documented false-positive table that silently drifts from
     * the measured one is worse than none at all. `ReadmeNoiseFloorTest`
     * checks the README against this.
     *
     * @return array<string, string[]> corpus case => "label/severity" pairs
     */
    public static function untunedNoiseFloor(): array
    {
        return [
            'sql tutorial in a search box' => ['SQL Injection UNION/high'],
            'javascript snippet in a blog post' => ['Command Chain Injection/medium', 'XSS Script Tag/high'],
            'php snippet in a blog post' => ['RCE Shell Function/high'],
            'an html attribute tip in a blog post' => ['OnError Event Handler/low', 'XSS HTML Event Handler/high'],
            'a traversal explainer in documentation' => ['Directory Traversal/medium', 'Sensitive File Access/medium'],
            'a legitimate relative file path' => ['Directory Traversal/medium'],
            'a pasted sql error in a support ticket' => ['SQL SELECT Query/low', 'SQLi Variant/high'],
            'a blade syntax question in a search box' => ['Blade/Liquid Template Injection/low'],
            'a placeholder syntax question' => ['Expression Language Injection/low'],
            'a markdown link through a redirector' => ['Open Redirect/medium'],
            'a windows path in a blog post' => ['Server Config Access/medium'],
            'a profile form collecting genuine indian pii' => [
                'Bank Account Number Detected/high', 'Mobile Number Detected/low', 'PAN Number Detected/high',
            ],
        ];
    }

    /**
     * A semicolon that is not preceded by a letter or digit is a Command Chain
     * Injection match, which is why the analytics snippet above logs one. It
     * is worth isolating, because it is the pattern most likely to fire on
     * pasted code of any language — and the shape of the false positive is
     * narrower than it first looks.
     */
    #[Test]
    public function a_semicolon_only_reads_as_command_chaining_when_it_does_not_follow_a_word_character(): void
    {
        $this->post('/support/tickets', ['body' => 'The build failed; I retried it.'], $this->browser());
        $this->assertNothingLogged('a semicolon directly after a word must not read as command chaining');

        DB::table('threat_logs')->delete();
        Cache::flush();

        $this->post('/support/tickets', ['body' => 'const a = [] ; const b = 2'], $this->browser());
        $this->assertContains('Command Chain Injection/medium', $this->logged());
    }

    // ── the mitigations must actually work ─────────────────────────────────

    /**
     * safe_fields on a rich-text body, which is what the README tells a CMS
     * operator to do.
     */
    #[Test]
    public function safe_fields_silences_a_code_sample_in_a_blog_body(): void
    {
        config(['threat-detection.safe_fields' => ['body']]);

        $this->post('/blog/posts', [
            'title' => 'Adding analytics',
            'body' => '<script>window.dataLayer=[];</script>',
        ], $this->browser())->assertStatus(200);

        $this->assertNothingLogged('safe_fields did not exempt the field it names');
    }

    /**
     * ...and the exemption must be a scalpel. An attack in a sibling field on
     * the same request is still scanned, otherwise safe_fields is a way to
     * turn the detector off one form at a time.
     */
    #[Test]
    public function safe_fields_does_not_exempt_a_sibling_field_on_the_same_request(): void
    {
        config(['threat-detection.safe_fields' => ['body']]);

        $this->post('/blog/posts', [
            'body' => '<script>window.dataLayer=[];</script>',
            'title' => "' UNION SELECT password FROM users--",
        ], $this->browser())->assertStatus(200);

        $this->assertContains('SQL Injection UNION/high', $this->logged());
    }

    #[Test]
    public function safe_paths_silences_a_legitimate_pii_field_without_exempting_the_key_everywhere(): void
    {
        config(['threat-detection.safe_paths' => ['mobile', 'pan']]);

        $this->postJson('/profile', ['name' => 'Priya Sharma', 'mobile' => '9876543210', 'pan' => 'ABCDE1234F'])
            ->assertStatus(200);

        $this->assertNothingLogged('safe_paths did not exempt the paths it names');
    }

    #[Test]
    public function safe_paths_still_scans_a_pii_value_that_arrives_under_a_different_key(): void
    {
        config(['threat-detection.safe_paths' => ['mobile', 'pan']]);

        // The same value, leaking through a field nobody exempted.
        $this->postJson('/profile', ['name' => 'Priya', 'bank_account' => '123456789012'])
            ->assertStatus(200);

        $this->assertContains('Bank Account Number Detected/high', $this->logged());
    }

    #[Test]
    public function content_paths_silences_the_medium_and_low_noise_from_a_cms_editor(): void
    {
        config(['threat-detection.content_paths' => ['blog/posts']]);

        $this->post('/blog/posts', [
            'body' => 'Use <img src=logo.png onerror="this.src=fallback.png"> as a fallback.',
        ], $this->browser())->assertStatus(200);

        $this->assertNotContains('OnError Event Handler/low', $this->logged());
    }

    /**
     * content_paths must not be a blanket exemption: a high-severity match on
     * a content path is still recorded. This is the guarantee that makes it
     * safe to recommend.
     */
    #[Test]
    public function content_paths_still_records_a_high_severity_attack(): void
    {
        config(['threat-detection.content_paths' => ['blog/posts']]);

        $this->post('/blog/posts', ['body' => "' UNION SELECT password FROM users--"], $this->browser())
            ->assertStatus(200);

        $this->assertContains('SQL Injection UNION/high', $this->logged());
    }

    /**
     * The last resort in the README for a route that legitimately serves a
     * path the endpoint patterns match. skip_paths turns scanning off for the
     * route entirely, which is why it is the last resort.
     */
    #[Test]
    public function skip_paths_silences_a_route_completely_including_real_attacks(): void
    {
        config(['threat-detection.skip_paths' => ['search']]);

        $this->get('/search?q=' . urlencode("' UNION SELECT password FROM users--"), $this->browser())
            ->assertStatus(200);

        $this->assertNothingLogged('skip_paths is documented as switching the route off entirely');
    }

    /**
     * Removing a pattern from custom_patterns is the surgical alternative to
     * skip_paths — the route keeps being scanned for everything else.
     */
    #[Test]
    public function dropping_one_custom_pattern_silences_it_without_unmonitoring_the_route(): void
    {
        $shipped = require __DIR__ . '/../../config/threat-detection.php';
        config([
            'threat-detection.custom_patterns' => array_filter(
                $shipped['custom_patterns'],
                fn ($entry) => (is_array($entry) ? ($entry['label'] ?? '') : $entry) !== 'Blade/Liquid Template Injection'
            ),
        ]);
        ThreatDetectionService::flushCaches();

        $this->get('/search?q=' . urlencode('what does {{ }} mean in blade'), $this->browser());
        $this->assertNothingLogged('the dropped pattern still fired');

        DB::table('threat_logs')->delete();
        Cache::flush();

        $this->get('/search?q=' . urlencode("' UNION SELECT password FROM users--"), $this->browser());
        $this->assertContains('SQL Injection UNION/high', $this->logged());
    }

    // ── mode differences on the same corpus ────────────────────────────────

    /**
     * relaxed mode keeps only high-severity patterns. It is the setting an
     * operator drowning in noise will reach for, and nothing exercised it
     * before this file — the relaxed branches in the service were uncovered.
     */
    #[Test]
    public function relaxed_mode_drops_the_low_and_medium_noise_from_legitimate_content(): void
    {
        config(['threat-detection.detection_mode' => 'relaxed']);

        $this->get('/search?q=' . urlencode('what does {{ }} mean in blade'), $this->browser());

        $this->assertNothingLogged('relaxed mode still logged a low-severity template match');
    }

    /**
     * BUG 5 (fixed) — in relaxed mode a lone high-severity match could never be logged.
     *
     * relaxed sets the minimum confidence to 40 (ThreatDetectionService, the
     * $modeMinConfidence match) *and* subtracts 10 from every score
     * (ConfidenceScorer::calculate()). The arithmetic for one match is then:
     *
     *     20 base + 0 extra + 15 high-severity + 10 context - 10 relaxed = 35
     *
     * and from a request body, where the context weight is 1.0 and earns no
     * bonus at all, 25. Both are below 40, so the detection is discarded
     * silently. The only way a single match clears the bar is an attack-tool
     * user agent (+25) — that is, an attacker who announces themselves.
     *
     * Two or more simultaneous high-severity matches reach 40 and are logged,
     * so relaxed mode is not inert; it is a two-signature minimum. But the
     * config describes it as "only high-severity patterns trigger"
     * (config/threat-detection.php:365), and it is recommended to exactly the
     * operators least able to notice — content-heavy sites already ignoring
     * their false positives.
     *
     * Fixed by lowering the relaxed floor to 25, the lowest score a lone
     * high-severity match can produce.
     */
    #[Test]
    public function relaxed_mode_still_records_a_high_severity_attack(): void
    {
        config(['threat-detection.detection_mode' => 'relaxed']);

        $this->get('/search?q=' . urlencode("' UNION SELECT password FROM users--"), $this->browser());

        $this->assertContains('SQL Injection UNION/high', $this->logged());
    }

    /** The same attack from a self-identifying tool does clear the bar. */
    #[Test]
    public function relaxed_mode_records_the_same_attack_when_the_user_agent_is_an_attack_tool(): void
    {
        config(['threat-detection.detection_mode' => 'relaxed']);

        $this->get(
            '/search?q=' . urlencode("' UNION SELECT password FROM users--"),
            ['HTTP_USER_AGENT' => 'sqlmap/1.7.2#stable (https://sqlmap.org)']
        );

        $this->assertContains('SQL Injection UNION/high', $this->logged());
    }

    #[Test]
    public function strict_mode_logs_at_least_as_much_as_balanced_on_the_same_request(): void
    {
        $query = '/search?q=' . urlencode('select a plan from our pricing page');

        config(['threat-detection.detection_mode' => 'balanced']);
        $this->get($query, $this->browser());
        $balanced = $this->logged();

        DB::table('threat_logs')->delete();
        Cache::flush();

        config(['threat-detection.detection_mode' => 'strict']);
        $this->get($query, $this->browser());
        $strict = $this->logged();

        $this->assertGreaterThanOrEqual(count($balanced), count($strict));
        foreach ($balanced as $entry) {
            $this->assertContains($entry, $strict, 'balanced logged something strict did not');
        }
    }

    // ── none of this ever costs the response ───────────────────────────────

    #[Test]
    public function every_piece_of_legitimate_content_still_gets_its_response(): void
    {
        $browser = $this->browser();

        $this->get('/search?q=' . urlencode('how to write a UNION SELECT in postgres'), $browser)->assertStatus(200);
        $this->post('/blog/posts', ['body' => '<script>window.dataLayer=[];</script>'], $browser)->assertStatus(200);
        $this->post('/docs/submit', ['body' => '../../etc/passwd is the classic payload'], $browser)->assertStatus(200);
        $this->postJson('/profile', ['mobile' => '9876543210', 'pan' => 'ABCDE1234F'])->assertStatus(200);
        $this->get('/files/download?path=' . urlencode('reports/2026/../2025/q4.pdf'), $browser)->assertStatus(200);
    }
}
