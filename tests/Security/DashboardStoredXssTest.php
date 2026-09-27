<?php

namespace JayAnta\ThreatDetection\Tests\Security;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * TD-001 — stored XSS in the dashboard.
 *
 * The package writes attacker-controlled strings to threat_logs and then
 * renders them to an authenticated administrator. If any of them reaches the
 * page unescaped, an attacker compromises the account of the person reading
 * the security log, from a request they made to a public route. That is the
 * worst failure this package can have.
 *
 * Every column is checked independently, because they take different routes to
 * the screen: ip_address and type are near-fixed, url is fully
 * attacker-controlled through the query string, and country_name comes from a
 * third party over cleartext HTTP.
 */
class DashboardStoredXssTest extends TestCase
{
    /**
     * Payloads chosen for the different sinks a dashboard can have: raw HTML,
     * an attribute, a JS string literal, a JSON island, and the Alpine
     * expression parser (which evaluates its argument).
     *
     * @return array<string, array{0: string}>
     */
    public static function xssPayloads(): array
    {
        return [
            'script tag' => ['<script>window.__pwned=1</script>'],
            'img onerror' => ['<img src=x onerror="window.__pwned=1">'],
            'svg onload' => ['<svg onload="window.__pwned=1">'],
            'attribute break-out' => ['" onmouseover="window.__pwned=1'],
            'single-quote break-out' => ["' onmouseover='window.__pwned=1"],
            'script close in a JS string' => ['</script><script>window.__pwned=1</script>'],
            'json island break-out' => ['</script><img src=x onerror=alert(1)>'],
            'alpine expression' => ['{{ constructor.constructor("window.__pwned=1")() }}'],
            'blade echo' => ['{{ $x }}'],
            'blade raw echo' => ['{!! $x !!}'],
            'html entity encoded' => ['&lt;script&gt;window.__pwned=1&lt;/script&gt;'],
            'javascript uri' => ['javascript:window.__pwned=1'],
            'data uri' => ['data:text/html,<script>window.__pwned=1</script>'],
            'unicode separators' => ["<script>\u{2028}window.__pwned=1</script>"],
        ];
    }

    /**
     * The dashboard's web route is registered while the provider boots, so
     * enabling it from setUp() would be too late and every request would 404.
     */
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('threat-detection.dashboard.enabled', true);
        $app['config']->set('threat-detection.dashboard.guard', 'none');
        $app['config']->set('threat-detection.dashboard.middleware', ['web']);

        // The 'web' group starts a session, which needs a key.
        $app['config']->set('app.key', 'base64:' . base64_encode(random_bytes(32)));
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();

        config([
            'threat-detection.enabled' => true,
            'cache.default' => 'array',
        ]);
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    /** Put a hostile value into one column, the way an attacker would. */
    private function seedRow(string $column, string $payload): void
    {
        DB::table('threat_logs')->insert(array_merge([
            'ip_address' => '203.0.113.9',
            'url' => 'https://example.com/search',
            'user_agent' => 'Mozilla/5.0',
            'type' => '[middleware] XSS Script Tag',
            'payload' => 'x',
            'threat_level' => 'high',
            'confidence_score' => 90,
            'confidence_label' => 'very_high',
            'action_taken' => 'logged',
            'country_name' => 'India',
            'country_code' => 'IN',
            'created_at' => now(),
            'updated_at' => now(),
        ], [$column => $payload]));
    }

    // ── the API, which is what the dashboard actually consumes ─────────────

    /**
     * The dashboard is an Alpine page that fetches JSON. So the first question
     * is whether the JSON response can itself be interpreted as HTML — if the
     * content type is wrong, or the payload can close a script tag, the escaping
     * on the page never gets a chance.
     */
    #[Test]
    #[DataProvider('xssPayloads')]
    public function the_threats_api_never_returns_an_attacker_payload_as_html(string $payload): void
    {
        $this->seedRow('url', $payload);

        $response = $this->getJson('/api/threat-detection/threats');

        $response->assertStatus(200);
        $this->assertStringStartsWith('application/json', $response->headers->get('Content-Type'));

        // The body must not be able to close a script tag. json_encode escapes
        // the forward slash by default, so "</script>" is emitted as
        // "<\/script>" — which is what makes embedding the response in HTML
        // survivable even though '<' itself is not hex-escaped.
        $this->assertStringNotContainsString(
            '</script>',
            $response->getContent(),
            'the JSON body can close a script tag'
        );
    }

    /**
     * TD-004 — the API sets no anti-sniffing header.
     *
     * The dashboard route sends a full set: CSP, X-Frame-Options,
     * X-Content-Type-Options and Referrer-Policy (DashboardController::
     * securityHeaders()). The API sends none — and the API is the half that
     * actually returns attacker-controlled strings, with '<' and '>' left
     * unescaped by json_encode.
     *
     * A modern browser will not sniff application/json as HTML, so this is
     * defence in depth rather than a live hole. It is asserted because the
     * package already decided these headers were worth sending on the other
     * route, and the inconsistency is the kind that gets noticed by an
     * attacker before an operator.
     */
    #[Test]
    public function every_api_endpoint_sends_an_anti_sniffing_header(): void
    {
        $this->seedRow('url', '<script>window.__pwned=1</script>');

        $missing = [];

        foreach (['/threats', '/stats', '/summary', '/top-ips', '/by-country', '/timeline', '/export', '/ai-threats'] as $endpoint) {
            $response = $this->get('/api/threat-detection' . $endpoint);

            if ($response->headers->get('X-Content-Type-Options') !== 'nosniff') {
                $missing[] = $endpoint;
            }
        }

        $this->assertSame([], $missing, 'endpoints returning attacker data without nosniff: ' . implode(', ', $missing));
    }

    /**
     * The CSV download is the one response that legitimately contains raw
     * attacker text. Content-Disposition: attachment is what stops a browser
     * rendering it, so that header is load-bearing and worth pinning.
     */
    #[Test]
    public function the_csv_export_is_served_as_an_attachment_rather_than_rendered(): void
    {
        $this->seedRow('url', '<script>window.__pwned=1</script>');

        $response = $this->get('/api/threat-detection/export');

        $response->assertStatus(200);
        $this->assertStringStartsWith('text/csv', (string) $response->headers->get('Content-Type'));
        $this->assertStringStartsWith(
            'attachment;',
            (string) $response->headers->get('Content-Disposition'),
            'the CSV is served inline, so a browser will render the attacker payload it contains'
        );
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function columns(): array
    {
        return [
            'url' => ['url'],
            'type' => ['type'],
            'ip_address' => ['ip_address'],
            'user_agent' => ['user_agent'],
            'country_name' => ['country_name'],
            'action_taken' => ['action_taken'],
        ];
    }

    #[Test]
    #[DataProvider('columns')]
    public function no_column_reaches_the_api_response_in_a_form_that_can_break_out_of_json(string $column): void
    {
        $this->seedRow($column, '</script><script>window.__pwned=1</script>');

        // JSON endpoints only. /export returns CSV, which legitimately carries
        // the raw text and is defended by Content-Disposition instead.
        foreach (['/threats', '/top-ips?limit=10', '/by-country', '/summary'] as $endpoint) {
            $response = $this->get('/api/threat-detection' . $endpoint);
            $body = $response->getContent();

            $this->assertStringNotContainsString(
                '</script>',
                $body,
                "{$endpoint} returned a closable script tag from the {$column} column"
            );
        }
    }

    // ── the rendered dashboard page ────────────────────────────────────────

    /**
     * The page itself is server-rendered Blade. Nothing from the database is
     * supposed to appear in it at all — the table is filled client-side from
     * the API — so any occurrence of a stored payload in the HTML is a finding
     * on its own, before asking whether it is escaped.
     */
    #[Test]
    #[DataProvider('xssPayloads')]
    public function the_dashboard_html_never_contains_stored_threat_data(string $payload): void
    {
        $this->seedRow('url', $payload);

        $response = $this->get('/threat-detection');
        $response->assertStatus(200);

        $html = $response->getContent();

        $this->assertStringNotContainsString(
            $payload,
            $html,
            'stored threat data was server-rendered into the dashboard'
        );
    }

    /**
     * The one server-rendered value on the page is the API prefix, injected
     * into a <script> block with @json. It is config-controlled rather than
     * attacker-controlled, but an operator who sets it from an environment
     * variable makes it a sink, so the escaping is worth pinning.
     */
    #[Test]
    public function the_api_prefix_cannot_break_out_of_the_script_block(): void
    {
        config(['threat-detection.api.prefix' => '</script><script>window.__pwned=1</script>']);

        $response = $this->get('/threat-detection');
        $response->assertStatus(200);

        $html = $response->getContent();

        // Blade's @json uses JSON_HEX_TAG, so '<' and '>' become </>.
        $this->assertStringNotContainsString('</script><script>', $html);
        $this->assertStringContainsString('<', $html, '@json did not hex-escape the tag characters');
    }

    /**
     * Alpine evaluates the *expression* in x-text, not the value it produces,
     * and x-text assigns to textContent. Both properties matter, and both are
     * structural: they hold because the template never interpolates data into
     * an expression and never uses x-html. Asserted against the template so a
     * future edit that introduces either fails here.
     */
    #[Test]
    public function the_dashboard_template_uses_no_html_rendering_sink(): void
    {
        $template = file_get_contents(__DIR__ . '/../../resources/views/dashboard.blade.php')
            . file_get_contents(__DIR__ . '/../../resources/views/layouts/app.blade.php');

        foreach (['x-html', '{!!', 'innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write'] as $sink) {
            $this->assertStringNotContainsString(
                $sink,
                $template,
                "the dashboard template uses {$sink}, which renders its argument as HTML"
            );
        }
    }

    /**
     * A :class or :style binding is an Alpine expression. If threat data were
     * concatenated into one, the value would be evaluated as JavaScript. The
     * template routes threat_level and confidence_label through lookup maps
     * with a fixed default instead, which is what makes them safe.
     */
    #[Test]
    public function a_hostile_threat_level_cannot_reach_an_alpine_class_binding(): void
    {
        $this->seedRow('threat_level', 'high\'); window.__pwned=1; (\'');

        $response = $this->getJson('/api/threat-detection/threats');
        $response->assertStatus(200);

        $level = $response->json('data.data.0.threat_level');

        // The value survives to the client, but levelBadge() maps it through a
        // dictionary and falls back to a constant, so it is never evaluated.
        $this->assertIsString($level);

        $template = file_get_contents(__DIR__ . '/../../resources/views/dashboard.blade.php');
        $this->assertStringContainsString('levelBadge(threat.threat_level)', $template);
        $this->assertMatchesRegularExpression(
            '/levelBadge\(level\)\s*\{\s*return\s*\{/',
            $template,
            'levelBadge no longer looks the level up in a fixed map'
        );
    }

    // ── the full round trip, as an attacker would run it ───────────────────

    /**
     * End to end: a public request carrying an XSS payload, then an
     * administrator opening the dashboard and the API behind it.
     */
    #[Test]
    public function a_payload_sent_to_a_public_route_never_executes_for_the_admin_reading_the_log(): void
    {
        Route::middleware('threat-detect')->get('/public-search', fn () => response('OK', 200));

        $payload = '</script><script>window.__pwned=1</script>';

        $this->get('/public-search?q=' . urlencode($payload))->assertStatus(200);
        $this->assertGreaterThan(0, DB::table('threat_logs')->count(), 'the payload was not even detected');

        $dashboard = $this->get('/threat-detection')->getContent();
        $this->assertStringNotContainsString('window.__pwned', $dashboard);

        foreach (['/threats', '/summary', '/top-ips'] as $endpoint) {
            $body = $this->get('/api/threat-detection' . $endpoint)->getContent();
            $this->assertStringNotContainsString('</script>', $body, "{$endpoint} leaked a closable script tag");
        }
    }
}
