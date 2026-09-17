<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use ReflectionClass;

/**
 * What ends up in threat_logs when the request that tripped a detection was
 * also carrying credentials.
 *
 * The package already takes this seriously — the redact block exists precisely
 * to stop the detector becoming "a second, concentrated copy of exactly what it
 * warns you about" (config/threat-detection.php, the Redaction section). These
 * tests check that it achieves that on the request shape that actually occurs:
 * a login form.
 *
 * It did not, until redaction stopped depending on a detection pattern having
 * fired. See BUG 6 below.
 */
class CredentialExposureTest extends TestCase
{
    /** Distinctive enough that finding it in a column is unambiguous. */
    private const SECRET = 'Tr0ub4dor&3-correct-horse-battery';

    private const ATTACK = "' UNION SELECT password FROM users--";

    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();

        config([
            'threat-detection.enabled' => true,
            'threat-detection.detection_mode' => 'balanced',
            'threat-detection.min_confidence' => 0,
            'threat-detection.redact.enabled' => true,
            'threat-detection.safe_fields' => [],
            'threat-detection.notifications.enabled' => false,
            'cache.default' => 'array',
        ]);

        Route::middleware('threat-detect')->group(function () {
            foreach (['login', 'register', 'password/reset', 'account/settings', 'search'] as $uri) {
                Route::get('/' . $uri, fn () => response('OK', 200));
                Route::post('/' . $uri, fn () => response('OK', 200));
            }
        });
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    /**
     * Everything persisted for this request, as one searchable string.
     *
     * The url column is appended a second time url-decoded: a secret in a
     * query string is stored percent-encoded, which is not protection —
     * anyone reading the dashboard sees it decoded — and searching only the
     * raw column would miss it whenever the secret contains a character the
     * encoder touches.
     */
    private function persisted(): string
    {
        return DB::table('threat_logs')
            ->get(['url', 'payload', 'type', 'user_agent'])
            ->map(fn ($r) => implode("\n", (array) $r) . "\n" . urldecode((string) $r->url))
            ->implode("\n");
    }

    private function assertSecretNotPersisted(string $what): void
    {
        $this->assertGreaterThan(0, DB::table('threat_logs')->count(), 'nothing was detected, so this proves nothing');

        $this->assertStringNotContainsString(
            self::SECRET,
            $this->persisted(),
            "{$what} was written to threat_logs in cleartext"
        );
    }

    // ── BUG 6: credentials were stored in cleartext ─────────────────────────

    /**
     * BUG 6 (fixed) — every credential pattern missed the form the package
     * actually scans, so redaction never ran and plaintext secrets were
     * persisted.
     *
     * buildPayloadSegments() json_encodes each segment before matching. A form
     * field arrives on the wire as
     *
     *     password=Tr0ub4dor
     *
     * and is scanned as
     *
     *     {"password":"Tr0ub4dor"}
     *
     * The credential patterns are all written for the wire form —
     * /\bpassword\s*=\s*["\']?.{8,40}["\']?/i wants the key followed by
     * optional whitespace and then = or :. In the JSON form there is a closing
     * quote in between, so the match failed. One character.
     *
     * Because the label never fired, sensitiveLabelsAmong() returned nothing
     * for it, redact() had nothing to mask, and the full body — password
     * included — was stored in threat_logs.payload for the whole retention
     * period, readable by anyone with dashboard or database access. If the
     * credential was in the query string it landed in the url column too.
     *
     * Six of the seven credential patterns were affected: Password Exposure,
     * API Key Exposure, Access Token Leak, Session ID Leak, PHP Session
     * Exposure and CSRF Token Reference. Only Bearer Token Detected escaped,
     * because its keyword lives in the value rather than the key.
     *
     * The trigger was ordinary. Any request that tripped any pattern while
     * also carrying a credential field was enough — a bot spraying SQL
     * injection at a login form produced one row per attempt, each holding a
     * real user's password.
     *
     * auth_paths did not help; it made this worse. It excludes the credential
     * labels from firing on /login and /register so they do not generate noise
     * there, which also guaranteed redaction could not run on the paths where
     * passwords are most likely to be present.
     *
     * The fix does not touch the patterns. Redaction now has a second,
     * independent pass — redactSensitiveFields() — that masks anything under a
     * name listed in redact.fields, whether or not a pattern noticed it.
     * Making the patterns match the JSON form instead would have fired
     * "Password Exposure" on every legitimate login; see
     * a_credential_pattern_reads_the_wire_form_but_not_the_json_form() below.
     */
    #[Test]
    public function a_password_posted_to_a_login_form_is_not_persisted_in_cleartext(): void
    {
        $this->post('/login', ['email' => self::ATTACK, 'password' => self::SECRET])->assertStatus(200);

        $this->assertSecretNotPersisted('a login password');
    }

    #[Test]
    public function a_password_posted_as_json_is_not_persisted_in_cleartext(): void
    {
        $this->postJson('/login', ['email' => self::ATTACK, 'password' => self::SECRET])->assertStatus(200);

        $this->assertSecretNotPersisted('a JSON login password');
    }

    #[Test]
    public function a_password_in_the_query_string_is_not_persisted_in_the_url_column(): void
    {
        $this->get('/search?password=' . urlencode(self::SECRET) . '&q=' . urlencode(self::ATTACK))
            ->assertStatus(200);

        $this->assertStringNotContainsString(
            self::SECRET,
            urldecode((string) DB::table('threat_logs')->value('url')),
            'a password in the query string was stored in the url column'
        );
        $this->assertSecretNotPersisted('a password in the query string');
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function credentialFieldNames(): array
    {
        return [
            'password' => ['password'],
            'password_confirmation' => ['password_confirmation'],
            'current_password' => ['current_password'],
            'new_password' => ['new_password'],
            'api_key' => ['api_key'],
            'access_token' => ['access_token'],
            'session_id' => ['session_id'],
            'secret' => ['secret'],
            'client_secret' => ['client_secret'],
            'private_key' => ['private_key'],
        ];
    }

    #[Test]
    #[DataProvider('credentialFieldNames')]
    public function a_secret_under_a_credential_field_name_is_not_persisted_in_cleartext(string $field): void
    {
        $this->post('/account/settings', [
            $field => self::SECRET,
            'bio' => '<script>alert(1)</script>',
        ])->assertStatus(200);

        $this->assertSecretNotPersisted("the {$field} field");
    }

    #[Test]
    public function a_registration_form_does_not_persist_the_password_twice_over(): void
    {
        $this->post('/register', [
            'name' => '<script>alert(1)</script>',
            'email' => 'jane@example.com',
            'password' => self::SECRET,
            'password_confirmation' => self::SECRET,
        ])->assertStatus(200);

        $this->assertSecretNotPersisted('a registration password');
    }

    #[Test]
    public function a_password_reset_does_not_persist_the_new_password(): void
    {
        $this->post('/password/reset', [
            'token' => self::ATTACK,
            'email' => 'jane@example.com',
            'password' => self::SECRET,
        ])->assertStatus(200);

        $this->assertSecretNotPersisted('a reset password');
    }

    #[Test]
    public function a_csrf_token_in_the_body_is_not_persisted(): void
    {
        $token = 'aBcD1234aBcD1234aBcD1234aBcD1234aBcD';

        $this->post('/account/settings', ['_token' => $token, 'bio' => '<script>alert(1)</script>']);

        $this->assertStringNotContainsString($token, $this->persisted(), 'a CSRF token was stored verbatim');
    }

    #[Test]
    public function a_php_session_id_in_the_body_is_not_persisted(): void
    {
        $sid = 'abcdef1234567890abcdefghij';

        $this->post('/account/settings', ['PHPSESSID' => $sid, 'bio' => '<script>alert(1)</script>']);

        $this->assertStringNotContainsString($sid, $this->persisted(), 'a session id was stored verbatim');
    }

    /**
     * The cause of BUG 6, pinned so the fix is not mistaken for something it
     * is not.
     *
     * The credential *patterns* still do not match the JSON segment form, and
     * that is fine — making them match would fire "Password Exposure" on every
     * legitimate login, which is why they were written for the wire form in
     * the first place. Redaction simply must not depend on them.
     *
     * This test documents the mismatch that made label-driven redaction
     * unworkable. If someone later rewrites these patterns to match the JSON
     * form, this fails and they get to reconsider the noise that creates.
     *
     * @return array<string, array{0: string, 1: string, 2: string}> label, key, value
     */
    public static function credentialPatterns(): array
    {
        return [
            'Password Exposure' => ['Password Exposure', 'password', 'Tr0ub4dor&3-correct'],
            // Deliberately matches no vendor's key format. An earlier fixture
            // here was shaped like a live Stripe key, and GitHub's push
            // protection blocked the push on it — correctly, since a scanner
            // cannot tell a fake prefix from a real one. The pattern under
            // test only requires 20+ characters of [A-Za-z0-9-_] after the
            // key name, so the prefix was never carrying any weight.
            'API Key Exposure' => ['API Key Exposure', 'api_key', 'example-api-key-0123456789-not-real'],
            // Same reasoning as the API key above: this was shaped like a Google
            // OAuth token ('ya29.' + base64ish). Push protection happened not to
            // flag it, but that is luck, not safety. The pattern only requires
            // 32+ characters of [A-Za-z0-9-_.=] after the key name.
            'Access Token Leak' => ['Access Token Leak', 'access_token', 'example-access-token-0123456789-not-real'],
            'Session ID Leak' => ['Session ID Leak', 'session_id', 'abcdef1234567890abcdefghij'],
            'PHP Session Exposure' => ['PHP Session Exposure', 'PHPSESSID', 'abcdef1234567890abcdef'],
            'CSRF Token Reference' => ['CSRF Token Reference', 'csrf_token', 'aBcD1234aBcD1234aBcD1234aBcD1234aBcD'],
        ];
    }

    #[Test]
    #[DataProvider('credentialPatterns')]
    public function a_credential_pattern_reads_the_wire_form_but_not_the_json_form(
        string $label,
        string $key,
        string $value
    ): void {
        $regex = $this->patternFor($label);

        // The wire form, which is what these patterns were written against.
        $this->assertSame(1, preg_match($regex, "{$key}={$value}"), "'{$label}' does not match even the wire form");

        // The form buildPayloadSegments() produces, and the only form the
        // detector ever sees. json_encode puts a closing quote between the key
        // and the separator, which every one of these patterns rejects.
        $segment = json_encode([$key => $value], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);

        $this->assertSame(
            0,
            preg_match($regex, $segment),
            "'{$label}' now matches the JSON form ({$segment}) — it will fire on every legitimate request carrying that field"
        );
    }

    /**
     * And the consequence: redaction must therefore not be driven by these
     * labels, because none of them fire on a login form.
     */
    #[Test]
    public function no_credential_label_fires_on_an_ordinary_login_form(): void
    {
        $this->post('/login', ['email' => self::ATTACK, 'password' => self::SECRET]);

        $labels = DB::table('threat_logs')->pluck('type')->all();

        foreach (['Password Exposure', 'API Key Exposure', 'Session ID Leak'] as $credentialLabel) {
            $this->assertNotContains("[custom] {$credentialLabel}", $labels);
        }

        // The attack beside it was still detected, and the password still
        // masked — by field name, not by label.
        $this->assertContains('[middleware] SQL Injection UNION', $labels);
        $this->assertSecretNotPersisted('the login password');
    }

    private function patternFor(string $label): string
    {
        $rc = new ReflectionClass(ThreatDetectionService::class);
        $defaults = $rc->getMethod('getDefaultThreatPatterns')->invoke($rc->newInstanceWithoutConstructor());

        if ($regex = array_search($label, $defaults, true)) {
            return $regex;
        }

        foreach (config('threat-detection.custom_patterns', []) as $regex => $entry) {
            if ((is_array($entry) ? ($entry['label'] ?? '') : $entry) === $label) {
                return $regex;
            }
        }

        $this->fail("no pattern is configured for '{$label}'");
    }

    // ── what does work, pinned so it stays working ─────────────────────────

    /**
     * The redaction machinery is not broken — it is simply never reached for
     * a credential field. Where a credential pattern does fire, masking works
     * exactly as documented.
     */
    #[Test]
    public function a_literal_password_assignment_inside_a_value_is_masked(): void
    {
        $this->post('/search', ['q' => 'password=' . self::SECRET . ' ' . self::ATTACK]);

        $this->assertSecretNotPersisted('a literal password= assignment');
        $this->assertStringContainsString('[REDACTED]', $this->persisted());
    }

    #[Test]
    public function a_bearer_token_in_a_custom_header_is_masked(): void
    {
        $token = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N';

        $this->post('/account/settings', ['bio' => '<script>alert(1)</script>'], ['X-Auth-Fallback' => 'Bearer ' . $token]);

        $this->assertStringNotContainsString($token, $this->persisted(), 'a bearer token in a header was stored verbatim');
    }

    /**
     * The Authorization header is dropped before scanning, so it is never at
     * risk. Worth an explicit test: it is the one credential channel the
     * package handles by exclusion rather than by redaction, and an
     * accidental change to the except() list would be invisible.
     */
    #[Test]
    public function the_authorization_header_is_never_scanned_or_stored(): void
    {
        $token = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzZWNyZXQtdG9rZW4ifQ.aBcDeFgHiJkLmNoPqRsTuV';

        $this->post('/account/settings', ['bio' => '<script>alert(1)</script>'], ['Authorization' => 'Bearer ' . $token]);

        $this->assertStringNotContainsString($token, $this->persisted());
    }

    #[Test]
    public function the_cookie_header_is_never_scanned_or_stored(): void
    {
        $this->withCredentials()
            ->withUnencryptedCookie('laravel_session', 'sensitive-session-value-123456')
            ->post('/account/settings', ['bio' => '<script>alert(1)</script>']);

        $this->assertStringNotContainsString('sensitive-session-value-123456', $this->persisted());
    }

    // ── the mitigation available today ─────────────────────────────────────

    /**
     * Until the patterns see the JSON form, safe_fields is the only thing that
     * keeps a password out of the log — and it does work, because it removes
     * the field before the segment is built rather than masking it after.
     *
     * This is the workaround an operator can apply now, so it is worth a test
     * that will fail loudly if it ever stops working.
     */
    #[Test]
    #[DataProvider('credentialFieldNames')]
    public function listing_a_credential_field_in_safe_fields_keeps_it_out_of_the_log(string $field): void
    {
        config(['threat-detection.safe_fields' => [$field]]);

        $this->post('/account/settings', [
            $field => self::SECRET,
            'bio' => '<script>alert(1)</script>',
        ])->assertStatus(200);

        $this->assertSecretNotPersisted("the {$field} field, exempted via safe_fields");
    }

    #[Test]
    public function safe_fields_covering_the_credential_still_records_the_attack_beside_it(): void
    {
        config(['threat-detection.safe_fields' => ['password']]);

        $this->post('/login', ['email' => self::ATTACK, 'password' => self::SECRET]);

        $this->assertStringContainsString('SQL Injection UNION', $this->persisted());
        $this->assertStringNotContainsString(self::SECRET, $this->persisted());
    }

    // ── redaction behaves as configured ────────────────────────────────────

    #[Test]
    public function turning_redaction_off_stops_masking_a_value_that_would_otherwise_be_masked(): void
    {
        config(['threat-detection.redact.enabled' => false]);

        $this->post('/search', ['q' => 'password=' . self::SECRET . ' ' . self::ATTACK]);

        $this->assertStringContainsString(self::SECRET, $this->persisted());
    }

    /**
     * The label list still governs the label-driven pass. Demonstrated with a
     * PAN rather than a password, because 'pan' is not a credential *field*
     * name — so the field pass leaves it alone and the label pass is the only
     * thing acting on it.
     */
    #[Test]
    public function removing_a_label_from_redact_labels_stops_masking_that_label(): void
    {
        $pan = 'ABCDE1234F';

        config(['threat-detection.redact.labels' => ['PAN Number Detected']]);
        $this->postJson('/account/settings', ['pan' => $pan, 'bio' => '<script>alert(1)</script>']);
        $this->assertStringNotContainsString($pan, $this->persisted(), 'a listed label was not masked');

        DB::table('threat_logs')->delete();
        Cache::flush();

        config(['threat-detection.redact.labels' => []]);
        $this->postJson('/account/settings', ['pan' => $pan, 'bio' => '<script>alert(1)</script>']);
        $this->assertStringContainsString($pan, $this->persisted(), 'an unlisted label was masked anyway');
    }

    /**
     * The two passes are independent. Emptying the label list must not stop a
     * credential field being masked — that was the whole failure mode.
     */
    #[Test]
    public function emptying_the_label_list_does_not_expose_a_credential_field(): void
    {
        config(['threat-detection.redact.labels' => []]);

        $this->post('/login', ['email' => self::ATTACK, 'password' => self::SECRET]);

        $this->assertSecretNotPersisted('a password, with label-driven redaction switched off');
    }

    /**
     * ...and the field list is configurable in the same way. An operator who
     * empties it gets the old behaviour back, deliberately.
     */
    #[Test]
    public function emptying_the_field_list_restores_the_previous_unmasked_behaviour(): void
    {
        config(['threat-detection.redact.fields' => []]);
        ThreatDetectionService::flushCaches();

        $this->post('/login', ['email' => self::ATTACK, 'password' => self::SECRET]);

        $this->assertStringContainsString(self::SECRET, $this->persisted());
    }

    // ── re-audit of the fix itself ─────────────────────────────────────────

    /**
     * RE-1 — the fix has to reach installs that published their config before
     * it existed.
     *
     * mergeConfigFrom() merges top-level keys only, so an application holding
     * its own 'redact' block keeps it wholesale and never receives the new
     * 'fields' key. Reading the list from config alone would therefore have
     * left exactly the installs that had been storing cleartext passwords
     * still storing them after upgrading — the fix would have shipped and done
     * nothing, silently, for everyone who most needed it.
     *
     * The default list lives in the service; config overrides rather than
     * enables it. This simulates a published config from before the key
     * existed.
     */
    #[Test]
    public function a_published_config_without_the_fields_key_still_masks_credentials(): void
    {
        config(['threat-detection.redact' => [
            'enabled' => true,
            'mask' => '[REDACTED]',
            'labels' => ['Password Exposure'],
            // no 'fields' — this is every config published before the fix
        ]]);
        ThreatDetectionService::flushCaches();

        $this->post('/login', ['email' => self::ATTACK, 'password' => self::SECRET])->assertStatus(200);

        $this->assertSecretNotPersisted('a password, with a pre-upgrade published config');
    }

    /**
     * RE-2 — a credential is not always a string.
     *
     * The first version of the fix matched the encoded JSON with a regex whose
     * value subpattern only recognised a quoted string, so a numeric PIN, a
     * null, an array of tokens or a nested object all went to the log
     * untouched. Masking the array before it is encoded covers every value
     * type and any depth.
     *
     * @return array<string, array{0: mixed}>
     */
    public static function nonStringCredentialValues(): array
    {
        return [
            'an integer pin' => [123456],
            'a long integer' => [98765432109876],
            'a float' => [1234.5],
            'a boolean' => [true],
            'null' => [null],
            'a list of values' => [['first-secret', 'second-secret']],
            'a nested object' => [['old' => 'aaaa1111', 'new' => 'bbbb2222']],
            'a deeply nested object' => [['a' => ['b' => ['c' => 'buried-secret']]]],
        ];
    }

    #[Test]
    #[DataProvider('nonStringCredentialValues')]
    public function a_credential_is_masked_whatever_type_its_value_is(mixed $value): void
    {
        $this->postJson('/account/settings', [
            'password' => $value,
            'bio' => '<script>alert(1)</script>',
        ])->assertStatus(200);

        $payload = (string) DB::table('threat_logs')->value('payload');

        $this->assertStringContainsString('[REDACTED]', $payload, 'the credential field was not masked at all');

        foreach (['first-secret', 'second-secret', 'aaaa1111', 'bbbb2222', 'buried-secret', '123456', '98765432109876'] as $fragment) {
            $this->assertStringNotContainsString($fragment, $payload, "a {$fragment} value survived masking");
        }
    }

    #[Test]
    public function a_credential_nested_several_levels_below_a_harmless_key_is_masked(): void
    {
        $this->postJson('/account/settings', [
            'profile' => ['auth' => ['password' => self::SECRET]],
            'bio' => '<script>alert(1)</script>',
        ])->assertStatus(200);

        $this->assertSecretNotPersisted('a password three levels down');
    }

    /**
     * RE-4 — the same field arrives under several spellings.
     *
     * Headers use hyphens and an x- prefix; bodies use underscores. Matching
     * the literal string meant "x-api-key" in a header segment was stored in
     * cleartext while "api_key" in a body was masked. Names are now compared
     * after folding case, normalising the separator and dropping a leading x-.
     *
     * @return array<string, array{0: string}>
     */
    public static function credentialFieldSpellings(): array
    {
        return [
            'underscored' => ['api_key'],
            'hyphenated' => ['api-key'],
            'x-prefixed' => ['x-api-key'],
            'x-prefixed underscored' => ['x_api_key'],
            'title case' => ['X-Api-Key'],
            'shouted' => ['API_KEY'],
            'run together' => ['apikey'],
            'hyphenated auth token' => ['auth-token'],
            'x-prefixed csrf token' => ['x-csrf-token'],
            'hyphenated session id' => ['session-id'],
        ];
    }

    #[Test]
    #[DataProvider('credentialFieldSpellings')]
    public function a_credential_is_masked_under_every_spelling_of_its_name(string $field): void
    {
        $this->postJson('/account/settings', [
            $field => self::SECRET,
            'bio' => '<script>alert(1)</script>',
        ])->assertStatus(200);

        $this->assertSecretNotPersisted("the {$field} field");
    }

    #[Test]
    public function a_credential_arriving_as_a_request_header_is_masked(): void
    {
        $this->post(
            '/account/settings',
            ['bio' => '<script>alert(1)</script>'],
            ['X-Api-Key' => self::SECRET]
        )->assertStatus(200);

        $this->assertSecretNotPersisted('an X-Api-Key header');
    }

    /**
     * Normalisation must not become a substring match. 'password' and
     * 'password_hint' are different names, and only the ones actually listed
     * are masked — otherwise redaction would quietly eat ordinary fields and
     * the log would stop being useful.
     */
    #[Test]
    public function a_field_that_merely_resembles_a_credential_name_is_left_alone(): void
    {
        $this->postJson('/account/settings', [
            'password_hint' => 'my first pet',
            'tokenizer' => 'whitespace',
            'pinned' => 'yes',
            'bio' => '<script>alert(1)</script>',
        ])->assertStatus(200);

        $payload = (string) DB::table('threat_logs')->value('payload');

        $this->assertStringContainsString('my first pet', $payload);
        $this->assertStringContainsString('whitespace', $payload);
        $this->assertStringContainsString('yes', $payload);
    }

    /**
     * RE-3 — redaction fails closed, so a regex that gave up would blank the
     * whole row and destroy the evidence along with the secret.
     *
     * The first version matched the encoded JSON with an alternation inside a
     * quantifier, which exhausted the PCRE JIT stack above about 8 KB. The
     * payload is capped at 2 KB, but the url column is not, so a long query
     * string reached it. Structured data no longer goes through a regex at
     * all, and the one that remains is a plain negated class.
     */
    #[Test]
    public function a_very_long_url_does_not_blank_the_stored_row(): void
    {
        // The attack goes first: only the first 8 KB of a segment is scanned,
        // so a payload parked behind 20 KB of filler would never be detected
        // and the test would prove nothing about redaction.
        $long = str_repeat('a', 20000);

        $this->get('/search?q=' . urlencode(self::ATTACK) . '&password=' . urlencode(self::SECRET) . '&filler=' . $long)
            ->assertStatus(200);

        $row = DB::table('threat_logs')->first();

        $this->assertNotNull($row);
        $this->assertStringContainsString('SQL Injection UNION', (string) $row->type);
        $this->assertNotSame('[REDACTED]', (string) $row->payload, 'the whole payload was blanked');
        $this->assertNotSame('[REDACTED]', (string) $row->url, 'the whole url was blanked');
        $this->assertStringNotContainsString(self::SECRET, urldecode((string) $row->url));
    }

    #[Test]
    public function a_very_long_credential_value_does_not_blank_the_stored_row(): void
    {
        // bio first, so the detection happens inside the 8 KB scan cap.
        $this->postJson('/account/settings', [
            'bio' => '<script>alert(1)</script>',
            'password' => str_repeat('s', 30000),
        ])->assertStatus(200);

        $payload = (string) DB::table('threat_logs')->value('payload');

        $this->assertNotSame('[REDACTED]', $payload, 'the whole payload was blanked');
        $this->assertStringContainsString('[REDACTED]', $payload);
        $this->assertStringNotContainsString(str_repeat('s', 100), $payload);
    }

    /**
     * The line between redaction and safe_fields, which is the thing most
     * likely to be broken by a careless change to either.
     *
     * safe_fields stops a field being *scanned*. Redaction keeps scanning it
     * and stops it being *stored*. So an attack delivered through a password
     * field must still be detected — masking happens afterwards, on the way to
     * the database, and must not blind the detector.
     */
    #[Test]
    public function an_attack_delivered_through_a_credential_field_is_still_detected(): void
    {
        $this->post('/login', ['email' => 'jane@example.com', 'password' => self::ATTACK])
            ->assertStatus(200);

        $this->assertStringContainsString(
            'SQL Injection UNION',
            $this->persisted(),
            'redaction blinded the detector to an attack inside a credential field'
        );
    }

    #[Test]
    public function safe_fields_by_contrast_does_stop_the_field_being_scanned(): void
    {
        config(['threat-detection.safe_fields' => ['password']]);

        $this->post('/login', ['email' => 'jane@example.com', 'password' => self::ATTACK])
            ->assertStatus(200);

        $this->assertSame(0, DB::table('threat_logs')->count());
    }

    // ── the passive guarantee still holds on every one of these ────────────

    #[Test]
    public function no_credential_carrying_request_is_ever_refused(): void
    {
        $this->post('/login', ['email' => self::ATTACK, 'password' => self::SECRET])->assertStatus(200);
        $this->postJson('/login', ['email' => self::ATTACK, 'password' => self::SECRET])->assertStatus(200);
        $this->post('/register', ['password' => self::SECRET, 'name' => '<script>x</script>'])->assertStatus(200);
        $this->get('/search?password=' . urlencode(self::SECRET))->assertStatus(200);
    }
}
