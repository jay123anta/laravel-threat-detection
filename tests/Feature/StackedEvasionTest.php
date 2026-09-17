<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * Evasion techniques stacked two at a time.
 *
 * The existing suite covers each technique on its own and they all passed.
 * That is not where a normalization pipeline breaks. It breaks where the order
 * of its passes matters, and normalizeForDetection() used to be a fixed,
 * single-pass sequence:
 *
 *     1. strip SQL comments   2. decode HTML entities   3. decode \uXXXX
 *     4. decode \xNN          5. urldecode (x3)         6. collapse whitespace
 *
 * Every step ran once, in that order, and never again — so any encoding a
 * *later* step revealed was never seen by an *earlier* one, which is exactly
 * what an attacker gets for free by combining two techniques.
 *
 * It now applies that sequence up to MAX_NORMALIZATION_PASSES times, stopping
 * as soon as a pass changes nothing, so a decoder can act on what another one
 * uncovers. Each test below names the two techniques and the attack class.
 */
class StackedEvasionTest extends TestCase
{
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
            'threat-detection.only_paths' => [],
            'threat-detection.whitelisted_ips' => [],
            'threat-detection.api_route_filtering.enabled' => false,
            'threat-detection.content_paths' => [],
            'threat-detection.notifications.enabled' => false,
            'threat-detection.queue.enabled' => false,
            'cache.default' => 'array',
        ]);

        Route::middleware('threat-detect')->group(function () {
            Route::get('/stacked', fn () => response('OK', 200));
            Route::post('/stacked', fn () => response('OK', 200));
        });
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    /**
     * Send a payload as the query string exactly as it would appear on the
     * wire. Only the characters that would otherwise break the query string
     * are escaped, so a payload that is *itself* percent-encoded reaches the
     * application with exactly the number of encoding layers intended.
     */
    private function sendOnTheWire(string $wire): void
    {
        $escaped = strtr($wire, [' ' => '%20', '&' => '%26', '#' => '%23', '+' => '%2B', '=' => '%3D']);

        $this->get('/stacked?q=' . $escaped)->assertStatus(200);
    }

    /**
     * Rewrite every ASCII punctuation character as a JavaScript \uXXXX escape,
     * leaving letters and digits alone — the shape a real \u-escaped payload
     * takes. Built rather than written out so the backslashes cannot be lost
     * to an editor or a copy-paste on the way in.
     */
    private static function unicodeEscaped(string $plain): string
    {
        return preg_replace_callback(
            '/[^A-Za-z0-9]/',
            fn ($m) => chr(92) . 'u' . sprintf('%04x', ord($m[0])),
            $plain
        );
    }

    /** The same, as \xNN escapes. */
    private static function hexEscaped(string $plain): string
    {
        return preg_replace_callback(
            '/[^A-Za-z0-9]/',
            fn ($m) => chr(92) . 'x' . sprintf('%02x', ord($m[0])),
            $plain
        );
    }

    /** @return string[] the labels logged, without their source tag */
    private function loggedLabels(): array
    {
        return DB::table('threat_logs')
            ->pluck('type')
            ->map(fn ($t) => preg_replace('/^\[[a-z-]+\] /', '', $t))
            ->sort()
            ->values()
            ->all();
    }

    private function assertLogged(string $label): void
    {
        $this->assertContains(
            $label,
            $this->loggedLabels(),
            "expected '{$label}'; got: " . (implode(', ', $this->loggedLabels()) ?: 'nothing at all')
        );
    }

    // ── stacked combinations that hold up ───────────────────────────────────

    #[Test]
    public function html_entity_encoding_wrapped_around_a_unicode_escape_still_detects_the_xss(): void
    {
        // &#92; is a backslash, so the entity pass produces < for the
        // unicode pass to decode. Entities decode before \u — the order works
        // in this direction.
        $this->sendOnTheWire('&#92;u003cscript&#92;u003ealert(1)&#92;u003c/script&#92;u003e');

        $this->assertLogged('XSS Script Tag');
    }

    #[Test]
    public function html_entity_encoding_wrapped_around_a_hex_escape_still_detects_the_xss(): void
    {
        $this->sendOnTheWire('&#92;x3cscript&#92;x3ealert(1)&#92;x3c/script&#92;x3e');

        $this->assertLogged('XSS Script Tag');
    }

    #[Test]
    public function html_entity_encoding_wrapped_around_a_hex_escape_still_detects_the_rce(): void
    {
        $this->sendOnTheWire('&#92;x73ystem("id")');

        $this->assertLogged('RCE Shell Function');
    }

    #[Test]
    public function entity_encoded_sql_keywords_around_a_comment_still_detect_the_union(): void
    {
        // The keywords are entity-encoded, the comment is literal. The comment
        // strip runs first and removes it, then the entities decode.
        $this->sendOnTheWire('&#117;nion/**/&#115;elect password from users');

        $this->assertLogged('SQL Injection UNION');
    }

    #[Test]
    public function double_url_encoding_wrapped_around_html_entities_still_detects_the_xss(): void
    {
        $this->sendOnTheWire('%26%2360%3Bscript%26%2362%3Balert(1)%26%2360%3B/script%26%2362%3B');

        $this->assertLogged('XSS Script Tag');
    }

    #[Test]
    public function double_url_encoded_traversal_mixed_with_entities_still_detects_the_path_attack(): void
    {
        $this->sendOnTheWire('%252e%252e&#47;%252e%252e&#47;etc/passwd');

        $this->assertLogged('Directory Traversal');
        $this->assertLogged('Sensitive File Access');
    }

    #[Test]
    public function triple_url_encoding_is_still_unwound_within_the_three_pass_budget(): void
    {
        $this->sendOnTheWire('%25252527%252520union%252520select%252520x%252520from%252520y');

        $this->assertLogged('SQL Injection UNION');
    }

    /**
     * The documented limit of the recursive decoder is three passes. A fourth
     * layer is not unwound — but the request is not silent: the evasion
     * pattern still fires on the raw query string, so the operator sees that
     * someone is encoding something four times, which is signal enough.
     */
    #[Test]
    public function a_fourth_url_encoding_layer_exceeds_the_decoder_budget_but_is_still_flagged_as_evasion(): void
    {
        $this->sendOnTheWire('%2525252527%25252520union%25252520select');

        $this->assertLogged('Double URL Encoding');
    }

    // ── BUG 3: \xNN and \uXXXX escapes were not actually decoded ────────────

    /**
     * BUG 3 (fixed) — the hex and unicode escape decoders were defeated by
     * the package's own JSON encoding of the segment.
     *
     * buildPayloadSegments() json_encodes each segment
     * (ThreatDetectionService, SEGMENT_JSON_FLAGS), and json_encode escapes a
     * backslash as two. normalizeForDetection() then runs
     *
     *     preg_replace_callback('/\\\\x([0-9a-fA-F]{2})/', ...)
     *
     * which matched the *second* backslash and replaced from there, leaving
     * the first behind: a hex-escaped "<" became a backslash followed by "<"
     * rather than "<". The payload normalized to an escaped-looking script tag
     * and the XSS Script Tag pattern — which needs a literal closing tag — no
     * longer matched.
     *
     * Both \xNN and \uXXXX were affected; the entity-wrapped forms above kept
     * working precisely because their backslash is introduced *after*
     * json_encode.
     *
     * The README lists "Unicode escapes" and "hex escapes" among the
     * techniques the normalization pipeline defeats (README, "Features",
     * the Evasion Resistance bullet — cited by name, since a line number
     * goes stale with every edit above it and these already had), and the
     * pre-existing tests passed throughout, because they assert only the
     * evasion *flag* ("Unicode Escape Evasion") — matched on the un-normalized
     * text, and never affected. That is why this went unnoticed for so long.
     *
     * Fixed by accepting a run of backslashes in both decoders. These four
     * tests assert the payload itself is identified, not merely flagged.
     */
    #[Test]
    public function a_hex_escaped_script_tag_is_identified_as_xss_not_merely_flagged(): void
    {
        $this->sendOnTheWire('\x3cscript\x3ealert(1)\x3c/script\x3e');

        $this->assertLogged('XSS Script Tag');
    }

    #[Test]
    public function a_unicode_escaped_script_tag_is_identified_as_xss_not_merely_flagged(): void
    {
        $this->sendOnTheWire(self::unicodeEscaped('<script>alert(1)</script>'));

        $this->assertLogged('XSS Script Tag');
    }

    #[Test]
    public function a_hex_escaped_traversal_combined_with_a_sql_comment_is_detected(): void
    {
        // Nothing at all is logged for this today.
        $this->sendOnTheWire('\x2e\x2e/**/\x2fetc\x2fpasswd');

        $this->assertNotSame([], $this->loggedLabels(), 'the request produced no detection of any kind');
    }

    #[Test]
    public function a_hex_escaped_rce_combined_with_a_sql_comment_is_detected(): void
    {
        // Nothing at all is logged for this today.
        $this->sendOnTheWire('\x73ystem/**/(\x22id\x22)');

        $this->assertNotSame([], $this->loggedLabels(), 'the request produced no detection of any kind');
    }

    // ── BUG 4: the decode order used to be fixed and single-pass ───────────

    /**
     * BUG 4a (fixed) — SQL comment stripping runs before any decoding, so a
     * comment that was itself encoded used to survive it.
     *
     * normalizeForDetection() strips /​*...*​/ as its first act. An attacker
     * writes the comment as HTML entities (&#47;&#42;x&#42;&#47;) or
     * percent-encodes it; the strip finds nothing, the entity or URL pass then
     * reconstitutes the comment, and \bunion\s+select\b no longer matches
     * because the comment is sitting between the two keywords.
     *
     * The detection is not lost entirely — "SQL SELECT Query" still fires —
     * but it drops from high to low severity, which is enough to fall below a
     * min_confidence threshold or an alerting rule keyed on level.
     */
    #[Test]
    public function an_entity_encoded_sql_comment_between_union_and_select_is_still_detected_as_union_injection(): void
    {
        $this->sendOnTheWire('union&#47;&#42;x&#42;&#47;select password from users');

        $this->assertLogged('SQL Injection UNION');
    }

    #[Test]
    public function a_double_url_encoded_sql_comment_between_union_and_select_is_still_detected_as_union_injection(): void
    {
        $this->sendOnTheWire('union%252F%252A%252A%252Fselect password from users');

        $this->assertLogged('SQL Injection UNION');
    }

    /**
     * BUG 4b (fixed) — URL decoding runs last, so an escape sequence it reveals
     * *after* URL decoding is never decoded at all.
     *
     * %5Cx3c becomes \x3c only at step 5; the \xNN pass was step 4 and has
     * already finished. The result is that a double-URL-encoded hex or unicode
     * escape leaves nothing but the generic "Double URL Encoding" flag — the
     * operator learns someone encoded something twice, and nothing about what.
     */
    #[Test]
    public function a_double_url_encoded_hex_escape_is_decoded_far_enough_to_identify_the_xss(): void
    {
        $this->sendOnTheWire('%255Cx3cscript%255Cx3ealert(1)%255Cx3c/script%255Cx3e');

        $this->assertLogged('XSS Script Tag');
    }

    #[Test]
    public function a_double_url_encoded_unicode_escape_is_decoded_far_enough_to_identify_the_xss(): void
    {
        $this->sendOnTheWire('%255Cu003cscript%255Cu003ealert(1)%255Cu003c/script%255Cu003e');

        $this->assertLogged('XSS Script Tag');
    }

    #[Test]
    public function a_hex_escape_wrapped_in_double_url_encoding_is_identified_as_sql_injection(): void
    {
        $this->sendOnTheWire('%255Cx75nion%2520select%2520password%2520from%2520users');

        $this->assertLogged('SQL Injection UNION');
    }

    /**
     * BUG 4c (fixed) — HTML entity decoding was a single pass, so a doubly
     * entity-encoded payload survived it: &amp;#60; decoded to &#60; and
     * stopped there.
     */
    #[Test]
    public function a_doubly_entity_encoded_script_tag_is_identified_as_xss(): void
    {
        $this->sendOnTheWire('&amp;#60;script&amp;#62;alert(1)&amp;#60;/script&amp;#62;');

        $this->assertLogged('XSS Script Tag');
    }

    /**
     * BUG 4d (fixed) — IIS %uXXXX encoding was flagged but never decoded, so
     * the payload behind it was never identified.
     *
     * Before the fix this was arguably by design: the README listed IIS
     * Unicode only under detected *evasion techniques* ("Detected Attack
     * Types", the Evasion row) and not among the encodings the pipeline
     * decodes ("Features", the Evasion Resistance bullet). A %uXXXX-encoded
     * attack was reported as "someone used IIS encoding" and never as
     * "someone attempted SQL injection".
     *
     * That boundary has moved. %uXXXX is now decoded like the others, this
     * test asserts the attack behind it is named, and the Features bullet
     * lists it. The evasion flag still fires as well — both facts are worth
     * having. (An earlier version of this comment still described the old
     * behaviour in the present tense, directly above a test asserting the
     * opposite.)
     */
    #[Test]
    public function an_iis_unicode_encoded_sql_injection_is_identified_as_sql_injection(): void
    {
        $this->sendOnTheWire('%u0075nion/**/%u0073elect password from users');

        $this->assertLogged('SQL Injection UNION');

        // Decoding the payload must not cost the other signal: that someone
        // bothered to encode it this way is itself worth recording.
        $this->assertLogged('IIS Unicode Encoding Evasion');
    }

    /**
     * An entity-encoded character inside a sensitive path.
     *
     * This is the shape the attack actually takes — encode one character of
     * "/etc/passwd" and hope the signature misses it — and both the encoded
     * letter and the encoded separator are now decoded before matching.
     */
    #[Test]
    public function an_entity_encoded_letter_inside_a_sensitive_path_is_still_detected(): void
    {
        $this->sendOnTheWire('/etc/&#112;asswd');

        $this->assertLogged('Sensitive File Access');
    }

    #[Test]
    public function an_entity_encoded_separator_inside_a_sensitive_path_is_still_detected(): void
    {
        $this->sendOnTheWire('/etc&#47;passwd');

        $this->assertLogged('Sensitive File Access');
    }

    #[Test]
    public function an_entity_encoded_traversal_prefix_is_still_detected(): void
    {
        $this->sendOnTheWire('&#46;&#46;/&#46;&#46;/etc/passwd');

        $this->assertLogged('Directory Traversal');
        $this->assertLogged('Sensitive File Access');
    }

    /**
     * The documented boundary: a SQL comment placed *inside* a path is not
     * undone into a path.
     *
     * Stripping a comment replaces it with a space, because it has to —
     * removing it outright would fuse UNION/​*​*​/SELECT into UNIONSELECT. So
     * "/etc/​*​*​/passwd" becomes "/etc passwd", not "/etc/passwd". Nor could
     * it: the slashes that would form the path are part of the comment token
     * itself, so there is no reading under which that string is a path
     * traversal payload.
     *
     * Pinned so the limitation is a known one rather than a surprise, and so
     * the evasion itself is still reported.
     */
    #[Test]
    public function a_sql_comment_inside_a_path_is_reported_as_evasion_rather_than_as_a_path_attack(): void
    {
        $this->sendOnTheWire('/etc/**/&#112;asswd');

        $labels = $this->loggedLabels();

        $this->assertNotSame([], $labels, 'the request went entirely unlogged');
        $this->assertContains('HTML Entity Encoding Evasion', $labels);
    }

    // ── stacking never costs the passive guarantee ─────────────────────────

    /**
     * @return array<string, array{0: string}>
     */
    public static function everyStackedPayload(): array
    {
        return [
            'entity + unicode escape' => ['&#92;u003cscript&#92;u003ealert(1)&#92;u003c/script&#92;u003e'],
            'entity + hex escape' => ['&#92;x3cscript&#92;x3ealert(1)&#92;x3c/script&#92;x3e'],
            'entity keywords + comment' => ['&#117;nion/**/&#115;elect password from users'],
            'double url + entity' => ['%26%2360%3Bscript%26%2362%3Balert(1)%26%2360%3B/script%26%2362%3B'],
            'double url + entity traversal' => ['%252e%252e&#47;%252e%252e&#47;etc/passwd'],
            'triple url' => ['%25252527%252520union%252520select%252520x%252520from%252520y'],
            'quad url' => ['%2525252527%25252520union%25252520select'],
            'hex escape xss' => ['\x3cscript\x3ealert(1)\x3c/script\x3e'],
            'unicode escape xss' => [self::unicodeEscaped('<script>alert(1)</script>')],
            'hex + comment traversal' => ['\x2e\x2e/**/\x2fetc\x2fpasswd'],
            'hex + comment rce' => ['\x73ystem/**/(\x22id\x22)'],
            'entity comment + union' => ['union&#47;&#42;x&#42;&#47;select password from users'],
            'double url comment + union' => ['union%252F%252A%252A%252Fselect password from users'],
            'double url + hex' => ['%255Cx3cscript%255Cx3ealert(1)%255Cx3c/script%255Cx3e'],
            'double url + unicode' => ['%255Cu003cscript%255Cu003ealert(1)%255Cu003c/script%255Cu003e'],
            'double entity' => ['&amp;#60;script&amp;#62;alert(1)&amp;#60;/script&amp;#62;'],
            'iis unicode + comment' => ['%u0075nion/**/%u0073elect password from users'],
            'entity path + comment' => ['/etc/**/&#112;asswd'],
            'comment inside the tag name' => ['<scr/**/ipt>alert(1)</scr/**/ipt>'],
        ];
    }

    /**
     * Whether a stacked payload is caught or missed, it must never change the
     * response. A miss is a detection bug; a 500 would be an availability bug.
     */
    #[Test]
    #[DataProvider('everyStackedPayload')]
    public function a_stacked_evasion_payload_never_changes_the_response(string $wire): void
    {
        $escaped = strtr($wire, [' ' => '%20', '&' => '%26', '#' => '%23', '+' => '%2B', '=' => '%3D']);

        $response = $this->get('/stacked?q=' . $escaped);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('OK', $response->getContent());
    }

    /**
     * The floor beneath every gap above: whatever the pipeline fails to
     * decode, the request must not pass through completely unremarked.
     *
     * Two payloads fail this today — the hex-escape-plus-comment pair — and
     * they are the two the audit ranks highest, because they are the only ones
     * that leave no trace at all.
     */
    #[Test]
    #[DataProvider('everyStackedPayload')]
    public function a_stacked_evasion_payload_always_leaves_some_trace_in_the_log(string $wire): void
    {
        $escaped = strtr($wire, [' ' => '%20', '&' => '%26', '#' => '%23', '+' => '%2B', '=' => '%3D']);
        $this->get('/stacked?q=' . $escaped);

        $this->assertGreaterThan(
            0,
            DB::table('threat_logs')->count(),
            'a stacked-evasion attack passed through entirely unlogged'
        );
    }
}
