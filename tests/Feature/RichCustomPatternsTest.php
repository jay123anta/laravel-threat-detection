<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * Rich custom patterns (array form).
 *
 * custom_patterns entries can now be an array with per-pattern options
 * alongside the classic 'regex' => 'Label' string form:
 *
 *   'label'     — required
 *   'level'     — low|medium|high, overrides threat_levels keyword derivation
 *   'contexts'  — restrict scanning to named segments (query|body|headers)
 *   'validator' — inline post-match checksum, wins over pattern_validators
 *
 * Malformed options fail open (scan unrestricted, warn) — a config mistake
 * must never silently disable or narrow a detection.
 *
 * Payloads include an email (the "@" passes the suspicious-character
 * pre-screen) and a "password" field (activates the token category so
 * custom patterns run) — mirroring a real credential/PII leak.
 */
class RichCustomPatternsTest extends TestCase
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
            'threat-detection.auth_paths' => [],
            'threat-detection.safe_fields' => [],
            'threat-detection.safe_paths' => [],
            'threat-detection.pattern_validators' => [],
            'threat-detection.notifications.enabled' => false,
            'threat-detection.queue.enabled' => false,
            'cache.default' => 'array',
        ]);

        Route::middleware('threat-detect')->post('/phase12-test', fn () => response('OK', 200));

        $this->resetCustomPatternCache();
    }

    protected function tearDown(): void
    {
        // The custom-pattern cache is a process-wide static; without a reset,
        // this file's per-test custom_patterns overrides would leak into
        // later test files (and earlier files' defaults into this one).
        $this->resetCustomPatternCache();
        Cache::flush();
        parent::tearDown();
    }

    private function resetCustomPatternCache(): void
    {
        ThreatDetectionService::flushCaches();
    }

    /** A body that passes the pre-screen and activates the token category. */
    private function bodyWith(array $fields): array
    {
        return $fields + ['email' => 'user@example.com', 'password' => 'irrelevant'];
    }

    // ── Backward compatibility ──────────────────────────────────────────────

    #[Test]
    public function string_form_patterns_keep_working_alongside_array_form(): void
    {
        config(['threat-detection.custom_patterns' => [
            '/\bREF-\d{6}\b/' => 'Internal Reference Leak',
            '/\bTOK-\d{4}\b/' => ['label' => 'Token Marker Found'],
        ]]);

        $this->postJson('/phase12-test', $this->bodyWith(['ref' => 'REF-123456']));

        $this->assertDatabaseHas('threat_logs', ['type' => '[custom] Internal Reference Leak']);
    }

    #[Test]
    public function array_form_label_names_the_logged_type(): void
    {
        config(['threat-detection.custom_patterns' => [
            '/\bREF-\d{6}\b/' => ['label' => 'Internal Reference Leak'],
        ]]);

        $this->postJson('/phase12-test', $this->bodyWith(['ref' => 'REF-123456']));

        $this->assertDatabaseHas('threat_logs', ['type' => '[custom] Internal Reference Leak']);
    }

    // ── Severity control ────────────────────────────────────────────────────

    #[Test]
    public function array_form_level_overrides_derived_severity(): void
    {
        config(['threat-detection.custom_patterns' => [
            '/\bREF-\d{6}\b/' => ['label' => 'Internal Reference Leak', 'level' => 'high'],
        ]]);

        $this->postJson('/phase12-test', $this->bodyWith(['ref' => 'REF-123456']));

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[custom] Internal Reference Leak',
            'threat_level' => 'high',
        ]);
    }

    #[Test]
    public function derived_severity_applies_when_level_is_omitted(): void
    {
        // No threat_levels keyword matches this label, so derivation
        // falls through to 'low' — the pre-feature behaviour.
        config(['threat-detection.custom_patterns' => [
            '/\bREF-\d{6}\b/' => ['label' => 'Internal Reference Leak'],
        ]]);

        $this->postJson('/phase12-test', $this->bodyWith(['ref' => 'REF-123456']));

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[custom] Internal Reference Leak',
            'threat_level' => 'low',
        ]);
    }

    #[Test]
    public function invalid_level_falls_back_to_derived_severity(): void
    {
        config(['threat-detection.custom_patterns' => [
            '/\bREF-\d{6}\b/' => ['label' => 'Internal Reference Leak', 'level' => 'catastrophic'],
        ]]);

        $this->postJson('/phase12-test', $this->bodyWith(['ref' => 'REF-123456']));

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[custom] Internal Reference Leak',
            'threat_level' => 'low',
        ]);
    }

    // ── Context restriction ─────────────────────────────────────────────────

    #[Test]
    public function contexts_restrict_a_pattern_to_named_segments(): void
    {
        config(['threat-detection.custom_patterns' => [
            '/\bREF-\d{6}\b/' => ['label' => 'Internal Reference Leak', 'contexts' => ['body']],
        ]]);

        $this->postJson('/phase12-test', $this->bodyWith(['ref' => 'REF-123456']));

        $this->assertDatabaseHas('threat_logs', ['type' => '[custom] Internal Reference Leak']);
    }

    #[Test]
    public function contexts_exclude_segments_not_listed(): void
    {
        config(['threat-detection.custom_patterns' => [
            '/\bREF-\d{6}\b/' => ['label' => 'Internal Reference Leak', 'contexts' => ['body']],
        ]]);

        // Same value, but in the query string — a segment the pattern
        // excludes — while the body carries only the pre-screen fields.
        $this->postJson(
            '/phase12-test?email=user@example.com&password=x&ref=REF-123456',
            []
        );

        $this->assertDatabaseMissing('threat_logs', ['type' => '[custom] Internal Reference Leak']);
    }

    #[Test]
    public function unknown_context_names_fail_open_to_all_segments(): void
    {
        // 'cookie' is not a segment; the restriction is dropped (with a
        // warning) rather than silently disabling the pattern.
        config(['threat-detection.custom_patterns' => [
            '/\bREF-\d{6}\b/' => ['label' => 'Internal Reference Leak', 'contexts' => ['cookie']],
        ]]);

        $this->postJson(
            '/phase12-test?email=user@example.com&password=x&ref=REF-123456',
            []
        );

        $this->assertDatabaseHas('threat_logs', ['type' => '[custom] Internal Reference Leak']);
    }

    // ── Inline validators ───────────────────────────────────────────────────

    #[Test]
    public function inline_validator_passes_checksum_valid_values(): void
    {
        config(['threat-detection.custom_patterns' => [
            '/\b(?:\d[ -]?){13,19}\b/' => [
                'label' => 'Card Number Detected',
                'level' => 'high',
                'validator' => 'luhn',
            ],
        ]]);

        $this->postJson('/phase12-test', $this->bodyWith(['card' => '4111111111111111']));

        $this->assertDatabaseHas('threat_logs', [
            'type' => '[custom] Card Number Detected',
            'threat_level' => 'high',
        ]);
    }

    #[Test]
    public function inline_validator_suppresses_checksum_invalid_values(): void
    {
        config(['threat-detection.custom_patterns' => [
            '/\b(?:\d[ -]?){13,19}\b/' => [
                'label' => 'Card Number Detected',
                'level' => 'high',
                'validator' => 'luhn',
            ],
        ]]);

        // 16-digit run that fails Luhn — a tracking number, not a card.
        $this->postJson('/phase12-test', $this->bodyWith(['card' => '4111111111111112']));

        $this->assertDatabaseMissing('threat_logs', ['type' => '[custom] Card Number Detected']);
    }

    #[Test]
    public function inline_validator_takes_precedence_over_the_label_map(): void
    {
        // "2363" passes Verhoeff but fails Luhn (too short). With the label
        // map saying luhn and the inline option saying verhoeff, detection
        // firing proves the inline validator won.
        config([
            'threat-detection.custom_patterns' => [
                '/\b\d{4}\b/' => ['label' => 'Loyalty Code Detected', 'validator' => 'verhoeff'],
            ],
            'threat-detection.pattern_validators' => [
                'Loyalty Code Detected' => 'luhn',
            ],
        ]);

        $this->postJson('/phase12-test', $this->bodyWith(['code' => '2363']));

        $this->assertDatabaseHas('threat_logs', ['type' => '[custom] Loyalty Code Detected']);
    }

    #[Test]
    public function inline_validator_wins_even_when_it_suppresses(): void
    {
        // Mirror image: label map would pass (verhoeff), inline fails (luhn).
        // Suppression proves precedence isn't "whichever passes".
        config([
            'threat-detection.custom_patterns' => [
                '/\b\d{4}\b/' => ['label' => 'Loyalty Code Detected', 'validator' => 'luhn'],
            ],
            'threat-detection.pattern_validators' => [
                'Loyalty Code Detected' => 'verhoeff',
            ],
        ]);

        $this->postJson('/phase12-test', $this->bodyWith(['code' => '2363']));

        $this->assertDatabaseMissing('threat_logs', ['type' => '[custom] Loyalty Code Detected']);
    }

    // ── Malformed entries ───────────────────────────────────────────────────

    #[Test]
    public function array_entry_without_a_label_is_skipped_and_others_still_run(): void
    {
        config(['threat-detection.custom_patterns' => [
            '/\bREF-\d{6}\b/' => ['level' => 'high'], // no label — skipped
            '/\bTOK-\d{4}\b/' => 'Token Marker Found',
        ]]);

        $this->postJson('/phase12-test', $this->bodyWith([
            'ref' => 'REF-123456',
            'tok' => 'TOK-9999',
        ]));

        $this->assertDatabaseHas('threat_logs', ['type' => '[custom] Token Marker Found']);
    }

    // ── Public detectThreatPatterns() API ───────────────────────────────────

    #[Test]
    public function detect_threat_patterns_method_honours_array_form(): void
    {
        config(['threat-detection.custom_patterns' => [
            '/\b(?:\d[ -]?){13,19}\b/' => [
                'label' => 'Card Number Detected',
                'level' => 'high',
                'validator' => 'luhn',
            ],
        ]]);

        $service = app(ThreatDetectionService::class);

        $matches = $service->detectThreatPatterns('card=4111111111111111');
        $this->assertContains(['Card Number Detected', 'high', 'custom'], $matches);

        $labels = array_column($service->detectThreatPatterns('card=4111111111111112'), 0);
        $this->assertNotContains('Card Number Detected', $labels);
    }
}
