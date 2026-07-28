<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use JayAnta\ThreatDetection\Tests\TestCase;
use JayAnta\ThreatDetection\Services\PatternValidators;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use PHPUnit\Framework\Attributes\Test;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Cache;

/**
 * Post-match validators (pattern_validators).
 *
 * A regex alone can't express every constraint: any 12-digit run matches the
 * Aadhaar pattern, but a real Aadhaar number also passes the Verhoeff
 * checksum. Mapping a pattern label to a named validator makes a regex hit
 * count only when at least one matched value passes — so timestamps, order
 * ids and barcodes stop being logged as PII, while genuine numbers still are.
 *
 * Verhoeff test vectors: "2363" is the worked example from the algorithm's
 * literature (input 236, check digit 3); "234123412346" is a 12-digit
 * checksum-valid number. Verhoeff detects all single-digit errors, so any
 * one-digit alteration of a valid number is guaranteed invalid.
 * Luhn test vectors: 4111111111111111 is the classic valid test card number.
 */
class Phase11ValidatorsTest extends TestCase
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
            'threat-detection.notifications.enabled' => false,
            'threat-detection.queue.enabled' => false,
            'cache.default' => 'array',
        ]);

        Route::middleware('threat-detect')->post('/phase11-test', fn() => response('OK', 200));

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
        $property = new \ReflectionProperty(ThreatDetectionService::class, 'validatedCustomPatterns');
        $property->setValue(null, null);
    }

    // ── Validator primitives ────────────────────────────────────────────────

    #[Test]
    public function verhoeff_accepts_checksum_valid_numbers(): void
    {
        $this->assertTrue(PatternValidators::passes('verhoeff', '2363'));
        $this->assertTrue(PatternValidators::passes('verhoeff', '234123412346'));
    }

    #[Test]
    public function verhoeff_rejects_single_digit_alterations(): void
    {
        $this->assertFalse(PatternValidators::passes('verhoeff', '2364'));
        $this->assertFalse(PatternValidators::passes('verhoeff', '234123412347'));
        $this->assertFalse(PatternValidators::passes('verhoeff', '134123412346'));
    }

    #[Test]
    public function verhoeff_strips_separators_and_rejects_empty(): void
    {
        $this->assertTrue(PatternValidators::passes('verhoeff', '2341 2341 2346'));
        $this->assertFalse(PatternValidators::passes('verhoeff', 'no digits here'));
    }

    #[Test]
    public function luhn_accepts_valid_card_numbers_with_or_without_separators(): void
    {
        $this->assertTrue(PatternValidators::passes('luhn', '4111111111111111'));
        $this->assertTrue(PatternValidators::passes('luhn', '4111-1111-1111-1111'));
    }

    #[Test]
    public function luhn_rejects_invalid_and_too_short_numbers(): void
    {
        $this->assertFalse(PatternValidators::passes('luhn', '4111111111111112'));
        // Checksum-valid but shorter than any real card number (11 digits).
        $this->assertFalse(PatternValidators::passes('luhn', '79927398713'));
    }

    #[Test]
    public function unknown_validator_name_fails_open(): void
    {
        $this->assertFalse(PatternValidators::known('nonexistent'));
        $this->assertTrue(PatternValidators::passes('nonexistent', 'anything'));
    }

    // ── Full cycle through the middleware ───────────────────────────────────

    #[Test]
    public function checksum_valid_aadhaar_number_is_still_detected(): void
    {
        // The "@" in the email passes the suspicious-character pre-screen and
        // "password" activates the token category the Aadhaar pattern belongs
        // to — mirroring a real leak, where PII travels alongside credentials.
        $this->postJson('/phase11-test', [
            'email' => 'user@example.com',
            'password' => 'irrelevant',
            'aadhaar' => '234123412346',
        ]);

        $this->assertDatabaseHas('threat_logs', ['type' => '[custom] Aadhaar Number Detected']);
    }

    #[Test]
    public function checksum_invalid_twelve_digit_run_is_no_longer_flagged(): void
    {
        // One digit off the valid vector — an order id, timestamp or barcode.
        $this->postJson('/phase11-test', [
            'email' => 'user@example.com',
            'password' => 'irrelevant',
            'aadhaar' => '234123412347',
        ]);

        $this->assertDatabaseMissing('threat_logs', ['type' => '[custom] Aadhaar Number Detected']);
    }

    #[Test]
    public function without_a_validator_mapping_behaviour_is_unchanged(): void
    {
        config(['threat-detection.pattern_validators' => []]);

        // Same checksum-invalid number: with no validator mapped, the plain
        // regex match logs it exactly as before this feature existed.
        $this->postJson('/phase11-test', [
            'email' => 'user@example.com',
            'password' => 'irrelevant',
            'aadhaar' => '234123412347',
        ]);

        $this->assertDatabaseHas('threat_logs', ['type' => '[custom] Aadhaar Number Detected']);
    }

    #[Test]
    public function unknown_validator_in_config_fails_open_and_still_detects(): void
    {
        config(['threat-detection.pattern_validators' => [
            'Aadhaar Number Detected' => 'no-such-validator',
        ]]);

        $this->postJson('/phase11-test', [
            'email' => 'user@example.com',
            'password' => 'irrelevant',
            'aadhaar' => '234123412347',
        ]);

        $this->assertDatabaseHas('threat_logs', ['type' => '[custom] Aadhaar Number Detected']);
    }

    #[Test]
    public function luhn_validator_gates_a_custom_card_pattern(): void
    {
        config([
            'threat-detection.custom_patterns' => [
                '/\b(?:\d[ -]?){13,19}\b/' => 'Card Number Detected',
            ],
            'threat-detection.pattern_validators' => [
                'Card Number Detected' => 'luhn',
            ],
        ]);

        // Checksum-valid card number → detected.
        $this->postJson('/phase11-test', [
            'email' => 'user@example.com',
            'password' => 'irrelevant',
            'card' => '4111111111111111',
        ]);
        $this->assertDatabaseHas('threat_logs', ['type' => '[custom] Card Number Detected']);
    }

    #[Test]
    public function luhn_validator_suppresses_a_checksum_invalid_card_lookalike(): void
    {
        config([
            'threat-detection.custom_patterns' => [
                '/\b(?:\d[ -]?){13,19}\b/' => 'Card Number Detected',
            ],
            'threat-detection.pattern_validators' => [
                'Card Number Detected' => 'luhn',
            ],
        ]);

        // 16-digit run that fails Luhn — a tracking number, not a card.
        $this->postJson('/phase11-test', [
            'email' => 'user@example.com',
            'password' => 'irrelevant',
            'card' => '4111111111111112',
        ]);
        $this->assertDatabaseMissing('threat_logs', ['type' => '[custom] Card Number Detected']);
    }

    #[Test]
    public function a_valid_value_among_invalid_ones_still_triggers_detection(): void
    {
        // Suppression must require ALL matched values to fail — one genuine
        // Aadhaar number among noise is still a leak.
        $this->postJson('/phase11-test', [
            'email' => 'user@example.com',
            'password' => 'irrelevant',
            'ref' => '234123412347',
            'aadhaar' => '234123412346',
        ]);

        $this->assertDatabaseHas('threat_logs', ['type' => '[custom] Aadhaar Number Detected']);
    }

    #[Test]
    public function patterns_without_a_validator_are_unaffected_by_the_mapping(): void
    {
        // The shipped mapping only touches the Aadhaar label; an unrelated
        // pattern in the same request must keep firing normally.
        $this->postJson('/phase11-test', [
            'q' => "' UNION SELECT password FROM users--",
        ]);

        $this->assertDatabaseHas('threat_logs', ['type' => '[middleware] SQL Injection UNION']);
    }
}
