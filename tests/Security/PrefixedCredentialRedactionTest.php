<?php

namespace JayAnta\ThreatDetection\Tests\Security;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * Credentials under a prefixed name were stored in cleartext.
 *
 * Masking by field name compared names exactly, so `api_key` was masked and
 * `X-Partner-Api-Key` was not; nor were `X-Vault-Token`,
 * `X-Amz-Security-Token`, `X-Webhook-Secret`, `Proxy-Authorization` or a body
 * field called `stripe_secret`. Every header but Cookie and Authorization is
 * kept with the row, so a legitimate client whose request tripped a pattern
 * left its key in threat_logs — readable, by default, by any signed-in user
 * of the API. The same class as the 1.8.0 advisory, one naming convention
 * over.
 *
 * A listed name now also covers any name ending in `_<name>`: `api_key`
 * covers `partner_api_key`, `token` covers `vault_token`. A name that merely
 * *starts* with one — `password_hint`, `token_count` — is still kept, as
 * documented.
 */
class PrefixedCredentialRedactionTest extends TestCase
{
    private const INJECTION = "' UNION SELECT password FROM users--";

    private const SECRET = 'live_s3cr3t_9f8e7d6c';

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
        ]);

        ThreatDetectionService::flushCaches();

        Route::middleware('threat-detect')->get('/search', fn () => response('OK'));
        Route::middleware('threat-detect')->post('/search', fn () => response('OK'));
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    private function storedRow(): object
    {
        $row = DB::table('threat_logs')->where('type', 'like', '%SQL Injection%')->first();

        $this->assertNotNull($row, 'the injection was not logged, so nothing below means anything');

        return $row;
    }

    public static function credentialHeaders(): array
    {
        return [
            'custom API key' => ['X-Partner-Api-Key'],
            'vault token' => ['X-Vault-Token'],
            'cloud session token' => ['X-Amz-Security-Token'],
            'webhook secret' => ['X-Webhook-Secret'],
            'proxy credentials' => ['Proxy-Authorization'],
            'session token' => ['X-Session-Token'],
        ];
    }

    #[Test]
    #[DataProvider('credentialHeaders')]
    public function a_prefixed_credential_header_is_masked(string $header): void
    {
        $this->withHeaders([$header => self::SECRET])
            ->get('/search?q=' . urlencode(self::INJECTION))
            ->assertStatus(200);

        $row = $this->storedRow();

        $this->assertStringNotContainsString(self::SECRET, (string) $row->payload, "{$header} was stored in cleartext");
        $this->assertStringContainsString('[REDACTED]', (string) $row->payload);
    }

    #[Test]
    public function a_prefixed_credential_in_the_body_is_masked(): void
    {
        $this->postJson('/search', ['q' => self::INJECTION, 'stripe_secret' => self::SECRET, 'db_password' => self::SECRET])
            ->assertStatus(200);

        $this->assertStringNotContainsString(self::SECRET, (string) $this->storedRow()->payload);
    }

    #[Test]
    public function a_prefixed_credential_in_the_query_string_is_masked(): void
    {
        $this->get('/search?partner_api_key=' . self::SECRET . '&q=' . urlencode(self::INJECTION))
            ->assertStatus(200);

        $row = $this->storedRow();

        $this->assertStringNotContainsString(self::SECRET, (string) $row->url, 'the key survived in the url column');
        $this->assertStringNotContainsString(self::SECRET, (string) $row->payload);
    }

    /** Positive control: names that only start with a listed word are kept. */
    #[Test]
    public function a_name_that_only_starts_with_a_listed_word_is_kept(): void
    {
        $this->postJson('/search', ['q' => self::INJECTION, 'password_hint' => 'first pet', 'token_count' => 'forty-two'])
            ->assertStatus(200);

        $payload = (string) $this->storedRow()->payload;

        $this->assertStringContainsString('first pet', $payload);
        $this->assertStringContainsString('forty-two', $payload);
    }

    /** Positive control: an ordinary header is stored as sent. */
    #[Test]
    public function an_ordinary_header_is_kept(): void
    {
        $this->withHeaders(['X-Request-Id' => 'req-7f3a'])
            ->get('/search?q=' . urlencode(self::INJECTION))
            ->assertStatus(200);

        $this->assertStringContainsString('req-7f3a', (string) $this->storedRow()->payload);
    }

    /**
     * Redaction fails closed: if its regex gives up, the whole URL is masked.
     * A regex that backtracked once per character of a parameter name would
     * give up on a long enough one — and hand a requester a way to blank the
     * url column of their own row.
     */
    #[Test]
    public function a_very_long_parameter_name_does_not_blank_the_url(): void
    {
        $this->get('/search?q=' . urlencode(self::INJECTION) . '&' . str_repeat('a', 1500000) . '=1')
            ->assertStatus(200);

        $url = (string) $this->storedRow()->url;

        $this->assertStringContainsString('/search?', $url, 'the url column was blanked: ' . substr($url, 0, 80));
        $this->assertStringContainsString('aaaa', $url);
    }

    /** Masking is applied to what is stored; detection still sees the request. */
    #[Test]
    public function detection_is_unaffected(): void
    {
        $this->withHeaders(['X-Partner-Api-Key' => self::SECRET])
            ->get('/search?q=' . urlencode(self::INJECTION))
            ->assertStatus(200);

        $this->assertGreaterThan(0, DB::table('threat_logs')->where('type', 'like', '%SQL Injection%')->count());
    }
}
