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
 * A credential nested in a query-string array was stored in the url column.
 *
 * The payload column was safe: it is built from the decoded array, and
 * `user[password]` is masked there by key. The url column is text, masked by
 * a regex over name=value pairs — and Symfony normalises the query string, so
 * `user[password]=…` arrives as `user%5Bpassword%5D=…`. The name was
 * preceded by the `B` of `%5B`, which the regex read as part of a longer
 * name, and the value was kept in cleartext.
 */
class NestedQueryCredentialTest extends TestCase
{
    private const INJECTION = "' UNION SELECT password FROM users--";

    private const SECRET = 'hunter2secret';

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
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    private function storedUrlFor(string $query): string
    {
        $this->get('/search?q=' . urlencode(self::INJECTION) . '&' . $query)->assertStatus(200);

        $url = DB::table('threat_logs')->where('type', 'like', '%SQL Injection%')->value('url');

        $this->assertNotNull($url, 'the injection was not logged, so nothing below means anything');

        return (string) $url;
    }

    public static function nestedCredentials(): array
    {
        return [
            'one level' => ['user[password]=' . self::SECRET],
            'a prefixed name' => ['filter[partner_api_key]=' . self::SECRET],
            'two levels' => ['a[b][token]=' . self::SECRET],
        ];
    }

    #[Test]
    #[DataProvider('nestedCredentials')]
    public function a_nested_credential_is_masked_in_the_url_column(string $query): void
    {
        $url = $this->storedUrlFor($query);

        $this->assertStringNotContainsString(self::SECRET, $url, "stored in cleartext: {$url}");
        $this->assertStringContainsString('[REDACTED]', $url);
    }

    /** Positive control: an ordinary nested value is stored as sent. */
    #[Test]
    public function an_ordinary_nested_value_is_kept(): void
    {
        $this->assertStringContainsString('alice', $this->storedUrlFor('user[name]=alice'));
    }

    /** Positive control: the flat form was already masked. */
    #[Test]
    public function the_flat_form_is_still_masked(): void
    {
        $this->assertStringNotContainsString(self::SECRET, $this->storedUrlFor('password=' . self::SECRET));
    }
}
