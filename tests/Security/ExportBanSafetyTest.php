<?php

namespace JayAnta\ThreatDetection\Tests\Security;

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * The exports turn detections into bans, which is the one place this passive
 * package's output can refuse someone's traffic. Two kinds of address were
 * banned that the operator had already said should not be:
 *
 *   - an address whose only rows were marked as false positives — the
 *     operator's own statement that it was not an attack;
 *   - an address on `whitelisted_ips`.
 *
 * Both are now left out. A private or reserved address is still exported —
 * some installs mean to ban internal clients — but announced, because the
 * common way one gets there is a proxy that TrustProxies does not know about,
 * where every request appears to come from the proxy and banning it blocks
 * everyone.
 */
class ExportBanSafetyTest extends TestCase
{
    private const ATTACKER = '203.0.113.77';

    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();

        config([
            'threat-detection.enabled' => true,
            'cache.default' => 'array',
            'threat-detection.whitelisted_ips' => [],
        ]);
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    private function seedRows(string $ip, bool $falsePositive = false, int $rows = 1): void
    {
        for ($i = 0; $i < $rows; $i++) {
            DB::table('threat_logs')->insert([
                'ip_address' => $ip,
                'url' => 'https://example.com/x',
                'user_agent' => 'Mozilla/5.0',
                'type' => '[query] SQL Injection UNION',
                'payload' => 'x',
                'threat_level' => 'high',
                'confidence_score' => 90,
                'confidence_label' => 'very_high',
                'is_false_positive' => $falsePositive,
                'action_taken' => 'logged',
                'created_at' => now()->subMinutes($i),
                'updated_at' => now()->subMinutes($i),
            ]);
        }
    }

    private function export(string $command, array $args = []): string
    {
        Artisan::call($command, $args);

        return Artisan::output();
    }

    public static function formats(): array
    {
        return [
            'fail2ban' => ['threat-detection:export-fail2ban', []],
            'fail2ban plain' => ['threat-detection:export-fail2ban', ['--format' => 'plain']],
            'blocklist plain' => ['threat-detection:export-blocklist', []],
            'blocklist nginx' => ['threat-detection:export-blocklist', ['--format' => 'nginx']],
            'blocklist csv' => ['threat-detection:export-blocklist', ['--format' => 'csv']],
        ];
    }

    #[Test]
    #[DataProvider('formats')]
    public function an_address_marked_as_a_false_positive_is_not_banned(string $command, array $args): void
    {
        $this->seedRows(self::ATTACKER);
        $this->seedRows('198.51.100.20', falsePositive: true);

        $output = $this->export($command, $args);

        $this->assertStringContainsString(self::ATTACKER, $output, 'positive control: the attacker should be exported');
        $this->assertStringNotContainsString('198.51.100.20', $output, 'a row the operator marked as a false positive produced a ban');
    }

    /** A false positive does not count toward --min-hits either. */
    #[Test]
    public function false_positives_do_not_count_toward_min_hits(): void
    {
        $this->seedRows(self::ATTACKER, rows: 2);
        $this->seedRows('198.51.100.20');
        $this->seedRows('198.51.100.20', falsePositive: true);

        $output = $this->export('threat-detection:export-blocklist', ['--min-hits' => '2']);

        $this->assertStringContainsString(self::ATTACKER, $output);
        $this->assertStringNotContainsString('198.51.100.20', $output);
    }

    #[Test]
    #[DataProvider('formats')]
    public function a_whitelisted_address_is_not_banned(string $command, array $args): void
    {
        config(['threat-detection.whitelisted_ips' => ['198.51.100.0/24']]);
        $this->seedRows(self::ATTACKER);
        $this->seedRows('198.51.100.20');

        $output = $this->export($command, $args);

        $this->assertStringContainsString(self::ATTACKER, $output);
        $this->assertStringNotContainsString('198.51.100.20', $output, 'a whitelisted address was put on a ban list');
    }

    public static function scriptFormats(): array
    {
        return [
            'fail2ban' => ['threat-detection:export-fail2ban', []],
            'blocklist nginx' => ['threat-detection:export-blocklist', ['--format' => 'nginx']],
            'blocklist apache' => ['threat-detection:export-blocklist', ['--format' => 'apache']],
            'blocklist plain' => ['threat-detection:export-blocklist', []],
        ];
    }

    /** Still exported — the operator may mean it — but never silently. */
    #[Test]
    #[DataProvider('scriptFormats')]
    public function a_private_address_is_exported_with_a_warning(string $command, array $args): void
    {
        $this->seedRows('10.0.0.5');

        $output = $this->export($command, $args);

        $this->assertStringContainsString('10.0.0.5', $output, 'private addresses are still exported');
        $this->assertMatchesRegularExpression('/^# WARNING: .*10\.0\.0\.5.*TrustProxies/m', $output);
    }

    /** CSV has no comment syntax, so the warning goes to the log instead of the file. */
    #[Test]
    public function the_csv_stays_pure_data(): void
    {
        $this->seedRows('10.0.0.5');

        $lines = array_filter(preg_split('/\R/', trim($this->export('threat-detection:export-blocklist', ['--format' => 'csv']))));

        $this->assertSame('ip_address,hits,last_seen,threat_level', array_shift($lines));
        foreach ($lines as $line) {
            $this->assertStringStartsWith('10.0.0.5,', $line);
        }
    }

    /**
     * `is_false_positive` arrived with the v1.2 migration. An install that
     * never ran it still has rows, and exported them before this filter
     * existed, so the filter must not cost it the export.
     */
    #[Test]
    #[DataProvider('formats')]
    public function a_table_from_before_the_false_positive_column_still_exports(string $command, array $args): void
    {
        Schema::create('legacy_threat_logs', function ($table) {
            $table->id();
            $table->string('ip_address');
            $table->text('url');
            $table->text('type');
            $table->string('threat_level')->default('medium');
            $table->timestamps();
        });
        config(['threat-detection.table_name' => 'legacy_threat_logs']);

        DB::table('legacy_threat_logs')->insert([
            'ip_address' => self::ATTACKER,
            'url' => 'https://example.com/x',
            'type' => '[query] SQL Injection UNION',
            'threat_level' => 'high',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->assertStringContainsString(self::ATTACKER, $this->export($command, $args));
    }

    /** Positive control: a public address produces no warning. */
    #[Test]
    public function a_public_address_produces_no_warning(): void
    {
        $this->seedRows(self::ATTACKER);

        $output = $this->export('threat-detection:export-fail2ban');

        $this->assertStringContainsString('banip ' . self::ATTACKER, $output);
        $this->assertStringNotContainsString('# WARNING', $output);
    }
}
