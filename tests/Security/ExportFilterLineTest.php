<?php

namespace JayAnta\ThreatDetection\Tests\Security;

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * The generated files open with a `# Filters: …` comment that repeats the
 * options as given. `--since` falls back to 24h when it does not parse, and
 * `--min-hits` is cast to an integer for the query, so neither needs to be
 * well formed for rows to be exported — and a newline in either ended the
 * comment and put the rest of the value on a line of its own: in the fail2ban
 * format, a line of a script run as root.
 *
 * These come from the operator's own command line, the same trust level as
 * `--jail`, which 1.8.0 already refuses to interpolate. The comment now stays
 * one line whatever it is given.
 */
class ExportFilterLineTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();

        config(['threat-detection.enabled' => true, 'cache.default' => 'array']);

        DB::table('threat_logs')->insert([
            'ip_address' => '203.0.113.77',
            'url' => 'https://example.com/x',
            'user_agent' => 'Mozilla/5.0',
            'type' => '[middleware] XSS Script Tag',
            'payload' => 'x',
            'threat_level' => 'high',
            'confidence_score' => 90,
            'confidence_label' => 'very_high',
            'action_taken' => 'logged',
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    public static function exports(): array
    {
        return [
            'fail2ban script' => ['threat-detection:export-fail2ban', [], 'fail2ban-client set '],
            'fail2ban plain' => ['threat-detection:export-fail2ban', ['--format' => 'plain'], '203.0.113.77'],
            'blocklist plain' => ['threat-detection:export-blocklist', [], '203.0.113.77'],
            'blocklist nginx' => ['threat-detection:export-blocklist', ['--format' => 'nginx'], 'deny '],
            'blocklist apache' => ['threat-detection:export-blocklist', ['--format' => 'apache'], 'Deny from '],
        ];
    }

    public static function unparsedOptions(): array
    {
        return [
            '--since' => ['--since', "24h\ntouch /tmp/td-marker"],
            '--min-hits' => ['--min-hits', "1\ntouch /tmp/td-marker"],
        ];
    }

    /** @return string[] every line that is not a comment, a shebang or blank */
    private function outputLines(string $command, array $args): array
    {
        Artisan::call($command, $args);

        return array_values(array_filter(
            array_map('trim', explode("\n", Artisan::output())),
            fn (string $line) => $line !== '' && !str_starts_with($line, '#')
        ));
    }

    #[Test]
    #[DataProvider('exports')]
    public function a_newline_in_an_option_stays_inside_the_comment(string $command, array $args, string $expectedPrefix): void
    {
        foreach (self::unparsedOptions() as [$option, $value]) {
            $lines = $this->outputLines($command, $args + [$option => $value]);

            $this->assertNotEmpty($lines, 'nothing was exported, so this proves nothing');

            foreach ($lines as $line) {
                $this->assertStringStartsWith(
                    $expectedPrefix,
                    $line,
                    "{$option} put a line of its own into the {$command} output"
                );
            }
        }
    }

    /**
     * `--since` given with no value arrives as null, and parseSince() takes a
     * string: the command died with a TypeError instead of falling back to
     * 24 hours, as it does for any other value it cannot read.
     */
    #[Test]
    #[DataProvider('exports')]
    public function a_bare_since_falls_back_to_the_default_window(string $command, array $args, string $expectedPrefix): void
    {
        $this->assertSame(0, Artisan::call($command, $args + ['--since' => null]));
        $this->assertStringContainsString('203.0.113.77', Artisan::output());
    }

    /** Positive control: ordinary options are described exactly as before. */
    #[Test]
    public function ordinary_options_are_described_as_given(): void
    {
        Artisan::call('threat-detection:export-fail2ban', ['--since' => '7d', '--min-hits' => '1', '--level' => 'high']);

        $this->assertStringContainsString('# Filters: level=high, since=7d, min-hits=1', Artisan::output());
    }
}
