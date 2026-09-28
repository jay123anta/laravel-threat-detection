<?php

namespace JayAnta\ThreatDetection\Tests\Security;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * The export's cells must be the cells a spreadsheet reads.
 *
 * fputcsv() escapes with a backslash by default, which RFC 4180 does not know:
 * a `"` after a `\` is written undoubled. PHP reads its own output back fine,
 * but Excel and LibreOffice follow the RFC, end the quoted cell at that quote,
 * and start a new cell with whatever follows — so a URL containing `\",=…`
 * arrived as two cells, the second beginning with `=`. sanitizeCsvCell() looks
 * at where each value starts, and that one never started a value.
 *
 * Parsed here the way a spreadsheet parses it: RFC 4180, no escape character.
 */
class CsvRecordIntegrityTest extends TestCase
{
    private const COLUMNS = 11;

    private const URL_COLUMN = 3;

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
        parent::tearDown();
    }

    /** @return array<int, array<int, string|null>> */
    private function exportedRecords(string $url): array
    {
        DB::table('threat_logs')->insert([
            'ip_address' => '203.0.113.9',
            'url' => $url,
            'user_agent' => 'Mozilla/5.0',
            'type' => '[query] XSS Script Tag',
            'payload' => 'x',
            'threat_level' => 'high',
            'confidence_score' => 90,
            'confidence_label' => 'very_high',
            'action_taken' => 'logged',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $response = $this->get('/api/threat-detection/export');
        $response->assertStatus(200);

        $handle = fopen('php://temp', 'r+');
        fwrite($handle, $response->getContent());
        rewind($handle);

        $records = [];
        while (($record = fgetcsv($handle, null, ',', '"', '')) !== false) {
            $records[] = $record;
        }
        fclose($handle);

        return $records;
    }

    public static function urls(): array
    {
        return [
            'an ordinary URL' => ['https://app.test/search'],
            'a backslash before a quote, then a formula' => ['https://app.test/x\\",=1+1'],
            'a backslash before a quote mid-value' => ['https://app.test/a\\"b'],
            'a trailing backslash' => ['https://app.test/x\\'],
        ];
    }

    #[Test]
    #[DataProvider('urls')]
    public function each_row_is_one_record_of_the_expected_width(string $url): void
    {
        $records = $this->exportedRecords($url);

        $this->assertCount(2, $records, 'expected the header and one row');
        $this->assertCount(self::COLUMNS, $records[0]);
        $this->assertCount(self::COLUMNS, $records[1], 'the row was split into more cells than the export wrote');
    }

    #[Test]
    #[DataProvider('urls')]
    public function the_url_cell_reads_back_as_written(string $url): void
    {
        $this->assertSame($url, $this->exportedRecords($url)[1][self::URL_COLUMN]);
    }
}
