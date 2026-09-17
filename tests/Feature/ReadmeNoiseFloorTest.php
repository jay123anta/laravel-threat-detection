<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The README publishes a sample of the measured noise floor, so that someone
 * evaluating the package learns what it flags on legitimate content before
 * installing rather than after.
 *
 * A documented false-positive table that has drifted from the measured one is
 * worse than none at all: it is a promise the code no longer keeps, in the one
 * section a sceptical reader is most likely to check.
 *
 * What is enforced, precisely — because an earlier version of this file
 * claimed more than it checked:
 *
 *   - Every row names the corpus case it describes, in a `<!-- case: ... -->`
 *     comment, and that case must exist in
 *     `LegitimateTrafficCorpusTest::untunedNoiseFloor()`.
 *   - The row must list that case's measured labels *exactly* — not a subset,
 *     and not labels borrowed from some other case. A request that logs three
 *     detections may not be published as logging one.
 *
 * What is deliberately not enforced: that every corpus case is published. The
 * table is a sample and the README says so.
 *
 * Plain PHPUnit, not the package TestCase: nothing here touches the container,
 * and booting a Laravel application to read a markdown file only means a
 * provider regression can fail a test about documentation.
 */
class ReadmeNoiseFloorTest extends TestCase
{
    private const START = '<!-- noise-floor:start -->';

    private const END = '<!-- noise-floor:end -->';

    private static ?string $readme = null;

    private static function readme(): string
    {
        if (self::$readme === null) {
            $path = __DIR__ . '/../../README.md';
            self::assertFileExists($path);
            self::$readme = (string) file_get_contents($path);
        }

        return self::$readme;
    }

    /** @return array{0: int, 1: int} byte offsets of the two markers */
    private static function markers(): array
    {
        $start = strpos(self::readme(), self::START);
        $end = strpos(self::readme(), self::END);

        self::assertNotFalse($start, 'the noise-floor opening marker is missing from README.md');
        self::assertNotFalse($end, 'the noise-floor closing marker is missing from README.md');
        self::assertGreaterThan($start, $end, 'the noise-floor markers are in the wrong order');

        return [$start, $end];
    }

    /**
     * The table's data rows, classified by position rather than by content:
     * the first piped line is the header, the second must be the separator,
     * the rest are data. Sniffing for '---' or for the header's wording would
     * silently drop a data row that happened to contain either.
     *
     * @return string[]
     */
    private static function dataRows(): array
    {
        [$start, $end] = self::markers();
        $block = substr(self::readme(), $start + strlen(self::START), $end - $start - strlen(self::START));

        $piped = array_values(array_filter(
            array_map('trim', explode("\n", $block)),
            fn (string $line) => str_starts_with($line, '|')
        ));

        self::assertGreaterThanOrEqual(3, count($piped), 'the noise-floor table has no data rows');
        self::assertMatchesRegularExpression(
            '/^\|[\s:|-]+\|$/',
            $piped[1],
            'the second line of the noise-floor table is not a separator row'
        );

        return array_slice($piped, 2);
    }

    /**
     * Split a row into cells on unescaped pipes, so a cell documenting a
     * pipe-containing payload (written `\|`, as GFM requires) stays one cell.
     *
     * @return string[]
     */
    private static function cells(string $row): array
    {
        $cells = preg_split('/(?<!\\\\)\|/', trim($row, " \t|")) ?: [];

        return array_map('trim', $cells);
    }

    /**
     * @return array<string, string[]> corpus case => sorted "Label/severity" pairs, as published
     */
    private static function publishedFloor(): array
    {
        $published = [];

        foreach (self::dataRows() as $row) {
            $cells = self::cells($row);
            self::assertCount(2, $cells, "malformed README row: {$row}");

            self::assertSame(
                1,
                preg_match('/<!--\s*case:\s*(.+?)\s*-->/', $cells[0], $case),
                "README row does not name its corpus case in a <!-- case: ... --> comment: {$row}"
            );

            self::assertGreaterThan(
                0,
                preg_match_all('/`([^`]+)`\s*\/\s*(\w+)/', $cells[1], $pairs, PREG_SET_ORDER),
                "README row lists no `Label` / severity pairs: {$row}"
            );

            $labels = array_map(fn (array $p) => $p[1] . '/' . $p[2], $pairs);
            sort($labels);

            self::assertArrayNotHasKey($case[1], $published, "corpus case published twice: {$case[1]}");
            $published[$case[1]] = $labels;
        }

        return $published;
    }

    /**
     * The assertion that matters: each row is checked against *its own* case,
     * in both directions. A label borrowed from another case fails; so does a
     * row that publishes one detection where the corpus measures three.
     */
    #[Test]
    public function every_row_lists_exactly_what_the_corpus_measures_for_that_request(): void
    {
        $measured = LegitimateTrafficCorpusTest::untunedNoiseFloor();

        foreach (self::publishedFloor() as $case => $labels) {
            $this->assertArrayHasKey(
                $case,
                $measured,
                "README row names a corpus case that does not exist: '{$case}'"
            );

            $expected = $measured[$case];
            sort($expected);

            $this->assertSame(
                $expected,
                $labels,
                "README row for '{$case}' does not match the measured floor. "
                . 'Either the patterns moved or the row is stale or incomplete.'
            );
        }
    }

    /**
     * The table must not be quietly emptied — that would pass the assertion
     * above vacuously while removing the disclosure it exists to make.
     */
    #[Test]
    public function the_readme_publishes_a_meaningful_number_of_examples(): void
    {
        $this->assertGreaterThanOrEqual(
            5,
            count(self::publishedFloor()),
            'the published noise-floor table has been emptied or trimmed below the point of being useful'
        );
    }

    /**
     * The disclosure must keep naming the remedy that actually works, and must
     * not go back to implying the ones that cannot.
     *
     * Four of the five published rows are high severity. `content_paths` and
     * `relaxed` mode suppress low and medium only — by design, and pinned by
     * LegitimateTrafficCorpusTest — so offering them as the fix sends an
     * operator to a switch that changes nothing. An earlier version of this
     * section did exactly that, and an earlier version of this test pinned it
     * in place.
     */
    #[Test]
    public function the_disclosure_names_the_remedy_that_actually_silences_these_rows(): void
    {
        $section = $this->disclosureProse();

        foreach (['safe_fields', 'safe_paths', '#reducing-false-positives'] as $needle) {
            $this->assertStringContainsString(
                $needle,
                $section,
                "the noise-floor disclosure no longer points at '{$needle}'"
            );
        }

        // If the section mentions the low/medium-only tools at all, it must say
        // in the same breath that they keep recording high-severity matches.
        if (str_contains($section, 'content_paths') || str_contains($section, 'relaxed')) {
            $this->assertMatchesRegularExpression(
                '/keep recording high-severity/i',
                $section,
                'the disclosure mentions content_paths/relaxed without saying they cannot silence a high-severity row'
            );
        }
    }

    /**
     * A link to an anchor is only a remedy if the anchor exists. Guard the
     * target, not just the pointer.
     */
    #[Test]
    public function the_tuning_section_the_disclosure_links_to_still_exists(): void
    {
        $slugs = [];
        preg_match_all('/^#{2,3}\s+(.+)$/m', self::readme(), $headings);
        foreach ($headings[1] as $heading) {
            $slug = strtolower(trim($heading));
            $slug = preg_replace('/[^a-z0-9 -]/', '', $slug);
            $slugs[] = str_replace(' ', '-', (string) $slug);
        }

        $this->assertContains(
            'reducing-false-positives',
            $slugs,
            'the disclosure links to #reducing-false-positives, but no heading slugs to that any more'
        );
    }

    /**
     * The prose belonging to the disclosure: from the closing marker to the
     * next `###` heading. Bounded by structure, not by a byte count — a fixed
     * window either spills into unrelated sections or fails a correct README
     * the day the table grows.
     */
    private function disclosureProse(): string
    {
        [, $end] = self::markers();
        $from = $end + strlen(self::END);

        $next = strpos(self::readme(), "\n### ", $from);
        $this->assertNotFalse($next, 'no heading follows the noise-floor disclosure');

        return substr(self::readme(), $from, $next - $from);
    }
}
