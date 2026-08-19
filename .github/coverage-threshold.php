<?php

/**
 * Fail the build when line coverage drops below a threshold.
 *
 * Deliberately not a coverage service. A percentage published to a third party
 * mostly buys a badge, and a badge is easy to satisfy with assertions that
 * never exercise the path that matters — which is the exact bug class this
 * package has shipped twice. What is worth having is a gate that notices when
 * a refactor stops covering something, and that can live in the repo with no
 * external account, no upload token and no extra party holding repo access.
 *
 * Usage: php .github/coverage-threshold.php coverage.xml 60
 */
$file = $argv[1] ?? 'coverage.xml';
$min = (float) ($argv[2] ?? 0);

if (! is_readable($file)) {
    fwrite(STDERR, "Coverage report not found: {$file}\n");
    exit(1);
}

$xml = simplexml_load_file($file);

if ($xml === false || ! isset($xml->project->metrics)) {
    fwrite(STDERR, "Could not parse clover report: {$file}\n");
    exit(1);
}

$metrics = $xml->project->metrics;
$statements = (int) $metrics['statements'];
$covered = (int) $metrics['coveredstatements'];
$methods = (int) $metrics['methods'];
$coveredMethods = (int) $metrics['coveredmethods'];

if ($statements === 0) {
    fwrite(STDERR, "Report contains no statements — is a coverage driver installed?\n");
    exit(1);
}

$linePct = round($covered / $statements * 100, 2);
$methodPct = $methods > 0 ? round($coveredMethods / $methods * 100, 2) : 0.0;

$summary = sprintf(
    "Lines:   %s%% (%d/%d)\nMethods: %s%% (%d/%d)\nMinimum: %s%%\n",
    $linePct, $covered, $statements,
    $methodPct, $coveredMethods, $methods,
    $min
);

echo $summary;

// Surface it on the run page so the number is visible without opening logs.
if ($stepSummary = getenv('GITHUB_STEP_SUMMARY')) {
    file_put_contents(
        $stepSummary,
        "## Coverage\n\n```\n{$summary}```\n",
        FILE_APPEND
    );
}

if ($linePct < $min) {
    fwrite(STDERR, "\nCoverage {$linePct}% is below the {$min}% minimum.\n");
    exit(1);
}

echo "\nCoverage gate passed.\n";
