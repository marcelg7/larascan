<?php

declare(strict_types=1);

// laravel-audit v0.4 — report diff tool
// Usage: php diff.php <old-report.json> <new-report.json> [--pretty]
//
// Emits a JSON object with `added`, `removed`, and `unchanged` arrays plus a
// `meta` block capturing scan timestamps and score movement. A one-line
// human-readable summary is also written to stderr so this tool is useful in
// pipelines where only stdout is captured.

function usage(): void
{
    fwrite(STDERR, "laravel-audit diff\n");
    fwrite(STDERR, "Usage: php diff.php <old-report.json> <new-report.json> [--pretty]\n");
}

function loadReport(string $path): array
{
    if (!is_file($path)) {
        fwrite(STDERR, "Not a file: {$path}\n");
        exit(1);
    }
    $raw = file_get_contents($path);
    if ($raw === false) {
        fwrite(STDERR, "Failed to read: {$path}\n");
        exit(1);
    }
    $data = json_decode($raw, true);
    if (!is_array($data) || !isset($data['findings']) || !is_array($data['findings'])) {
        fwrite(STDERR, "Not a laravel-audit report: {$path}\n");
        exit(1);
    }
    return $data;
}

/**
 * Identity key for a finding: (rule_id, file, line). Two findings are "the same"
 * if all three match. line can be null; we coerce to 'null' for the key.
 */
function findingKey(array $f): string
{
    return ($f['rule_id'] ?? '')
        . '|' . ($f['file'] ?? '')
        . '|' . ($f['line'] === null ? 'null' : (string)$f['line']);
}

function main(array $argv): int
{
    $positional = array_values(array_filter(
        array_slice($argv, 1),
        fn($a) => !str_starts_with($a, '--')
    ));
    $pretty = in_array('--pretty', $argv, true);

    if (in_array('--help', $argv, true) || count($positional) < 2) {
        usage();
        return 1;
    }

    [$oldPath, $newPath] = $positional;
    $old = loadReport($oldPath);
    $new = loadReport($newPath);

    $oldIdx = [];
    foreach ($old['findings'] as $f) $oldIdx[findingKey($f)] = $f;
    $newIdx = [];
    foreach ($new['findings'] as $f) $newIdx[findingKey($f)] = $f;

    $added = $removed = $unchanged = [];
    foreach ($newIdx as $k => $f) {
        if (!isset($oldIdx[$k])) $added[] = $f;
        else $unchanged[] = $f;
    }
    foreach ($oldIdx as $k => $f) {
        if (!isset($newIdx[$k])) $removed[] = $f;
    }

    $oldScore = $old['meta']['score'] ?? null;
    $newScore = $new['meta']['score'] ?? null;
    $delta = ($oldScore !== null && $newScore !== null) ? ($newScore - $oldScore) : null;

    $result = [
        'meta' => [
            'old_scanned_at' => $old['meta']['scanned_at'] ?? null,
            'new_scanned_at' => $new['meta']['scanned_at'] ?? null,
            'old_score'      => $oldScore,
            'new_score'      => $newScore,
            'score_delta'    => $delta,
        ],
        'added'     => $added,
        'removed'   => $removed,
        'unchanged' => $unchanged,
    ];

    // Human summary → stderr so stdout stays pure JSON.
    $scoreBit = ($oldScore !== null && $newScore !== null)
        ? sprintf(" Score: %d → %d (%+d).", $oldScore, $newScore, $delta)
        : '';
    fwrite(STDERR, sprintf(
        "+%d new findings, -%d resolved, %d unchanged.%s\n",
        count($added), count($removed), count($unchanged), $scoreBit
    ));

    echo json_encode(
        $result,
        $pretty ? JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES : JSON_UNESCAPED_SLASHES
    ) . "\n";
    return 0;
}

exit(main($argv));
