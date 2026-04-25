<?php

declare(strict_types=1);

// laravel-audit — Markdown action-plan renderer
// Reads a JSON report (from audit.php) on stdin or as argv[1], writes a
// Claude-friendly markdown checklist to stdout.
//
// Usage:
//   php audit.php <repo> | php render-markdown.php > ACTION-PLAN.md
//   php render-markdown.php report.json > ACTION-PLAN.md

function loadJson(array $argv): array
{
    if (isset($argv[1]) && $argv[1] !== '-') {
        $raw = file_get_contents($argv[1]);
    } else {
        $raw = stream_get_contents(STDIN);
    }
    if (!$raw) {
        fwrite(STDERR, "No input. Pipe audit.php output or pass a JSON file path.\n");
        exit(1);
    }
    $data = json_decode($raw, true);
    if (!is_array($data)) {
        fwrite(STDERR, "Invalid JSON input.\n");
        exit(1);
    }
    return $data;
}

function severityRank(string $sev): int
{
    return match ($sev) {
        'critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3, default => 4,
    };
}

function severityEmoji(string $sev): string
{
    return match ($sev) {
        'critical' => '🔴', 'high' => '🟠', 'medium' => '🟡', 'low' => '⚪', default => '•',
    };
}

const AUTO_FIXABLE_RULES = ['SEC-001', 'SEC-005', 'SEC-008', 'SEC-009', 'SEC-010', 'DEPLOY-003'];

$data = loadJson($argv);
$meta = $data['meta'] ?? [];
$findings = $data['findings'] ?? [];

usort($findings, function ($a, $b) {
    $s = severityRank($a['severity']) <=> severityRank($b['severity']);
    if ($s !== 0) return $s;
    return ($a['rule_id'] ?? '') <=> ($b['rule_id'] ?? '');
});

$repoName = basename((string)($meta['repo'] ?? 'unknown'));
$score = (int)($meta['score'] ?? 0);
$grade = (string)($meta['grade'] ?? '?');
$scanner = (string)($meta['scanner'] ?? 'laravel-audit');
$scannedAt = (string)($meta['scanned_at'] ?? date('c'));
$profile = (string)($meta['profile'] ?? 'default');

$counts = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
foreach ($findings as $f) {
    $counts[$f['severity']] = ($counts[$f['severity']] ?? 0) + 1;
}

$autoFixable = array_values(array_filter(
    $findings,
    fn($f) => in_array($f['rule_id'], AUTO_FIXABLE_RULES, true)
));
$advisoryBySeverity = [];
foreach ($findings as $f) {
    if (in_array($f['rule_id'], AUTO_FIXABLE_RULES, true)) continue;
    $advisoryBySeverity[$f['severity']][] = $f;
}

// ---------- Output ----------

echo "# Laravel Audit — Action Plan\n\n";
echo "| | |\n|---|---|\n";
echo "| **Repo** | `{$repoName}` |\n";
echo "| **Scanner** | {$scanner} (profile: {$profile}) |\n";
echo "| **Generated** | {$scannedAt} |\n";
echo "| **Score** | **{$score} / 100 — Grade {$grade}** |\n";
echo "| **Findings** | " . count($findings) . " total ({$counts['critical']} critical, {$counts['high']} high, {$counts['medium']} medium, {$counts['low']} low) |\n";
echo "\n";

echo "---\n\n";
echo "## For Claude: how to work this plan\n\n";
echo "You're looking at the output of a Laravel static-analysis scanner. Work through items systematically:\n\n";
echo "1. **Start with auto-fixable findings** — run the scanner's `--fix` mode to clear them in one shot. Commit the result before moving on.\n";
echo "2. **Then work through Critical → High → Medium → Low**, one item at a time.\n";
echo "3. For each item: read the file at the reported line, understand it in context, apply the fix (or skip with a written reason), and check the box.\n";
echo "4. **Respect the heuristic warnings** — *Potential N+1* is not proof; verify the loop actually triggers per-iteration queries before refactoring.\n";
echo "5. **Don't blindly remove dangerous primitives** (`unserialize`, `eval`, raw SQL) without understanding why they're there — that can break features.\n";
echo "6. **Re-scan** when you've made changes to confirm findings are resolved:\n";
echo "\n";
echo "```bash\n";
echo "# Re-scan and overwrite the plan\n";
echo "php /Users/marcelg/Herd/brainstorm/laravel-audit/scripts/audit.php . > .laravel-audit/report-latest.json\n";
echo "php /Users/marcelg/Herd/brainstorm/laravel-audit/scripts/render-markdown.php .laravel-audit/report-latest.json > .laravel-audit/ACTION-PLAN.md\n";
echo "\n";
echo "# Or apply safe fixes automatically (commit first — scanner aborts on dirty git)\n";
echo "php /Users/marcelg/Herd/brainstorm/laravel-audit/scripts/audit.php . --fix --dry-run   # preview\n";
echo "php /Users/marcelg/Herd/brainstorm/laravel-audit/scripts/audit.php . --fix              # apply\n";
echo "```\n";
echo "\n";
echo "7. If new findings appear after a re-scan, investigate them before checking anything else off.\n";
echo "\n";
echo "---\n\n";

// Auto-fixable section
if (!empty($autoFixable)) {
    echo "## ⚡ Auto-fixable (run `--fix` to resolve all at once)\n\n";
    echo "```bash\n";
    echo "# First: commit or stash any uncommitted work (scanner aborts on dirty git)\n";
    echo "php /Users/marcelg/Herd/brainstorm/laravel-audit/scripts/audit.php . --fix\n";
    echo "```\n\n";
    foreach ($autoFixable as $f) {
        echo "- [ ] " . severityEmoji($f['severity']) . " **{$f['rule_id']} · " . strtoupper($f['severity']) . "** — {$f['title']}  \n";
        echo "  - **File**: `{$f['file']}" . ($f['line'] ? ':' . $f['line'] : '') . "`\n";
        echo "  - **Why**: {$f['detail']}\n";
        echo "  - **Fix**: {$f['fix']}\n\n";
    }
    echo "---\n\n";
}

// Advisory findings by severity
$severityLabels = [
    'critical' => '🔴 Critical — fix today',
    'high'     => '🟠 High — fix this sprint',
    'medium'   => '🟡 Medium — fix this month',
    'low'      => '⚪ Low — when convenient',
];

foreach (['critical', 'high', 'medium', 'low'] as $sev) {
    $items = $advisoryBySeverity[$sev] ?? [];
    if (empty($items)) continue;
    echo "## " . $severityLabels[$sev] . " (" . count($items) . ")\n\n";
    foreach ($items as $f) {
        echo "- [ ] **{$f['rule_id']}** — {$f['title']}  \n";
        echo "  - **File**: `{$f['file']}" . ($f['line'] ? ':' . $f['line'] : '') . "`\n";
        echo "  - **Why it matters**: {$f['detail']}\n";
        echo "  - **Fix**: {$f['fix']}\n";
        // v0.5.3: surface PERF-001 sibling DB-call sites inline so fixers see the whole
        // loop at once and don't play whack-a-mole across rescans. Schema-additive:
        // only rendered when `siblings` is present and non-empty on the finding.
        if (!empty($f['siblings']) && is_array($f['siblings'])) {
            $parts = [];
            foreach ($f['siblings'] as $sib) {
                if (!is_array($sib)) continue;
                $line = $sib['line'] ?? null;
                $call = $sib['call'] ?? '';
                if ($line === null) continue;
                $parts[] = "`:{$line}` (`{$call}`)";
            }
            if (!empty($parts)) {
                echo "  - **Also in this loop**: " . implode(', ', $parts) . "\n";
            }
        }
        echo "\n";
    }
    echo "---\n\n";
}

if (empty($findings)) {
    echo "## ✨ No findings\n\nThe scanner found no issues. Nice. Re-scan after any significant changes to keep this clean.\n\n";
}

// ---------- Accepted (baselined) section ----------
// Read the baseline file from disk when the report says a baseline exists. This keeps
// the JSON report lean (it only carries a summary under meta.baseline) while still
// giving users a visible breadcrumb of what they've accepted and why.
$baselineMeta = $meta['baseline'] ?? null;
if (is_array($baselineMeta) && !empty($baselineMeta['present']) && !empty($meta['repo'])) {
    $baselinePath = rtrim((string)$meta['repo'], '/') . '/.laravel-audit/baseline.json';
    if (is_file($baselinePath)) {
        $baselineRaw = @file_get_contents($baselinePath);
        $baselineDoc = is_string($baselineRaw) ? json_decode($baselineRaw, true) : null;
        $baselineEntries = (is_array($baselineDoc) && isset($baselineDoc['entries']) && is_array($baselineDoc['entries']))
            ? $baselineDoc['entries']
            : [];
        if (!empty($baselineEntries)) {
            echo "## 🗂 Accepted (baselined)\n\n";
            echo "These findings are tracked in `.laravel-audit/baseline.json` and suppressed from the active plan. Re-surface them with `--ignore-baseline`.\n\n";
            foreach ($baselineEntries as $e) {
                if (!is_array($e)) continue;
                $ruleId = (string)($e['rule_id'] ?? '?');
                $title  = (string)($e['title'] ?? '(no title)');
                $file   = (string)($e['file'] ?? '');
                $line   = $e['line'] ?? null;
                $reason = isset($e['reason']) && is_string($e['reason']) && $e['reason'] !== '' ? $e['reason'] : null;
                $note   = isset($e['note']) && is_string($e['note']) && $e['note'] !== '' ? $e['note'] : null;
                echo "- **{$ruleId}** — {$title}\n";
                if ($file !== '') {
                    echo "  - `{$file}" . ($line ? ':' . $line : '') . "`\n";
                }
                if ($reason !== null || $note !== null) {
                    $bits = [];
                    if ($reason !== null) $bits[] = "Reason: `{$reason}`";
                    if ($note !== null)   $bits[] = $note;
                    echo "  - " . implode(' · ', $bits) . "\n";
                }
            }
            echo "\n---\n\n";
        }
    }
}

echo "## Reference — rule IDs\n\n";
echo "| Prefix | Category |\n|---|---|\n";
echo "| SEC-* | Security |\n";
echo "| BLADE-* | Blade template (XSS, CSRF) |\n";
echo "| PERF-* | Performance |\n";
echo "| SLOP-* | AI-generated code smells |\n";
echo "| DEPLOY-* | Deploy hygiene |\n";
echo "| USER-* | Custom rule plugin from `.laravel-audit/rules/` |\n\n";
echo "Full rule reference: https://mjgapp.com/products/laravel-audit\n";
