<?php

declare(strict_types=1);

// larascan v0.5.4 — dependency-free scanner with auto-fix, trend tracking, CI support
// Usage:
//   php audit.php <repo-path> [--pretty]               scan, JSON report to stdout
//   php audit.php <repo-path> --fix [--dry-run]        scan + apply safe fixes
//   php audit.php <repo-path> --save-history           scan + append to .larascan/history
//   php audit.php <repo-path> --profile=pre-launch     use a stricter/tuned rule profile
//   php audit.php <repo-path> --interactive            step through findings (TTY required)
//   php audit.php <repo-path> --webhook=<URL>          POST summary to Slack/Discord/generic webhook
//   php audit.php <repo-path> --update-baseline        write current findings to .larascan/baseline.json
//   php audit.php <repo-path> --ignore-baseline        scan without filtering baselined findings
//   php audit.php <repo-path> --format=sarif           emit SARIF 2.1.0 instead of JSON

const LARASCAN_VERSION = '0.5.4';

const SEVERITY_CRIT = 'critical';
const SEVERITY_HIGH = 'high';
const SEVERITY_MED  = 'medium';
const SEVERITY_LOW  = 'low';

const SEVERITY_WEIGHT = [
    SEVERITY_CRIT => 20,
    SEVERITY_HIGH => 10,
    SEVERITY_MED  => 4,
    SEVERITY_LOW  => 1,
];

// Rule profiles. A profile is an override layer on top of the default scoring:
//   - rules:             null = run every registered rule; array = run only those.
//   - severity_weights:  per-severity weight overrides (merged into SEVERITY_WEIGHT).
//   - per_severity_cap:  per-severity penalty cap overrides (replaces defaults for listed severities).
//   - description:       human-readable, shown in help text.
//
// Calibration rationale:
//   - pre-launch: every rule still runs, but penalties bite harder so a "ready to ship" bar
//     actually requires cleaning up medium/low hygiene stuff. Caps are lifted so stacked
//     findings keep hurting.
//   - rescue: security-weighted. Criticals/highs ramp up (+25%/+50%) while lows stay cheap —
//     the goal when inheriting an abandoned codebase is to surface landmines, not nitpicks.
//   - monthly: quick health check. Only core security/perf/deploy rules run; advisory rules
//     (TODO density, stub functions, namespace hygiene, sync-mail advisory, etc.) are skipped
//     so recurring scans don't drown signal in noise.
const PROFILES = [
    'default' => [
        'description'      => 'Balanced default — every rule, standard weights',
        'rules'            => null,
        'severity_weights' => [],
        'per_severity_cap' => [],
    ],
    'pre-launch' => [
        'description'      => 'All rules, stricter scoring — use before shipping to prod',
        'rules'            => null,
        'severity_weights' => [
            SEVERITY_CRIT => 25,
            SEVERITY_HIGH => 14,
            SEVERITY_MED  => 6,
            SEVERITY_LOW  => 2,
        ],
        'per_severity_cap' => [
            SEVERITY_HIGH => 60,
            SEVERITY_MED  => 40,
            SEVERITY_LOW  => 20,
        ],
    ],
    'rescue' => [
        'description'      => 'Security-weighted — use when taking over an abandoned codebase',
        'rules'            => null,
        'severity_weights' => [
            SEVERITY_CRIT => 25,
            SEVERITY_HIGH => 15,
            SEVERITY_MED  => 4,
            SEVERITY_LOW  => 1,
        ],
        'per_severity_cap' => [
            SEVERITY_HIGH => 50,
            SEVERITY_MED  => 20,
            SEVERITY_LOW  => 10,
        ],
    ],
    'monthly' => [
        'description'      => 'Quick health check — skips advisory/low-signal rules',
        'rules'            => [
            'ruleAppDebug', 'ruleMassAssignment', 'ruleRawSqlInterpolation',
            'ruleSqlKeywordInterpolation',
            'ruleHardcodedSecrets', 'ruleUnserialize', 'ruleEval', 'ruleAppKey',
            'ruleBladeUnescaped', 'ruleBladeFormCsrf',
            'ruleNPlusOneHeuristic', 'ruleMissingForeignKeyIndexes',
            'ruleComposerLock',
        ],
        'severity_weights' => [],
        'per_severity_cap' => [],
    ],
];

class Finding
{
    public function __construct(
        public string $ruleId,
        public string $title,
        public string $severity,
        public string $file,
        public ?int $line,
        public string $detail,
        public string $fix,
        // v0.5.3: optional list of sibling DB-call sites within the same foreach body
        // (PERF-001 only). Each entry is ['line' => int, 'call' => string]. Additive
        // field — only serialized when non-empty to preserve backward-compatible JSON.
        public array $siblings = [],
    ) {}

    public function toArray(): array
    {
        $out = [
            'rule_id'  => $this->ruleId,
            'title'    => $this->title,
            'severity' => $this->severity,
            'file'     => $this->file,
            'line'     => $this->line,
            'detail'   => $this->detail,
            'fix'      => $this->fix,
        ];
        if (!empty($this->siblings)) {
            $out['siblings'] = $this->siblings;
        }
        return $out;
    }
}

class Context
{
    /** @var Finding[] */
    public array $findings = [];
    public array $stats = [
        'files_scanned' => 0,
        'php_files'     => 0,
        'blade_files'   => 0,
    ];
    // Repo-level config loaded via loadRepoConfig(). Populated in main().
    // Rules that want user-extensible behaviour (e.g. blade_safe_helpers) read this.
    public array $config = [];

    public function __construct(public string $root) {}

    public function add(Finding $f): void
    {
        $this->findings[] = $f;
    }

    public function relative(string $path): string
    {
        return ltrim(str_replace($this->root, '', $path), '/');
    }
}

// ---------- Helpers ----------

/**
 * Check whether a relative path is listed in the repo's .gitignore.
 *
 * Naive match against .gitignore lines. Not a full pattern engine — we just
 * check whether the exact file path or a prefix directory appears as an
 * ignore rule. Good enough for distinguishing shipped files from local ones
 * (the main use case: deciding whether a local `.env` is actually going
 * to reach a server or is platform-injected from Laravel Cloud/Vercel/etc).
 */
function isGitignored(string $root, string $relativeFile): bool
{
    $gitignore = $root . '/.gitignore';
    if (!is_file($gitignore)) return false;
    $lines = file($gitignore, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($lines === false) return false;
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#' || $line[0] === '!') continue;
        $rule = trim($line, "/ \t");
        if ($rule === $relativeFile) return true;
        if ($rule === basename($relativeFile)) return true; // bare filename match
    }
    return false;
}

// ---------- File iteration ----------

function iterateFiles(string $root, array $extensions): Generator
{
    // Two skip categories:
    // - segment skips match at ANY depth (vendor nested inside .claude/worktrees/* was missed pre-fix)
    // - prefix skips only match relative to the repo root
    $segmentSkips = ['vendor', 'node_modules', '.git', '.next'];
    $prefixSkips  = ['storage/framework', 'storage/logs', 'public/build', '.claude/worktrees'];
    $it = new RecursiveIteratorIterator(
        new RecursiveCallbackFilterIterator(
            new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
            function ($current) use ($segmentSkips, $prefixSkips, $root) {
                if (!$current->isDir()) return true;
                $rel = ltrim(str_replace($root, '', $current->getPathname()), '/');
                foreach ($prefixSkips as $skip) {
                    if ($rel === $skip || str_starts_with($rel, $skip . '/')) return false;
                }
                $segments = explode('/', $rel);
                foreach ($segmentSkips as $skip) {
                    if (in_array($skip, $segments, true)) return false;
                }
                return true;
            }
        )
    );
    foreach ($it as $file) {
        if (!$file->isFile()) continue;
        $ext = strtolower($file->getExtension());
        if (in_array($ext, $extensions, true)) {
            yield $file->getPathname();
        }
    }
}

function iterateBladeFiles(string $root): Generator
{
    $viewsDir = $root . '/resources/views';
    if (!is_dir($viewsDir)) return;
    foreach (iterateFiles($viewsDir, ['php']) as $path) {
        if (str_ends_with($path, '.blade.php')) yield $path;
    }
}

// ---------- Rules ----------

function ruleAppDebug(Context $ctx): void
{
    foreach (['.env', '.env.production', '.env.prod'] as $name) {
        $path = $ctx->root . '/' . $name;
        if (!is_file($path)) continue;
        // Only the bare `.env` gets the gitignore-aware downgrade. Production variants
        // (.env.production / .env.prod / .env.staging) stay at full severity no matter
        // what — if someone accidentally commits one of those, the damage is the same
        // whether or not it's listed in .gitignore.
        $gitignored = ($name === '.env') && isGitignored($ctx->root, '.env');
        $lines = file($path, FILE_IGNORE_NEW_LINES) ?: [];
        foreach ($lines as $i => $line) {
            if (preg_match('/^\s*APP_DEBUG\s*=\s*(true|1)\s*$/i', $line)) {
                $severity = $gitignored ? SEVERITY_LOW : SEVERITY_CRIT;
                $detail = "Debug mode leaks stack traces, env vars, and DB credentials to end users on errors.";
                if ($gitignored) {
                    $detail = "Local `.env` is gitignored (detected in .gitignore) so it's unlikely to ship — but fix before any scenario where this file could reach production. " . $detail;
                }
                $ctx->add(new Finding(
                    ruleId: 'SEC-001',
                    title: 'APP_DEBUG enabled',
                    severity: $severity,
                    file: $name,
                    line: $i + 1,
                    detail: $detail,
                    fix: "Set APP_DEBUG=false in {$name} before deploying.",
                ));
            }
        }
    }
}

function ruleMassAssignment(Context $ctx): void
{
    $modelsDir = $ctx->root . '/app/Models';
    if (!is_dir($modelsDir)) $modelsDir = $ctx->root . '/app';
    if (!is_dir($modelsDir)) return;

    foreach (iterateFiles($modelsDir, ['php']) as $path) {
        $src = file_get_contents($path);
        if ($src === false) continue;
        if (!preg_match('/extends\s+(Model|Authenticatable)/', $src)) continue;

        if (preg_match('/protected\s+\$guarded\s*=\s*\[\s*\]/', $src, $m, PREG_OFFSET_CAPTURE)) {
            $line = substr_count(substr($src, 0, $m[0][1]), "\n") + 1;
            $ctx->add(new Finding(
                ruleId: 'SEC-002',
                title: 'Unbounded mass assignment ($guarded = [])',
                severity: SEVERITY_HIGH,
                file: $ctx->relative($path),
                line: $line,
                detail: "Empty \$guarded lets any request field overwrite any column, including is_admin, email_verified_at, etc.",
                fix: "Replace with \$fillable listing only user-editable columns, or explicitly guard sensitive fields.",
            ));
        }
    }
}

function ruleRawSqlInterpolation(Context $ctx): void
{
    $appDir = $ctx->root . '/app';
    if (!is_dir($appDir)) return;

    foreach (iterateFiles($appDir, ['php']) as $path) {
        $src = file_get_contents($path);
        if ($src === false) continue;

        $patterns = [
            '/DB::(?:statement|raw|select|insert|update|delete)\s*\(\s*["\'][^"\']*\$[a-zA-Z_][a-zA-Z0-9_]*/',
            '/DB::(?:statement|raw|select|insert|update|delete)\s*\(\s*["\'][^"\']*\.\s*\$/',
        ];
        foreach ($patterns as $pattern) {
            if (preg_match_all($pattern, $src, $matches, PREG_OFFSET_CAPTURE)) {
                foreach ($matches[0] as $match) {
                    $line = substr_count(substr($src, 0, $match[1]), "\n") + 1;
                    $ctx->add(new Finding(
                        ruleId: 'SEC-003',
                        title: 'Raw SQL with variable interpolation',
                        severity: SEVERITY_CRIT,
                        file: $ctx->relative($path),
                        line: $line,
                        detail: "String-interpolated SQL is a classic injection vector. Parameter binding is bypassed.",
                        fix: "Use bound parameters: DB::select('... WHERE x = ?', [\$value]).",
                    ));
                }
            }
        }
    }
}

// SEC-011: detect SQL keyword strings with variable interpolation regardless of
// the DB call site. Complements SEC-003, which only catches interpolation that
// happens directly inside a DB::method(...) argument. SEC-011 catches cases
// where an SQL-shaped string is built in an accessor, helper, or returned for
// later display/use — e.g. `return "CREATE INDEX `{$n}` ON `{$t}` ({$cols})"`.
//
// Known limitations:
//   - Does NOT match string concatenation across multiple literals
//     (`'SHOW INDEX FROM ' . $name`). Future extension.
//   - Single-quoted strings without interpolation are correctly skipped (no
//     interpolation syntax to detect).
//   - Test fixtures / seeders with hardcoded SQL (no interpolation) are skipped.
//   - Dedupes against SEC-003 on same file:line so a DB::raw("UPDATE ... $x")
//     reports once, under SEC-003.
function ruleSqlKeywordInterpolation(Context $ctx): void
{
    $appDir = $ctx->root . '/app';
    if (!is_dir($appDir)) return;

    // Build a set of (file, line) pairs already flagged by SEC-003 so we can
    // dedupe. SEC-003 runs before SEC-011 in the $allRules array, so its
    // findings are already in $ctx->findings by the time we execute.
    $sec003Hits = [];
    foreach ($ctx->findings as $f) {
        if ($f->ruleId === 'SEC-003' && $f->line !== null) {
            $sec003Hits[$f->file . ':' . $f->line] = true;
        }
    }

    // Match double-quoted string literals containing a SQL DDL/DML keyword
    // followed by another uppercase word (keyword pair like "CREATE INDEX",
    // "SHOW TABLES", "DROP TABLE", "INSERT INTO", etc.). The uppercase-follow
    // requirement reduces false positives from prose that happens to contain
    // a single keyword (e.g. "Please SELECT a value below").
    $sqlKeywordPattern = '/"(?:[^"\\\\]|\\\\.)*\b(?:SHOW|SELECT|CREATE|ALTER|DROP|INSERT|UPDATE|DELETE|TRUNCATE|RENAME)\s+[A-Z]+(?:[^"\\\\]|\\\\.)*"/';

    foreach (iterateFiles($appDir, ['php']) as $path) {
        $src = file_get_contents($path);
        if ($src === false) continue;

        if (!preg_match_all($sqlKeywordPattern, $src, $matches, PREG_OFFSET_CAPTURE)) continue;

        $relFile = $ctx->relative($path);
        $perFileCount = 0;
        foreach ($matches[0] as $match) {
            $literal = $match[0];
            // Must contain an interpolation: $var, {$expr}, or ${var}.
            $hasInterpolation =
                preg_match('/\{\$[a-zA-Z_]/', $literal) === 1
                || preg_match('/\$\{[a-zA-Z_]/', $literal) === 1
                || preg_match('/(?<!\\\\)\$[a-zA-Z_][a-zA-Z0-9_]*/', $literal) === 1;
            if (!$hasInterpolation) continue;

            $line = substr_count(substr($src, 0, $match[1]), "\n") + 1;

            // Dedupe against SEC-003 at the exact same file:line.
            if (isset($sec003Hits[$relFile . ':' . $line])) continue;

            $ctx->add(new Finding(
                ruleId: 'SEC-011',
                title: 'SQL keyword string with variable interpolation',
                severity: SEVERITY_HIGH,
                file: $relFile,
                line: $line,
                detail: "A string literal containing a SQL keyword is built with interpolated variables. If any interpolated value is user-controlled, this is a SQL injection vector even when the string is not passed directly to a DB:: call (it may be stored, rendered, or executed later).",
                fix: "SQL identifiers (table/column names) cannot be parameter-bound. If the interpolated value is a user-controlled identifier, validate it against a strict whitelist (e.g., preg_match('/^[A-Za-z0-9_]+\$/', \$name)) before interpolation. For values, switch to DB::select('... WHERE x = ?', [\$value]) with bound parameters.",
            ));

            if (++$perFileCount >= 3) break; // cap per-file, consistent with other rules
        }
    }
}

function ruleHardcodedSecrets(Context $ctx): void
{
    $appDir = $ctx->root . '/app';
    if (!is_dir($appDir)) return;

    $secretPatterns = [
        '/(["\'])(sk_live_[a-zA-Z0-9]{20,})\1/' => 'Stripe live secret key',
        '/(["\'])(sk-[a-zA-Z0-9]{40,})\1/'      => 'OpenAI/Anthropic API key',
        '/(["\'])(AKIA[0-9A-Z]{16})\1/'         => 'AWS access key',
        '/(["\'])(ghp_[a-zA-Z0-9]{36})\1/'      => 'GitHub personal access token',
    ];

    foreach (iterateFiles($appDir, ['php']) as $path) {
        $src = file_get_contents($path);
        if ($src === false) continue;

        foreach ($secretPatterns as $pattern => $label) {
            if (preg_match_all($pattern, $src, $matches, PREG_OFFSET_CAPTURE)) {
                foreach ($matches[0] as $match) {
                    $line = substr_count(substr($src, 0, $match[1]), "\n") + 1;
                    $ctx->add(new Finding(
                        ruleId: 'SEC-004',
                        title: "Hardcoded {$label}",
                        severity: SEVERITY_CRIT,
                        file: $ctx->relative($path),
                        line: $line,
                        detail: "Secrets in source code are leaked to every person with repo access and every future AI scan.",
                        fix: "Move to .env, access via config()/env(), and rotate the key immediately since it must be treated as compromised.",
                    ));
                }
            }
        }
    }
}

function ruleDebugLeftovers(Context $ctx): void
{
    $appDir = $ctx->root . '/app';
    if (!is_dir($appDir)) return;

    foreach (iterateFiles($appDir, ['php']) as $path) {
        $src = file_get_contents($path);
        if ($src === false) continue;

        if (preg_match_all('/\b(dd|dump|var_dump|print_r)\s*\(/', $src, $matches, PREG_OFFSET_CAPTURE)) {
            foreach ($matches[0] as $match) {
                $line = substr_count(substr($src, 0, $match[1]), "\n") + 1;
                $fn = trim(rtrim($match[0], '('));
                $ctx->add(new Finding(
                    ruleId: 'SEC-005',
                    title: "{$fn}() left in source",
                    severity: SEVERITY_MED,
                    file: $ctx->relative($path),
                    line: $line,
                    detail: "Debug dumps ship to production, halting requests (dd) or leaking internal state to logs/users.",
                    fix: "Remove the {$fn}() call or replace with Log::debug() if the inspection is needed in production.",
                ));
            }
        }
    }
}

function ruleNPlusOneHeuristic(Context $ctx): void
{
    $appDir = $ctx->root . '/app';
    if (!is_dir($appDir)) return;

    // Only match method names that are overwhelmingly DB-specific on Eloquent builders / relations.
    // Deliberately excluded: bare ->get()/->first()/->count() (too many Collection/Request collisions),
    // ->isPast / Carbon / Collection methods, generic ->method( chains.
    //
    // Note: ->increment() and ->decrement() are deliberately NOT in this list. They are counter
    // WRITES, not lookups — a per-iteration write is usually intentional (e.g. bumping a tally).
    // Including them caused confirmed false positives on RuleProcessorService:41 during MailLore
    // dogfood, where $model->increment('counter') inside a foreach was flagged as N+1.
    $dbCallPattern = '/(?:'
        . '->(?:firstOrFail|findOrFail|firstOrCreate|updateOrCreate|paginate|simplePaginate|chunk|lazy|cursor)\s*\('
        . '|->(?:pluck|exists|doesntExist)\s*\('
        . '|::(?:where|find|findOrFail|firstWhere|create|firstOrCreate|updateOrCreate|destroy)\s*\('
        . '|DB::(?:table|select|insert|update|delete|statement|raw|scalar)\s*\('
        . ')/';

    foreach (iterateFiles($appDir, ['php']) as $path) {
        $src = file_get_contents($path);
        if ($src === false) continue;

        if (!preg_match_all('/foreach\s*\([^)]+\)\s*\{/', $src, $loopMatches, PREG_OFFSET_CAPTURE)) continue;

        // Cap hits at 3 per file. The cap exists because a single file with many loops
        // would otherwise produce a wall of near-identical PERF-001 findings and drown
        // the rest of the report. 1 was too tight: in CleanupJob.php during MailLore
        // dogfood the outer foreach at line 60 was a false positive while the REAL
        // N+1 nested inside it at line 72 never got reported. 3 covers the realistic
        // "nested loops in one method" case without going into noise-storm territory.
        $fileHits = 0;
        foreach ($loopMatches[0] as $loop) {
            if ($fileHits >= 3) break;
            $start = $loop[1];
            $depth = 0;
            $end = $start;
            for ($i = $start; $i < strlen($src); $i++) {
                if ($src[$i] === '{') $depth++;
                elseif ($src[$i] === '}') {
                    $depth--;
                    if ($depth === 0) { $end = $i; break; }
                }
            }
            $body = substr($src, $start, $end - $start);

            // v0.5.3: collect ALL DB-call matches in the body, not just the first.
            // The primary finding still uses the first match's line (preserving v0.5.2
            // behaviour); any additional matches surface as `siblings` so re-scans don't
            // turn fixed loops into whack-a-mole on the next DB call below.
            if (preg_match_all($dbCallPattern, $body, $allHits, PREG_OFFSET_CAPTURE)) {
                $firstOffset  = $allHits[0][0][1];
                $hitLine      = substr_count(substr($src, 0, $start + $firstOffset), "\n") + 1;
                $callSnippet  = trim($allHits[0][0][0]);

                // Siblings: any match after the first. Dedupe by line (a one-liner with
                // two DB calls only surfaces once). Cap at 5 to guard runaway output on
                // pathological code.
                $siblings = [];
                $seenLines = [$hitLine => true];
                $totalHits = count($allHits[0]);
                for ($h = 1; $h < $totalHits; $h++) {
                    if (count($siblings) >= 5) break;
                    $sibOffset = $allHits[0][$h][1];
                    $sibLine   = substr_count(substr($src, 0, $start + $sibOffset), "\n") + 1;
                    if (isset($seenLines[$sibLine])) continue;
                    $seenLines[$sibLine] = true;
                    $siblings[] = [
                        'line' => $sibLine,
                        'call' => trim($allHits[0][$h][0]),
                    ];
                }

                $ctx->add(new Finding(
                    ruleId: 'PERF-001',
                    title: 'Potential N+1: DB call inside foreach',
                    severity: SEVERITY_HIGH,
                    file: $ctx->relative($path),
                    line: $hitLine,
                    detail: "A database call (`{$callSnippet}`) runs on every iteration of a foreach, producing one query per row.",
                    fix: "Collect the IDs and run one query before the loop, or eager-load the relation with Model::with('relation') so no per-item queries are needed.",
                    siblings: $siblings,
                ));
                $fileHits++;
            }
        }
    }
}

function ruleMissingForeignKeyIndexes(Context $ctx): void
{
    $migDir = $ctx->root . '/database/migrations';
    if (!is_dir($migDir)) return;

    foreach (iterateFiles($migDir, ['php']) as $path) {
        $src = file_get_contents($path);
        if ($src === false) continue;

        if (preg_match_all('/->foreignId\s*\(\s*[\'"]([a-z_]+)[\'"]\s*\)(?![^;]*->(?:constrained|index))/', $src, $matches, PREG_OFFSET_CAPTURE)) {
            foreach ($matches[0] as $idx => $match) {
                $line = substr_count(substr($src, 0, $match[1]), "\n") + 1;
                $col  = $matches[1][$idx][0];
                $ctx->add(new Finding(
                    ruleId: 'PERF-002',
                    title: "Foreign key '{$col}' lacks index",
                    severity: SEVERITY_MED,
                    file: $ctx->relative($path),
                    line: $line,
                    detail: "Unindexed foreign keys cause full table scans on every join or lookup by that column.",
                    fix: "Chain ->constrained() (adds index + FK) or ->index() after foreignId('{$col}').",
                ));
            }
        }
    }
}

function ruleSyncMail(Context $ctx): void
{
    $appDir = $ctx->root . '/app';
    if (!is_dir($appDir)) return;

    foreach (iterateFiles($appDir, ['php']) as $path) {
        $src = file_get_contents($path);
        if ($src === false) continue;

        if (preg_match_all('/Mail::(?:to|send|raw)\s*\(/', $src, $matches, PREG_OFFSET_CAPTURE)) {
            foreach ($matches[0] as $match) {
                $offset = $match[1];
                $snippet = substr($src, $offset, 400);
                if (str_contains($snippet, '->queue(') || str_contains($snippet, '->later(')) continue;
                $line = substr_count(substr($src, 0, $offset), "\n") + 1;
                $ctx->add(new Finding(
                    ruleId: 'PERF-003',
                    title: 'Synchronous Mail send blocks the request',
                    severity: SEVERITY_MED,
                    file: $ctx->relative($path),
                    line: $line,
                    detail: "Mail::send without ->queue() runs SMTP in-process, adding seconds to user-facing requests.",
                    fix: "Use Mail::to(\$user)->queue(new YourMailable()) with a queued Mailable (implements ShouldQueue).",
                ));
                break;
            }
        }
    }
}

function ruleTodoDensity(Context $ctx): void
{
    $appDir = $ctx->root . '/app';
    if (!is_dir($appDir)) return;

    foreach (iterateFiles($appDir, ['php']) as $path) {
        $src = file_get_contents($path);
        if ($src === false) continue;

        $count = preg_match_all('/(?:\/\/|#|\*)\s*(TODO|FIXME|XXX|HACK)\b/i', $src);
        if ($count >= 5) {
            $ctx->add(new Finding(
                ruleId: 'SLOP-001',
                title: "High TODO/FIXME density ({$count} markers)",
                severity: SEVERITY_LOW,
                file: $ctx->relative($path),
                line: null,
                detail: "Concentrations of TODO/FIXME/HACK markers typically indicate unfinished AI-generated scaffolding that was never revisited.",
                fix: "Triage each marker: resolve it, convert to a tracked issue, or delete dead stubs entirely.",
            ));
        }
    }
}

function ruleStubFunctions(Context $ctx): void
{
    $appDir = $ctx->root . '/app';
    if (!is_dir($appDir)) return;

    foreach (iterateFiles($appDir, ['php']) as $path) {
        $src = file_get_contents($path);
        if ($src === false) continue;

        // functions whose body is only "return null;" / "return [];" / "return true;" / "return;"
        if (preg_match_all('/function\s+([a-zA-Z_]\w*)\s*\([^)]*\)\s*(?::\s*[\w\\\\|?]+\s*)?\{\s*return\s*(?:null|\[\s*\]|true|false)?\s*;\s*\}/', $src, $matches, PREG_OFFSET_CAPTURE)) {
            if (count($matches[0]) >= 2) {
                $first = $matches[0][0];
                $line = substr_count(substr($src, 0, $first[1]), "\n") + 1;
                $ctx->add(new Finding(
                    ruleId: 'SLOP-002',
                    title: 'Multiple stub functions with empty returns',
                    severity: SEVERITY_LOW,
                    file: $ctx->relative($path),
                    line: $line,
                    detail: count($matches[0]) . " functions only `return null/[]/true`. Typical of AI scaffolds where the intent was never filled in.",
                    fix: "Implement the logic, remove the stubs, or mark the class abstract if stubs represent a contract.",
                ));
            }
        }
    }
}

function ruleComposerLock(Context $ctx): void
{
    $composerJson = $ctx->root . '/composer.json';
    $composerLock = $ctx->root . '/composer.lock';
    if (!is_file($composerJson)) return;

    if (!is_file($composerLock)) {
        $ctx->add(new Finding(
            ruleId: 'DEPLOY-001',
            title: 'composer.lock missing',
            severity: SEVERITY_HIGH,
            file: 'composer.json',
            line: null,
            detail: "Without composer.lock, every deploy resolves different package versions. Prod and local drift silently.",
            fix: "Run `composer install`, commit composer.lock, and deploy with `composer install --no-dev`.",
        ));
        return;
    }

    $jsonHash = hash_file('md5', $composerJson);
    $lockData = json_decode(file_get_contents($composerLock), true);
    if (isset($lockData['content-hash'])) {
        $content = json_decode(file_get_contents($composerJson), true);
        unset($content['scripts'], $content['scripts-descriptions'], $content['support']);
        $expected = md5(json_encode(ksort_recursive($content)));
        // lock content-hash is computed differently by composer; we only flag stale when the filehash says modified
        $lockMtime = filemtime($composerLock);
        $jsonMtime = filemtime($composerJson);
        if ($jsonMtime > $lockMtime + 60) {
            $ctx->add(new Finding(
                ruleId: 'DEPLOY-002',
                title: 'composer.lock older than composer.json',
                severity: SEVERITY_MED,
                file: 'composer.lock',
                line: null,
                detail: "composer.json was edited after composer.lock was regenerated. Deploys may install unexpected versions.",
                fix: "Run `composer update` (or `composer install` if you only reordered), then commit the refreshed lock.",
            ));
        }
    }
}

function ksort_recursive(array $arr): array
{
    ksort($arr);
    foreach ($arr as $k => $v) if (is_array($v)) $arr[$k] = ksort_recursive($v);
    return $arr;
}

function rulePhpVersionPin(Context $ctx): void
{
    $composerJson = $ctx->root . '/composer.json';
    if (!is_file($composerJson)) return;
    $data = json_decode(file_get_contents($composerJson), true);
    if (!isset($data['require']['php'])) {
        $ctx->add(new Finding(
            ruleId: 'DEPLOY-003',
            title: 'PHP version not constrained in composer.json',
            severity: SEVERITY_LOW,
            file: 'composer.json',
            line: null,
            detail: "No `require.php` means Composer accepts any PHP, allowing a version mismatch between dev and prod.",
            fix: 'Add "php": "^8.3" (or your target) to the require block in composer.json.',
        ));
    }
}

// ---------- v0.2 rules ----------

function ruleBladeUnescaped(Context $ctx): void
{
    // Built-in safe-helpers: calls whose output is framework-escaped or framework-owned.
    $safeHelpers = '/^\s*(?:route|url|asset|config|env|trans|__|csrf_field|method_field|old|session|cache|view)\s*\(/';

    // Nested-escape safe wrappers (v0.5.2).
    //   {!! nl2br(e($foo)) !!}         — canonical Laravel pattern: e() escapes, nl2br wraps.
    //   {!! Str::markdown(e($foo)) !!} — markdown output with prior escaping.
    // The outer call is only safe because the inner e() runs first. If the inner is not e(),
    // the rule still fires correctly.
    $nestedEscape = '/^\s*(?:nl2br|Str::markdown)\s*\(\s*e\s*\(/';

    // Framework-method allowlist (v0.5.2): methods that return framework-rendered safe HTML.
    // Matched on the trailing `->method()` form only (no-arg method calls).
    $safeMethodSuffixes = [
        // Jetstream / Fortify
        'twoFactorQrCodeSvg', 'twoFactorQrCodeUrl', 'twoFactorSecret',
        // Common Laravel helpers that return escaped/safe HTML
        'toHtml', 'renderMarkdown',
    ];
    $safeMethodSuffixMap = array_flip($safeMethodSuffixes);

    // User-extensible safe-helpers list (v0.5.2) — configured via
    // `.larascan/config.json` → "blade_safe_helpers": ["markdown_to_html", ...].
    // Each entry is a bare function name; treated the same as the built-in list.
    $userHelpers = [];
    if (isset($ctx->config['blade_safe_helpers']) && is_array($ctx->config['blade_safe_helpers'])) {
        foreach ($ctx->config['blade_safe_helpers'] as $name) {
            if (!is_string($name) || $name === '') continue;
            // Only allow identifier-like tokens (optional namespace separators / double-colons).
            if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]*(?:(?:\\\\|::)[A-Za-z_][A-Za-z0-9_]*)*$/', $name)) continue;
            $userHelpers[] = $name;
        }
    }
    $userHelpersPattern = null;
    if (!empty($userHelpers)) {
        // Same anchor shape as $safeHelpers: each user helper must be the first identifier
        // and be immediately followed by an opening paren.
        $escaped = array_map(fn($n) => preg_quote($n, '/'), $userHelpers);
        $userHelpersPattern = '/^\s*(?:' . implode('|', $escaped) . ')\s*\(/';
    }

    foreach (iterateBladeFiles($ctx->root) as $path) {
        $src = file_get_contents($path);
        if ($src === false) continue;
        if (!preg_match_all('/\{!!\s*(.+?)\s*!!\}/s', $src, $matches, PREG_OFFSET_CAPTURE)) continue;
        $reported = 0;
        foreach ($matches[0] as $idx => $match) {
            $content = $matches[1][$idx][0];
            $trimmed = trim($content);
            $offset  = $match[1];

            // (1) Built-in safe helpers (route(), url(), csrf_field(), ...).
            if (preg_match($safeHelpers, $trimmed)) continue;

            // (2) v0.5.2 — <script> context awareness: suppress json_encode(...) inside a
            // <script>...</script> block. The XSS class BLADE-001 targets is HTML injection;
            // json_encode inside <script> is a separate concern (</script> break-out) that
            // Laravel's json_encode defaults (JSON_HEX_TAG via @json) mitigate. Users who want
            // tighter scanning of JS-embedded data can add custom rules in .larascan/rules/.
            // Use strripos so we find the *most recent* <script / </script> before $offset.
            $before = substr($src, 0, $offset);
            $lastScriptOpen  = strripos($before, '<script');
            $lastScriptClose = strripos($before, '</script>');
            $insideScript = ($lastScriptOpen !== false)
                && ($lastScriptClose === false || $lastScriptOpen > $lastScriptClose);
            if ($insideScript && preg_match('/^\s*json_encode\s*\(/', $trimmed)) continue;

            // (3) v0.5.2 — nested e() escape wrappers: {!! nl2br(e(...)) !!}, Str::markdown(e(...)).
            if (preg_match($nestedEscape, $trimmed)) continue;

            // (4) v0.5.2 — framework-method suffix allowlist for trailing ->method() calls.
            if (preg_match('/->(\w+)\s*\(\s*\)\s*$/', $trimmed, $m)) {
                if (isset($safeMethodSuffixMap[$m[1]])) continue;
            }

            // (5) v0.5.2 — user-configured safe helpers (blade_safe_helpers).
            if ($userHelpersPattern !== null && preg_match($userHelpersPattern, $trimmed)) continue;

            $line = substr_count(substr($src, 0, $offset), "\n") + 1;
            $ctx->add(new Finding(
                ruleId: 'BLADE-001',
                title: 'Unescaped Blade output ({!! !!})',
                severity: SEVERITY_HIGH,
                file: $ctx->relative($path),
                line: $line,
                detail: "Blade's {!! \$var !!} outputs raw HTML without escaping. If \$var ever contains user input, this is a stored XSS vulnerability.",
                fix: "Use {{ \$var }} (double-brace) to auto-escape. Only use {!! !!} when the value is trusted HTML and user-supplied parts are escaped.",
            ));
            if (++$reported >= 3) break; // cap per file
        }
    }
}

function ruleBladeFormCsrf(Context $ctx): void
{
    foreach (iterateBladeFiles($ctx->root) as $path) {
        $src = file_get_contents($path);
        if ($src === false) continue;
        if (!preg_match_all('/<form\b[^>]*\bmethod\s*=\s*["\']?(POST|PUT|PATCH|DELETE)[^>]*>(.*?)<\/form>/is', $src, $matches, PREG_OFFSET_CAPTURE)) continue;
        foreach ($matches[0] as $idx => $match) {
            $body = $matches[2][$idx][0];
            if (preg_match('/@csrf\b|csrf_field\s*\(\s*\)|name=[\'"]_token[\'"]/', $body)) continue;
            $line = substr_count(substr($src, 0, $match[1]), "\n") + 1;
            $ctx->add(new Finding(
                ruleId: 'BLADE-002',
                title: 'State-changing form missing @csrf',
                severity: SEVERITY_HIGH,
                file: $ctx->relative($path),
                line: $line,
                detail: "A <form> with POST/PUT/PATCH/DELETE has no @csrf directive or _token field. Laravel's CSRF middleware rejects these submissions, or worse, disabling CSRF exposes it to cross-site request forgery.",
                fix: "Add @csrf as the first child of the <form> element.",
            ));
        }
    }
}

function ruleUnserialize(Context $ctx): void
{
    $appDir = $ctx->root . '/app';
    if (!is_dir($appDir)) return;
    foreach (iterateFiles($appDir, ['php']) as $path) {
        $src = file_get_contents($path);
        if ($src === false) continue;
        if (!preg_match_all('/(?<![a-zA-Z_\\\\])unserialize\s*\(/', $src, $matches, PREG_OFFSET_CAPTURE)) continue;
        foreach ($matches[0] as $match) {
            $line = substr_count(substr($src, 0, $match[1]), "\n") + 1;
            $ctx->add(new Finding(
                ruleId: 'SEC-006',
                title: 'unserialize() call',
                severity: SEVERITY_CRIT,
                file: $ctx->relative($path),
                line: $line,
                detail: "unserialize() on any untrusted input enables PHP object injection — a well-documented RCE vector. The PHP manual explicitly warns against passing untrusted data to it.",
                fix: "Use json_decode(\$data, true) when you control the format. If you must deserialize, pass ['allowed_classes' => [YourClass::class]] to restrict what can be instantiated.",
            ));
        }
    }
}

function ruleEval(Context $ctx): void
{
    $appDir = $ctx->root . '/app';
    if (!is_dir($appDir)) return;
    foreach (iterateFiles($appDir, ['php']) as $path) {
        $src = file_get_contents($path);
        if ($src === false) continue;
        if (!preg_match_all('/(?<![a-zA-Z_\\\\])eval\s*\(/', $src, $matches, PREG_OFFSET_CAPTURE)) continue;
        foreach ($matches[0] as $match) {
            $line = substr_count(substr($src, 0, $match[1]), "\n") + 1;
            $ctx->add(new Finding(
                ruleId: 'SEC-007',
                title: 'eval() call',
                severity: SEVERITY_CRIT,
                file: $ctx->relative($path),
                line: $line,
                detail: "eval() executes arbitrary PHP. If the argument ever reaches user input, this is immediate remote code execution. Laravel apps almost never need this.",
                fix: "Remove the eval(). Use closures, strategy patterns, or call_user_func with a whitelisted callable for dynamic behavior.",
            ));
        }
    }
}

function ruleAppKey(Context $ctx): void
{
    foreach (['.env', '.env.production', '.env.prod'] as $name) {
        $path = $ctx->root . '/' . $name;
        if (!is_file($path)) continue;
        // See ruleAppDebug for the gitignore-aware downgrade rationale.
        $gitignored = ($name === '.env') && isGitignored($ctx->root, '.env');
        $lines = file($path, FILE_IGNORE_NEW_LINES) ?: [];
        foreach ($lines as $i => $line) {
            if (!preg_match('/^\s*APP_KEY\s*=\s*(.*?)\s*$/', $line, $m)) continue;
            $value = trim($m[1], '"\'');
            $isEmpty = $value === '' || $value === 'base64:' || $value === 'SomeRandomString';
            $isTooShort = !$isEmpty && strlen(str_replace('base64:', '', $value)) < 32;
            if ($isEmpty || $isTooShort) {
                $severity = $gitignored ? SEVERITY_LOW : SEVERITY_CRIT;
                $detail = "APP_KEY encrypts cookies, signs sessions, and powers the Encrypter facade. Empty or placeholder keys break encryption, leak signed values, and let attackers forge sessions.";
                if ($gitignored) {
                    $detail = "Local `.env` is gitignored (detected in .gitignore) so it's unlikely to ship — but fix before any scenario where this file could reach production. " . $detail;
                }
                $ctx->add(new Finding(
                    ruleId: 'SEC-008',
                    title: $isEmpty ? 'APP_KEY empty or placeholder' : 'APP_KEY too short',
                    severity: $severity,
                    file: $name,
                    line: $i + 1,
                    detail: $detail,
                    fix: "Run `php artisan key:generate` to produce a cryptographically strong 32-byte key, then redeploy.",
                ));
            }
        }
    }
}

function ruleAppEnvLocal(Context $ctx): void
{
    foreach (['.env', '.env.production', '.env.prod'] as $name) {
        $path = $ctx->root . '/' . $name;
        if (!is_file($path)) continue;
        // See ruleAppDebug for the gitignore-aware downgrade rationale.
        $gitignored = ($name === '.env') && isGitignored($ctx->root, '.env');
        $lines = file($path, FILE_IGNORE_NEW_LINES) ?: [];
        foreach ($lines as $i => $line) {
            if (preg_match('/^\s*APP_ENV\s*=\s*(local|development|dev)\s*$/i', $line)) {
                $severity = $gitignored ? SEVERITY_LOW : SEVERITY_MED;
                $detail = "APP_ENV=local enables dev-only helpers (Telescope UI, friendlier errors, dev routes) and skips production safeguards. If this file deploys to production, internals leak.";
                if ($gitignored) {
                    $detail = "Local `.env` is gitignored (detected in .gitignore) so it's unlikely to ship — but fix before any scenario where this file could reach production. " . $detail;
                }
                $ctx->add(new Finding(
                    ruleId: 'SEC-009',
                    title: 'APP_ENV set to local',
                    severity: $severity,
                    file: $name,
                    line: $i + 1,
                    detail: $detail,
                    fix: "Set APP_ENV=production in your production environment. Keep APP_ENV=local only in your local .env, which should never be committed or deployed.",
                ));
            }
        }
    }
}

function ruleCookieFlags(Context $ctx): void
{
    $path = $ctx->root . '/config/session.php';
    if (!is_file($path)) return;
    $src = file_get_contents($path);
    if ($src === false) return;

    if (preg_match("/'http_only'\s*=>\s*false/", $src, $m, PREG_OFFSET_CAPTURE)) {
        $line = substr_count(substr($src, 0, $m[0][1]), "\n") + 1;
        $ctx->add(new Finding(
            ruleId: 'SEC-010',
            title: "Session cookie 'http_only' disabled",
            severity: SEVERITY_MED,
            file: 'config/session.php',
            line: $line,
            detail: "Cookies without HttpOnly are readable from JavaScript, so any XSS vulnerability immediately becomes session theft.",
            fix: "Set 'http_only' => true in config/session.php. Only disable with a specific reason (e.g. a client-side SDK that needs to read it).",
        ));
    }
    if (preg_match("/'secure'\s*=>\s*false/", $src, $m, PREG_OFFSET_CAPTURE)) {
        $line = substr_count(substr($src, 0, $m[0][1]), "\n") + 1;
        $ctx->add(new Finding(
            ruleId: 'SEC-010',
            title: "Session cookie 'secure' hard-coded to false",
            severity: SEVERITY_LOW,
            file: 'config/session.php',
            line: $line,
            detail: "Cookies without the Secure flag are sent over plain HTTP, enabling session theft over untrusted networks.",
            fix: "Use 'secure' => env('SESSION_SECURE_COOKIE', true) so production defaults to secure while local dev can opt out.",
        ));
    }
}

function ruleSessionDriverFile(Context $ctx): void
{
    foreach (['.env', '.env.production', '.env.prod'] as $name) {
        $path = $ctx->root . '/' . $name;
        if (!is_file($path)) continue;
        $lines = file($path, FILE_IGNORE_NEW_LINES) ?: [];
        foreach ($lines as $i => $line) {
            if (preg_match('/^\s*SESSION_DRIVER\s*=\s*file\s*$/', $line)) {
                $ctx->add(new Finding(
                    ruleId: 'DEPLOY-004',
                    title: 'SESSION_DRIVER=file',
                    severity: SEVERITY_LOW,
                    file: $name,
                    line: $i + 1,
                    detail: "File-based sessions only work when every request hits the same server. On Vercel, Laravel Cloud, Kubernetes, or any multi-instance deploy, users get logged out randomly.",
                    fix: "Switch to database (run `php artisan session:table && php artisan migrate`), redis, or cookie driver.",
                ));
            }
        }
    }
}

function ruleEloquentAll(Context $ctx): void
{
    $appDir = $ctx->root . '/app';
    if (!is_dir($appDir)) return;
    foreach (iterateFiles($appDir, ['php']) as $path) {
        $src = file_get_contents($path);
        if ($src === false) continue;
        if (!preg_match_all('/\b([A-Z][a-zA-Z0-9]+)::all\s*\(\s*\)/', $src, $matches, PREG_OFFSET_CAPTURE)) continue;
        foreach ($matches[0] as $match) {
            $line = substr_count(substr($src, 0, $match[1]), "\n") + 1;
            $ctx->add(new Finding(
                ruleId: 'PERF-004',
                title: 'Model::all() loads every row into memory',
                severity: SEVERITY_LOW,
                file: $ctx->relative($path),
                line: $line,
                detail: "Model::all() fetches every row at once. Fine in seeders and small-table admin views; dangerous in request handlers once the table grows.",
                fix: "Use ->paginate() for listings, ->cursor() for iteration, or an explicit ->where()->limit()->get() when you know what you need.",
            ));
            break; // one per file to avoid noise
        }
    }
}

function ruleUnnamespacedFiles(Context $ctx): void
{
    $appDir = $ctx->root . '/app';
    if (!is_dir($appDir)) return;
    foreach (iterateFiles($appDir, ['php']) as $path) {
        $src = file_get_contents($path);
        if ($src === false) continue;
        $head = substr($src, 0, 4000);
        if (!preg_match('/\b(class|interface|trait|enum)\s+\w+/', $head)) continue;
        if (preg_match('/^\s*<\?php\s*(?:.*?\n){0,30}?\s*namespace\s+[A-Z]/s', $head)) continue;
        $ctx->add(new Finding(
            ruleId: 'SLOP-003',
            title: 'PHP class in app/ has no namespace',
            severity: SEVERITY_LOW,
            file: $ctx->relative($path),
            line: null,
            detail: "Laravel's PSR-4 autoload needs a namespace matching the folder. A class without a namespace won't autoload and usually signals hand-copied or AI-generated code that bypassed the framework convention.",
            fix: "Add `namespace App\\...;` at the top of the file, matching its folder under app/.",
        ));
    }
}

// ---------- Auto-fix (v0.3) ----------

// Rules eligible for automatic fixing. Other rules stay advisory.
const FIXERS = [
    'SEC-001'    => 'fixAppDebug',
    'SEC-005'    => 'fixDebugLeftovers',
    'SEC-008'    => 'fixAppKey',
    'SEC-009'    => 'fixAppEnvLocal',
    'SEC-010'    => 'fixCookieFlags',
    'DEPLOY-003' => 'fixPhpVersionPin',
];

function fixFinding(Context $ctx, Finding $f, bool $dryRun): array
{
    $fn = FIXERS[$f->ruleId] ?? null;
    if (!$fn) {
        return ['status' => 'not-fixable', 'note' => 'no auto-fix available'];
    }
    return $fn($ctx, $f, $dryRun);
}

function fixAppDebug(Context $ctx, Finding $f, bool $dryRun): array
{
    // v0.5.2: never rewrite a gitignored local .env. Platforms (Laravel Cloud, Vercel, Heroku,
    // etc.) inject production env; fixing a dev file contradicts the finding's own advisory.
    if ($f->file === '.env' && isGitignored($ctx->root, '.env')) {
        return [
            'status' => 'skipped',
            'note'   => "Local .env is gitignored; not rewriting a local-dev file. Set production values on your deploy platform (Laravel Cloud, Vercel, Heroku, etc.) or edit .env.production directly.",
        ];
    }
    $path = $ctx->root . '/' . $f->file;
    if (!is_file($path)) return ['status' => 'failed', 'note' => 'file missing'];
    $src = file_get_contents($path);
    // Use [ \t]* instead of \s* so we never cross line boundaries.
    $new = preg_replace('/^([ \t]*APP_DEBUG[ \t]*=[ \t]*)(true|1)[ \t]*$/mi', '${1}false', $src);
    if ($new === $src) return ['status' => 'skipped', 'note' => 'no match'];
    if (!$dryRun) file_put_contents($path, $new);
    return ['status' => 'applied', 'note' => 'APP_DEBUG=true → false'];
}

function fixDebugLeftovers(Context $ctx, Finding $f, bool $dryRun): array
{
    $path = $ctx->root . '/' . $f->file;
    if (!is_file($path)) return ['status' => 'failed', 'note' => 'file missing'];
    $src = file_get_contents($path);
    // Remove whole lines that are ONLY a dd()/dump()/var_dump()/print_r() statement.
    // Lines with inline debug calls mixed with other code are left alone (too risky).
    $new = preg_replace('/^\s*(?:dd|dump|var_dump|print_r)\s*\([^;]*\)\s*;\s*\n/m', '', $src);
    if ($new === $src) return ['status' => 'skipped', 'note' => 'debug call mixed with other code — fix manually'];
    if (!$dryRun) file_put_contents($path, $new);
    $removed = substr_count($src, "\n") - substr_count($new, "\n");
    return ['status' => 'applied', 'note' => "removed {$removed} standalone debug line(s)"];
}

function fixAppKey(Context $ctx, Finding $f, bool $dryRun): array
{
    // v0.5.2: never rewrite a gitignored local .env. See fixAppDebug() for rationale.
    if ($f->file === '.env' && isGitignored($ctx->root, '.env')) {
        return [
            'status' => 'skipped',
            'note'   => "Local .env is gitignored; not rewriting a local-dev file. Set production values on your deploy platform (Laravel Cloud, Vercel, Heroku, etc.) or edit .env.production directly.",
        ];
    }
    $path = $ctx->root . '/' . $f->file;
    if (!is_file($path)) return ['status' => 'failed', 'note' => 'file missing'];
    $src = file_get_contents($path);
    $key = 'base64:' . base64_encode(random_bytes(32));
    // Match only the current line — [^\n]* not .* with \s* which can cross lines.
    $new = preg_replace('/^([ \t]*APP_KEY[ \t]*=[ \t]*)[^\n]*$/m', '${1}' . $key, $src, 1);
    if ($new === $src) return ['status' => 'skipped', 'note' => 'no APP_KEY line to replace'];
    if (!$dryRun) file_put_contents($path, $new);
    return ['status' => 'applied', 'note' => 'generated fresh 32-byte APP_KEY'];
}

function fixAppEnvLocal(Context $ctx, Finding $f, bool $dryRun): array
{
    // v0.5.2: never rewrite a gitignored local .env. See fixAppDebug() for rationale.
    if ($f->file === '.env' && isGitignored($ctx->root, '.env')) {
        return [
            'status' => 'skipped',
            'note'   => "Local .env is gitignored; not rewriting a local-dev file. Set production values on your deploy platform (Laravel Cloud, Vercel, Heroku, etc.) or edit .env.production directly.",
        ];
    }
    $path = $ctx->root . '/' . $f->file;
    if (!is_file($path)) return ['status' => 'failed', 'note' => 'file missing'];
    $src = file_get_contents($path);
    $new = preg_replace('/^([ \t]*APP_ENV[ \t]*=[ \t]*)(local|development|dev)[ \t]*$/mi', '${1}production', $src);
    if ($new === $src) return ['status' => 'skipped', 'note' => 'no match'];
    if (!$dryRun) file_put_contents($path, $new);
    return ['status' => 'applied', 'note' => 'APP_ENV → production'];
}

function fixCookieFlags(Context $ctx, Finding $f, bool $dryRun): array
{
    $path = $ctx->root . '/' . $f->file;
    if (!is_file($path)) return ['status' => 'failed', 'note' => 'file missing'];
    $src = file_get_contents($path);
    $new = $src;
    $new = preg_replace("/('http_only'\s*=>\s*)false/", "$1true", $new, 1);
    $new = preg_replace("/('secure'\s*=>\s*)false/", "$1env('SESSION_SECURE_COOKIE', true)", $new, 1);
    if ($new === $src) return ['status' => 'skipped', 'note' => 'no match'];
    if (!$dryRun) file_put_contents($path, $new);
    return ['status' => 'applied', 'note' => 'cookie flags hardened'];
}

function fixPhpVersionPin(Context $ctx, Finding $f, bool $dryRun): array
{
    $path = $ctx->root . '/composer.json';
    if (!is_file($path)) return ['status' => 'failed', 'note' => 'composer.json missing'];
    $data = json_decode(file_get_contents($path), true);
    if (!is_array($data)) return ['status' => 'failed', 'note' => 'invalid composer.json'];
    if (isset($data['require']['php'])) return ['status' => 'skipped', 'note' => 'already pinned'];

    $runtimeVersion = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
    $constraint = "^{$runtimeVersion}";

    $require = $data['require'] ?? [];
    $newRequire = ['php' => $constraint];
    foreach ($require as $k => $v) $newRequire[$k] = $v;
    $data['require'] = $newRequire;

    if (!$dryRun) {
        file_put_contents(
            $path,
            json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n"
        );
    }
    return ['status' => 'applied', 'note' => "added \"php\": \"{$constraint}\" to require"];
}

function gitIsDirty(string $root): bool
{
    if (!is_dir($root . '/.git')) return false;
    $cmd = sprintf('cd %s && git status --porcelain 2>/dev/null', escapeshellarg($root));
    $out = shell_exec($cmd) ?? '';
    // Ignore our own history directory — otherwise every scan with --save-history
    // would immediately look "dirty" and abort the next --fix.
    $lines = array_filter(
        explode("\n", trim($out)),
        fn($l) => $l !== '' && !str_contains($l, '.larascan/')
    );
    return !empty($lines);
}

function runFixMode(Context $ctx, array $findings, bool $dryRun, bool $force): array
{
    $results = [];
    $fixableFindings = array_values(array_filter($findings, fn($f) => isset(FIXERS[$f->ruleId])));

    if (empty($fixableFindings)) {
        return [
            'total_findings'    => count($findings),
            'fixable_findings'  => 0,
            'applied'           => 0,
            'dry_run'           => $dryRun,
            'results'           => [],
            'note'              => 'No auto-fixable findings.',
        ];
    }

    if (!$force && gitIsDirty($ctx->root)) {
        return [
            'total_findings'    => count($findings),
            'fixable_findings'  => count($fixableFindings),
            'applied'           => 0,
            'dry_run'           => $dryRun,
            'results'           => [],
            'note'              => 'Working tree has uncommitted changes. Commit or stash first, or re-run with --force.',
            'aborted'           => true,
        ];
    }

    $applied = 0;
    foreach ($fixableFindings as $f) {
        $result = fixFinding($ctx, $f, $dryRun);
        $results[] = [
            'rule_id'  => $f->ruleId,
            'file'     => $f->file,
            'line'     => $f->line,
            'title'    => $f->title,
            'status'   => $result['status'],
            'note'     => $result['note'],
        ];
        if ($result['status'] === 'applied') $applied++;
    }

    return [
        'total_findings'    => count($findings),
        'fixable_findings'  => count($fixableFindings),
        'applied'           => $applied,
        'dry_run'           => $dryRun,
        'results'           => $results,
    ];
}

// ---------- Scoring ----------

function score(array $findings, array $weightOverrides = [], array $capOverrides = []): int
{
    // Per-severity cap prevents one noisy category from auto-0ing a large repo.
    // Critical stays uncapped — stacking critical findings SHOULD keep tanking the score.
    $perSeverityCap = [
        SEVERITY_HIGH => 35,
        SEVERITY_MED  => 20,
        SEVERITY_LOW  => 12,
    ];
    foreach ($capOverrides as $sev => $cap) {
        $perSeverityCap[$sev] = $cap;
    }
    $weights = SEVERITY_WEIGHT;
    foreach ($weightOverrides as $sev => $w) {
        $weights[$sev] = $w;
    }
    $raw = [];
    foreach ($findings as $f) {
        $raw[$f->severity] = ($raw[$f->severity] ?? 0) + ($weights[$f->severity] ?? 0);
    }
    $penalty = 0;
    foreach ($raw as $sev => $value) {
        $penalty += isset($perSeverityCap[$sev]) ? min($value, $perSeverityCap[$sev]) : $value;
    }
    return max(0, 100 - $penalty);
}

function grade(int $score): string
{
    return match (true) {
        $score >= 90 => 'A',
        $score >= 75 => 'B',
        $score >= 60 => 'C',
        $score >= 40 => 'D',
        default      => 'F',
    };
}

// ---------- Main ----------

function loadHistory(string $root): ?array
{
    $dir = $root . '/.larascan/history';
    if (!is_dir($dir)) return null;
    $files = glob($dir . '/*.json') ?: [];
    if (empty($files)) return null;
    rsort($files);
    $data = json_decode(file_get_contents($files[0]), true);
    return is_array($data) ? $data : null;
}

function saveHistory(string $root, array $report): string
{
    $dir = $root . '/.larascan/history';
    if (!is_dir($dir)) @mkdir($dir, 0755, true);
    $summary = [
        'scanned_at'    => $report['meta']['scanned_at'] ?? date('c'),
        'scanner'       => $report['meta']['scanner'] ?? 'larascan',
        'score'         => $report['meta']['score'] ?? null,
        'grade'         => $report['meta']['grade'] ?? null,
        'finding_count' => $report['meta']['finding_count'] ?? 0,
        'stats'         => $report['meta']['stats'] ?? [],
    ];
    // Sub-second precision avoids filename collisions when back-to-back scans run within 1 second.
    $stamp = date('Ymd-His') . sprintf('-%03d', (int)((microtime(true) - floor(microtime(true))) * 1000));
    $path = "{$dir}/{$stamp}.json";
    file_put_contents($path, json_encode($summary, JSON_PRETTY_PRINT) . "\n");
    return $path;
}

// ---------- v0.4 helpers: CLI parse, profiles, plugins, webhooks, interactive ----------

function cliFlagValue(array $argv, string $name): ?string
{
    // Supports `--name=value` and `--name value`. Returns null if not present.
    foreach ($argv as $i => $a) {
        if ($a === "--{$name}") {
            return $argv[$i + 1] ?? '';
        }
        if (str_starts_with($a, "--{$name}=")) {
            return substr($a, strlen($name) + 3);
        }
    }
    return null;
}

function resolveProfile(?string $name): array
{
    $name = $name ?: 'default';
    if (!isset(PROFILES[$name])) {
        fwrite(STDERR, "Unknown profile '{$name}'. Known: " . implode(', ', array_keys(PROFILES)) . "\n");
        fwrite(STDERR, "Falling back to 'default'.\n");
        $name = 'default';
    }
    return ['name' => $name] + PROFILES[$name];
}

/**
 * Load user-defined rule plugins from <repo>/.larascan/rules/*.php.
 *
 * Safety: each file must start with <?php and contain only function definitions
 * (no top-level statements). Anything else is skipped with a warning.
 *
 * Returns an array of discovered function names (e.g. 'userRule_MyThing').
 */
function loadUserRules(string $root): array
{
    $dir = $root . '/.larascan/rules';
    if (!is_dir($dir)) return [];

    $loaded = [];
    $files = glob($dir . '/*.php') ?: [];
    sort($files);

    foreach ($files as $path) {
        $src = file_get_contents($path);
        if ($src === false) {
            fwrite(STDERR, "[plugin] skipped (unreadable): {$path}\n");
            continue;
        }
        if (!preg_match('/^<\?php\b/', ltrim($src))) {
            fwrite(STDERR, "[plugin] skipped (missing <?php header): {$path}\n");
            continue;
        }
        if (!pluginFileIsSafe($src)) {
            fwrite(STDERR, "[plugin] skipped (top-level code outside function defs): {$path}\n");
            continue;
        }

        // Snapshot defined functions before/after require to pick up what this file added.
        $before = get_defined_functions()['user'];
        try {
            require_once $path;
        } catch (\Throwable $e) {
            fwrite(STDERR, "[plugin] load error in {$path}: " . $e->getMessage() . "\n");
            continue;
        }
        $after = get_defined_functions()['user'];
        $added = array_diff($after, $before);

        foreach ($added as $fn) {
            if (str_starts_with(strtolower($fn), 'userrule_')) {
                $loaded[] = $fn;
            }
        }
    }

    return $loaded;
}

/**
 * Lightweight validator: ensures the file contains only `<?php`, whitespace/comments,
 * `declare(...)`/`namespace`/`use` statements, and function definitions at the top level.
 * Any top-level side-effect code (echo, assignments, calls, if/while, class definitions,
 * etc.) causes the file to be rejected.
 *
 * Strategy: walk the token stream with a small state machine.
 *   - state "top"        : between statements at file scope
 *   - state "skip_stmt"  : discarding tokens until the matching ';' of a declare/namespace/use
 *   - state "fn_header"  : inside a function signature, wait for the opening `{`
 *   - state "fn_body"    : inside a function body, counting braces; anything allowed
 */
function pluginFileIsSafe(string $src): bool
{
    if (!function_exists('token_get_all')) return false;
    $tokens = @token_get_all($src);
    if (!is_array($tokens)) return false;

    $state = 'top';
    $braceDepth = 0;
    $sawOpenTag = false;

    foreach ($tokens as $tok) {
        // Normalise: $id is null for single-char tokens.
        if (is_array($tok)) {
            $id = $tok[0];
            $text = $tok[1];
        } else {
            $id = null;
            $text = $tok;
        }

        if ($id === T_OPEN_TAG) { $sawOpenTag = true; continue; }
        if (!$sawOpenTag) {
            // Anything before <?php (HTML/inline output) is a side effect.
            if ($id === T_INLINE_HTML && trim($text) === '') continue;
            return false;
        }

        if ($id === T_WHITESPACE || $id === T_COMMENT || $id === T_DOC_COMMENT) continue;

        if ($state === 'fn_body') {
            if ($text === '{') $braceDepth++;
            elseif ($text === '}') {
                $braceDepth--;
                if ($braceDepth === 0) $state = 'top';
            }
            continue;
        }

        if ($state === 'fn_header') {
            if ($text === '{') { $state = 'fn_body'; $braceDepth = 1; }
            continue;
        }

        if ($state === 'skip_stmt') {
            if ($text === ';') $state = 'top';
            continue;
        }

        // state === 'top'
        if ($id === T_FUNCTION) { $state = 'fn_header'; continue; }
        if ($id === T_DECLARE)  { $state = 'skip_stmt'; continue; }
        if (defined('T_NAMESPACE') && $id === T_NAMESPACE) { $state = 'skip_stmt'; continue; }
        if (defined('T_USE') && $id === T_USE)             { $state = 'skip_stmt'; continue; }

        // Stray `;` at top level is harmless.
        if ($text === ';') continue;

        // Anything else at top level = side effect / class definition / etc.
        return false;
    }

    return $state === 'top';
}

/**
 * POST a summary to a Slack/Discord/generic webhook. Never throws — failures warn to stderr.
 */
function postWebhook(string $url, ?string $type, array $report): void
{
    $type = $type ?: detectWebhookType($url);
    $payload = match ($type) {
        'slack'   => buildSlackPayload($report),
        'discord' => buildDiscordPayload($report),
        default   => $report,
    };

    $ctx = stream_context_create([
        'http' => [
            'method'        => 'POST',
            'header'        => "Content-Type: application/json\r\n",
            'content'       => json_encode($payload),
            'ignore_errors' => true,
            'timeout'       => 10,
        ],
    ]);

    $result = @file_get_contents($url, false, $ctx);
    if ($result === false) {
        fwrite(STDERR, "[webhook] POST to {$url} failed (no response)\n");
        return;
    }
    // Slack/Discord return 200 with "ok" or a short string; anything 4xx/5xx lands in $http_response_header.
    $status = $http_response_header[0] ?? '';
    if ($status && !preg_match('/\b2\d\d\b/', $status)) {
        fwrite(STDERR, "[webhook] non-2xx response: {$status}\n");
    }
}

function detectWebhookType(string $url): string
{
    $host = parse_url($url, PHP_URL_HOST) ?? '';
    if (str_contains($host, 'hooks.slack.com')) return 'slack';
    if (str_contains($host, 'discord.com') || str_contains($host, 'discordapp.com')) return 'discord';
    return 'generic';
}

function topFindings(array $report, int $n = 3): array
{
    $severities = [SEVERITY_CRIT => 0, SEVERITY_HIGH => 1, SEVERITY_MED => 2, SEVERITY_LOW => 3];
    $findings = $report['findings'] ?? [];
    usort($findings, fn($a, $b) =>
        ($severities[$a['severity']] ?? 9) <=> ($severities[$b['severity']] ?? 9)
    );
    return array_slice($findings, 0, $n);
}

function buildSlackPayload(array $report): array
{
    $meta = $report['meta'];
    $score = $meta['score'] ?? '?';
    $grade = $meta['grade'] ?? '?';
    $count = $meta['finding_count'] ?? 0;
    $profile = $meta['profile'] ?? 'default';
    $top = topFindings($report, 3);

    $lines = [];
    foreach ($top as $f) {
        $lines[] = sprintf(
            "• *[%s]* %s — `%s%s`",
            strtoupper($f['severity']),
            $f['title'],
            $f['file'],
            $f['line'] !== null ? ':' . $f['line'] : ''
        );
    }
    $topText = $lines ? implode("\n", $lines) : "_No findings_";

    $text = "larascan: score *{$score}* (grade {$grade}) — {$count} finding(s) on profile `{$profile}`";

    return [
        'text'   => $text,
        'blocks' => [
            ['type' => 'section', 'text' => ['type' => 'mrkdwn', 'text' => $text]],
            ['type' => 'section', 'text' => ['type' => 'mrkdwn', 'text' => "*Top findings:*\n{$topText}"]],
        ],
    ];
}

function buildDiscordPayload(array $report): array
{
    $meta = $report['meta'];
    $score = $meta['score'] ?? '?';
    $grade = $meta['grade'] ?? '?';
    $count = $meta['finding_count'] ?? 0;
    $profile = $meta['profile'] ?? 'default';
    $top = topFindings($report, 3);

    $fields = [];
    foreach ($top as $f) {
        $fields[] = [
            'name'  => '[' . strtoupper($f['severity']) . '] ' . $f['title'],
            'value' => '`' . $f['file'] . ($f['line'] !== null ? ':' . $f['line'] : '') . '`',
        ];
    }

    return [
        'content' => "**larascan:** score **{$score}** (grade {$grade}) — {$count} finding(s) [profile: `{$profile}`]",
        'embeds'  => [[
            'title'  => 'Top findings',
            'color'  => $score >= 75 ? 0x2ECC71 : ($score >= 40 ? 0xF1C40F : 0xE74C3C),
            'fields' => $fields ?: [['name' => 'None', 'value' => 'Clean scan.']],
        ]],
    ];
}

// ---------- v0.5: config file, baseline, SARIF ----------

/**
 * Load the repo-level config file if present. Checks:
 *   1. <repo>/.larascan/config.json  (preferred)
 *   2. <repo>/.larascan.json          (fallback)
 *
 * Returns an associative array with any of: profile, exclude_rules,
 * exclude_paths, webhook.url, webhook.type, brand.*. Missing file → [].
 * Malformed JSON prints a stderr warning and returns [].
 */
function loadRepoConfig(string $root): array
{
    $candidates = [
        $root . '/.larascan/config.json',
        $root . '/.larascan.json',
    ];
    foreach ($candidates as $path) {
        if (!is_file($path)) continue;
        $raw = @file_get_contents($path);
        if ($raw === false) {
            fwrite(STDERR, "[config] unreadable: {$path}\n");
            continue;
        }
        $data = json_decode($raw, true);
        if (!is_array($data)) {
            fwrite(STDERR, "[config] invalid JSON in {$path}\n");
            return [];
        }
        $data['_path'] = $path;
        return $data;
    }
    return [];
}

/**
 * Deterministic short hash of a finding's identity. Used for baseline matching.
 * Line numbers deliberately included — a shifted finding should reappear (that's
 * the point: if the code moved, you might have rewritten it).
 */
function fingerprintFinding(string $ruleId, string $file, ?int $line, string $title): string
{
    $payload = $ruleId . '|' . $file . '|' . (string)($line ?? '') . '|' . $title;
    return substr(sha1($payload), 0, 16);
}

/**
 * Read the baseline file into an associative array keyed by fingerprint.
 * Returns [entries=>[], generated_at=>null] if no file exists.
 */
function loadBaseline(string $root): array
{
    $path = $root . '/.larascan/baseline.json';
    if (!is_file($path)) {
        return ['present' => false, 'path' => $path, 'entries' => [], 'generated_at' => null];
    }
    $raw = @file_get_contents($path);
    $data = is_string($raw) ? json_decode($raw, true) : null;
    if (!is_array($data)) {
        fwrite(STDERR, "[baseline] invalid JSON in {$path}\n");
        return ['present' => false, 'path' => $path, 'entries' => [], 'generated_at' => null];
    }
    $entries = [];
    foreach ($data['entries'] ?? [] as $e) {
        if (!is_array($e) || !isset($e['fingerprint'])) continue;
        $entries[$e['fingerprint']] = $e;
    }
    return [
        'present'      => true,
        'path'         => $path,
        'entries'      => $entries,
        'generated_at' => $data['generated_at'] ?? null,
    ];
}

/**
 * Write the current findings as the new baseline. Overwrites any existing file.
 * Returns the absolute path written.
 *
 * Schema (v0.5.1+): each entry may optionally carry `reason` (e.g. `false_positive`,
 * `deferred`, `accepted`, or a freeform string) and `note` (freeform text). Both are
 * optional; entries without them (e.g. from v0.5 baselines) continue to load unchanged.
 *
 * When regenerating via --update-baseline, we preserve any pre-existing reason/note
 * that lived on a matching fingerprint in the previous baseline, so users don't lose
 * their annotations on a rescan.
 *
 * v0.5.3: when $prune is true, previous entries whose fingerprints don't match a
 * current finding are dropped. When $prune is false (default), stale previous entries
 * are carried forward so nothing a user baselined disappears silently across a rescan
 * — users opt into cleanup with --prune-baseline.
 */
function writeBaseline(string $root, array $findings, array $previousEntries = [], bool $prune = false): string
{
    $dir = $root . '/.larascan';
    if (!is_dir($dir)) @mkdir($dir, 0755, true);
    $path = $dir . '/baseline.json';

    $entries = [];
    $seenFingerprints = [];
    foreach ($findings as $f) {
        /** @var Finding $f */
        $fp = fingerprintFinding($f->ruleId, $f->file, $f->line, $f->title);
        $entry = [
            'rule_id'     => $f->ruleId,
            'file'        => $f->file,
            'line'        => $f->line,
            'title'       => $f->title,
            'fingerprint' => $fp,
        ];
        // Preserve reason/note from the previous baseline if this fingerprint existed there.
        if (isset($previousEntries[$fp])) {
            $prev = $previousEntries[$fp];
            if (isset($prev['reason']) && is_string($prev['reason']) && $prev['reason'] !== '') {
                $entry['reason'] = $prev['reason'];
            }
            if (isset($prev['note']) && is_string($prev['note']) && $prev['note'] !== '') {
                $entry['note'] = $prev['note'];
            }
        }
        $entries[] = $entry;
        $seenFingerprints[$fp] = true;
    }

    // Carry forward any previous entries that didn't match a current finding UNLESS
    // --prune-baseline was passed. This preserves pre-v0.5.3 behaviour by default.
    if (!$prune) {
        foreach ($previousEntries as $fp => $prev) {
            if (isset($seenFingerprints[$fp])) continue;
            if (!is_array($prev)) continue;
            $entries[] = $prev;
        }
    }

    $doc = [
        'generated_at' => date('c'),
        'generated_by' => 'larascan v' . LARASCAN_VERSION,
        'entries'      => $entries,
    ];
    file_put_contents($path, json_encode($doc, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
    return $path;
}

/**
 * Split findings into (kept, ignored) using the baseline entries map.
 * Matching is by fingerprint only; line shifts deliberately break the match.
 *
 * @param Finding[] $findings
 * @return array{0: Finding[], 1: Finding[]} [kept, ignored]
 */
function applyBaseline(array $findings, array $baselineEntries): array
{
    $kept = [];
    $ignored = [];
    foreach ($findings as $f) {
        $fp = fingerprintFinding($f->ruleId, $f->file, $f->line, $f->title);
        if (isset($baselineEntries[$fp])) {
            $ignored[] = $f;
        } else {
            $kept[] = $f;
        }
    }
    return [$kept, $ignored];
}

/**
 * Remove findings whose rule_id is in the exclusion list OR whose file matches
 * any glob pattern in $excludePaths (via fnmatch on the relative path).
 *
 * @param Finding[] $findings
 * @return Finding[]
 */
function applyConfigFilters(array $findings, array $excludeRules, array $excludePaths): array
{
    if (empty($excludeRules) && empty($excludePaths)) return $findings;
    $excludeRulesSet = array_flip($excludeRules);
    $filtered = [];
    foreach ($findings as $f) {
        if (isset($excludeRulesSet[$f->ruleId])) continue;
        $matched = false;
        foreach ($excludePaths as $pattern) {
            if (!is_string($pattern) || $pattern === '') continue;
            if (fnmatch($pattern, $f->file)) { $matched = true; break; }
        }
        if ($matched) continue;
        $filtered[] = $f;
    }
    return $filtered;
}

/**
 * Convert the larascan report to SARIF 2.1.0. Only rules that fired are
 * included in tool.driver.rules (keeps output compact on large repos).
 *
 * Severity map (larascan → SARIF level):
 *   critical → error  (breaks things now)
 *   high     → error  (breaks things soon)
 *   medium   → warning
 *   low      → note
 *
 * Rationale: SARIF has 4 levels (none/note/warning/error). GitHub's Security
 * tab treats 'error' as blocking, 'warning' as informational. We collapse
 * critical+high to error because both should gate a PR; medium is the
 * warning tier; low is a note. 'none' is reserved for suppressed/pass results.
 */
function buildSarif(array $report): array
{
    $findings = $report['findings'] ?? [];

    // Build rules registry from firing rules only. First occurrence wins for
    // rule metadata (id, name, short/full description, level).
    $rulesMap = [];
    foreach ($findings as $f) {
        $rid = $f['rule_id'];
        if (isset($rulesMap[$rid])) continue;
        $rulesMap[$rid] = [
            'id'                   => $rid,
            'name'                 => sarifRuleName($f['title'] ?? $rid),
            'shortDescription'     => ['text' => $f['title'] ?? $rid],
            'fullDescription'      => ['text' => $f['detail'] ?? ($f['title'] ?? $rid)],
            'defaultConfiguration' => ['level' => sarifLevel($f['severity'] ?? 'medium')],
            'helpUri'              => 'https://mjgapp.com/products/larascan',
        ];
    }

    $results = [];
    foreach ($findings as $f) {
        $result = [
            'ruleId'  => $f['rule_id'],
            'level'   => sarifLevel($f['severity'] ?? 'medium'),
            'message' => ['text' => $f['title'] ?? $f['rule_id']],
        ];
        $location = [
            'physicalLocation' => [
                'artifactLocation' => ['uri' => $f['file'] ?? ''],
            ],
        ];
        if (isset($f['line']) && $f['line'] !== null) {
            $location['physicalLocation']['region'] = ['startLine' => (int)$f['line']];
        }
        $result['locations'] = [$location];
        $results[] = $result;
    }

    return [
        '$schema' => 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json',
        'version' => '2.1.0',
        'runs'    => [[
            'tool' => [
                'driver' => [
                    'name'           => 'larascan',
                    'version'        => LARASCAN_VERSION,
                    'informationUri' => 'https://mjgapp.com/products/larascan',
                    'rules'          => array_values($rulesMap),
                ],
            ],
            'results' => $results,
        ]],
    ];
}

function sarifLevel(string $severity): string
{
    return match ($severity) {
        SEVERITY_CRIT, SEVERITY_HIGH => 'error',
        SEVERITY_MED                 => 'warning',
        SEVERITY_LOW                 => 'note',
        default                      => 'warning',
    };
}

/**
 * Derive a stable, CamelCase rule name from a finding title for SARIF's
 * `rules[].name` field. SARIF 2.1.0 requires name to be a non-empty string;
 * consumers like GitHub render it as the rule's human label. Punctuation and
 * common non-alphanumeric characters are stripped.
 */
function sarifRuleName(string $title): string
{
    $clean = preg_replace('/[^A-Za-z0-9 ]+/', ' ', $title) ?? $title;
    $words = preg_split('/\s+/', trim($clean)) ?: [];
    $camel = '';
    foreach ($words as $w) {
        if ($w === '') continue;
        $camel .= strtoupper(substr($w, 0, 1)) . substr($w, 1);
    }
    return $camel !== '' ? $camel : 'Rule';
}

/**
 * Interactive walkthrough. Loops over findings; user can fix, skip, open, or quit.
 * Requires STDIN to be a TTY.
 */
function runInteractive(Context $ctx, array $findings): void
{
    if (!isatty_stdin()) {
        fwrite(STDERR, "--interactive requires a TTY on STDIN. Run from a terminal.\n");
        return;
    }
    if (empty($findings)) {
        fwrite(STDERR, "No findings to walk through.\n");
        return;
    }

    $total = count($findings);
    foreach ($findings as $i => $f) {
        // Clear screen (ANSI; falls back to blank lines if not a real terminal).
        fwrite(STDOUT, "\033[H\033[2J");
        fwrite(STDOUT, sprintf("Finding %d of %d\n", $i + 1, $total));
        fwrite(STDOUT, str_repeat('─', 60) . "\n");
        fwrite(STDOUT, "[{$f->severity}] {$f->ruleId}: {$f->title}\n");
        fwrite(STDOUT, "File: {$f->file}" . ($f->line !== null ? ":{$f->line}" : '') . "\n\n");
        fwrite(STDOUT, "Detail: {$f->detail}\n\n");
        fwrite(STDOUT, "Fix:    {$f->fix}\n");

        $abs = $ctx->root . '/' . $f->file;
        if (is_file($abs) && $f->line !== null) {
            $lines = file($abs);
            if ($lines !== false) {
                $start = max(0, $f->line - 3);
                $end   = min(count($lines) - 1, $f->line + 1);
                fwrite(STDOUT, "\nContext:\n");
                for ($ln = $start; $ln <= $end; $ln++) {
                    $marker = ($ln + 1) === $f->line ? '>' : ' ';
                    fwrite(STDOUT, sprintf("  %s %4d | %s", $marker, $ln + 1, $lines[$ln]));
                }
                if (!str_ends_with($lines[$end] ?? '', "\n")) fwrite(STDOUT, "\n");
            }
        }

        $fixable = isset(FIXERS[$f->ruleId]);
        $prompt = $fixable ? "\n[f]ix, [s]kip, [o]pen, [q]uit > " : "\n[s]kip, [o]pen, [q]uit > ";
        fwrite(STDOUT, $prompt);

        $input = fgets(STDIN);
        if ($input === false) return;
        $choice = strtolower(trim($input));

        if ($choice === 'q') return;
        if ($choice === 'o') {
            fwrite(STDOUT, "Open: {$abs}\n");
            fwrite(STDOUT, "Press enter to continue…");
            fgets(STDIN);
            continue;
        }
        if ($choice === 'f' && $fixable) {
            $result = fixFinding($ctx, $f, false);
            fwrite(STDOUT, "[{$result['status']}] {$result['note']}\n");
            fwrite(STDOUT, "Press enter to continue…");
            fgets(STDIN);
            continue;
        }
        // skip / anything else: continue
    }
    fwrite(STDOUT, "\nDone.\n");
}

function isatty_stdin(): bool
{
    if (function_exists('stream_isatty')) return @stream_isatty(STDIN);
    if (function_exists('posix_isatty')) return @posix_isatty(STDIN);
    return false;
}

function main(array $argv): int
{
    if (count($argv) < 2 || in_array('--help', $argv, true)) {
        fwrite(STDERR, "larascan v" . LARASCAN_VERSION . "\n");
        fwrite(STDERR, "Usage:\n");
        fwrite(STDERR, "  php audit.php <repo-path> [--pretty]                   scan, JSON to stdout\n");
        fwrite(STDERR, "  php audit.php <repo-path> --fix [--dry-run]            scan + apply safe fixes\n");
        fwrite(STDERR, "  php audit.php <repo-path> --save-history               append summary to .larascan/history/\n");
        fwrite(STDERR, "  php audit.php <repo-path> --profile=<name>             use a named rule profile\n");
        fwrite(STDERR, "  php audit.php <repo-path> --interactive                step through findings in a TTY\n");
        fwrite(STDERR, "  php audit.php <repo-path> --webhook=<URL>              POST summary to a webhook\n");
        fwrite(STDERR, "  php audit.php <repo-path> --update-baseline            write current findings as the accepted baseline\n");
        fwrite(STDERR, "  php audit.php <repo-path> --ignore-baseline            scan without filtering baselined findings\n");
        fwrite(STDERR, "  php audit.php <repo-path> --format=sarif               emit SARIF 2.1.0 instead of JSON\n");
        fwrite(STDERR, "\nFlags:\n");
        fwrite(STDERR, "  --pretty            pretty-print the JSON output\n");
        fwrite(STDERR, "  --fix               apply auto-fixers for eligible rules (aborts on dirty git;\n");
        fwrite(STDERR, "                      skips gitignored local .env — set prod values on your deploy platform)\n");
        fwrite(STDERR, "  --dry-run           with --fix, show what would change without writing\n");
        fwrite(STDERR, "  --force             with --fix, bypass the dirty git check\n");
        fwrite(STDERR, "  --save-history      append summary to .larascan/history (for score-delta tracking)\n");
        fwrite(STDERR, "  --profile=NAME      rule profile: default | pre-launch | rescue | monthly\n");
        fwrite(STDERR, "  --interactive       walk through findings one at a time (requires TTY)\n");
        fwrite(STDERR, "  --webhook=URL       POST scan summary to a webhook after scanning\n");
        fwrite(STDERR, "  --webhook-type=T    force webhook format: slack | discord | generic (auto-detect by default)\n");
        fwrite(STDERR, "  --update-baseline   rescan and overwrite .larascan/baseline.json with current findings\n");
        fwrite(STDERR, "  --prune-baseline    with --update-baseline, drop previous entries whose fingerprints\n");
        fwrite(STDERR, "                      no longer match any current finding (no-op on its own)\n");
        fwrite(STDERR, "  --ignore-baseline   do not filter findings that match .larascan/baseline.json\n");
        fwrite(STDERR, "  --format=NAME       output format: json (default) | sarif\n");
        fwrite(STDERR, "\nProfiles:\n");
        foreach (PROFILES as $pname => $pdata) {
            fwrite(STDERR, sprintf("  %-12s %s\n", $pname, $pdata['description'] ?? ''));
        }
        fwrite(STDERR, "\nCustom rules: drop PHP files into <repo>/.larascan/rules/ defining userRule_* functions.\n");
        fwrite(STDERR, "Config file:  <repo>/.larascan/config.json (or <repo>/.larascan.json) — CLI flags override.\n");
        fwrite(STDERR, "              Supported keys: profile, exclude_rules, exclude_paths, webhook, brand,\n");
        fwrite(STDERR, "              blade_safe_helpers (BLADE-001 extra allowlist, e.g. [\"markdown_to_html\"]).\n");
        return 1;
    }

    $root = rtrim(realpath($argv[1]) ?: $argv[1], '/');
    if (!is_dir($root)) {
        fwrite(STDERR, "Not a directory: {$root}\n");
        return 1;
    }

    $fix             = in_array('--fix', $argv, true);
    $dryRun          = in_array('--dry-run', $argv, true);
    $force           = in_array('--force', $argv, true);
    $saveHistory     = in_array('--save-history', $argv, true);
    $interactive     = in_array('--interactive', $argv, true);
    $updateBaseline  = in_array('--update-baseline', $argv, true);
    $pruneBaseline   = in_array('--prune-baseline', $argv, true);
    $ignoreBaseline  = in_array('--ignore-baseline', $argv, true);
    $profileName     = cliFlagValue($argv, 'profile');
    $webhookUrl      = cliFlagValue($argv, 'webhook');
    $webhookType     = cliFlagValue($argv, 'webhook-type');
    $format          = cliFlagValue($argv, 'format') ?: 'json';

    if (!in_array($format, ['json', 'sarif'], true)) {
        fwrite(STDERR, "Unknown --format '{$format}'. Supported: json, sarif. Falling back to json.\n");
        $format = 'json';
    }

    // Load repo-level config (if any). CLI flags take precedence.
    $config = loadRepoConfig($root);

    // Config → profile (CLI override wins).
    if ($profileName === null && isset($config['profile']) && is_string($config['profile'])) {
        $profileName = $config['profile'];
    }
    // Config → webhook (CLI override wins; webhook section can be a scalar URL or {url,type}).
    if ($webhookUrl === null && isset($config['webhook'])) {
        if (is_array($config['webhook'])) {
            $webhookUrl  = $webhookUrl  ?: ($config['webhook']['url']  ?? null);
            $webhookType = $webhookType ?: ($config['webhook']['type'] ?? null);
        } elseif (is_string($config['webhook'])) {
            $webhookUrl = $config['webhook'];
        }
    }

    $excludeRules = [];
    if (isset($config['exclude_rules']) && is_array($config['exclude_rules'])) {
        $excludeRules = array_values(array_filter($config['exclude_rules'], 'is_string'));
    }
    $excludePaths = [];
    if (isset($config['exclude_paths']) && is_array($config['exclude_paths'])) {
        $excludePaths = array_values(array_filter($config['exclude_paths'], 'is_string'));
    }

    $profile = resolveProfile($profileName);

    $ctx = new Context($root);
    $ctx->config = $config;

    // Quick stats pass
    foreach (iterateFiles($root, ['php', 'blade.php']) as $path) {
        $ctx->stats['files_scanned']++;
        if (str_ends_with($path, '.blade.php')) $ctx->stats['blade_files']++;
        else $ctx->stats['php_files']++;
    }

    $allRules = [
        // Security
        'ruleAppDebug',
        'ruleMassAssignment',
        'ruleRawSqlInterpolation',
        'ruleSqlKeywordInterpolation',
        'ruleHardcodedSecrets',
        'ruleDebugLeftovers',
        'ruleUnserialize',
        'ruleEval',
        'ruleAppKey',
        'ruleAppEnvLocal',
        'ruleCookieFlags',
        // Blade (XSS + CSRF)
        'ruleBladeUnescaped',
        'ruleBladeFormCsrf',
        // Performance
        'ruleNPlusOneHeuristic',
        'ruleMissingForeignKeyIndexes',
        'ruleSyncMail',
        'ruleEloquentAll',
        // AI-slop
        'ruleTodoDensity',
        'ruleStubFunctions',
        'ruleUnnamespacedFiles',
        // Deploy hygiene
        'ruleComposerLock',
        'rulePhpVersionPin',
        'ruleSessionDriverFile',
    ];

    // Apply profile filter: null → all rules; array → intersect.
    if (is_array($profile['rules'])) {
        $allowed = array_flip($profile['rules']);
        $rules = array_values(array_filter($allRules, fn($r) => isset($allowed[$r])));
    } else {
        $rules = $allRules;
    }

    // Discover & register user rule plugins (appended after built-in rules).
    $userRules = loadUserRules($root);
    $rules = array_merge($rules, $userRules);

    foreach ($rules as $rule) {
        if (!function_exists($rule)) {
            fwrite(STDERR, "[scan] skipping unknown rule: {$rule}\n");
            continue;
        }
        $rule($ctx);
    }

    // Stage 1: config-level filters (exclude_rules / exclude_paths) run first,
    // since they represent "this rule / this path should never be reported here".
    $filteredFindings = applyConfigFilters($ctx->findings, $excludeRules, $excludePaths);
    $configExcludedCount = count($ctx->findings) - count($filteredFindings);

    // --update-baseline: snapshot the (config-filtered) findings as the new baseline,
    // print a one-line status to stdout, and exit. We don't emit a full report here,
    // matching the deliverable contract.
    //
    // Preserve any existing reason/note annotations on matching fingerprints so users
    // don't lose their hand-edited context when they rescan.
    if ($updateBaseline) {
        $existing = loadBaseline($root);
        $previousEntries = $existing['entries'] ?? [];

        // Compute current fingerprint set so we can report how many previous entries
        // would be pruned / preserved with reason|note. Always useful for the stderr
        // summary; only actually drops stale entries when --prune-baseline is set.
        $currentFingerprints = [];
        foreach ($filteredFindings as $f) {
            /** @var Finding $f */
            $currentFingerprints[fingerprintFinding($f->ruleId, $f->file, $f->line, $f->title)] = true;
        }
        $staleEntries = [];
        $preservedAnnotated = 0;
        foreach ($previousEntries as $fp => $prev) {
            if (isset($currentFingerprints[$fp])) {
                $hasReason = isset($prev['reason']) && is_string($prev['reason']) && $prev['reason'] !== '';
                $hasNote   = isset($prev['note'])   && is_string($prev['note'])   && $prev['note']   !== '';
                if ($hasReason || $hasNote) $preservedAnnotated++;
            } else {
                $staleEntries[$fp] = $prev;
            }
        }

        $baselinePath = writeBaseline(
            $root,
            $filteredFindings,
            $previousEntries,
            $pruneBaseline,
        );
        $relPath = ltrim(str_replace($root, '', $baselinePath), '/');
        $currentCount = count($filteredFindings);
        $staleCount   = count($staleEntries);
        // Total entries actually written to disk: current findings, plus any stale
        // previous entries carried forward when --prune-baseline is not set.
        $totalWritten = $pruneBaseline ? $currentCount : ($currentCount + $staleCount);

        // Human-readable breadcrumb on stderr (stdout stays JSON for scripting).
        if ($pruneBaseline) {
            fwrite(STDERR, "Baseline updated: {$totalWritten} entries ({$staleCount} pruned, {$preservedAnnotated} preserved with reason/note)\n");
        } elseif ($staleCount > 0) {
            fwrite(STDERR, "Baseline updated: {$totalWritten} entries ({$staleCount} stale retained — pass --prune-baseline to drop, {$preservedAnnotated} preserved with reason/note)\n");
        } else {
            fwrite(STDERR, "Baseline updated: {$totalWritten} entries ({$preservedAnnotated} preserved with reason/note)\n");
        }

        echo json_encode([
            'meta' => [
                'action'        => 'update-baseline',
                'scanner'       => 'larascan v' . LARASCAN_VERSION,
                'baseline_path' => $relPath,
                'entry_count'   => $totalWritten,
                'pruned'        => $pruneBaseline ? $staleCount : 0,
                'generated_at'  => date('c'),
            ],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
        return 0;
    }

    // Stage 2: baseline filter (unless --ignore-baseline). Baselined findings are
    // moved out of the report entirely; score is computed on post-filter findings.
    $baseline = loadBaseline($root);
    $baselineIgnored = [];
    if (!$ignoreBaseline && $baseline['present']) {
        [$filteredFindings, $baselineIgnored] = applyBaseline($filteredFindings, $baseline['entries']);
    }

    $findings = array_map(fn(Finding $f) => $f->toArray(), $filteredFindings);
    $scoreNow = score(
        $filteredFindings,
        $profile['severity_weights'] ?? [],
        $profile['per_severity_cap'] ?? [],
    );

    $previous = loadHistory($root);
    $scoreDelta = $previous !== null && isset($previous['score'])
        ? $scoreNow - (int)$previous['score']
        : null;

    $meta = [
        'repo'            => $root,
        'scanned_at'      => date('c'),
        'scanner'         => 'larascan v' . LARASCAN_VERSION,
        'profile'         => $profile['name'],
        'stats'           => $ctx->stats,
        'rule_count'      => count($rules),
        'user_rule_count' => count($userRules),
        'finding_count'   => count($findings),
        'score'           => $scoreNow,
        'grade'           => grade($scoreNow),
        'score_previous'  => $previous['score'] ?? null,
        'score_delta'     => $scoreDelta,
        'findings_previous' => $previous['finding_count'] ?? null,
    ];

    // Additive metadata: baseline + config. Kept off the hot path (only emitted
    // when relevant) so default JSON stays backward compatible.
    $meta['baseline'] = [
        'present'       => $baseline['present'],
        'ignored_count' => count($baselineIgnored),
        'generated_at'  => $baseline['generated_at'],
    ];
    if (!empty($config)) {
        $meta['config'] = [
            'present'               => true,
            'path'                  => ltrim(str_replace($root, '', $config['_path'] ?? ''), '/'),
            'config_excluded_count' => $configExcludedCount,
            'exclude_rules'         => $excludeRules,
            'exclude_paths'         => $excludePaths,
        ];
    }

    $report = [
        'meta'     => $meta,
        'findings' => $findings,
    ];

    if ($fix) {
        $fixResult = runFixMode($ctx, $filteredFindings, $dryRun, $force);
        $report['fix'] = $fixResult;
        $pretty = true; // always pretty for fix mode
    } else {
        $pretty = in_array('--pretty', $argv, true);
    }

    if ($saveHistory) {
        $report['meta']['history_saved'] = saveHistory($root, $report);
    }

    if ($webhookUrl) {
        postWebhook($webhookUrl, $webhookType, $report);
    }

    if ($interactive && !$fix) {
        runInteractive($ctx, $filteredFindings);
    }

    if ($format === 'sarif') {
        $sarif = buildSarif($report);
        // SARIF is always pretty-printed — consumers (GitHub, IDEs) tolerate it
        // and human review benefits. JSON_UNESCAPED_SLASHES keeps URIs readable.
        echo json_encode($sarif, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
    } else {
        echo json_encode($report, $pretty ? JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES : JSON_UNESCAPED_SLASHES) . "\n";
    }
    return 0;
}

exit(main($argv));
