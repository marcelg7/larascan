<?php

declare(strict_types=1);

// Reads a report JSON from stdin or file and prints a self-contained HTML report.
// Usage:
//   php audit.php <repo> | php render.php > report.html
//   php render.php report.json > report.html

function loadJson(array $argv): array
{
    if (isset($argv[1]) && $argv[1] !== '-') {
        $raw = file_get_contents($argv[1]);
    } else {
        $raw = stream_get_contents(STDIN);
    }
    if (!$raw) {
        fwrite(STDERR, "No input. Pipe audit.php output or pass a JSON file.\n");
        exit(1);
    }
    $data = json_decode($raw, true);
    if (!is_array($data)) {
        fwrite(STDERR, "Invalid JSON input.\n");
        exit(1);
    }
    return $data;
}

function loadBrandConfig(): array
{
    // Look in three places, first hit wins: env override, skill dir, user home.
    $candidates = [
        getenv('LARAVEL_AUDIT_CONFIG') ?: null,
        __DIR__ . '/../config.json',
        ($_SERVER['HOME'] ?? '') . '/.config/laravel-audit/config.json',
    ];
    foreach ($candidates as $path) {
        if ($path && is_file($path)) {
            $data = json_decode(file_get_contents($path), true);
            if (is_array($data)) return $data;
        }
    }
    return [];
}

function e(string $s): string { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }

function severityColor(string $sev): string
{
    return match ($sev) {
        'critical' => '#b91c1c',
        'high'     => '#c2410c',
        'medium'   => '#a16207',
        'low'      => '#475569',
        default    => '#475569',
    };
}

function severityRank(string $sev): int
{
    return match ($sev) {
        'critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3, default => 4,
    };
}

function categoryOf(string $ruleId): string
{
    return match (true) {
        str_starts_with($ruleId, 'SEC-')    => 'Security',
        str_starts_with($ruleId, 'PERF-')   => 'Performance',
        str_starts_with($ruleId, 'BLADE-')  => 'Blade',
        str_starts_with($ruleId, 'SLOP-')   => 'AI-slop',
        str_starts_with($ruleId, 'DEPLOY-') => 'Deploy',
        default => 'Other',
    };
}

$data = loadJson($argv);
$brand = loadBrandConfig();
$meta = $data['meta'] ?? [];
$findings = $data['findings'] ?? [];

usort($findings, fn($a, $b) => severityRank($a['severity']) <=> severityRank($b['severity']));

$score = (int)($meta['score'] ?? 0);
$grade = (string)($meta['grade'] ?? '?');
$repoName = basename((string)($meta['repo'] ?? 'unknown'));

$counts = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
foreach ($findings as $f) $counts[$f['severity']]++;

$scoreColor = $score >= 75 ? '#15803d' : ($score >= 50 ? '#a16207' : '#b91c1c');
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Laravel Audit — <?= e($repoName) ?></title>
<style>
  @page { margin: 20mm; }
  * { box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; color: #0f172a; margin: 0; padding: 32px; max-width: 900px; margin-inline: auto; line-height: 1.5; }
  h1 { margin: 0 0 4px; font-size: 28px; }
  h2 { margin: 32px 0 12px; font-size: 20px; border-bottom: 2px solid #e2e8f0; padding-bottom: 6px; }
  .sub { color: #64748b; font-size: 14px; margin-bottom: 24px; }
  .score-card { display: flex; gap: 24px; align-items: stretch; padding: 24px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 12px; }
  .score-num { font-size: 72px; font-weight: 800; line-height: 1; color: <?= $scoreColor ?>; }
  .score-grade { font-size: 36px; font-weight: 700; color: <?= $scoreColor ?>; margin-top: 4px; }
  .score-meta { flex: 1; font-size: 14px; color: #334155; }
  .score-meta div { margin-bottom: 4px; }
  .counts { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin-top: 12px; }
  .count-pill { background: white; border: 1px solid #e2e8f0; border-radius: 8px; padding: 8px; text-align: center; }
  .count-pill .n { font-size: 20px; font-weight: 700; }
  .count-pill .label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: #64748b; }
  .top-actions { margin-top: 24px; padding: 16px 18px; border-radius: 10px; background: #fef3c7; border: 1px solid #fde68a; }
  .top-actions h3 { margin: 0 0 8px; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; color: #78350f; }
  .top-actions ol { margin: 0; padding-left: 22px; color: #451a03; }
  .top-actions li { margin-bottom: 4px; font-size: 14px; }
  .top-actions .loc { font-family: "SF Mono", Menlo, Consolas, monospace; font-size: 11px; color: #78350f; background: rgba(120, 53, 15, 0.08); padding: 1px 5px; border-radius: 3px; margin-left: 6px; }
  .finding { border: 1px solid #e2e8f0; border-radius: 10px; padding: 16px 18px; margin-bottom: 12px; page-break-inside: avoid; }
  .finding-head { display: flex; gap: 12px; align-items: baseline; margin-bottom: 8px; flex-wrap: wrap; }
  .sev-badge { font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; padding: 3px 8px; border-radius: 4px; color: white; }
  .cat-chip { font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; padding: 3px 8px; border-radius: 4px; background: #f1f5f9; color: #475569; border: 1px solid #e2e8f0; }
  .finding-title { font-size: 16px; font-weight: 600; flex: 1; }
  .rule-id { font-family: "SF Mono", Menlo, Consolas, monospace; font-size: 11px; color: #64748b; }
  .finding-loc { font-family: "SF Mono", Menlo, Consolas, monospace; font-size: 12px; color: #334155; background: #f1f5f9; padding: 4px 8px; border-radius: 4px; display: inline-block; margin-bottom: 8px; }
  .finding-detail { font-size: 14px; color: #334155; margin: 8px 0; }
  .finding-fix { font-size: 14px; background: #f0fdf4; border-left: 3px solid #22c55e; padding: 8px 12px; border-radius: 0 6px 6px 0; }
  .finding-fix strong { color: #15803d; }
  .summary { display: flex; gap: 16px; font-size: 13px; color: #64748b; margin-top: 8px; }
  footer { margin-top: 48px; padding-top: 16px; border-top: 1px solid #e2e8f0; font-size: 12px; color: #94a3b8; display: flex; justify-content: space-between; gap: 16px; align-items: flex-start; }
  footer .generator { flex: 1; }
  footer .brand { text-align: right; color: #334155; }
  footer .brand-name { font-weight: 600; color: #0f172a; display: block; }
  footer .brand a { color: #0ea5e9; text-decoration: none; }
  footer .cta { margin-top: 4px; font-size: 11px; }
  .empty { padding: 32px; text-align: center; color: #64748b; background: #f0fdf4; border-radius: 10px; }
</style>
</head>
<body>
  <h1>Laravel Health Report</h1>
  <div class="sub"><?= e($repoName) ?> &middot; scanned <?= e($meta['scanned_at'] ?? '') ?></div>

  <section class="score-card">
    <div>
      <div class="score-num"><?= $score ?></div>
      <div class="score-grade">Grade <?= e($grade) ?></div>
    </div>
    <div class="score-meta">
      <div><strong><?= (int)($meta['stats']['files_scanned'] ?? 0) ?></strong> files scanned (<?= (int)($meta['stats']['php_files'] ?? 0) ?> PHP, <?= (int)($meta['stats']['blade_files'] ?? 0) ?> Blade)</div>
      <div><strong><?= (int)($meta['rule_count'] ?? 0) ?></strong> rules evaluated</div>
      <div><strong><?= count($findings) ?></strong> findings</div>
      <div class="counts">
        <div class="count-pill"><div class="n" style="color:<?= severityColor('critical') ?>"><?= $counts['critical'] ?></div><div class="label">Critical</div></div>
        <div class="count-pill"><div class="n" style="color:<?= severityColor('high') ?>"><?= $counts['high'] ?></div><div class="label">High</div></div>
        <div class="count-pill"><div class="n" style="color:<?= severityColor('medium') ?>"><?= $counts['medium'] ?></div><div class="label">Medium</div></div>
        <div class="count-pill"><div class="n" style="color:<?= severityColor('low') ?>"><?= $counts['low'] ?></div><div class="label">Low</div></div>
      </div>
    </div>
  </section>

<?php
  $topActions = array_slice($findings, 0, 3);
  if (!empty($topActions) && in_array($topActions[0]['severity'] ?? '', ['critical', 'high'], true)):
?>
  <div class="top-actions">
    <h3>Top priority fixes</h3>
    <ol>
<?php foreach ($topActions as $action): if (!in_array($action['severity'], ['critical', 'high'], true)) continue; ?>
      <li>
        <strong><?= e($action['title']) ?></strong>
        <span class="loc"><?= e($action['file']) ?><?= $action['line'] ? ':' . (int)$action['line'] : '' ?></span>
        &nbsp;— <?= e($action['fix']) ?>
      </li>
<?php endforeach; ?>
    </ol>
  </div>
<?php endif; ?>

  <h2>Findings</h2>
<?php if (empty($findings)): ?>
  <div class="empty">No issues detected by the ruleset. Nice.</div>
<?php else: foreach ($findings as $f): ?>
  <article class="finding">
    <div class="finding-head">
      <span class="sev-badge" style="background:<?= severityColor($f['severity']) ?>"><?= e($f['severity']) ?></span>
      <span class="cat-chip"><?= e(categoryOf($f['rule_id'])) ?></span>
      <div class="finding-title"><?= e($f['title']) ?></div>
      <div class="rule-id"><?= e($f['rule_id']) ?></div>
    </div>
    <div class="finding-loc"><?= e($f['file']) ?><?= $f['line'] ? ':' . (int)$f['line'] : '' ?></div>
    <div class="finding-detail"><?= e($f['detail']) ?></div>
    <div class="finding-fix"><strong>Fix:</strong> <?= e($f['fix']) ?></div>
  </article>
<?php endforeach; endif; ?>

  <footer>
    <div class="generator">
      Generated by <?= e($meta['scanner'] ?? 'laravel-audit') ?> &middot; automated scan, not a substitute for a human code review.
    </div>
<?php if (!empty($brand['brand_name'])): ?>
    <div class="brand">
      <span class="brand-name"><?= e($brand['brand_name']) ?></span>
<?php if (!empty($brand['brand_url'])): ?>
      <a href="<?= e($brand['brand_url']) ?>"><?= e(preg_replace('#^https?://#', '', $brand['brand_url'])) ?></a>
<?php endif; ?>
<?php if (!empty($brand['footer_cta'])): ?>
      <div class="cta"><?= e($brand['footer_cta']) ?></div>
<?php endif; ?>
    </div>
<?php endif; ?>
  </footer>
</body>
</html>
