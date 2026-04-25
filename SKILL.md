---
name: laravel-audit
description: Scans a Laravel codebase for security issues (Blade XSS, CSRF gaps, unserialize/eval, APP_KEY strength), performance traps (N+1, missing indexes), AI-generated code smells, and deploy hygiene — produces a scored HTML + SARIF report, can auto-fix safe issues, supports rule profiles (pre-launch, rescue, monthly), baseline files to ignore accepted findings, .laravel-audit/config.json, diff mode, custom rule plugins, webhooks, and interactive walkthrough. Installs via Composer (mjgapp/laravel-audit). Triggers when the user asks for a Laravel health check, audit, code review, security review, wants a pre-launch or monthly scan, says "fix the easy stuff", "baseline this repo", or "export SARIF for GitHub". Works on any Laravel 9/10/11/12/13 project.
---

# Laravel Audit

You are operating the `laravel-audit` skill. Your job is to scan a Laravel repository and produce a clear, actionable health report for the user.

## When to run this skill

Trigger on phrases like:
- "audit this Laravel app"
- "is this Laravel repo production ready?"
- "health check / code review / security review this Laravel codebase"
- "find N+1 queries / mass assignment issues / debug leftovers"
- "laravel-audit", "/laravel-audit", "run the audit"

If the user's repository is not Laravel (no `composer.json` with `"laravel/framework"` in require, or no `artisan` file), tell them this skill only runs on Laravel projects and stop.

## How to run the audit

The skill bundles these scripts next to this file:

- `scripts/audit.php` — scanner + auto-fix + history, outputs JSON
- `scripts/render.php` — takes JSON on stdin, outputs a self-contained HTML report
- `templates/github-workflows/laravel-audit.yml` — drop-in CI workflow for PR checks

**Standard flow:**

1. **Identify the target repo.** If the user didn't name one, assume the current working directory. Confirm with `ls` that an `artisan` file and `composer.json` are present.

2. **Run the scanner.** Use the Bash tool:
   ```bash
   php <SKILL_DIR>/scripts/audit.php <REPO_PATH> > /tmp/laravel-audit.json
   ```
   Replace `<SKILL_DIR>` with the absolute path to this skill's directory, and `<REPO_PATH>` with the target repo's absolute path. The scanner has zero runtime dependencies — it does not need `composer install`.

3. **Render the HTML report:**
   ```bash
   php <SKILL_DIR>/scripts/render.php /tmp/laravel-audit.json > <REPO_PATH>/laravel-audit-report.html
   ```

4. **Summarize findings in the conversation.** Read `/tmp/laravel-audit.json`, then write a short markdown summary that includes:
   - The overall score (0–100), grade (A–F), and the **score delta** from last scan if available
   - A table of critical + high findings with file:line and one-line fixes
   - A note about medium/low counts (don't enumerate every one)
   - The count of auto-fixable findings (see Auto-fix section below)
   - The path to the HTML report

5. **Offer next steps.** Ask the user if they want you to:
   - **Apply auto-fixes** (see Auto-fix section)
   - Fix the top remaining findings manually with your help
   - Open the HTML report (`open <REPO_PATH>/laravel-audit-report.html` on macOS)
   - Export to PDF (open the HTML in Chrome/Safari → Cmd+P → Save as PDF)
   - Install the CI workflow (see CI section)

## Auto-fix (v0.3)

Six rules have safe auto-fixers: **SEC-001** (APP_DEBUG=true → false), **SEC-005** (remove `dd()`/`dump()`/`var_dump()`/`print_r()` standalone lines), **SEC-008** (generate a fresh APP_KEY), **SEC-009** (APP_ENV=local → production), **SEC-010** (harden cookie flags), **DEPLOY-003** (pin PHP version in composer.json).

To apply:

```bash
# Preview without writing anything
php <SKILL_DIR>/scripts/audit.php <REPO_PATH> --fix --dry-run

# Apply fixes (aborts on uncommitted changes unless --force)
php <SKILL_DIR>/scripts/audit.php <REPO_PATH> --fix
```

**Always** suggest the user commit or stash their working tree before running `--fix`. The scanner aborts if it detects a dirty git working tree — respect that; don't add `--force` without the user explicitly asking.

After a fix run, re-scan and report the score delta. Remaining findings are advisory — they need human judgment.

## Trend tracking

```bash
php <SKILL_DIR>/scripts/audit.php <REPO_PATH> --save-history
```

Appends a summary to `<REPO_PATH>/.laravel-audit/history/`. On every subsequent scan, the report's `meta.score_previous` and `meta.score_delta` fields compare against the most recent saved summary. Use these to celebrate progress in monthly audits.

## CI integration

The template at `templates/github-workflows/laravel-audit.yml` installs as `.github/workflows/laravel-audit.yml` in the target repo. It runs the scanner on every PR and posts findings as a sticky bot comment. Fails the build if the grade is F.

## Rule profiles (v0.4)

Four named profiles adjust which rules run and how findings are weighted:

- **`default`** — all 22 rules, v0.3 weights (20/10/4/1) and caps
- **`pre-launch`** — all 22 rules, stricter weights (25/14/6/2) and wider caps; use right before shipping to prod
- **`rescue`** — security-weighted (crits +25%, highs +50%); use when taking over an abandoned codebase
- **`monthly`** — 12 core rules only; fastest path to a recurring health signal

```bash
php <SKILL_DIR>/scripts/audit.php <REPO> --profile=pre-launch
php <SKILL_DIR>/scripts/audit.php <REPO> --profile=monthly --save-history
```

Pick the right one for the moment. Default is fine if the user didn't specify.

## Diff mode (v0.4)

```bash
php <SKILL_DIR>/scripts/diff.php <OLD_REPORT>.json <NEW_REPORT>.json --pretty
```

Outputs added/removed/unchanged findings + score delta. Useful for monthly check-ins or PR comparisons. Finding identity = (rule_id, file, line) — so a rename or line shift counts as "removed + added".

## Custom rule plugins (v0.4)

Users drop PHP files into `<REPO>/.laravel-audit/rules/`. Each file defines a function named `userRule_<IDENTIFIER>(Context $ctx): void` that adds `USER-XXX`-prefixed findings. Files containing any top-level code outside function definitions are rejected with a warning.

Example:

```php
<?php
function userRule_NoTodoInControllers(Context $ctx): void
{
    // ... scan logic, add Finding with rule_id 'USER-001'
}
```

## Webhooks (v0.4)

```bash
php <SKILL_DIR>/scripts/audit.php <REPO> --webhook=https://hooks.slack.com/services/T00/B00/XXX
```

Auto-detects Slack / Discord / generic from the hostname. Override with `--webhook-type=slack|discord|generic`. Generic posts the full report JSON; Slack/Discord post a formatted summary (score, grade, top findings). Webhook failure never fails the scan.

## Interactive walkthrough (v0.4)

```bash
php <SKILL_DIR>/scripts/audit.php <REPO> --interactive
```

Steps through findings one at a time. Per finding: `[f]ix, [s]kip, [o]pen, [q]uit`. Requires a TTY — skipped cleanly in CI/non-interactive shells. Good for consultants reviewing someone else's codebase live with the client.

## Baseline — ignore accepted findings (v0.5)

Legacy codebases shouldn't fail every PR. `.laravel-audit/baseline.json` snapshots the findings you've accepted; the scanner filters them out on every subsequent scan.

```bash
# First time — accept current findings as the starting line
php <SKILL_DIR>/scripts/audit.php <REPO> --update-baseline

# Every subsequent scan automatically filters baselined findings
php <SKILL_DIR>/scripts/audit.php <REPO>

# Occasionally, do a full audit ignoring the baseline
php <SKILL_DIR>/scripts/audit.php <REPO> --ignore-baseline
```

The score is computed on post-filter findings — so a clean baseline means a clean score, and any new regression lands in the report as the only finding.

## Config file (v0.5)

Drop `.laravel-audit/config.json` (preferred) or `.laravel-audit.json` at the repo root:

```json
{
  "profile": "pre-launch",
  "exclude_rules": ["SLOP-001"],
  "exclude_paths": ["app/Legacy/**", "app/LegacyPlugin/**"],
  "webhook": { "url": "https://hooks.slack.com/...", "type": "slack" },
  "brand": { "brand_name": "Acme Code Reviews", "brand_url": "https://acme.example.com" }
}
```

CLI flags override config. Every field is optional.

## Gitignore-aware `.env` severity (v0.5.1)

Bare `.env` (not `.env.production` / `.env.prod` / `.env.staging`) is treated as local-only when `.gitignore` excludes it. In that case:
- `SEC-001` APP_DEBUG=true → downgraded from critical to low
- `SEC-008` empty/placeholder APP_KEY → critical to low
- `SEC-009` APP_ENV=local → medium to low

Downgraded findings still appear in the report, but with an advisory note explaining why they're demoted. This removes the noisy "critical!" alarm on local-dev configs that never ship, while keeping a breadcrumb in case the env-injection assumption ever breaks.

Production-suffix env files (`.env.production` etc.) keep full severity unconditionally.

## SARIF output (v0.5)

```bash
php <SKILL_DIR>/scripts/audit.php <REPO> --format=sarif > audit.sarif
```

SARIF 2.1.0, spec-compliant, GitHub Security tab compatible. Upload via `github/codeql-action/upload-sarif` and findings appear as native PR annotations + repo-level security alerts.

## Installation via Composer (v0.5)

In addition to the skill location (`~/.claude/skills/laravel-audit/`), buyers can install into any Laravel repo:

```bash
composer require --dev mjgapp/laravel-audit
vendor/bin/laravel-audit . --pretty
vendor/bin/laravel-audit . --format=sarif > audit.sarif
vendor/bin/laravel-audit . --update-baseline
```

Zero runtime dependencies; just PHP 8.1+.

## Rules the scanner checks (v0.2)

| Rule ID      | Title                                                | Severity |
|--------------|------------------------------------------------------|----------|
| SEC-001      | APP_DEBUG=true in .env                               | critical |
| SEC-002      | Unbounded mass assignment (`$guarded = []`)          | high     |
| SEC-003      | Raw SQL with variable interpolation                  | critical |
| SEC-004      | Hardcoded API keys / secrets in source               | critical |
| SEC-005      | `dd()` / `dump()` / `var_dump()` left in code        | medium   |
| SEC-006      | `unserialize()` call                                 | critical |
| SEC-007      | `eval()` call                                        | critical |
| SEC-008      | APP_KEY empty or placeholder                         | critical |
| SEC-009      | APP_ENV set to local                                 | medium   |
| SEC-010      | Session cookie `http_only` or `secure` disabled      | medium/low |
| SEC-011      | SQL keyword string with variable interpolation       | high     |
| BLADE-001    | Unescaped Blade output (`{!! !!}`)                   | high     |
| BLADE-002    | State-changing form missing `@csrf`                  | high     |
| PERF-001     | Potential N+1 query inside `foreach`                 | high     |
| PERF-002     | Foreign key column without index                     | medium   |
| PERF-003     | Synchronous Mail send (not queued)                   | medium   |
| PERF-004     | `Model::all()` loads every row into memory           | low      |
| SLOP-001     | High TODO/FIXME density in a file                    | low      |
| SLOP-002     | Multiple stub functions with empty returns           | low      |
| SLOP-003     | PHP class in app/ has no namespace                   | low      |
| DEPLOY-001   | composer.lock missing                                | high     |
| DEPLOY-002   | composer.lock older than composer.json               | medium   |
| DEPLOY-003   | PHP version not constrained in composer.json         | low      |
| DEPLOY-004   | SESSION_DRIVER=file                                  | low      |

## Scoring

Starts at 100. Each finding contributes a severity weight (critical 20, high 10, medium 4, low 1), but the total contribution **per severity level is capped** so one category can't auto-fail a large repo:

- Critical cap: 40 points (2+ criticals already flirt with F)
- High cap: 25 points
- Medium cap: 15 points
- Low cap: 10 points

Grades: A (90+), B (75–89), C (60–74), D (40–59), F (<40).

## Important behavior notes

- **Don't argue with findings.** The scanner uses static heuristics. Some hits are false positives (especially PERF-001 — N+1 inside foreach is a heuristic, not proof). When presenting findings, say "potential" and encourage the user to verify before fixing.
- **Don't mass-edit.** Never apply fixes across many files at once without the user saying yes to each change.
- **Respect `vendor/`, `node_modules/`, `.git/`, `storage/framework/`.** The scanner already skips these; don't re-scan them manually.
- **If the scan finds zero issues**, say so directly. Don't manufacture problems to look useful.
- **Do not suggest adding this skill to the user's repo.** It lives in `~/.claude/skills/laravel-audit/` and is a tool, not a dependency.

## Example response skeleton

After running the scan, structure your reply like this:

```
## Laravel Audit — <repo-name>

**Score: 70/100 (C)** — 2 findings across 90 files

### Top issues
1. **APP_DEBUG enabled** — `.env:4` (critical)
   Fix: set `APP_DEBUG=false` before deploying.
2. **Potential N+1 inside foreach** — `app/Services/AlertService.php:47` (high)
   Fix: eager-load the relation with `Model::with('...')->get()` before the loop.

Full HTML report: `<repo>/laravel-audit-report.html` — open it in Chrome/Safari and Cmd+P → Save as PDF if you want to archive or share.

Want me to fix the top issues now?
```

Keep the summary under ~200 words unless the user asks for detail. The HTML report is where the depth lives.
