---
title: "Ultimate Security Audit Script"
description: "Pre-push security sweep for static sites and web projects (Hugo, Jekyll, Astro, Next.js export, Eleventy, generic)."
date: 2025-12-24
tags: ["security", "bash", "static-sites", "hugo", "jekyll", "astro", "nextjs", "eleventy", "devops"]
---

## What it does

A fast, local audit script you run before pushing changes—focused on the most common "oops" moments that later become incident tickets:

- Secrets and credentials in config and repo files (tokens, keys, passwords, etc.)
- Private keys committed anywhere (**hard stop**)
- Backup, temp, or debug artifacts tracked by Git (`.bak`, `.old`, `debug.log`, `phpinfo.php`, etc.)
- Risky output exposure (for example `.git/` or config/key files inside built output)
- Internal URL or IP leakage in generated output (`localhost`, `192.168.x.x`, `.local`, etc.)
- Mixed content (`http://` references inside HTTPS pages)
- Large file sanity checks (accidental dumps committed to Git)
- Basic dependency signal (optional `npm audit` if `package.json` exists)
- Git history reminder (flags file types that may still exist in history)
- Netlify build-log "oops" checks (commands that might echo env vars)

This script also tries to:
- Detect your generator (Hugo/Jekyll/Astro/Next/Eleventy)
- Detect the most likely output directory (`public/`, `dist/`, `_site/`, `out/`, `build/`)
- Run "output-based" checks only when it finds a real output dir

## Why this exists

Most security incidents don't start with zero-days or nation-state actors.  
They start with small, human mistakes:

- A debug file left behind
- A token copied "just for testing"
- A local URL that leaks into production output
- A build artifact that exposes more than intended

Every check in this script exists because I've personally tripped over at least one of these mistakes while building and publishing this site.

This script exists to catch those issues **before** they leave your machine.

It's designed for solo operators, small teams, and engineers who want a fast, local safety net—without waiting for CI, code review, or a security team to notice after the fact.

Think of it as a **seatbelt**, not an airbag.

## Threat model (what this is protecting against)

This script is intentionally scoped. It focuses on **high-probability, low-friction failure modes**, not theoretical edge cases.

### In scope

- **Accidental credential exposure**
  - API tokens, secrets, private keys committed to Git
- **Unsafe artifacts**
  - Backup files, debug output, temp files accidentally tracked
- **Static output leakage**
  - Internal IPs, localhost references, `.git/` exposure in published output
- **Configuration drift**
  - Mixed HTTP/HTTPS content
  - Environment-specific values leaking into production builds
- **Operational mistakes**
  - Large unintended files committed
  - Dependency issues surfaced late

### Explicitly out of scope

- Advanced code exploitation
- Runtime vulnerabilities
- Authentication or authorization logic flaws
- Deep dependency graph analysis
- Adversarial code review

If you need those, you want a **real SAST pipeline and human review**—not a Bash script.

## What it works on

This script is designed for static sites and web projects, including:

- Hugo
- Jekyll
- Astro
- Next.js static export (common output: `out/`)
- Eleventy
- Generic static output (detects common output directories such as `public/`, `dist/`, `_site/`, `out/`, `build/`)

The script attempts to auto-detect your generator and output directory so output-based checks run safely and accurately.

## Where you can run it

- Linux (Debian, Ubuntu, and similar)

### Requirements (minimal)

- `bash`
- `grep`
- `find`
- `sed`
- `cut`
- `wc`

### Optional (enables additional checks)

- `git` — Git history and tracked-file checks
- `npm` — dependency audit section
- `hugo`, `jekyll`, Bundler, or Node-based build tooling (only if using `--rebuild`)

## What it does not do

This is **not** a full SAST pipeline and does **not** replace:

- GitHub Secret Scanning or Push Protection
- Dependabot
- CodeQL, Semgrep, or Snyk
- A real security review

This is a **pre-push gut check**: fast, local, opinionated, and useful.

## CI / automation disclaimer

This script is **not intended as your primary CI gate**.

Reasons:

- It's opinionated and geared toward fast local feedback
- Some checks are environment-aware (local output dirs, local build tooling)
- It may intentionally "fail loud" on critical findings

If you want automated enforcement:

- Use GitHub Secret Scanning and Push Protection
- Use Dependabot (or equivalent)
- Add SAST tools (CodeQL, Semgrep, Snyk) in CI

This script is designed to run **before** all of that—on your machine, on your terms.

---

## Usage

### Run it locally (scan current directory)

From your repo root:

```bash
./ultimate-security-audit.sh
```

### Scan a specific directory

```bash
./ultimate-security-audit.sh /path/to/repo
```

### Print version

```bash
./ultimate-security-audit.sh --version
```

---

## Options and Flags

### `--clean` (or `CLEAN=1`)

Safely remove build artifacts (output directory and some generator caches).  
Safe-by-default with guardrails to prevent accidental `rm -rf /`.

**Examples:**

```bash
./ultimate-security-audit.sh --clean .
CLEAN=1 ./ultimate-security-audit.sh .
```

---

### `--auto-clean` (or `AUTO_CLEAN_ENV=1`)

Only cleans if output directory exists and looks "dev-tainted" (contains `localhost`, `127.0.0.1`, `192.168.x.x`, `10.x.x.x`, `172.16-31.x.x`, etc.).

Keeps cleanup conservative and avoids unnecessary deletes.

**Examples:**

```bash
./ultimate-security-audit.sh --auto-clean .
AUTO_CLEAN_ENV=1 ./ultimate-security-audit.sh .
```

---

### `--rebuild` (or `REBUILD=1`)

Attempt generator-appropriate rebuild so output-based checks run against fresh artifacts.

**Rebuild commands:**
- **Hugo:** `hugo --gc --minify`
- **Jekyll:** `bundle exec jekyll build` (if Gemfile + bundler), else `jekyll build`
- **Node projects (Astro/Next/Eleventy/generic):** `npm run build` (if package.json exists)

**Note on Next.js static export:**  
Some Next.js projects require explicit export step (`next export` or `npm run export`) to generate `out/`. Ensure your `package.json` includes the proper export script and run it before auditing.

**Examples:**

```bash
./ultimate-security-audit.sh --rebuild .
REBUILD=1 ./ultimate-security-audit.sh .
```

---

### Combine flags

```bash
./ultimate-security-audit.sh --clean --rebuild .
./ultimate-security-audit.sh --auto-clean --rebuild .
```

## Exit codes

The script exits with severity-aware codes so results can be interpreted consistently by humans, shell scripts, or automation.

| Exit Code | Severity | Meaning |
|----------:|----------|---------|
| `0` | None | No issues found |
| `1` | Medium / Low | Non-blocking issues detected |
| `2` | High | High-severity issues detected |
| `3` | Critical | Critical issues detected (credentials, keys, or major exposure) |

### How to use these exit codes

- **`0`** — Safe to push
- **`1`** — Review findings; push only if intentional
- **`2`** — Fix before pushing
- **`3`** — Do not push

---

## Notes on generator detection

The script tries to detect the generator and output directory automatically:
- **Hugo** → output usually `public/`
- **Jekyll** → output usually `_site/`
- **Astro** → output usually `dist/`
- **Next export** → output usually `out/` (or `.next/` if not exported)
- **Eleventy** → often `_site/` (sometimes `dist/` or `build/`)

If no output directory is found, output-based checks are skipped (and you'll see a warning).

**Tip:** Run `--rebuild` when you want the audit to validate fresh output artifacts.

---

## Next steps (future enhancements)

Possible future enhancements that keep this tool lean and opinionated:

- **Dedicated secret scanner as a git hook (optional)**  
  Add a lightweight `pre-commit` or `pre-push` hook using a purpose-built secret scanner (e.g., gitleaks or trufflehog).  
  This script remains the broad, repo-wide audit; the hook provides fast, staged-file secret detection without bloating core logic.

- **`--json` output**  
  Emit structured JSON for CI pipelines, scripting, and automation, while keeping human-readable output as the default.

- **`--fail-on high|critical` flag**  
  Allow severity-based exit behavior so teams can enforce stricter gates in automation without changing checks.

- **Short "Common fixes" reference**  
  Print a concise remediation guide for frequent findings (secrets, large files, build output leaks, `.git` exposure).

Feedback and contributions welcome.

---

## Sample output

Example (abbreviated and redacted):

```text
╔════════════════════════════════════════════════════════════════╗
║              🦛 Published by Oob Skulden™ 🦛                   ║
║        Ultimate Security Audit (Web/Static) v0.36.9            ║
║          "The threats you don't see coming" - 95% underwater   ║
╚════════════════════════════════════════════════════════════════╝

Scanning directory: /home/user/my-site

ℹ️  Detected generator: hugo
ℹ️  Detected output dir: /home/user/my-site/public

CHECK 2: Private Keys in Any File [MUST-HAVE]
✓ No private keys found

CHECK 4: Sensitive Files in Output Directory
✓ No critical files found in output dir

CHECK 5: Internal URLs/IPs Exposed [MUST-HAVE]
⚠️  Found 3 reference(s) to internal URLs/IPs [MEDIUM]
  public/index.html: http://localhost:1313
  ...

🔒 FINAL SECURITY SUMMARY 🔒
CRITICAL: 0
HIGH:     1
MEDIUM:   2
LOW:      1

Exit code: 2
```