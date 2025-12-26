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

## Why this exists

Most security incidents don’t start with zero-days or nation-state actors.  
They start with small, human mistakes:

- A debug file left behind
- A token copied “just for testing”
- A local URL that leaks into production output
- A build artifact that exposes more than intended

Every check in this script exists because I’ve personally tripped over at least one of these mistakes while building and publishing this site.

This script exists to catch those issues **before** they leave your machine.

It’s designed for solo operators, small teams, and engineers who want a fast, local safety net—without waiting for CI, code review, or a security team to notice after the fact.

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
- macOS

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
- `hugo`, `jekyll`, or Node-based build tooling (only if using `--rebuild`)

## What it does not do

This is **not** a full SAST pipeline and does **not** replace:

- GitHub Secret Scanning or Push Protection
- Dependabot
- CodeQL, Semgrep, or Snyk
- A real security review

This is a **pre-push gut check**: fast, local, opinionated, and useful.

## CI / automation disclaimer

This script is **not intended for CI pipelines**.

Reasons:

- It is interactive and opinionated
- It favors fast feedback over exhaustive coverage
- Some checks are environment-aware (local paths, build outputs)
- It may intentionally fail fast on critical findings

If you want automated enforcement:

- Use GitHub Secret Scanning and Push Protection
- Use Dependabot or similar dependency tooling
- Add SAST tools (CodeQL, Semgrep, Snyk) in CI

This script is designed to run **before** all of that—on your machine, on your terms.

## Usage

### Run it locally

Run the script from the root of your repository:

```bash
./ultimate-security-audit.sh
```

Scan a specifc directory

```bash
./ultimate-security-audit.sh /path/to/repo
```
or

```bash
./ultimate-security-audit.sh /path/to/folder
```

### Exit codes
[current content]

Print the installed version and exit

```bash
./ultimate-security-audit.sh --version
```

## Exit codes

The script exits with severity-aware codes so results can be interpreted consistently by humans, shell scripts, or automation.

| Exit Code | Severity  | Meaning |
|----------:|-----------|---------|
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

## Next steps

Possible future enhancements that keep this tool lean and opinionated:

- **Dedicated secret scanner as a git hook (optional)**  
  Add a lightweight `pre-commit` or `pre-push` hook using a purpose-built secret scanner (e.g., gitleaks or trufflehog).  
  This script remains the broad, repo-wide audit; the hook provides fast, staged-file secret detection without bloating core logic.

- **`--json` output**  
  Emit structured JSON for CI pipelines, scripting, and automation, while keeping human-readable output as the default.

- **`--fail-on high|critical` flag**  
  Allow severity-based exit behavior so teams can enforce stricter gates in CI without changing checks.

- **Short “Common fixes” reference**  
  Print a concise remediation guide for frequent findings (secrets, large files, build output leaks, `.git` exposure).

- **Optional OWASP Top 10 mapping (informational only)**  
  Tag findings with relevant OWASP Top 10 categories to provide context—no scoring, no compliance overhead.

Feedback and contributions welcome.


## Sample output

Example (abbreviated and redacted):

```text
==============================================
🔒 ULTIMATE SECURITY AUDIT
==============================================

[+] Scan directory: /home/user/my-site
[+] Detected generator: Hugo
[+] Output directory: public/

[✓] No private keys detected
[!] Potential secrets found:
    - config.toml: line 42 (API_TOKEN)
    - netlify.toml: line 18 (AUTH_HEADER)

[!] Risky artifacts tracked by git:
    - debug.log
    - backup.old

[!] Internal URLs found in output:
    - public/index.html → http://localhost:1313
    - public/about/index.html → 192.168.1.10

[✓] No exposed .git directories in output
[✓] No oversized files detected

[!] Git history reminder:
    Files matching *.key may still exist in history

----------------------------------------------
Result: HIGH ISSUES DETECTED
Exit code: 2
----------------------------------------------
