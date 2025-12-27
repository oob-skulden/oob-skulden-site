#!/usr/bin/env bash
# ultimate-security-audit.sh
# Complete security audit for static sites + web projects (Hugo, Jekyll, Astro, Next export, Eleventy, generic)
# Published by Oob Skulden™
#
# Platform support:
# - Targeted for: Linux (Debian/Ubuntu) + macOS
# - Requires: bash, grep, find, sed, cut, wc (standard on both)
# - Optional: git (history checks), npm (npm audit), hugo/jekyll (only if using --rebuild)
#
# What this does (high level):
# - Scans a repo for the usual “oops” moments: secrets, private keys, backup files, leaked IPs/URLs, etc.
# - Tries to detect your generator (Hugo/Jekyll/Astro/Next/Eleventy) and find its output directory.
# - Scans OUTPUT separately (by default) and excludes output from SOURCE scan by default to reduce noise.
#
# Quick usage:
#   ./ultimate-security-audit.sh                  # scan current directory
#   ./ultimate-security-audit.sh /path/to/repo    # scan a specific repo
#   ./ultimate-security-audit.sh --version
#
# Optional cleanup (safe-by-default):
#   CLEAN=1 ./ultimate-security-audit.sh .
#   CLEAN=1 REBUILD=1 ./ultimate-security-audit.sh .
#   ./ultimate-security-audit.sh --clean --rebuild .
#   ./ultimate-security-audit.sh --auto-clean .   # only cleans if output looks dev-tainted
#
# New scan control flags:
#   ./ultimate-security-audit.sh --list-excludes .
#   ./ultimate-security-audit.sh --exclude .cache --exclude vendor .
#   ./ultimate-security-audit.sh --skip-output .
#   ./ultimate-security-audit.sh --only-output .
#   ./ultimate-security-audit.sh --include-output-in-source .
#
# Exit codes (handy for CI):
#   0 = clean
#   1 = medium/low issues exist
#   2 = high issues exist
#   3 = critical issues exist

set -euo pipefail

# ------------------------------------------------------------
# Shell sanity: refuse sh/dash, enforce bash, keep errors clear
# ------------------------------------------------------------
if [[ -z "${BASH_VERSION:-}" ]]; then
  printf 'ERROR: This script must be run with bash (not sh).\n' >&2
  printf 'Try: bash %q\n' "$0" >&2
  exit 2
fi

# Bump this when you tag releases.
VERSION="0.37.0"

# ----------------------------
# Output helpers (portable; no echo -e)
# ----------------------------
RED=$'\033[0;31m'
YELLOW=$'\033[1;33m'
GREEN=$'\033[0;32m'
BLUE=$'\033[0;34m'
PURPLE=$'\033[0;35m'
CYAN=$'\033[0;36m'
NC=$'\033[0m' # No Color

say()      { printf '%s\n' "$*"; }
sayc()     { printf '%b\n' "$*"; }  # interprets color escapes
hr()       { sayc "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }

die() {
  local msg="$1"
  sayc "${RED}Error: ${msg}${NC}" >&2
  exit 1
}

# Simple version flag
if [[ "${1:-}" == "--version" ]]; then
  say "ultimate-security-audit version $VERSION (macOS + Linux) — Published by Oob Skulden™"
  exit 0
fi

# Branding banner
say ""
sayc "${PURPLE}╔════════════════════════════════════════════════════════════════╗${NC}"
sayc "${PURPLE}║              🦛 Published by Oob Skulden™ 🦛                   ║${NC}"
sayc "${PURPLE}║        Ultimate Security Audit (Web/Static) v${VERSION}              ║${NC}"
sayc "${PURPLE}║          \"The threats you don't see coming\" - 95% underwater  ║${NC}"
sayc "${PURPLE}╚════════════════════════════════════════════════════════════════╝${NC}"
say ""

# ----------------------------
# Flag parsing (supports scan dir + new exclude controls)
# ----------------------------
AUTO_CLEAN=0
DO_CLEAN=0
DO_REBUILD=0

SKIP_OUTPUT=0
ONLY_OUTPUT=0
INCLUDE_OUTPUT_IN_SOURCE=0
LIST_EXCLUDES=0

# Default excludes for SOURCE scan
EXCLUDE_DIRS_DEFAULT=(
  ".git"
  "node_modules"
  ".next"
  "vendor"
  ".bundle"
  ".jekyll-cache"
  ".sass-cache"
  "coverage"
  ".venv"
  ".pytest_cache"
)

EXCLUDE_DIRS=("${EXCLUDE_DIRS_DEFAULT[@]}")
USER_EXCLUDES=()
ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --clean) DO_CLEAN=1 ;;
    --rebuild) DO_REBUILD=1 ;;
    --auto-clean) AUTO_CLEAN=1 ;;

    --skip-output) SKIP_OUTPUT=1 ;;
    --only-output) ONLY_OUTPUT=1 ;;
    --include-output-in-source) INCLUDE_OUTPUT_IN_SOURCE=1 ;;
    --list-excludes) LIST_EXCLUDES=1 ;;
    --exclude)
      shift
      [[ -z "${1:-}" ]] && die "--exclude requires a value"
      USER_EXCLUDES+=("$1")
      ;;
    --version) : ;;
    *) ARGS+=("$1") ;;
  esac
  shift
done

SCAN_DIR="${ARGS[0]:-.}"

# Env var support (lets you do CLEAN=1 REBUILD=1)
[[ "${CLEAN:-0}" == "1" ]] && DO_CLEAN=1
[[ "${REBUILD:-0}" == "1" ]] && DO_REBUILD=1
[[ "${AUTO_CLEAN_ENV:-0}" == "1" ]] && AUTO_CLEAN=1

# Optional env for scan controls (handy for CI)
[[ "${SKIP_OUTPUT_ENV:-0}" == "1" ]] && SKIP_OUTPUT=1
[[ "${ONLY_OUTPUT_ENV:-0}" == "1" ]] && ONLY_OUTPUT=1
[[ "${INCLUDE_OUTPUT_IN_SOURCE_ENV:-0}" == "1" ]] && INCLUDE_OUTPUT_IN_SOURCE=1

if [[ ! -d "$SCAN_DIR" ]]; then
  die "Directory '$SCAN_DIR' not found"
fi

say "Scanning directory: $SCAN_DIR"
say ""

# ----------------------------
# macOS + Linux portable realpath
# ----------------------------
realpath_portable() {
  if command -v realpath >/dev/null 2>&1; then
    realpath "$1" 2>/dev/null && return 0
  fi
  if command -v readlink >/dev/null 2>&1; then
    readlink -f "$1" 2>/dev/null && return 0
  fi
  (cd "$1" 2>/dev/null && pwd -P) || printf '%s\n' "$1"
}

REAL_SCAN_DIR="$(realpath_portable "$SCAN_DIR")"

# ----------------------------
# Grep portability helpers
# ----------------------------
GREP_P=0
if grep -P "" </dev/null >/dev/null 2>&1; then
  GREP_P=1
fi

grep_qi_re() { # grep_qi_re "pattern" "file"
  local pat="$1"; shift
  if [[ "$GREP_P" -eq 1 ]]; then
    grep -qiP "$pat" "$@" 2>/dev/null
  else
    grep -qiE "$pat" "$@" 2>/dev/null
  fi
}

# Helper: build grep --exclude-dir args
build_grep_excludes() {
  local -a out=()
  local d
  for d in "${EXCLUDE_DIRS[@]}"; do
    out+=( "--exclude-dir=$d" )
  done
  printf '%s\n' "${out[@]}"
}

# Helper: find prune expression args (portable)
# Usage: find "$SCAN_DIR" "$(find_prune_args)" -type f ...
find_prune_args() {
  local -a expr=()
  local d
  for d in "${EXCLUDE_DIRS[@]}"; do
    expr+=( -name "$d" -prune -o )
  done
  printf '%s\n' "${expr[@]}"
}

# ----------------------------
# Generator + output directory detection
# ----------------------------
GENERATOR="unknown"
OUTPUT_DIR=""

detect_generator_and_output() {
  GENERATOR="unknown"
  OUTPUT_DIR=""

  # Hugo
  if [[ -f "$SCAN_DIR/hugo.toml" || -f "$SCAN_DIR/config.toml" || -f "$SCAN_DIR/config.yaml" || -f "$SCAN_DIR/config.yml" ]] && [[ -d "$SCAN_DIR/content" ]]; then
    GENERATOR="hugo"
    [[ -d "$SCAN_DIR/public" ]] && OUTPUT_DIR="$SCAN_DIR/public"
  fi

  # Jekyll
  if [[ "$GENERATOR" == "unknown" && ( -f "$SCAN_DIR/_config.yml" || -f "$SCAN_DIR/_config.yaml" ) ]] && [[ -d "$SCAN_DIR/_posts" ]]; then
    GENERATOR="jekyll"
    [[ -d "$SCAN_DIR/_site" ]] && OUTPUT_DIR="$SCAN_DIR/_site"
  fi

  # Next.js (export)
  if [[ "$GENERATOR" == "unknown" && -f "$SCAN_DIR/package.json" ]] && grep -qi '"next"' "$SCAN_DIR/package.json" 2>/dev/null; then
    GENERATOR="next"
    [[ -d "$SCAN_DIR/out" ]] && OUTPUT_DIR="$SCAN_DIR/out"
    [[ -z "$OUTPUT_DIR" && -d "$SCAN_DIR/.next" ]] && OUTPUT_DIR="$SCAN_DIR/.next"
  fi

  # Astro
  if [[ "$GENERATOR" == "unknown" && -f "$SCAN_DIR/package.json" ]] && grep -qi '"astro"' "$SCAN_DIR/package.json" 2>/dev/null; then
    GENERATOR="astro"
    [[ -d "$SCAN_DIR/dist" ]] && OUTPUT_DIR="$SCAN_DIR/dist"
  fi

  # Eleventy
  if [[ "$GENERATOR" == "unknown" && -f "$SCAN_DIR/package.json" ]] && grep -qi '"@11ty/eleventy"\|"eleventy"' "$SCAN_DIR/package.json" 2>/dev/null; then
    GENERATOR="eleventy"
    [[ -d "$SCAN_DIR/_site" ]] && OUTPUT_DIR="$SCAN_DIR/_site"
    [[ -z "$OUTPUT_DIR" && -d "$SCAN_DIR/dist" ]] && OUTPUT_DIR="$SCAN_DIR/dist"
    [[ -z "$OUTPUT_DIR" && -d "$SCAN_DIR/build" ]] && OUTPUT_DIR="$SCAN_DIR/build"
  fi

  # Generic fallback
  if [[ -z "$OUTPUT_DIR" ]]; then
    for d in public dist out _site build; do
      if [[ -d "$SCAN_DIR/$d" ]]; then
        OUTPUT_DIR="$SCAN_DIR/$d"
        [[ "$GENERATOR" == "unknown" ]] && GENERATOR="static"
        break
      fi
    done
  fi
}

detect_generator_and_output

sayc "${BLUE}ℹ️  Detected generator: ${GENERATOR}${NC}"
if [[ -n "$OUTPUT_DIR" ]]; then
  sayc "${BLUE}ℹ️  Detected output dir: ${OUTPUT_DIR}${NC}"
else
  sayc "${YELLOW}⚠️  No output directory detected (public/dist/out/_site/build). Output-based checks will be limited.${NC}"
fi
say ""

# Merge user excludes
if [[ ${#USER_EXCLUDES[@]} -gt 0 ]]; then
  EXCLUDE_DIRS+=("${USER_EXCLUDES[@]}")
fi

# Automatically exclude output dir from SOURCE scan unless explicitly included
OUTPUT_BASENAME=""
if [[ -n "$OUTPUT_DIR" ]]; then
  OUTPUT_BASENAME="$(basename "$OUTPUT_DIR")"
  if [[ "$INCLUDE_OUTPUT_IN_SOURCE" -eq 0 ]]; then
    EXCLUDE_DIRS+=("$OUTPUT_BASENAME")
  fi
fi

# Build grep exclude args once (array)
mapfile -t GREP_EXCLUDES < <(build_grep_excludes)

if [[ "$LIST_EXCLUDES" -eq 1 ]]; then
  say "Source scan excludes:"
  printf "  - %s\n" "${EXCLUDE_DIRS[@]}"
  say ""
  say "Output scan:"
  if [[ "$SKIP_OUTPUT" -eq 1 ]]; then
    say "  - skipped (--skip-output)"
  else
    say "  - enabled (scans detected output dir only)"
  fi
  exit 0
fi

# ============================================
# OPTIONAL: Safe cleanup of build artifacts
# ============================================
safe_cleanup() {
  if [[ -z "${REAL_SCAN_DIR:-}" || "$REAL_SCAN_DIR" == "/" || "$REAL_SCAN_DIR" == "$HOME" ]]; then
    sayc "${RED}✗ Refusing cleanup: unsafe SCAN_DIR='${REAL_SCAN_DIR}'${NC}"
    say "  Tip: run from your repo root and pass '.'"
    return 1
  fi

  # Auto-clean gate: only if output exists and looks dev-tainted
  if [[ "$AUTO_CLEAN" -eq 1 ]]; then
    if [[ -z "$OUTPUT_DIR" || ! -d "$OUTPUT_DIR" ]]; then
      sayc "${GREEN}✓ Auto-clean: no output dir detected; skipping cleanup${NC}"
      return 0
    fi
    if ! grep -RqiE "(localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)" "$OUTPUT_DIR" 2>/dev/null; then
      sayc "${GREEN}✓ Auto-clean: output does not appear dev-tainted; skipping cleanup${NC}"
      return 0
    fi
  fi

  sayc "${BLUE}ℹ️  Cleanup enabled. Removing build artifacts:${NC}"

  if [[ -n "$OUTPUT_DIR" && -d "$OUTPUT_DIR" ]]; then
    case "$OUTPUT_DIR" in
      "$SCAN_DIR"/*)
        say "  - $OUTPUT_DIR/"
        rm -rf -- "$OUTPUT_DIR" 2>/dev/null || true
        ;;
      *)
        sayc "${YELLOW}⚠️  Skipping output cleanup (path not under SCAN_DIR): $OUTPUT_DIR${NC}"
        ;;
    esac
  else
    say "  - (no output dir to remove)"
  fi

  case "$GENERATOR" in
    hugo)
      if [[ -d "$SCAN_DIR/resources/_gen" ]]; then
        say "  - $SCAN_DIR/resources/_gen/"
        rm -rf -- "$SCAN_DIR/resources/_gen" 2>/dev/null || true
      fi
      ;;
    jekyll)
      if [[ -d "$SCAN_DIR/.jekyll-cache" ]]; then
        say "  - $SCAN_DIR/.jekyll-cache/"
        rm -rf -- "$SCAN_DIR/.jekyll-cache" 2>/dev/null || true
      fi
      if [[ -d "$SCAN_DIR/.sass-cache" ]]; then
        say "  - $SCAN_DIR/.sass-cache/"
        rm -rf -- "$SCAN_DIR/.sass-cache" 2>/dev/null || true
      fi
      ;;
    next|astro|eleventy|static|unknown)
      if [[ -d "$SCAN_DIR/.next" ]]; then
        say "  - $SCAN_DIR/.next/"
        rm -rf -- "$SCAN_DIR/.next" 2>/dev/null || true
      fi
      ;;
  esac

  sayc "${GREEN}✓ Cleanup complete${NC}"
  return 0
}

maybe_rebuild() {
  sayc "${BLUE}ℹ️  Rebuild requested. Attempting generator-appropriate build...${NC}"
  case "$GENERATOR" in
    hugo)
      if command -v hugo >/dev/null 2>&1; then
        (cd "$SCAN_DIR" && hugo --gc --minify) || {
          sayc "${YELLOW}⚠️  Hugo rebuild failed (audit will continue).${NC}"
          return 0
        }
        sayc "${GREEN}✓ Hugo rebuild complete${NC}"
      else
        sayc "${YELLOW}⚠️  Rebuild requested, but 'hugo' not found. Skipping.${NC}"
      fi
      ;;
    jekyll)
      if command -v bundle >/dev/null 2>&1 && [[ -f "$SCAN_DIR/Gemfile" ]]; then
        (cd "$SCAN_DIR" && bundle exec jekyll build) || sayc "${YELLOW}⚠️  Jekyll rebuild failed (audit continues).${NC}"
      elif command -v jekyll >/dev/null 2>&1; then
        (cd "$SCAN_DIR" && jekyll build) || sayc "${YELLOW}⚠️  Jekyll rebuild failed (audit continues).${NC}"
      else
        sayc "${YELLOW}⚠️  Rebuild requested, but Jekyll not found. Skipping.${NC}"
      fi
      ;;
    next|astro|eleventy|static|unknown)
      if [[ -f "$SCAN_DIR/package.json" ]]; then
        if command -v npm >/dev/null 2>&1; then
          (cd "$SCAN_DIR" && npm run build) || sayc "${YELLOW}⚠️  npm run build failed (audit continues).${NC}"
        else
          sayc "${YELLOW}⚠️  npm not installed - skipping rebuild.${NC}"
        fi
      else
        sayc "${YELLOW}⚠️  No known rebuild method for this project. Skipping.${NC}"
      fi
      ;;
  esac

  detect_generator_and_output
  if [[ -n "$OUTPUT_DIR" ]]; then
    sayc "${GREEN}✓ Output dir now: $OUTPUT_DIR${NC}"
  else
    sayc "${YELLOW}⚠️  Still no output dir detected after rebuild.${NC}"
  fi
}

if [[ "$DO_CLEAN" -eq 1 || "$AUTO_CLEAN" -eq 1 ]]; then
  safe_cleanup || true
fi

if [[ "$DO_REBUILD" -eq 1 ]]; then
  maybe_rebuild || true
fi

say ""

# Issue counters
CRITICAL_ISSUES=0
HIGH_ISSUES=0
MEDIUM_ISSUES=0
LOW_ISSUES=0

# ============================================
# CHECK 1: Secrets in Config Files
# ============================================
hr
sayc "${PURPLE}CHECK 1: Secrets in Configuration Files${NC}"
hr
say ""

SECRETS_FOUND=0

declare -A SECRET_PATTERNS=(
  ["API Keys"]="['\"]?api[_-]?key['\"]?[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]"
  ["Access Tokens"]="['\"]?access[_-]?token['\"]?[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]"
  ["Secret Keys"]="['\"]?secret[_-]?key['\"]?[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]"
  ["Bearer Tokens"]="bearer[[:space:]]+[a-zA-Z0-9_-]{20,}"
  ["GitHub Tokens"]="gh[pousr]_[a-zA-Z0-9]{36,}"
  ["Slack Tokens"]="xox[baprs]-[a-zA-Z0-9-]+"
  ["AWS Keys"]="AKIA[0-9A-Z]{16}"
  ["Private Keys"]="-----BEGIN[[:space:]]+(RSA|EC|OPENSSH)?[[:space:]]*PRIVATE[[:space:]]+KEY-----"
  ["Passwords"]="['\"]?password['\"]?[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]"
  ["Database URLs"]="postgres://|mysql://|mongodb://"
  ["Netlify Auth Tokens"]="NETLIFY_AUTH_TOKEN"
  ["Netlify Site IDs"]="NETLIFY_SITE_ID"
)

CONFIG_FILES=()
# NOTE: keep this tight; these are "likely to contain secrets"
while IFS= read -r -d '' file; do
  CONFIG_FILES+=("$file")
done < <(find "$SCAN_DIR" -maxdepth 3 \
  \( -name "hugo.toml" -o -name "config.toml" -o -name "config.yaml" -o -name "config.yml" -o \
     -name "_config.yml" -o -name "_config.yaml" -o -name "netlify.toml" -o \
     -name "*.backup*" -o -name "*.bak" -o -name "*.old" -o -name ".env*" \) \
  -type f -print0 2>/dev/null)

for file in "${CONFIG_FILES[@]}"; do
  file_has_secrets=0

  for pattern_name in "${!SECRET_PATTERNS[@]}"; do
    pattern="${SECRET_PATTERNS[$pattern_name]}"
    if grep_qi_re "$pattern" "$file"; then
      if [[ $file_has_secrets -eq 0 ]]; then
        sayc "${RED}⚠️  Secrets found in: $file${NC}"
        file_has_secrets=1
        SECRETS_FOUND=$((SECRETS_FOUND + 1))
      fi
      sayc "  ${YELLOW}• $pattern_name${NC}"
    fi
  done
done

if [[ $SECRETS_FOUND -gt 0 ]]; then
  sayc "${RED}✗ Found secrets in $SECRETS_FOUND file(s) [CRITICAL]${NC}"
  CRITICAL_ISSUES=$((CRITICAL_ISSUES + SECRETS_FOUND))
else
  sayc "${GREEN}✓ No secrets detected in ${#CONFIG_FILES[@]} config file(s)${NC}"
fi
say ""

# ============================================
# CHECK 2: SSH/SSL Private Keys in ALL Files
# ============================================
hr
sayc "${PURPLE}CHECK 2: Private Keys in Any File [MUST-HAVE]${NC}"
hr
say ""

PRIVATE_KEYS_FOUND=0
PRIVATE_KEY_FILES=$(grep -R "-----BEGIN.*PRIVATE KEY-----" "$SCAN_DIR" \
  "${GREP_EXCLUDES[@]}" \
  2>/dev/null | cut -d: -f1 | sort -u || true)

if [[ -n "$PRIVATE_KEY_FILES" ]]; then
  PRIVATE_KEYS_FOUND=$(printf '%s\n' "$PRIVATE_KEY_FILES" | wc -l | tr -d ' ')
  sayc "${RED}✗ Found private keys in $PRIVATE_KEYS_FOUND file(s) [CRITICAL]${NC}"
  printf '%s\n' "$PRIVATE_KEY_FILES" | sed 's/^/  /'
  CRITICAL_ISSUES=$((CRITICAL_ISSUES + PRIVATE_KEYS_FOUND))
else
  sayc "${GREEN}✓ No private keys found${NC}"
fi
say ""

# ============================================
# CHECK 3: Backup Files in Repository
# ============================================
hr
sayc "${PURPLE}CHECK 3: Backup Files in Git Repository${NC}"
hr
say ""

BACKUP_FILES=()
if [[ -d "$SCAN_DIR/.git" ]]; then
  while IFS= read -r file; do
    [[ -n "$file" ]] && BACKUP_FILES+=("$file")
  done < <(cd "$SCAN_DIR" && git ls-files | grep -E '\.(backup|bak|old|orig|tmp)' 2>/dev/null || true)

  if [[ ${#BACKUP_FILES[@]} -gt 0 ]]; then
    sayc "${RED}✗ Found ${#BACKUP_FILES[@]} backup file(s) tracked by git [HIGH]${NC}"
    printf '  %s\n' "${BACKUP_FILES[@]}"
    say ""
    say "  Recommendation: git rm <file> && add to .gitignore"
    HIGH_ISSUES=$((HIGH_ISSUES + ${#BACKUP_FILES[@]}))
  else
    sayc "${GREEN}✓ No backup files tracked by git${NC}"
  fi
else
  sayc "${YELLOW}⚠️  Not a git repository - skipping${NC}"
fi
say ""

# ============================================
# CHECK 4: Sensitive Files in Output Directory
# ============================================
hr
sayc "${PURPLE}CHECK 4: Sensitive Files in Output Directory${NC}"
hr
say ""

if [[ "$SKIP_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Output scanning disabled (--skip-output)${NC}"
  say ""
else
  SENSITIVE_IN_OUTPUT=0
  if [[ -n "$OUTPUT_DIR" && -d "$OUTPUT_DIR" ]]; then
    if [[ -d "$OUTPUT_DIR/.git" ]]; then
      sayc "${RED}✗ CRITICAL: .git directory found in output dir!${NC}"
      say "  This exposes your entire git history to the web"
      CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
      SENSITIVE_IN_OUTPUT=$((SENSITIVE_IN_OUTPUT + 1))
    fi

    OUTPUT_CONFIGS=$(find "$OUTPUT_DIR" -type f \( \
      -name "*.toml" -o -name "*.env" -o -name "*.key" -o -name "*.pem" \
    \) 2>/dev/null | wc -l | tr -d ' ')

    if [[ ${OUTPUT_CONFIGS:-0} -gt 0 ]]; then
      sayc "${RED}✗ Found $OUTPUT_CONFIGS config/key file(s) in output dir [CRITICAL]${NC}"
      find "$OUTPUT_DIR" -type f \( -name "*.toml" -o -name "*.env" -o -name "*.key" -o -name "*.pem" \) 2>/dev/null | sed 's/^/  /'
      CRITICAL_ISSUES=$((CRITICAL_ISSUES + OUTPUT_CONFIGS))
    fi

    SOURCEMAPS=$(find "$OUTPUT_DIR" -name "*.map" 2>/dev/null | wc -l | tr -d ' ')
    if [[ ${SOURCEMAPS:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Found $SOURCEMAPS source map file(s) in output dir [MEDIUM]${NC}"
      say "  Source maps can expose original source code"
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    fi

    if [[ $SENSITIVE_IN_OUTPUT -eq 0 && ${OUTPUT_CONFIGS:-0} -eq 0 ]]; then
      sayc "${GREEN}✓ No critical files found in output dir${NC}"
    fi
  else
    sayc "${YELLOW}⚠️  No output directory found - skipping${NC}"
  fi
  say ""
fi

# ============================================
# CHECK 5: Internal URLs/IPs Exposed [MUST-HAVE]
# ============================================
hr
sayc "${PURPLE}CHECK 5: Internal URLs/IPs Exposed [MUST-HAVE]${NC}"
hr
say ""

if [[ "$SKIP_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Output scanning disabled (--skip-output)${NC}"
  say ""
else
  if [[ -n "$OUTPUT_DIR" && -d "$OUTPUT_DIR" ]]; then
    INTERNAL_URLS=$(grep -riE "(localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|\.local|\.internal|docker\.sock)" "$OUTPUT_DIR" 2>/dev/null | wc -l | tr -d ' ' || true)

    if [[ ${INTERNAL_URLS:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Found $INTERNAL_URLS reference(s) to internal URLs/IPs [MEDIUM]${NC}"
      grep -riE "(localhost|127\.0\.0\.1|192\.168\.|10\.0\.|\.local|\.internal)" "$OUTPUT_DIR" 2>/dev/null | head -5 | sed 's/^/  /' || true
      say "  ..."
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    else
      sayc "${GREEN}✓ No internal URLs/IPs found in output${NC}"
    fi
  else
    sayc "${YELLOW}⚠️  No output directory found - skipping${NC}"
  fi
  say ""
fi

# ============================================
# CHECK 6: Large Files That Shouldn't Be Committed [MUST-HAVE]
# ============================================
hr
sayc "${PURPLE}CHECK 6: Large Files (>10MB) [MUST-HAVE]${NC}"
hr
say ""

if [[ -d "$SCAN_DIR/.git" ]]; then
  # Respect excludes for large-file scanning too (avoid scanning node_modules/dist/public duplicates)
  LARGE_FILE_LIST=$(find "$SCAN_DIR" \
    \( $(find_prune_args) \) \
    -type f -size +10M -print 2>/dev/null || true)

  if [[ -n "$LARGE_FILE_LIST" ]]; then
    LARGE_FILES=$(printf '%s\n' "$LARGE_FILE_LIST" | wc -l | tr -d ' ')
    sayc "${YELLOW}⚠️  Found $LARGE_FILES file(s) larger than 10MB [MEDIUM]${NC}"
    printf '%s\n' "$LARGE_FILE_LIST" | while IFS= read -r file; do
      [[ -z "$file" ]] && continue
      size=$(du -h "$file" | cut -f1)
      say "  $file ($size)"
    done
    say "  Consider: Git LFS or CDN hosting for large assets"
    MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
  else
    sayc "${GREEN}✓ No files larger than 10MB${NC}"
  fi
else
  sayc "${YELLOW}⚠️  Not a git repository - skipping${NC}"
fi
say ""

# ============================================
# CHECK 7: Testing/Debug Files [MUST-HAVE]
# ============================================
hr
sayc "${PURPLE}CHECK 7: Testing/Debug Files [MUST-HAVE]${NC}"
hr
say ""

DEBUG_FILES=()
while IFS= read -r -d '' file; do
  DEBUG_FILES+=("$file")
done < <(find "$SCAN_DIR" \
  \( $(find_prune_args) \) \
  -type f \( \
    -name "test.html" -o \
    -name "debug.log" -o \
    -name "*.swp" -o \
    -name "*.swo" -o \
    -name ".DS_Store" -o \
    -name "Thumbs.db" -o \
    -name "phpinfo.php" -o \
    -name "*.sql" \
  \) -print0 2>/dev/null)

if [[ ${#DEBUG_FILES[@]} -gt 0 ]]; then
  sayc "${YELLOW}⚠️  Found ${#DEBUG_FILES[@]} debug/test file(s) [HIGH]${NC}"
  printf '  %s\n' "${DEBUG_FILES[@]}"
  HIGH_ISSUES=$((HIGH_ISSUES + ${#DEBUG_FILES[@]}))
else
  sayc "${GREEN}✓ No debug/test files found${NC}"
fi
say ""

# ============================================
# CHECK 8: Email/Phone Numbers Exposed [SHOULD-HAVE]
# ============================================
hr
sayc "${PURPLE}CHECK 8: Email/Phone Scraping Risk [SHOULD-HAVE]${NC}"
hr
say ""

if [[ "$SKIP_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Output scanning disabled (--skip-output)${NC}"
  say ""
else
  if [[ -n "$OUTPUT_DIR" && -d "$OUTPUT_DIR" ]]; then
    EMAIL_COUNT=$(grep -roE "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" "$OUTPUT_DIR" 2>/dev/null | wc -l | tr -d ' ' || true)
    PHONE_COUNT=$(grep -roE "\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}" "$OUTPUT_DIR" 2>/dev/null | wc -l | tr -d ' ' || true)

    if [[ ${EMAIL_COUNT:-0} -gt 0 || ${PHONE_COUNT:-0} -gt 0 ]]; then
      sayc "${BLUE}ℹ️  Found contact information in output HTML:${NC}"
      [[ ${EMAIL_COUNT:-0} -gt 0 ]] && say "  • $EMAIL_COUNT email address(es)"
      [[ ${PHONE_COUNT:-0} -gt 0 ]] && say "  • $PHONE_COUNT phone number(s)"
      say "  Note: May be intentional for contact pages"
      say "  Consider: Contact forms instead of raw emails"
      LOW_ISSUES=$((LOW_ISSUES + 1))
    else
      sayc "${GREEN}✓ No email/phone numbers in output HTML${NC}"
    fi
  else
    sayc "${YELLOW}⚠️  No output directory found - skipping${NC}"
  fi
  say ""
fi

# ============================================
# CHECK 9: Mixed Content (HTTP in HTTPS) [SHOULD-HAVE]
# ============================================
hr
sayc "${PURPLE}CHECK 9: Mixed Content (HTTP/HTTPS) [SHOULD-HAVE]${NC}"
hr
say ""

if [[ "$SKIP_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Output scanning disabled (--skip-output)${NC}"
  say ""
else
  HTTP_REFS=0
  PROTO_RELATIVE=0
  if [[ -n "$OUTPUT_DIR" && -d "$OUTPUT_DIR" ]]; then
    HTTP_REFS=$(grep -roE "http://[^\"' ]+" "$OUTPUT_DIR" 2>/dev/null | grep -v "http://www.w3.org" | wc -l | tr -d ' ' || true)
    PROTO_RELATIVE=$(grep -roE "//[^\"' ]+\.(js|css|png|jpg|gif|svg|webp|woff|woff2)" "$OUTPUT_DIR" 2>/dev/null | wc -l | tr -d ' ' || true)

    if [[ ${HTTP_REFS:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Found $HTTP_REFS HTTP (non-HTTPS) reference(s) [MEDIUM]${NC}"
      grep -roE "http://[^\"' ]+" "$OUTPUT_DIR" 2>/dev/null | grep -v "http://www.w3.org" | head -5 | sed 's/^/  /' || true
      say "  Note: Can cause mixed content warnings in browsers"
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    fi

    if [[ ${PROTO_RELATIVE:-0} -gt 0 ]]; then
      sayc "${BLUE}ℹ️  Found $PROTO_RELATIVE protocol-relative URL(s) (//example.com/...) [LOW]${NC}"
      say "  Note: Can cause issues with offline viewing or local testing"
      LOW_ISSUES=$((LOW_ISSUES + 1))
    fi

    if [[ ${HTTP_REFS:-0} -eq 0 && ${PROTO_RELATIVE:-0} -eq 0 ]]; then
      sayc "${GREEN}✓ No HTTP references or protocol-relative URLs found${NC}"
    fi
  else
    sayc "${YELLOW}⚠️  No output directory found - skipping${NC}"
  fi
  say ""
fi

# ============================================
# CHECK 10: Default/Demo Content [SHOULD-HAVE]
# ============================================
hr
sayc "${PURPLE}CHECK 10: Default/Demo Content [SHOULD-HAVE]${NC}"
hr
say ""

if [[ "$SKIP_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Output scanning disabled (--skip-output)${NC}"
  say ""
else
  if [[ -n "$OUTPUT_DIR" && -d "$OUTPUT_DIR" ]]; then
    DEMO_REFS=$(grep -riE "(example\.com|Your Name Here|Lorem ipsum|Demo Site|Test Site)" "$OUTPUT_DIR" 2>/dev/null | wc -l | tr -d ' ' || true)

    if [[ ${DEMO_REFS:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Found $DEMO_REFS potential demo/placeholder content reference(s) [LOW]${NC}"
      grep -riE "(example\.com|Your Name Here|Lorem ipsum)" "$OUTPUT_DIR" 2>/dev/null | head -3 | sed 's/^/  /' || true
      LOW_ISSUES=$((LOW_ISSUES + 1))
    else
      sayc "${GREEN}✓ No obvious demo content found${NC}"
    fi
  else
    sayc "${YELLOW}⚠️  No output directory found - skipping${NC}"
  fi
  say ""
fi

# ============================================
# CHECK 11: .gitignore Coverage
# ============================================
hr
sayc "${PURPLE}CHECK 11: .gitignore Configuration${NC}"
hr
say ""

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output). Skipping.${NC}"
  say ""
else
  if [[ -f "$SCAN_DIR/.gitignore" ]]; then
    REQUIRED_PATTERNS=(
      "*.backup*"
      "*.bak"
      ".env"
      "*.key"
      "*.pem"
      "*.log"
      ".DS_Store"
    )

    MISSING_PATTERNS=()
    for pattern in "${REQUIRED_PATTERNS[@]}"; do
      if ! grep -q "$pattern" "$SCAN_DIR/.gitignore" 2>/dev/null; then
        MISSING_PATTERNS+=("$pattern")
      fi
    done

    if [[ ${#MISSING_PATTERNS[@]} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Missing recommended patterns in .gitignore: [LOW]${NC}"
      printf '  %s\n' "${MISSING_PATTERNS[@]}"
      LOW_ISSUES=$((LOW_ISSUES + 1))
    else
      sayc "${GREEN}✓ .gitignore has good coverage${NC}"
    fi
  else
    sayc "${RED}✗ No .gitignore file found [MEDIUM]${NC}"
    MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
  fi
  say ""
fi

# ============================================
# CHECK 12: Hardcoded Credentials in Code
# ============================================
hr
sayc "${PURPLE}CHECK 12: Hardcoded Credentials in Code${NC}"
hr
say ""

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output). Skipping.${NC}"
  say ""
else
  HARDCODED_FOUND=0
  CODE_DIRS=("content" "layouts" "themes" "static" "src" "app" "lib" "pages")

  for dir in "${CODE_DIRS[@]}"; do
    if [[ -d "$SCAN_DIR/$dir" ]]; then
      MATCHES=$(grep -riE "(password|api_key|secret|token)[[:space:]]*=[[:space:]]*['\"][^'\"]{8,}" "$SCAN_DIR/$dir" \
        "${GREP_EXCLUDES[@]}" \
        2>/dev/null | wc -l | tr -d ' ' || true)
      if [[ ${MATCHES:-0} -gt 0 ]]; then
        sayc "${YELLOW}⚠️  Found $MATCHES potential hardcoded credential(s) in $dir/ [HIGH]${NC}"
        grep -riE "(password|api_key|secret|token)[[:space:]]*=[[:space:]]*['\"][^'\"]{8,}" "$SCAN_DIR/$dir" \
          "${GREP_EXCLUDES[@]}" \
          2>/dev/null | head -3 | sed 's/^/  /' || true
        HARDCODED_FOUND=$((HARDCODED_FOUND + MATCHES))
      fi
    fi
  done

  if [[ $HARDCODED_FOUND -gt 0 ]]; then
    HIGH_ISSUES=$((HIGH_ISSUES + 1))
  else
    sayc "${GREEN}✓ No obvious hardcoded credentials in code${NC}"
  fi
  say ""
fi

# ============================================
# CHECK 13: HTML Comments with Sensitive Info
# ============================================
hr
sayc "${PURPLE}CHECK 13: Sensitive HTML Comments${NC}"
hr
say ""

if [[ "$SKIP_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Output scanning disabled (--skip-output)${NC}"
  say ""
else
  if [[ -n "$OUTPUT_DIR" && -d "$OUTPUT_DIR" ]]; then
    DEV_COMMENTS=$(grep -riE "<!--.*\b(TODO|DEBUG|FIXME|XXX|HACK|password|token|key)\b" "$OUTPUT_DIR" 2>/dev/null | wc -l | tr -d ' ' || true)

    if [[ ${DEV_COMMENTS:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Found $DEV_COMMENTS development comment(s) in output HTML [LOW]${NC}"
      grep -riE "<!--.*\b(TODO|DEBUG|FIXME)\b" "$OUTPUT_DIR" 2>/dev/null | head -3 | sed 's/^/  /' || true
      LOW_ISSUES=$((LOW_ISSUES + 1))
    else
      sayc "${GREEN}✓ No sensitive comments in output HTML${NC}"
    fi
  else
    sayc "${YELLOW}⚠️  No output directory found - skipping${NC}"
  fi
  say ""
fi

# ============================================
# CHECK 14: Security Headers in netlify.toml [NICE-TO-HAVE]
# ============================================
hr
sayc "${PURPLE}CHECK 14: Security Headers [NICE-TO-HAVE]${NC}"
hr
say ""

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output). Skipping.${NC}"
  say ""
else
  if [[ -f "$SCAN_DIR/netlify.toml" ]]; then
    SECURITY_HEADERS=(
      "X-Frame-Options"
      "X-Content-Type-Options"
      "Content-Security-Policy"
      "Strict-Transport-Security"
      "Permissions-Policy"
      "Referrer-Policy"
    )

    MISSING_HEADERS=()
    for header in "${SECURITY_HEADERS[@]}"; do
      if ! grep -qi "$header" "$SCAN_DIR/netlify.toml"; then
        MISSING_HEADERS+=("$header")
      fi
    done

    if [[ ${#MISSING_HEADERS[@]} -gt 0 ]]; then
      sayc "${BLUE}ℹ️  Missing recommended security headers in netlify.toml:${NC}"
      printf '  %s\n' "${MISSING_HEADERS[@]}"
      LOW_ISSUES=$((LOW_ISSUES + 1))
    else
      sayc "${GREEN}✓ netlify.toml has good security headers${NC}"
    fi
  else
    sayc "${BLUE}ℹ️  No netlify.toml found (deployment headers not configured)${NC}"
  fi
  say ""
fi

# ============================================
# CHECK 15: Metadata/Identity Leaks [NICE-TO-HAVE]
# ============================================
hr
sayc "${PURPLE}CHECK 15: Metadata/Identity Leaks [NICE-TO-HAVE]${NC}"
hr
say ""

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output). Skipping.${NC}"
  say ""
else
  IDENTITY_REFS=0
  if [[ -d "$SCAN_DIR/.git" ]]; then
    GIT_USER=$(cd "$SCAN_DIR" && git config user.name 2>/dev/null || echo "")
    GIT_EMAIL=$(cd "$SCAN_DIR" && git config user.email 2>/dev/null || echo "")

    if [[ -n "$GIT_USER" && "$GIT_USER" != "oob" ]]; then
      sayc "${BLUE}ℹ️  Git config has name: $GIT_USER${NC}"
      say "  Consider: Setting per-repo git config for anonymity"
      IDENTITY_REFS=$((IDENTITY_REFS + 1))
    fi

    DRAFT_MARKERS=$(grep -ri "\[TODO\]|\[DRAFT\]|\[PLACEHOLDER\]" "$SCAN_DIR/content" \
      "${GREP_EXCLUDES[@]}" \
      2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${DRAFT_MARKERS:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Found $DRAFT_MARKERS draft marker(s) in content/ [LOW]${NC}"
      say "  Make sure these aren't published"
      LOW_ISSUES=$((LOW_ISSUES + 1))
    fi
  fi

  if [[ $IDENTITY_REFS -eq 0 ]]; then
    sayc "${GREEN}✓ No obvious identity leaks detected${NC}"
  fi
  say ""
fi

# ============================================
# CHECK 16: Dependency Vulnerabilities [NICE-TO-HAVE]
# ============================================
hr
sayc "${PURPLE}CHECK 16: Dependency Vulnerabilities [NICE-TO-HAVE]${NC}"
hr
say ""

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output). Skipping.${NC}"
  say ""
else
  if [[ -f "$SCAN_DIR/package.json" ]]; then
    sayc "${BLUE}ℹ️  package.json found - checking for npm audit${NC}"
    if command -v npm >/dev/null 2>&1; then
      say "  Running npm audit (this may take a moment)..."
      AUDIT_OUTPUT=$((cd "$SCAN_DIR" && npm audit --json 2>/dev/null) || echo '{"error": true}')

      if printf '%s' "$AUDIT_OUTPUT" | grep -q '"error"'; then
        sayc "${YELLOW}  ⚠️  npm audit had issues (dependencies may not be installed)${NC}"
      else
        VULNS=$(printf '%s' "$AUDIT_OUTPUT" | grep -o '"total":[0-9]*' | head -1 | cut -d: -f2 || echo "0")
        if [[ ${VULNS:-0} -gt 0 ]]; then
          sayc "${YELLOW}  ⚠️  Found $VULNS vulnerability/vulnerabilities${NC}"
          say "  Run 'npm audit' for details"
          MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
        else
          sayc "${GREEN}  ✓ No vulnerabilities found${NC}"
        fi
      fi
    else
      sayc "${BLUE}  ℹ️  npm not installed - skipping audit${NC}"
    fi
  else
    sayc "${GREEN}✓ No package.json found (no npm dependencies)${NC}"
  fi
  say ""
fi

# ============================================
# CHECK 17: Git History Analysis
# ============================================
hr
sayc "${PURPLE}CHECK 17: Git History Analysis${NC}"
hr
say ""

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output). Skipping.${NC}"
  say ""
else
  if [[ -d "$SCAN_DIR/.git" ]]; then
    SENSITIVE_HISTORY=$(cd "$SCAN_DIR" && git log --all --oneline --name-only | grep -E '\.(env|key|pem|backup|bak)$' | wc -l | tr -d ' ' || true)

    if [[ ${SENSITIVE_HISTORY:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Found $SENSITIVE_HISTORY reference(s) to sensitive files in git history [MEDIUM]${NC}"
      say "  These files may still exist in git history even if deleted"
      say "  Consider: git filter-repo or BFG to clean history"
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    else
      sayc "${GREEN}✓ No obvious sensitive files in git history${NC}"
    fi
  else
    sayc "${YELLOW}⚠️  Not a git repository - skipping${NC}"
  fi
  say ""
fi

# ============================================
# CHECK 18: Hugo Module/Theme Supply Chain
# ============================================
hr
sayc "${PURPLE}CHECK 18: Hugo Module/Theme Supply Chain${NC}"
hr
say ""

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output). Skipping.${NC}"
  say ""
else
  if [[ -f "$SCAN_DIR/go.mod" ]]; then
    sayc "${BLUE}ℹ️  Hugo modules detected - checking dependencies${NC}"

    NON_OFFICIAL=$(grep -E "github\.com/[^/]+/[^/]+" "$SCAN_DIR/go.mod" | grep -v "gohugoio" | wc -l | tr -d ' ' || true)

    if [[ ${NON_OFFICIAL:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Found $NON_OFFICIAL third-party Hugo module(s) [MEDIUM]${NC}"
      say "  Third-party modules can execute code during build"
      grep -E "github\.com/[^/]+/[^/]+" "$SCAN_DIR/go.mod" | grep -v "gohugoio" | sed 's/^/  /'
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    else
      sayc "${GREEN}✓ Only official Hugo modules in use${NC}"
    fi
  fi

  if [[ -d "$SCAN_DIR/themes" ]]; then
    THEME_COUNT=$(find "$SCAN_DIR/themes" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
    if [[ ${THEME_COUNT:-0} -gt 0 ]]; then
      sayc "${BLUE}ℹ️  Found $THEME_COUNT theme(s) - checking origins and licenses${NC}"

      for theme_dir in "$SCAN_DIR/themes"/*; do
        [[ -d "$theme_dir" ]] || continue
        theme_name=$(basename "$theme_dir")

        if [[ -d "$theme_dir/.git" ]]; then
          REMOTE=$(cd "$theme_dir" && git remote get-url origin 2>/dev/null || echo "unknown")
          sayc "  ${GREEN}✓${NC} $theme_name: git submodule ($REMOTE)"

          if [[ -f "$theme_dir/LICENSE" || -f "$theme_dir/LICENSE.md" ]]; then
            LICENSE_FILE="$theme_dir/LICENSE"
            [[ -f "$theme_dir/LICENSE.md" ]] && LICENSE_FILE="$theme_dir/LICENSE.md"

            LICENSE_TYPE=$(grep -iE "(MIT|Apache|GPL|BSD)" "$LICENSE_FILE" 2>/dev/null | head -1 || echo "Unknown")

            if printf '%s' "$LICENSE_TYPE" | grep -qi "GPL"; then
              sayc "    ${YELLOW}⚠️${NC}  GPL license detected - may require content disclosure"
              LOW_ISSUES=$((LOW_ISSUES + 1))
            else
              sayc "    ${GREEN}✓${NC}  License: $LICENSE_TYPE"
            fi
          else
            sayc "    ${YELLOW}⚠️${NC}  No LICENSE file found"
          fi
        else
          sayc "  ${YELLOW}⚠️${NC} $theme_name: copied theme (no version tracking)"
          MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
        fi
      done
    fi
  else
    sayc "${GREEN}✓ No themes directory found${NC}"
  fi
  say ""
fi

# ============================================
# CHECK 19: Custom Shortcode Security
# ============================================
hr
sayc "${PURPLE}CHECK 19: Custom Shortcode Injection Risks${NC}"
hr
say ""

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output). Skipping.${NC}"
  say ""
else
  if [[ -d "$SCAN_DIR/layouts/shortcodes" ]]; then
    SHORTCODE_COUNT=$(find "$SCAN_DIR/layouts/shortcodes" -name "*.html" 2>/dev/null | wc -l | tr -d ' ')

    if [[ ${SHORTCODE_COUNT:-0} -gt 0 ]]; then
      sayc "${BLUE}ℹ️  Found $SHORTCODE_COUNT custom shortcode(s)${NC}"

      UNSAFE_SHORTCODES=$(grep -rE "(\.Get|\.Inner|readFile|getJSON|getCSV)" "$SCAN_DIR/layouts/shortcodes" --include="*.html" \
        "${GREP_EXCLUDES[@]}" \
        2>/dev/null | wc -l | tr -d ' ' || true)

      if [[ ${UNSAFE_SHORTCODES:-0} -gt 0 ]]; then
        sayc "${YELLOW}⚠️  Found $UNSAFE_SHORTCODES shortcode(s) using dynamic content [MEDIUM]${NC}"
        say "  Shortcodes using .Get/.Inner can inject untrusted content"
        grep -rE "(\.Get|\.Inner)" "$SCAN_DIR/layouts/shortcodes" --include="*.html" -l \
          "${GREP_EXCLUDES[@]}" \
          2>/dev/null | sed 's/^/  /' || true
        MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
      else
        sayc "${GREEN}✓ Shortcodes appear safe${NC}"
      fi
    fi
  else
    sayc "${GREEN}✓ No custom shortcodes found${NC}"
  fi
  say ""
fi

# ============================================
# CHECK 20: Netlify Build Logs/Env Leaks
# ============================================
hr
sayc "${PURPLE}CHECK 20: Netlify Build Environment Exposure${NC}"
hr
say ""

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output). Skipping.${NC}"
  say ""
else
  if [[ -f "$SCAN_DIR/netlify.toml" ]]; then
    ECHO_COMMANDS=$(grep -E "(echo|print|console\.log).*\\\$" "$SCAN_DIR/netlify.toml" 2>/dev/null | wc -l | tr -d ' ' || true)

    if [[ ${ECHO_COMMANDS:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Found $ECHO_COMMANDS command(s) that might leak env vars in build logs [HIGH]${NC}"
      grep -E "(echo|print|console\.log).*\\\$" "$SCAN_DIR/netlify.toml" 2>/dev/null | sed 's/^/  /' || true
      HIGH_ISSUES=$((HIGH_ISSUES + 1))
    else
      sayc "${GREEN}✓ No obvious env var leaks in build commands${NC}"
    fi

    if ! grep -qi 'publish[[:space:]]*=[[:space:]]*"public"' "$SCAN_DIR/netlify.toml"; then
      sayc "${YELLOW}⚠️  Publish directory not explicitly set - verify draft handling [LOW]${NC}"
      LOW_ISSUES=$((LOW_ISSUES + 1))
    fi
  else
    sayc "${GREEN}✓ No netlify.toml found${NC}"
  fi
  say ""
fi

# ============================================
# CHECK 21: RSS/Sitemap Unintended Disclosure
# ============================================
hr
sayc "${PURPLE}CHECK 21: RSS/Sitemap Information Leaks${NC}"
hr
say ""

if [[ "$SKIP_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Output scanning disabled (--skip-output)${NC}"
  say ""
else
  RSS_SITEMAP_ISSUES=0
  if [[ -n "$OUTPUT_DIR" && -d "$OUTPUT_DIR" ]]; then
    if [[ -f "$OUTPUT_DIR/index.xml" ]]; then
      DRAFT_IN_RSS=$(grep -i "draft.*true" "$OUTPUT_DIR/index.xml" 2>/dev/null | wc -l | tr -d ' ' || true)

      if [[ ${DRAFT_IN_RSS:-0} -gt 0 ]]; then
        sayc "${RED}✗ RSS feed includes $DRAFT_IN_RSS draft post(s) [HIGH]${NC}"
        say "  Drafts should not be in RSS - check generator config"
        HIGH_ISSUES=$((HIGH_ISSUES + 1))
        RSS_SITEMAP_ISSUES=$((RSS_SITEMAP_ISSUES + 1))
      fi
    fi

    if [[ -f "$OUTPUT_DIR/sitemap.xml" ]]; then
      SENSITIVE_PATHS=$(grep -E "(admin|private|internal|test|staging)" "$OUTPUT_DIR/sitemap.xml" 2>/dev/null | wc -l | tr -d ' ' || true)

      if [[ ${SENSITIVE_PATHS:-0} -gt 0 ]]; then
        sayc "${YELLOW}⚠️  Sitemap includes $SENSITIVE_PATHS potentially sensitive path(s) [MEDIUM]${NC}"
        grep -E "(admin|private|internal)" "$OUTPUT_DIR/sitemap.xml" 2>/dev/null | head -3 | sed 's/^/  /' || true
        MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
        RSS_SITEMAP_ISSUES=$((RSS_SITEMAP_ISSUES + 1))
      fi
    fi

    if [[ $RSS_SITEMAP_ISSUES -eq 0 ]]; then
      sayc "${GREEN}✓ RSS and sitemap look clean${NC}"
    fi
  else
    sayc "${YELLOW}⚠️  No output directory found - skipping${NC}"
  fi
  say ""
fi

# ============================================
# CHECK 22: Front Matter Secrets [NEW]
# ============================================
hr
sayc "${PURPLE}CHECK 22: Front Matter Secrets [NEW]${NC}"
hr
say ""

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output). Skipping.${NC}"
  say ""
else
  FRONTMATTER_ISSUES=0
  if [[ -d "$SCAN_DIR/content" ]]; then
    FRONTMATTER_SECRETS=$(grep -rE "^(api_key|apikey|token|secret|password):[[:space:]]*['\"]?[a-zA-Z0-9_-]{20,}" "$SCAN_DIR/content" --include="*.md" \
      "${GREP_EXCLUDES[@]}" \
      2>/dev/null | wc -l | tr -d ' ' || true)

    if [[ ${FRONTMATTER_SECRETS:-0} -gt 0 ]]; then
      sayc "${RED}✗ Found $FRONTMATTER_SECRETS potential secret(s) in content front matter [CRITICAL]${NC}"
      say "  Common in tutorials: \"add your API key to front matter\""
      grep -rE "^(api_key|apikey|token|secret):" "$SCAN_DIR/content" --include="*.md" \
        "${GREP_EXCLUDES[@]}" \
        2>/dev/null | head -5 | sed 's/^/  /' || true
      CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
      FRONTMATTER_ISSUES=$((FRONTMATTER_ISSUES + 1))
    fi

    FRONTMATTER_CONFIGS=$(grep -rE "^(baseURL|publishDir|contentDir):" "$SCAN_DIR/content" --include="*.md" \
      "${GREP_EXCLUDES[@]}" \
      2>/dev/null | wc -l | tr -d ' ' || true)

    if [[ ${FRONTMATTER_CONFIGS:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Found $FRONTMATTER_CONFIGS config parameter(s) in front matter [MEDIUM]${NC}"
      say "  These should be in generator config, not content files"
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
      FRONTMATTER_ISSUES=$((FRONTMATTER_ISSUES + 1))
    fi

    if [[ $FRONTMATTER_ISSUES -eq 0 ]]; then
      sayc "${GREEN}✓ No secrets or misconfigurations in content front matter${NC}"
    fi
  else
    sayc "${YELLOW}⚠️  No content/ directory found - skipping${NC}"
  fi
  say ""
fi

# ============================================
# CHECK 23: Git Hooks Pre-Commit Validation [NEW]
# ============================================
hr
sayc "${PURPLE}CHECK 23: Git Hooks Pre-Commit Validation [NEW]${NC}"
hr
say ""

if [[ "$ONLY_OUTPUT" -eq 1 ]]; then
  sayc "${BLUE}ℹ️  Source scanning disabled (--only-output). Skipping.${NC}"
  say ""
else
  if [[ -d "$SCAN_DIR/.git/hooks" ]]; then
    HAS_PRECOMMIT=0

    if [[ -f "$SCAN_DIR/.git/hooks/pre-commit" ]]; then
      HAS_PRECOMMIT=1
      sayc "${GREEN}✓ Pre-commit hook exists${NC}"

      if grep -qiE "(secret|credential|key|token|trufflehog|gitleaks)" "$SCAN_DIR/.git/hooks/pre-commit" 2>/dev/null; then
        sayc "${GREEN}✓ Pre-commit hook includes secret scanning${NC}"
      else
        sayc "${YELLOW}⚠️  Pre-commit hook exists but doesn't validate secrets [LOW]${NC}"
        say "  Consider: Adding TruffleHog or gitleaks to pre-commit"
        LOW_ISSUES=$((LOW_ISSUES + 1))
      fi
    fi

    if [[ -f "$SCAN_DIR/.pre-commit-config.yaml" ]]; then
      sayc "${GREEN}✓ Pre-commit framework config found${NC}"

      if grep -qiE "(trufflehog|gitleaks|detect-secrets|secret)" "$SCAN_DIR/.pre-commit-config.yaml" 2>/dev/null; then
        sayc "${GREEN}✓ Pre-commit config includes security checks${NC}"
      else
        sayc "${YELLOW}⚠️  Pre-commit config doesn't include secret scanning [LOW]${NC}"
        LOW_ISSUES=$((LOW_ISSUES + 1))
      fi
    fi

    if [[ $HAS_PRECOMMIT -eq 0 && ! -f "$SCAN_DIR/.pre-commit-config.yaml" ]]; then
      sayc "${YELLOW}⚠️  No pre-commit hooks configured [MEDIUM]${NC}"
      say "  Secrets could be committed without validation"
      say "  Consider: Installing pre-commit framework with secret detection"
      MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    fi
  else
    sayc "${YELLOW}⚠️  No .git/hooks directory found${NC}"
  fi
  say ""
fi

# ============================================
# CHECK 24: Output directory committed (Hugo/Netlify sanity)
# ============================================
hr
sayc "${PURPLE}CHECK 24: Output Directory Committed (Build Artifact Hygiene)${NC}"
hr
say ""

if [[ -d "$SCAN_DIR/.git" && -n "$OUTPUT_DIR" && -d "$OUTPUT_DIR" ]]; then
  if [[ "$INCLUDE_OUTPUT_IN_SOURCE" -eq 0 ]]; then
    # Only warn if output appears tracked by git
    OUTPUT_TRACKED_COUNT=$(cd "$SCAN_DIR" && git ls-files "$OUTPUT_BASENAME" 2>/dev/null | wc -l | tr -d ' ' || true)
    if [[ ${OUTPUT_TRACKED_COUNT:-0} -gt 0 ]]; then
      sayc "${YELLOW}⚠️  Output directory '$OUTPUT_BASENAME/' appears tracked by git (${OUTPUT_TRACKED_COUNT} file(s)) [HIGH]${NC}"
      say "  For Netlify builds, you typically do NOT commit build output."
      say "  Recommendation: add '$OUTPUT_BASENAME/' to .gitignore and remove tracked files:"
      say "    git rm -r --cached \"$OUTPUT_BASENAME\""
      say "    echo \"$OUTPUT_BASENAME/\" >> .gitignore"
      HIGH_ISSUES=$((HIGH_ISSUES + 1))
    else
      sayc "${GREEN}✓ Output dir '$OUTPUT_BASENAME/' is not tracked by git${NC}"
    fi
  else
    sayc "${BLUE}ℹ️  Output dir inclusion requested (--include-output-in-source). No hygiene warning.${NC}"
  fi
else
  sayc "${BLUE}ℹ️  Not applicable (no git repo or no output dir detected)${NC}"
fi
say ""

# ============================================
# FINAL SUMMARY
# ============================================
say "=============================================="
say "🔒 FINAL SECURITY SUMMARY 🔒"
say "=============================================="
say ""
say "Directory scanned: $SCAN_DIR"
say "Generator detected: $GENERATOR"
[[ -n "$OUTPUT_DIR" ]] && say "Output dir detected: $OUTPUT_DIR"
say ""

TOTAL_ISSUES=$((CRITICAL_ISSUES + HIGH_ISSUES + MEDIUM_ISSUES + LOW_ISSUES))

if [[ $CRITICAL_ISSUES -gt 0 ]]; then
  sayc "${RED}🚨 CRITICAL: $CRITICAL_ISSUES issue(s) - FIX IMMEDIATELY${NC}"
fi

if [[ $HIGH_ISSUES -gt 0 ]]; then
  sayc "${RED}⚠️  HIGH:     $HIGH_ISSUES issue(s) - Fix soon${NC}"
fi

if [[ $MEDIUM_ISSUES -gt 0 ]]; then
  sayc "${YELLOW}⚠️  MEDIUM:   $MEDIUM_ISSUES issue(s) - Address when possible${NC}"
fi

if [[ $LOW_ISSUES -gt 0 ]]; then
  sayc "${BLUE}ℹ️  LOW:      $LOW_ISSUES issue(s) - Nice to fix${NC}"
fi

say ""

if [[ $TOTAL_ISSUES -eq 0 ]]; then
  sayc "${GREEN}✅ EXCELLENT! No security issues found!${NC}"
  say ""
  say "Your repository follows security best practices:"
  say "  ✓ No secrets or credentials exposed"
  say "  ✓ No backup files committed"
  say "  ✓ Clean output directory"
  say "  ✓ Good .gitignore coverage"
  say "  ✓ No obvious vulnerabilities (where checks apply)"
  say ""
  sayc "${PURPLE}🦛 Published by Oob Skulden™ — stay vigilant, stay submerged.${NC}"
else
  sayc "${YELLOW}⚠️  Found $TOTAL_ISSUES total security issue(s)${NC}"
  say ""
  say "Priority actions (in order):"
  [[ $CRITICAL_ISSUES -gt 0 ]] && say "  1. 🚨 Fix CRITICAL issues immediately"
  [[ $HIGH_ISSUES -gt 0 ]] && say "  2. ⚠️  Address HIGH priority issues"
  [[ $MEDIUM_ISSUES -gt 0 ]] && say "  3. ⚠️  Review MEDIUM priority issues"
  [[ $LOW_ISSUES -gt 0 ]] && say "  4. ℹ️  Consider LOW priority improvements"
fi

say ""
say "=============================================="
sayc "${PURPLE}Generated by: 🦛 Published by Oob Skulden™ 🦛${NC}"
sayc "${PURPLE}\"The threats you don't see coming\"${NC}"
say "=============================================="
say ""

# Exit code reflects severity
if [[ $CRITICAL_ISSUES -gt 0 ]]; then
  exit 3
elif [[ $HIGH_ISSUES -gt 0 ]]; then
  exit 2
elif [[ $MEDIUM_ISSUES -gt 0 ]]; then
  exit 1
else
  exit 0
fi