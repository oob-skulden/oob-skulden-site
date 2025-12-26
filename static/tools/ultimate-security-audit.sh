#!/bin/bash
# ultimate-security-audit.sh
# Complete security audit for Hugo sites and web projects
# Oob Skulden: The threats you don't see coming
# Includes: secrets, backups, exposure risks, code quality, metadata leaks, supply chain
# Enhanced with: shortcodes, Netlify leaks, RSS/sitemap disclosure, front matter secrets

set -euo pipefail
VERSION="0.35.0"

if [[ "${1:-}" == "--version" ]]; then
  echo "ultimate-security-audit version $VERSION"
  exit 0
fi

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Oob Skulden ASCII Art
echo ""
echo -e "${PURPLE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${PURPLE}║                    🦛 OOB SKULDEN 🦛                           ║${NC}"
echo -e "${PURPLE}║              Ultimate Hugo Security Audit v$VERSION              ║${NC}"
echo -e "${PURPLE}║          \"The threats you don't see coming\" - 95% underwater  ║${NC}"
echo -e "${PURPLE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if a directory was provided
SCAN_DIR="${1:-.}"

if [[ ! -d "$SCAN_DIR" ]]; then
    echo -e "${RED}Error: Directory '$SCAN_DIR' not found${NC}"
    exit 1
fi

echo "Scanning directory: $SCAN_DIR"
echo ""

# ============================================
# OPTIONAL: Safe cleanup of Hugo build artifacts
# ============================================
# Usage:
#   CLEAN=1 ./ultimate-security-audit.sh .
#   CLEAN=1 REBUILD=1 ./ultimate-security-audit.sh .
#   Or: ./ultimate-security-audit.sh --clean --rebuild .
#
# Safety rules:
# - Never run cleanup unless explicitly enabled.
# - Only deletes "$SCAN_DIR/public" and "$SCAN_DIR/resources/_gen"
# - Refuses to run if SCAN_DIR resolves to /, $HOME, or empty.
# - Supports "auto" mode: clean only if public/ looks dev-tainted.

AUTO_CLEAN=0
DO_CLEAN=0
DO_REBUILD=0

# Simple flag parsing (does not break existing positional SCAN_DIR usage)
ARGS=()
for arg in "$@"; do
  case "$arg" in
    --clean) DO_CLEAN=1 ;;
    --rebuild) DO_REBUILD=1 ;;
    --auto-clean) AUTO_CLEAN=1 ;;   # clean only if dev-tainted
    *) ARGS+=("$arg") ;;
  esac
done

# Re-assign SCAN_DIR from remaining args (preserves old behavior)
SCAN_DIR="${ARGS[0]:-$SCAN_DIR}"

# Env var support (lets you use CLEAN=1 REBUILD=1 style)
[[ "${CLEAN:-0}" == "1" ]] && DO_CLEAN=1
[[ "${REBUILD:-0}" == "1" ]] && DO_REBUILD=1
[[ "${AUTO_CLEAN_ENV:-0}" == "1" ]] && AUTO_CLEAN=1

# Resolve SCAN_DIR safely (best effort; readlink may not exist everywhere)
REAL_SCAN_DIR="$SCAN_DIR"
if command -v readlink >/dev/null 2>&1; then
  REAL_SCAN_DIR="$(readlink -f "$SCAN_DIR" 2>/dev/null || echo "$SCAN_DIR")"
fi

safe_cleanup() {
  # Refuse obviously dangerous targets
  if [[ -z "${REAL_SCAN_DIR:-}" || "$REAL_SCAN_DIR" == "/" || "$REAL_SCAN_DIR" == "$HOME" ]]; then
    echo -e "${RED}✗ Refusing cleanup: unsafe SCAN_DIR='$REAL_SCAN_DIR'${NC}"
    echo "  Tip: run from your repo root and pass '.'"
    return 1
  fi

  # Only allow cleanup if this looks like a Hugo project root
  if [[ ! -f "$SCAN_DIR/hugo.toml" && ! -f "$SCAN_DIR/config.toml" && ! -f "$SCAN_DIR/config.yaml" && ! -d "$SCAN_DIR/content" ]]; then
    echo -e "${YELLOW}⚠️  Cleanup skipped: '$SCAN_DIR' does not look like a Hugo site root${NC}"
    return 0
  fi

  # Auto-clean gate (only clean if public/ looks dev-tainted)
  if [[ "$AUTO_CLEAN" -eq 1 && -d "$SCAN_DIR/public" ]]; then
    if ! grep -RqiE "(localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)" "$SCAN_DIR/public" 2>/dev/null; then
      echo -e "${GREEN}✓ Auto-clean: public/ does not appear dev-tainted; skipping cleanup${NC}"
      return 0
    fi
  fi

  echo -e "${BLUE}ℹ️  Cleanup enabled. Removing Hugo build artifacts:${NC}"
  [[ -d "$SCAN_DIR/public" ]] && echo "  - $SCAN_DIR/public/"
  [[ -d "$SCAN_DIR/resources/_gen" ]] && echo "  - $SCAN_DIR/resources/_gen/"
  [[ ! -d "$SCAN_DIR/public" && ! -d "$SCAN_DIR/resources/_gen" ]] && echo "  - (nothing to remove)"

  # Defensive deletes (targeted paths only)
  rm -rf -- "$SCAN_DIR/public" "$SCAN_DIR/resources/_gen" 2>/dev/null || true
  echo -e "${GREEN}✓ Cleanup complete${NC}"
  return 0
}

maybe_rebuild() {
  # Only rebuild if hugo exists and a config exists
  if ! command -v hugo >/dev/null 2>&1; then
    echo -e "${YELLOW}⚠️  Rebuild requested, but 'hugo' not found in PATH. Skipping rebuild.${NC}"
    return 0
  fi
  if [[ ! -f "$SCAN_DIR/hugo.toml" && ! -f "$SCAN_DIR/config.toml" && ! -f "$SCAN_DIR/config.yaml" ]]; then
    echo -e "${YELLOW}⚠️  Rebuild requested, but no Hugo config found. Skipping rebuild.${NC}"
    return 0
  fi

  echo -e "${BLUE}ℹ️  Rebuilding Hugo output (clean build)...${NC}"
  (cd "$SCAN_DIR" && hugo --gc --minify) || {
    echo -e "${YELLOW}⚠️  Hugo rebuild failed (audit will continue).${NC}"
    return 0
  }
  echo -e "${GREEN}✓ Hugo rebuild complete${NC}"
}

if [[ "$DO_CLEAN" -eq 1 || "$AUTO_CLEAN" -eq 1 ]]; then
  safe_cleanup || true
fi

if [[ "$DO_REBUILD" -eq 1 ]]; then
  maybe_rebuild || true
fi

echo ""

CRITICAL_ISSUES=0
HIGH_ISSUES=0
MEDIUM_ISSUES=0
LOW_ISSUES=0

# ============================================
# CHECK 1: Secrets in Config Files
# ============================================
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${PURPLE}CHECK 1: Secrets in Configuration Files${NC}"
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

SECRETS_FOUND=0

# Secret patterns (enhanced with Netlify tokens)
declare -A SECRET_PATTERNS=(
    ["API Keys"]="['\"]?api[_-]?key['\"]?\s*=\s*['\"][^'\"]+['\"]"
    ["Access Tokens"]="['\"]?access[_-]?token['\"]?\s*=\s*['\"][^'\"]+['\"]"
    ["Secret Keys"]="['\"]?secret[_-]?key['\"]?\s*=\s*['\"][^'\"]+['\"]"
    ["Bearer Tokens"]="bearer\s+[a-zA-Z0-9_-]{20,}"
    ["GitHub Tokens"]="gh[pousr]_[a-zA-Z0-9]{36,}"
    ["Slack Tokens"]="xox[baprs]-[a-zA-Z0-9-]+"
    ["AWS Keys"]="AKIA[0-9A-Z]{16}"
    ["Private Keys"]="-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"
    ["Passwords"]="['\"]?password['\"]?\s*=\s*['\"][^'\"]+['\"]"
    ["Database URLs"]="postgres://|mysql://|mongodb://"
    ["Netlify Auth Tokens"]="NETLIFY_AUTH_TOKEN"
    ["Netlify Site IDs"]="NETLIFY_SITE_ID"
)

# Find config files
CONFIG_FILES=()
while IFS= read -r -d '' file; do
    CONFIG_FILES+=("$file")
done < <(find "$SCAN_DIR" -maxdepth 2 \( \
    -name "hugo.toml" -o \
    -name "config.toml" -o \
    -name "*.backup*" -o \
    -name "*.bak" -o \
    -name "*.old" -o \
    -name ".env*" \
    \) -type f -print0 2>/dev/null)

for file in "${CONFIG_FILES[@]}"; do
    file_has_secrets=0
    
    for pattern_name in "${!SECRET_PATTERNS[@]}"; do
        pattern="${SECRET_PATTERNS[$pattern_name]}"
        if grep -qiP "$pattern" "$file" 2>/dev/null; then
            if [[ $file_has_secrets -eq 0 ]]; then
                echo -e "${RED}⚠️  Secrets found in: $file${NC}"
                file_has_secrets=1
                SECRETS_FOUND=$((SECRETS_FOUND + 1))
            fi
            echo -e "  ${YELLOW}• $pattern_name${NC}"
        fi
    done
done

if [[ $SECRETS_FOUND -gt 0 ]]; then
    echo -e "${RED}✗ Found secrets in $SECRETS_FOUND file(s) [CRITICAL]${NC}"
    CRITICAL_ISSUES=$((CRITICAL_ISSUES + SECRETS_FOUND))
else
    echo -e "${GREEN}✓ No secrets detected in ${#CONFIG_FILES[@]} config file(s)${NC}"
fi
echo ""

# ============================================
# CHECK 2: SSH/SSL Private Keys in ALL Files
# ============================================
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${PURPLE}CHECK 2: Private Keys in Any File [MUST-HAVE]${NC}"
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

PRIVATE_KEYS_FOUND=0
# Search all files (excluding .git and node_modules)
PRIVATE_KEY_FILES=$(grep -r "-----BEGIN.*PRIVATE KEY-----" "$SCAN_DIR" \
    --exclude-dir=".git" \
    --exclude-dir="node_modules" \
    --exclude-dir=".next" \
    2>/dev/null | cut -d: -f1 | sort -u || true)

if [[ -n "$PRIVATE_KEY_FILES" ]]; then
    PRIVATE_KEYS_FOUND=$(echo "$PRIVATE_KEY_FILES" | wc -l)
    echo -e "${RED}✗ Found private keys in $PRIVATE_KEYS_FOUND file(s) [CRITICAL]${NC}"
    echo "$PRIVATE_KEY_FILES" | sed 's/^/  /'
    CRITICAL_ISSUES=$((CRITICAL_ISSUES + PRIVATE_KEYS_FOUND))
else
    echo -e "${GREEN}✓ No private keys found${NC}"
fi
echo ""

# ============================================
# CHECK 3: Backup Files in Repository
# ============================================
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${PURPLE}CHECK 3: Backup Files in Git Repository${NC}"
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

BACKUP_FILES=()
if [[ -d "$SCAN_DIR/.git" ]]; then
    while IFS= read -r file; do
        BACKUP_FILES+=("$file")
    done < <(cd "$SCAN_DIR" && git ls-files | grep -E '\.(backup|bak|old|orig|tmp)' 2>/dev/null || true)
    
    if [[ ${#BACKUP_FILES[@]} -gt 0 ]]; then
        echo -e "${RED}✗ Found ${#BACKUP_FILES[@]} backup file(s) tracked by git [HIGH]${NC}"
        printf '  %s\n' "${BACKUP_FILES[@]}"
        echo ""
        echo "  Recommendation: git rm <file> && add to .gitignore"
        HIGH_ISSUES=$((HIGH_ISSUES + ${#BACKUP_FILES[@]}))
    else
        echo -e "${GREEN}✓ No backup files tracked by git${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  Not a git repository - skipping${NC}"
fi
echo ""

# ============================================
# CHECK 4: Sensitive Files in Public Directory
# ============================================
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${PURPLE}CHECK 4: Sensitive Files in Public Output${NC}"
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

SENSITIVE_IN_PUBLIC=0
if [[ -d "$SCAN_DIR/public" ]]; then
    # CRITICAL: .git directory in public
    if [[ -d "$SCAN_DIR/public/.git" ]]; then
        echo -e "${RED}✗ CRITICAL: .git directory found in public/!${NC}"
        echo "  This exposes your entire git history to the web"
        CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
        SENSITIVE_IN_PUBLIC=$((SENSITIVE_IN_PUBLIC + 1))
    fi
    
    # Config files
    PUBLIC_CONFIGS=$(find "$SCAN_DIR/public" -type f \( \
        -name "*.toml" -o \
        -name "*.env" -o \
        -name "*.key" -o \
        -name "*.pem" \
        \) 2>/dev/null | wc -l)
    
    if [[ $PUBLIC_CONFIGS -gt 0 ]]; then
        echo -e "${RED}✗ Found $PUBLIC_CONFIGS config/key file(s) in public/ [CRITICAL]${NC}"
        find "$SCAN_DIR/public" -type f \( -name "*.toml" -o -name "*.env" -o -name "*.key" -o -name "*.pem" \) 2>/dev/null | sed 's/^/  /'
        CRITICAL_ISSUES=$((CRITICAL_ISSUES + PUBLIC_CONFIGS))
    fi
    
    # Source maps
    SOURCEMAPS=$(find "$SCAN_DIR/public" -name "*.map" 2>/dev/null | wc -l)
    if [[ $SOURCEMAPS -gt 0 ]]; then
        echo -e "${YELLOW}⚠️  Found $SOURCEMAPS source map file(s) in public/ [MEDIUM]${NC}"
        echo "  Source maps can expose original source code"
        MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    fi
    
    if [[ $SENSITIVE_IN_PUBLIC -eq 0 && $PUBLIC_CONFIGS -eq 0 ]]; then
        echo -e "${GREEN}✓ No critical files found in public/${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  No public/ directory found - skipping${NC}"
fi
echo ""

# ============================================
# CHECK 5: Internal URLs/IPs Exposed [MUST-HAVE]
# ============================================
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${PURPLE}CHECK 5: Internal URLs/IPs Exposed [MUST-HAVE]${NC}"
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

INTERNAL_REFS=0
if [[ -d "$SCAN_DIR/public" ]]; then
    # Look for localhost, 127.0.0.1, private IPs, Docker/K8s patterns
    INTERNAL_URLS=$(grep -riE "(localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|\.local|\.internal|docker\.sock)" "$SCAN_DIR/public" 2>/dev/null | wc -l || true)
    
    if [[ $INTERNAL_URLS -gt 0 ]]; then
        echo -e "${YELLOW}⚠️  Found $INTERNAL_URLS reference(s) to internal URLs/IPs [MEDIUM]${NC}"
        grep -riE "(localhost|127\.0\.0\.1|192\.168\.|10\.0\.|\.local|\.internal)" "$SCAN_DIR/public" 2>/dev/null | head -5 | sed 's/^/  /' || true
        echo "  ..."
        MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    else
        echo -e "${GREEN}✓ No internal URLs/IPs found in public output${NC}"
    fi
fi
echo ""

# ============================================
# CHECK 6: Large Files That Shouldn't Be Committed [MUST-HAVE]
# ============================================
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${PURPLE}CHECK 6: Large Files (>10MB) [MUST-HAVE]${NC}"
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

LARGE_FILES=0
if [[ -d "$SCAN_DIR/.git" ]]; then
    # Find files >10MB (10485760 bytes)
    LARGE_FILE_LIST=$(find "$SCAN_DIR" -type f -size +10M \
        ! -path "*/.git/*" \
        ! -path "*/node_modules/*" \
        2>/dev/null || true)
    
    if [[ -n "$LARGE_FILE_LIST" ]]; then
        LARGE_FILES=$(echo "$LARGE_FILE_LIST" | wc -l)
        echo -e "${YELLOW}⚠️  Found $LARGE_FILES file(s) larger than 10MB [MEDIUM]${NC}"
        echo "$LARGE_FILE_LIST" | while read -r file; do
            size=$(du -h "$file" | cut -f1)
            echo "  $file ($size)"
        done
        echo "  Consider: Git LFS or CDN hosting for large assets"
        MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    else
        echo -e "${GREEN}✓ No files larger than 10MB${NC}"
    fi
fi
echo ""

# ============================================
# CHECK 7: Testing/Debug Files [MUST-HAVE]
# ============================================
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${PURPLE}CHECK 7: Testing/Debug Files [MUST-HAVE]${NC}"
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

DEBUG_FILES=()
# Common debug/test file patterns
while IFS= read -r -d '' file; do
    DEBUG_FILES+=("$file")
done < <(find "$SCAN_DIR" -type f \( \
    -name "test.html" -o \
    -name "debug.log" -o \
    -name "*.swp" -o \
    -name "*.swo" -o \
    -name ".DS_Store" -o \
    -name "Thumbs.db" -o \
    -name "phpinfo.php" \
    \) ! -path "*/.git/*" -print0 2>/dev/null)

# Check for .sql files (database dumps)
while IFS= read -r -d '' file; do
    DEBUG_FILES+=("$file")
done < <(find "$SCAN_DIR" -type f -name "*.sql" ! -path "*/.git/*" -print0 2>/dev/null)

if [[ ${#DEBUG_FILES[@]} -gt 0 ]]; then
    echo -e "${YELLOW}⚠️  Found ${#DEBUG_FILES[@]} debug/test file(s) [HIGH]${NC}"
    printf '  %s\n' "${DEBUG_FILES[@]}"
    HIGH_ISSUES=$((HIGH_ISSUES + ${#DEBUG_FILES[@]}))
else
    echo -e "${GREEN}✓ No debug/test files found${NC}"
fi
echo ""

# ============================================
# CHECK 8: Email/Phone Numbers Exposed [SHOULD-HAVE]
# ============================================
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${PURPLE}CHECK 8: Email/Phone Scraping Risk [SHOULD-HAVE]${NC}"
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

if [[ -d "$SCAN_DIR/public" ]]; then
    # Count emails (may be intentional for contact pages)
    EMAIL_COUNT=$(grep -roE "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" "$SCAN_DIR/public" 2>/dev/null | wc -l || true)
    
    # Count phone numbers (US format)
    PHONE_COUNT=$(grep -roE "\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}" "$SCAN_DIR/public" 2>/dev/null | wc -l || true)
    
    if [[ $EMAIL_COUNT -gt 0 || $PHONE_COUNT -gt 0 ]]; then
        echo -e "${BLUE}ℹ️  Found contact information in public HTML:${NC}"
        [[ $EMAIL_COUNT -gt 0 ]] && echo "  • $EMAIL_COUNT email address(es)"
        [[ $PHONE_COUNT -gt 0 ]] && echo "  • $PHONE_COUNT phone number(s)"
        echo "  Note: May be intentional for contact pages"
        echo "  Consider: Contact forms instead of raw emails"
        LOW_ISSUES=$((LOW_ISSUES + 1))
    else
        echo -e "${GREEN}✓ No email/phone numbers in public HTML${NC}"
    fi
fi
echo ""

# ============================================
# CHECK 9: Mixed Content (HTTP in HTTPS) [SHOULD-HAVE]
# ============================================
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${PURPLE}CHECK 9: Mixed Content (HTTP/HTTPS) [SHOULD-HAVE]${NC}"
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

HTTP_REFS=0
PROTO_RELATIVE=0
if [[ -d "$SCAN_DIR/public" ]]; then
    # Look for http:// (not https://) in HTML
    HTTP_REFS=$(grep -roE 'http://[^"'\'' ]+' "$SCAN_DIR/public" 2>/dev/null | grep -v "http://www.w3.org" | wc -l || true)
    
    # Check for protocol-relative URLs which can cause issues
    PROTO_RELATIVE=$(grep -roE '//[^"'\'' ]+\.(js|css|png|jpg|gif|svg|webp|woff|woff2)' "$SCAN_DIR/public" 2>/dev/null | wc -l || true)
    
    if [[ $HTTP_REFS -gt 0 ]]; then
        echo -e "${YELLOW}⚠️  Found $HTTP_REFS HTTP (non-HTTPS) reference(s) [MEDIUM]${NC}"
        grep -roE 'http://[^"'\'' ]+' "$SCAN_DIR/public" 2>/dev/null | grep -v "http://www.w3.org" | head -5 | sed 's/^/  /' || true
        echo "  Note: Can cause mixed content warnings in browsers"
        MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    fi
    
    if [[ $PROTO_RELATIVE -gt 0 ]]; then
        echo -e "${BLUE}ℹ️  Found $PROTO_RELATIVE protocol-relative URL(s) (//example.com/...) [LOW]${NC}"
        echo "  Note: Can cause issues with offline viewing or local testing"
        LOW_ISSUES=$((LOW_ISSUES + 1))
    fi
    
    if [[ $HTTP_REFS -eq 0 && $PROTO_RELATIVE -eq 0 ]]; then
        echo -e "${GREEN}✓ No HTTP references or protocol-relative URLs found${NC}"
    fi
fi
echo ""

# ============================================
# CHECK 10: Default/Demo Content [SHOULD-HAVE]
# ============================================
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${PURPLE}CHECK 10: Default/Demo Content [SHOULD-HAVE]${NC}"
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

DEMO_CONTENT=0
if [[ -d "$SCAN_DIR/public" ]]; then
    # Look for common placeholder text
    DEMO_REFS=$(grep -riE "(example\.com|Your Name Here|Lorem ipsum|Demo Site|Test Site)" "$SCAN_DIR/public" 2>/dev/null | wc -l || true)
    
    if [[ $DEMO_REFS -gt 0 ]]; then
        echo -e "${YELLOW}⚠️  Found $DEMO_REFS potential demo/placeholder content reference(s) [LOW]${NC}"
        grep -riE "(example\.com|Your Name Here|Lorem ipsum)" "$SCAN_DIR/public" 2>/dev/null | head -3 | sed 's/^/  /' || true
        LOW_ISSUES=$((LOW_ISSUES + 1))
    else
        echo -e "${GREEN}✓ No obvious demo content found${NC}"
    fi
fi
echo ""

# ============================================
# CHECK 11: .gitignore Coverage
# ============================================
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${PURPLE}CHECK 11: .gitignore Configuration${NC}"
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

GITIGNORE_ISSUES=0
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
        echo -e "${YELLOW}⚠️  Missing recommended patterns in .gitignore: [LOW]${NC}"
        printf '  %s\n' "${MISSING_PATTERNS[@]}"
        LOW_ISSUES=$((LOW_ISSUES + 1))
    else
        echo -e "${GREEN}✓ .gitignore has good coverage${NC}"
    fi
else
    echo -e "${RED}✗ No .gitignore file found [MEDIUM]${NC}"
    MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
fi
echo ""

# ============================================
# CHECK 12: Hardcoded Credentials in Code
# ============================================
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${PURPLE}CHECK 12: Hardcoded Credentials in Code${NC}"
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

HARDCODED_FOUND=0
CODE_DIRS=("content" "layouts" "themes" "static")

for dir in "${CODE_DIRS[@]}"; do
    if [[ -d "$SCAN_DIR/$dir" ]]; then
        MATCHES=$(grep -riE "(password|api_key|secret|token)\s*=\s*['\"][^'\"]{8,}" "$SCAN_DIR/$dir" 2>/dev/null | wc -l || true)
        if [[ $MATCHES -gt 0 ]]; then
            echo -e "${YELLOW}⚠️  Found $MATCHES potential hardcoded credential(s) in $dir/ [HIGH]${NC}"
            grep -riE "(password|api_key|secret|token)\s*=\s*['\"][^'\"]{8,}" "$SCAN_DIR/$dir" 2>/dev/null | head -3 | sed 's/^/  /' || true
            HARDCODED_FOUND=$((HARDCODED_FOUND + MATCHES))
        fi
    fi
done

if [[ $HARDCODED_FOUND -gt 0 ]]; then
    HIGH_ISSUES=$((HIGH_ISSUES + 1))
else
    echo -e "${GREEN}✓ No obvious hardcoded credentials in code${NC}"
fi
echo ""

# ============================================
# CHECK 13: HTML Comments with Sensitive Info
# ============================================
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${PURPLE}CHECK 13: Sensitive HTML Comments${NC}"
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

if [[ -d "$SCAN_DIR/public" ]]; then
    DEV_COMMENTS=$(grep -riE "<!--.*\b(TODO|DEBUG|FIXME|XXX|HACK|password|token|key)\b" "$SCAN_DIR/public" 2>/dev/null | wc -l || true)
    
    if [[ $DEV_COMMENTS -gt 0 ]]; then
        echo -e "${YELLOW}⚠️  Found $DEV_COMMENTS development comment(s) in public HTML [LOW]${NC}"
        grep -riE "<!--.*\b(TODO|DEBUG|FIXME)\b" "$SCAN_DIR/public" 2>/dev/null | head -3 | sed 's/^/  /' || true
        LOW_ISSUES=$((LOW_ISSUES + 1))
    else
        echo -e "${GREEN}✓ No sensitive comments in public HTML${NC}"
    fi
fi
echo ""

# ============================================
# CHECK 14: Security Headers in netlify.toml [NICE-TO-HAVE]
# ============================================
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${PURPLE}CHECK 14: Security Headers [NICE-TO-HAVE]${NC}"
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

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
        echo -e "${BLUE}ℹ️  Missing recommended security headers in netlify.toml:${NC}"
        printf '  %s\n' "${MISSING_HEADERS[@]}"
        LOW_ISSUES=$((LOW_ISSUES + 1))
    else
        echo -e "${GREEN}✓ netlify.toml has good security headers${NC}"
    fi
else
    echo -e "${BLUE}ℹ️  No netlify.toml found (deployment headers not configured)${NC}"
fi
echo ""

# ============================================
# CHECK 15: Metadata/Identity Leaks [NICE-TO-HAVE]
# ============================================
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${PURPLE}CHECK 15: Metadata/Identity Leaks [NICE-TO-HAVE]${NC}"
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Look for common personal identifiers
IDENTITY_REFS=0
if [[ -d "$SCAN_DIR/.git" ]]; then
    # Check git config for real names/emails
    GIT_USER=$(cd "$SCAN_DIR" && git config user.name 2>/dev/null || echo "")
    GIT_EMAIL=$(cd "$SCAN_DIR" && git config user.email 2>/dev/null || echo "")
    
    if [[ -n "$GIT_USER" && "$GIT_USER" != "oob" ]]; then
        echo -e "${BLUE}ℹ️  Git config has name: $GIT_USER${NC}"
        echo "  Consider: Setting per-repo git config for anonymity"
        IDENTITY_REFS=$((IDENTITY_REFS + 1))
    fi
    
    # Search for TODO/DRAFT markers in content
    DRAFT_MARKERS=$(grep -ri "\[TODO\]|\[DRAFT\]|\[PLACEHOLDER\]" "$SCAN_DIR/content" 2>/dev/null | wc -l || true)
    if [[ $DRAFT_MARKERS -gt 0 ]]; then
        echo -e "${YELLOW}⚠️  Found $DRAFT_MARKERS draft marker(s) in content/ [LOW]${NC}"
        echo "  Make sure these aren't published"
        LOW_ISSUES=$((LOW_ISSUES + 1))
    fi
fi

if [[ $IDENTITY_REFS -eq 0 ]]; then
    echo -e "${GREEN}✓ No obvious identity leaks detected${NC}"
fi
echo ""

# ============================================
# CHECK 16: Dependency Vulnerabilities [NICE-TO-HAVE]
# ============================================
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${PURPLE}CHECK 16: Dependency Vulnerabilities [NICE-TO-HAVE]${NC}"
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

if [[ -f "$SCAN_DIR/package.json" ]]; then
    echo -e "${BLUE}ℹ️  package.json found - checking for npm audit${NC}"
    if command -v npm &> /dev/null; then
        echo "  Running npm audit (this may take a moment)..."
        cd "$SCAN_DIR"
        AUDIT_OUTPUT=$(npm audit --json 2>/dev/null || echo '{"error": true}')
        
        if echo "$AUDIT_OUTPUT" | grep -q '"error"'; then
            echo -e "${YELLOW}  ⚠️  npm audit had issues (dependencies may not be installed)${NC}"
        else
            VULNS=$(echo "$AUDIT_OUTPUT" | grep -o '"total":[0-9]*' | head -1 | cut -d: -f2 || echo "0")
            if [[ $VULNS -gt 0 ]]; then
                echo -e "${YELLOW}  ⚠️  Found $VULNS vulnerability/vulnerabilities${NC}"
                echo "  Run 'npm audit' for details"
                MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
            else
                echo -e "${GREEN}  ✓ No vulnerabilities found${NC}"
            fi
        fi
    else
        echo -e "${BLUE}  ℹ️  npm not installed - skipping audit${NC}"
    fi
else
    echo -e "${GREEN}✓ No package.json found (no npm dependencies)${NC}"
fi
echo ""

# ============================================
# CHECK 17: Git History Analysis
# ============================================
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${PURPLE}CHECK 17: Git History Analysis${NC}"
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

if [[ -d "$SCAN_DIR/.git" ]]; then
    SENSITIVE_HISTORY=$(cd "$SCAN_DIR" && git log --all --oneline --name-only | grep -E '\.(env|key|pem|backup|bak)$' | wc -l || true)
    
    if [[ $SENSITIVE_HISTORY -gt 0 ]]; then
        echo -e "${YELLOW}⚠️  Found $SENSITIVE_HISTORY reference(s) to sensitive files in git history [MEDIUM]${NC}"
        echo "  These files may still exist in git history even if deleted"
        echo "  Consider: git filter-repo or BFG to clean history"
        MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    else
        echo -e "${GREEN}✓ No obvious sensitive files in git history${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  Not a git repository - skipping${NC}"
fi
echo ""

# ============================================
# CHECK 18: Hugo Module/Theme Supply Chain
# ============================================
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${PURPLE}CHECK 18: Hugo Module/Theme Supply Chain${NC}"
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Check go.mod for Hugo modules (often overlooked attack surface)
if [[ -f "$SCAN_DIR/go.mod" ]]; then
    echo -e "${BLUE}ℹ️  Hugo modules detected - checking dependencies${NC}"
    
    # Look for modules pointing to non-official sources
    NON_OFFICIAL=$(grep -E "github\.com/[^/]+/[^/]+" "$SCAN_DIR/go.mod" | grep -v "gohugoio" | wc -l || true)
    
    if [[ $NON_OFFICIAL -gt 0 ]]; then
        echo -e "${YELLOW}⚠️  Found $NON_OFFICIAL third-party Hugo module(s) [MEDIUM]${NC}"
        echo "  Third-party modules can execute code during build"
        grep -E "github\.com/[^/]+/[^/]+" "$SCAN_DIR/go.mod" | grep -v "gohugoio" | sed 's/^/  /'
        MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    else
        echo -e "${GREEN}✓ Only official Hugo modules in use${NC}"
    fi
fi

# Check themes/ directory for git submodules (supply chain risk)
if [[ -d "$SCAN_DIR/themes" ]]; then
    THEME_COUNT=$(find "$SCAN_DIR/themes" -mindepth 1 -maxdepth 1 -type d | wc -l)
    if [[ $THEME_COUNT -gt 0 ]]; then
        echo -e "${BLUE}ℹ️  Found $THEME_COUNT theme(s) - checking origins and licenses${NC}"
        
        # Check if themes are git submodules (better) or copied (worse)
        for theme_dir in "$SCAN_DIR/themes"/*; do
            theme_name=$(basename "$theme_dir")
            
            if [[ -d "$theme_dir/.git" ]]; then
                REMOTE=$(cd "$theme_dir" && git remote get-url origin 2>/dev/null || echo "unknown")
                echo -e "  ${GREEN}✓${NC} $theme_name: git submodule ($REMOTE)"
                
                # Check for license
                if [[ -f "$theme_dir/LICENSE" ]] || [[ -f "$theme_dir/LICENSE.md" ]]; then
                    LICENSE_FILE="$theme_dir/LICENSE"
                    [[ -f "$theme_dir/LICENSE.md" ]] && LICENSE_FILE="$theme_dir/LICENSE.md"
                    
                    LICENSE_TYPE=$(grep -iE "(MIT|Apache|GPL|BSD)" "$LICENSE_FILE" 2>/dev/null | head -1 || echo "Unknown")
                    
                    if echo "$LICENSE_TYPE" | grep -qi "GPL"; then
                        echo -e "    ${YELLOW}⚠️${NC}  GPL license detected - may require content disclosure"
                        LOW_ISSUES=$((LOW_ISSUES + 1))
                    else
                        echo -e "    ${GREEN}✓${NC}  License: $LICENSE_TYPE"
                    fi
                else
                    echo -e "    ${YELLOW}⚠️${NC}  No LICENSE file found"
                fi
            else
                echo -e "  ${YELLOW}⚠️${NC} $theme_name: copied theme (no version tracking)"
                MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
            fi
        done
    fi
else
    echo -e "${GREEN}✓ No themes directory found${NC}"
fi
echo ""

# ============================================
# CHECK 19: Custom Shortcode Security
# ============================================
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${PURPLE}CHECK 19: Custom Shortcode Injection Risks${NC}"
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

if [[ -d "$SCAN_DIR/layouts/shortcodes" ]]; then
    SHORTCODE_COUNT=$(find "$SCAN_DIR/layouts/shortcodes" -name "*.html" | wc -l)
    
    if [[ $SHORTCODE_COUNT -gt 0 ]]; then
        echo -e "${BLUE}ℹ️  Found $SHORTCODE_COUNT custom shortcode(s)${NC}"
        
        # Check for unsafe functions in shortcodes
        UNSAFE_SHORTCODES=$(grep -rE "(\.Get|\.Inner|readFile|getJSON|getCSV)" "$SCAN_DIR/layouts/shortcodes" --include="*.html" 2>/dev/null | wc -l || true)
        
        if [[ $UNSAFE_SHORTCODES -gt 0 ]]; then
            echo -e "${YELLOW}⚠️  Found $UNSAFE_SHORTCODES shortcode(s) using dynamic content [MEDIUM]${NC}"
            echo "  Shortcodes using .Get/.Inner can inject untrusted content"
            grep -rE "(\.Get|\.Inner)" "$SCAN_DIR/layouts/shortcodes" --include="*.html" -l 2>/dev/null | sed 's/^/  /' || true
            MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
        else
            echo -e "${GREEN}✓ Shortcodes appear safe${NC}"
        fi
    fi
else
    echo -e "${GREEN}✓ No custom shortcodes found${NC}"
fi
echo ""

# ============================================
# CHECK 20: Netlify Build Logs/Env Leaks
# ============================================
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${PURPLE}CHECK 20: Netlify Build Environment Exposure${NC}"
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Check if build logs might leak secrets
if [[ -f "$SCAN_DIR/netlify.toml" ]]; then
    # Look for build commands that echo/print env vars
    ECHO_COMMANDS=$(grep -E "(echo|print|console\.log).*\\\$" "$SCAN_DIR/netlify.toml" 2>/dev/null | wc -l || true)
    
    if [[ $ECHO_COMMANDS -gt 0 ]]; then
        echo -e "${YELLOW}⚠️  Found $ECHO_COMMANDS command(s) that might leak env vars in build logs [HIGH]${NC}"
        grep -E "(echo|print|console\.log).*\\\$" "$SCAN_DIR/netlify.toml" 2>/dev/null | sed 's/^/  /' || true
        HIGH_ISSUES=$((HIGH_ISSUES + 1))
    else
        echo -e "${GREEN}✓ No obvious env var leaks in build commands${NC}"
    fi
    
    # Check for deploy previews exposing drafts
    if ! grep -qi "publish = \"public\"" "$SCAN_DIR/netlify.toml"; then
        echo -e "${YELLOW}⚠️  Publish directory not explicitly set - verify draft handling [LOW]${NC}"
        LOW_ISSUES=$((LOW_ISSUES + 1))
    fi
else
    echo -e "${GREEN}✓ No netlify.toml found${NC}"
fi
echo ""

# ============================================
# CHECK 21: RSS/Sitemap Unintended Disclosure
# ============================================
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${PURPLE}CHECK 21: RSS/Sitemap Information Leaks${NC}"
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

RSS_SITEMAP_ISSUES=0

if [[ -d "$SCAN_DIR/public" ]]; then
    # Check if RSS includes draft/future posts
    if [[ -f "$SCAN_DIR/public/index.xml" ]]; then
        DRAFT_IN_RSS=$(grep -i "draft.*true" "$SCAN_DIR/public/index.xml" 2>/dev/null | wc -l || true)
        
        if [[ $DRAFT_IN_RSS -gt 0 ]]; then
            echo -e "${RED}✗ RSS feed includes $DRAFT_IN_RSS draft post(s) [HIGH]${NC}"
            echo "  Drafts should not be in RSS - check Hugo config"
            HIGH_ISSUES=$((HIGH_ISSUES + 1))
            RSS_SITEMAP_ISSUES=$((RSS_SITEMAP_ISSUES + 1))
        fi
    fi
    
    # Check sitemap for sensitive paths
    if [[ -f "$SCAN_DIR/public/sitemap.xml" ]]; then
        SENSITIVE_PATHS=$(grep -E "(admin|private|internal|test|staging)" "$SCAN_DIR/public/sitemap.xml" 2>/dev/null | wc -l || true)
        
        if [[ $SENSITIVE_PATHS -gt 0 ]]; then
            echo -e "${YELLOW}⚠️  Sitemap includes $SENSITIVE_PATHS potentially sensitive path(s) [MEDIUM]${NC}"
            grep -E "(admin|private|internal)" "$SCAN_DIR/public/sitemap.xml" 2>/dev/null | head -3 | sed 's/^/  /' || true
            MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
            RSS_SITEMAP_ISSUES=$((RSS_SITEMAP_ISSUES + 1))
        fi
    fi
    
    if [[ $RSS_SITEMAP_ISSUES -eq 0 ]]; then
        echo -e "${GREEN}✓ RSS and sitemap look clean${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  No public/ directory found - skipping${NC}"
fi
echo ""

# ============================================
# CHECK 22: Front Matter Secrets [NEW]
# ============================================
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${PURPLE}CHECK 22: Front Matter Secrets [NEW]${NC}"
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

FRONTMATTER_ISSUES=0
if [[ -d "$SCAN_DIR/content" ]]; then
    # Check for API keys/tokens in markdown front matter
    FRONTMATTER_SECRETS=$(grep -rE "^(api_key|apikey|token|secret|password):\s*['\"]?[a-zA-Z0-9_-]{20,}" "$SCAN_DIR/content" --include="*.md" 2>/dev/null | wc -l || true)
    
    if [[ $FRONTMATTER_SECRETS -gt 0 ]]; then
        echo -e "${RED}✗ Found $FRONTMATTER_SECRETS potential secret(s) in content front matter [CRITICAL]${NC}"
        echo "  Common in Hugo tutorials: \"add your API key to front matter\""
        grep -rE "^(api_key|apikey|token|secret):" "$SCAN_DIR/content" --include="*.md" 2>/dev/null | head -5 | sed 's/^/  /' || true
        CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
        FRONTMATTER_ISSUES=$((FRONTMATTER_ISSUES + 1))
    fi
    
    # Check for common config mistakes in front matter
    FRONTMATTER_CONFIGS=$(grep -rE "^(baseURL|publishDir|contentDir):" "$SCAN_DIR/content" --include="*.md" 2>/dev/null | wc -l || true)
    
    if [[ $FRONTMATTER_CONFIGS -gt 0 ]]; then
        echo -e "${YELLOW}⚠️  Found $FRONTMATTER_CONFIGS Hugo config parameter(s) in front matter [MEDIUM]${NC}"
        echo "  These should be in hugo.toml, not content files"
        MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
        FRONTMATTER_ISSUES=$((FRONTMATTER_ISSUES + 1))
    fi
    
    if [[ $FRONTMATTER_ISSUES -eq 0 ]]; then
        echo -e "${GREEN}✓ No secrets or misconfigurations in content front matter${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  No content/ directory found - skipping${NC}"
fi
echo ""

# ============================================
# CHECK 23: Git Hooks for CI/CD Secrets [NEW]
# ============================================
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${PURPLE}CHECK 23: Git Hooks Pre-Commit Validation [NEW]${NC}"
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

if [[ -d "$SCAN_DIR/.git/hooks" ]]; then
    HAS_PRECOMMIT=0
    
    # Check for pre-commit hook
    if [[ -f "$SCAN_DIR/.git/hooks/pre-commit" ]]; then
        HAS_PRECOMMIT=1
        echo -e "${GREEN}✓ Pre-commit hook exists${NC}"
        
        # Check if it validates secrets
        if grep -qiE "(secret|credential|key|token|trufflehog|gitleaks)" "$SCAN_DIR/.git/hooks/pre-commit" 2>/dev/null; then
            echo -e "${GREEN}✓ Pre-commit hook includes secret scanning${NC}"
        else
            echo -e "${YELLOW}⚠️  Pre-commit hook exists but doesn't validate secrets [LOW]${NC}"
            echo "  Consider: Adding TruffleHog or gitleaks to pre-commit"
            LOW_ISSUES=$((LOW_ISSUES + 1))
        fi
    fi
    
    # Check for pre-commit framework config
    if [[ -f "$SCAN_DIR/.pre-commit-config.yaml" ]]; then
        echo -e "${GREEN}✓ Pre-commit framework config found${NC}"
        
        # Check for security hooks
        if grep -qiE "(trufflehog|gitleaks|detect-secrets|secret)" "$SCAN_DIR/.pre-commit-config.yaml" 2>/dev/null; then
            echo -e "${GREEN}✓ Pre-commit config includes security checks${NC}"
        else
            echo -e "${YELLOW}⚠️  Pre-commit config doesn't include secret scanning [LOW]${NC}"
            LOW_ISSUES=$((LOW_ISSUES + 1))
        fi
    fi
    
    if [[ $HAS_PRECOMMIT -eq 0 && ! -f "$SCAN_DIR/.pre-commit-config.yaml" ]]; then
        echo -e "${YELLOW}⚠️  No pre-commit hooks configured [MEDIUM]${NC}"
        echo "  Secrets could be committed without validation"
        echo "  Consider: Installing pre-commit framework with secret detection"
        MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
    fi
else
    echo -e "${YELLOW}⚠️  No .git/hooks directory found${NC}"
fi
echo ""

# ============================================
# FINAL SUMMARY
# ============================================
echo "=============================================="
echo "🔒 FINAL SECURITY SUMMARY 🔒"
echo "=============================================="
echo ""
echo "Directory scanned: $SCAN_DIR"
echo ""

TOTAL_ISSUES=$((CRITICAL_ISSUES + HIGH_ISSUES + MEDIUM_ISSUES + LOW_ISSUES))

if [[ $CRITICAL_ISSUES -gt 0 ]]; then
    echo -e "${RED}🚨 CRITICAL: $CRITICAL_ISSUES issue(s) - FIX IMMEDIATELY${NC}"
fi

if [[ $HIGH_ISSUES -gt 0 ]]; then
    echo -e "${RED}⚠️  HIGH:     $HIGH_ISSUES issue(s) - Fix soon${NC}"
fi

if [[ $MEDIUM_ISSUES -gt 0 ]]; then
    echo -e "${YELLOW}⚠️  MEDIUM:   $MEDIUM_ISSUES issue(s) - Address when possible${NC}"
fi

if [[ $LOW_ISSUES -gt 0 ]]; then
    echo -e "${BLUE}ℹ️  LOW:      $LOW_ISSUES issue(s) - Nice to fix${NC}"
fi

echo ""

if [[ $TOTAL_ISSUES -eq 0 ]]; then
    echo -e "${GREEN}✅ EXCELLENT! No security issues found!${NC}"
    echo ""
    echo "Your repository follows security best practices:"
    echo "  ✓ No secrets or credentials exposed"
    echo "  ✓ No backup files committed"
    echo "  ✓ Clean public output directory"
    echo "  ✓ Good .gitignore coverage"
    echo "  ✓ No obvious vulnerabilities"
    echo "  ✓ Supply chain security verified"
    echo "  ✓ No shortcode injection risks"
    echo "  ✓ Netlify build security confirmed"
    echo "  ✓ RSS/sitemap properly configured"
    echo "  ✓ No front matter secrets"
    echo "  ✓ Pre-commit hooks configured (if applicable)"
    echo ""
    echo -e "${PURPLE}🦛 Oob Skulden Approved! Stay vigilant, stay submerged.${NC}"
else
    echo -e "${YELLOW}⚠️  Found $TOTAL_ISSUES total security issue(s)${NC}"
    echo ""
    echo "Priority actions (in order):"
    [[ $CRITICAL_ISSUES -gt 0 ]] && echo "  1. 🚨 Fix CRITICAL issues immediately"
    [[ $HIGH_ISSUES -gt 0 ]] && echo "  2. ⚠️  Address HIGH priority issues"
    [[ $MEDIUM_ISSUES -gt 0 ]] && echo "  3. ⚠️  Review MEDIUM priority issues"
    [[ $LOW_ISSUES -gt 0 ]] && echo "  4. ℹ️  Consider LOW priority improvements"
fi

echo ""
echo "=============================================="
echo -e "${PURPLE}Generated by Oob Skulden Security Audit${NC}"
echo -e "${PURPLE}\"The threats you don't see coming\"${NC}"
echo "=============================================="
echo ""

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