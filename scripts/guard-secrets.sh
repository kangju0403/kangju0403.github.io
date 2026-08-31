#!/usr/bin/env bash
# guard-secrets.sh — hard-blocking secret scanner.
#
# Usage:
#   scripts/guard-secrets.sh              # scan staged files (git index), or all files if not in a git repo
#   scripts/guard-secrets.sh <file> ...    # scan specific files
#
# Exit codes: 0 = clean, 1 = secret-like content or forbidden filename found (BLOCK).
#
# Wired as a pre-commit hook via .git/hooks/pre-commit (see scripts/install-hooks.sh).

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." >/dev/null 2>&1 && pwd)"

RED='\033[1;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

FOUND=0

# --- Content patterns that must never appear in a committed file ---
CONTENT_PATTERNS=(
  'BEGIN.*PRIVATE KEY'
  'BEGIN.*EC PRIVATE KEY'
  'sk-'
  'ghp_'
  'gho_'
  'AKIA'
  'eyJ'
  'ANTHROPIC_API_KEY'
  'OPENAI_API_KEY'
  'INTUIT_CLIENT'
  'HERMES_'
  'Bearer '
  'refresh_token'
  'client_secret'
  'password='
  'api_key'
)

# --- Filename patterns that must never be committed (mirrors .gitignore secret rules) ---
FILENAME_PATTERNS=(
  '\.pem$'
  '\.key$'
  '\.p8$'
  '(^|/)\.env$'
  '(^|/)\.env\.'
  '\.pem\.bak$'
  '(^|/)CLAUDE\.md$'
  '(^|/)credentials.*\.json$'
  'token.*\.json$'
  '(^|/)auth\.json$'
  '(^|/)\.claude\.json$'
  '(^|/)config\.yaml$'
  '(^|/)secrets'
  'private.*key'
)

ALLOWLIST_FILES=(
  ".well-known/appspecific/com.tesla.3p.public-key.pem"
)

# Files whose source legitimately contains the literal pattern strings above
# (this scanner's own code) and must be skipped for content scanning only.
CONTENT_ALLOWLIST_FILES=(
  "scripts/guard-secrets.sh"
)

is_allowlisted() {
  local f="$1"
  for a in "${ALLOWLIST_FILES[@]}"; do
    [[ "$f" == "$a" ]] && return 0
  done
  return 1
}

is_content_allowlisted() {
  local f="$1"
  for a in "${CONTENT_ALLOWLIST_FILES[@]}"; do
    [[ "$f" == "$a" ]] && return 0
  done
  return 1
}

get_target_files() {
  if [[ $# -gt 0 ]]; then
    printf '%s\n' "$@"
    return
  fi
  if git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git -C "$REPO_ROOT" diff --cached --name-only --diff-filter=ACM
  else
    (cd "$REPO_ROOT" && find . -type f -not -path './.git/*' | sed 's|^\./||')
  fi
}

check_filename() {
  local f="$1"
  if is_allowlisted "$f"; then
    return 0
  fi
  for pat in "${FILENAME_PATTERNS[@]}"; do
    if echo "$f" | grep -Eiq "$pat"; then
      echo -e "${RED}[BLOCKED]${NC} filename matches forbidden secret pattern '${pat}': ${f}"
      FOUND=1
    fi
  done
}

check_content() {
  local f="$1"
  [[ -f "$REPO_ROOT/$f" ]] || return 0
  is_content_allowlisted "$f" && return 0
  # Skip binary files
  if file -b --mime "$REPO_ROOT/$f" 2>/dev/null | grep -qi 'charset=binary'; then
    return 0
  fi
  for pat in "${CONTENT_PATTERNS[@]}"; do
    if grep -Eiqn "$pat" "$REPO_ROOT/$f" 2>/dev/null; then
      echo -e "${RED}[BLOCKED]${NC} file '${f}' contains forbidden pattern matching '${pat}'"
      FOUND=1
    fi
  done
}

echo "guard-secrets: scanning for exposed credentials..."

mapfile -t TARGETS < <(get_target_files "$@")

if [[ ${#TARGETS[@]} -eq 0 ]]; then
  echo "guard-secrets: no files to scan."
  exit 0
fi

for f in "${TARGETS[@]}"; do
  [[ -z "$f" ]] && continue
  check_filename "$f"
  check_content "$f"
done

if [[ "$FOUND" -eq 1 ]]; then
  echo ""
  echo -e "${RED}=============================================${NC}"
  echo -e "${RED} SECRET DETECTED — COMMIT/PUSH HARD-BLOCKED  ${NC}"
  echo -e "${RED}=============================================${NC}"
  echo -e "${YELLOW}This repository is PUBLIC. Remove the offending content or file, then retry.${NC}"
  exit 1
fi

echo "guard-secrets: clean. No secrets detected."
exit 0
