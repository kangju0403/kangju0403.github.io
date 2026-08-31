#!/usr/bin/env bash
# Wires scripts/guard-secrets.sh in as this repo's pre-commit hook.
# Run once after `git init` (or after cloning): scripts/install-hooks.sh
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
chmod +x "$REPO_ROOT/scripts/guard-secrets.sh" "$REPO_ROOT/scripts/hooks/pre-commit"
git -C "$REPO_ROOT" config core.hooksPath scripts/hooks
echo "Installed: pre-commit hook now runs scripts/guard-secrets.sh on every commit."
