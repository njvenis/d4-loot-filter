#!/usr/bin/env bash
# run_local.sh — run the job locally with .env loaded.
#
# The job itself deliberately does NOT read .env: it takes config from the
# process environment only, so that in CI the sole source of credentials is
# repo secrets. This wrapper does the loading explicitly, for local testing.
#
#   ./scripts/run_local.sh                    # uses .env as-is
#   DRY_RUN=true ./scripts/run_local.sh       # override anything inline
#   QDS_MIN=90 MAX_ISSUES_PER_RUN=5 ./scripts/run_local.sh
#
# Variables already exported in your shell win over .env, same as the job's
# own precedence — so an inline override on the command line always applies.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ ! -f .env ]; then
  echo "No .env at $ROOT/.env — copy .env.example and fill it in." >&2
  exit 1
fi

# Load .env without clobbering anything already exported (inline overrides win).
while IFS= read -r line || [ -n "$line" ]; do
  line="${line#"${line%%[![:space:]]*}"}"          # ltrim
  [ -z "$line" ] && continue
  case "$line" in \#*) continue ;; esac
  line="${line#export }"
  key="${line%%=*}"
  val="${line#*=}"
  case "$key" in [A-Z_]*) ;; *) continue ;; esac    # skip malformed / lowercase
  key="$(echo "$key" | tr -d '[:space:]')"
  val="${val#"${val%%[![:space:]]*}"}"             # ltrim value
  val="${val%"${val##*[![:space:]]}"}"             # rtrim value
  val="${val%\"}"; val="${val#\"}"                  # strip matching quotes
  val="${val%\'}"; val="${val#\'}"
  if [ -z "${!key-}" ]; then
    export "$key=$val"
  fi
done < .env

# GitHub credentials are not kept in .env. Fall back to the gh CLI if present.
if [ -z "${GITHUB_TOKEN-}" ] && command -v gh >/dev/null 2>&1; then
  if tok="$(gh auth token 2>/dev/null)" && [ -n "$tok" ]; then
    export GITHUB_TOKEN="$tok"
    echo "GITHUB_TOKEN taken from the gh CLI (acting as you)."
  fi
fi

missing=()
for v in QUALYS_BASE_URL QUALYS_USERNAME QUALYS_PASSWORD GITHUB_REPO GITHUB_TOKEN; do
  [ -z "${!v-}" ] && missing+=("$v")
done
if [ ${#missing[@]} -gt 0 ]; then
  echo "Missing: ${missing[*]}" >&2
  echo >&2
  echo "  QUALYS_* belong in .env." >&2
  echo "  GITHUB_REPO can go in .env; GITHUB_TOKEN is best exported:" >&2
  echo "      export GITHUB_TOKEN=\$(gh auth token)     # or a PAT" >&2
  exit 2
fi

echo "Running against ${GITHUB_REPO} as ${QUALYS_USERNAME}"
echo "  QDS_MIN=${QDS_MIN:-70}  DRY_RUN=${DRY_RUN:-false}" \
     "MAX_ISSUES_PER_RUN=${MAX_ISSUES_PER_RUN:-50}" \
     "TRACK_ABSENCE=${TRACK_ABSENCE:-true}"
echo

exec python3 qualys_qds_to_github.py "$@"
