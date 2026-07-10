#!/usr/bin/env bash
# Framework conformance harness (task #29): build the server if needed, then
# run the e2e suite (pytest -m e2e) — real frameworks, real server, real
# Postgres. Framework churn fails HERE (and in the weekly canary), not at a
# user's desk.
#
# Env:
#   VERITY_BIN       server binary override (default: ../target/release/verity,
#                    built via cargo if missing)
#   VERITY_TEST_DSN  Postgres DSN (default: the dev DSN,
#                    postgres://verity:verity@localhost:5433/verity)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
BIN="${VERITY_BIN:-$REPO_ROOT/target/release/verity}"

if [[ ! -x "$BIN" ]]; then
  echo "verity binary missing at $BIN — building (cargo build --release -p verity-server)"
  (cd "$REPO_ROOT" && cargo build --release -p verity-server)
fi

# Prefer the shared integrations venv; fall back to whatever python is active
# (CI installs the adapter packages into the runner's python).
if [[ -x "$HERE/.venv/bin/pytest" ]]; then
  PYTEST=("$HERE/.venv/bin/pytest")
else
  PYTEST=(python3 -m pytest)
fi

cd "$HERE"
# The trailing -m e2e overrides the `-m "not e2e"` in pytest.ini addopts.
exec "${PYTEST[@]}" e2e -m e2e -v "$@"
