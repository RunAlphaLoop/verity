#!/usr/bin/env bash
# ============================================================================
# Verity clean-VM quickstart gate.
#
# Run this on a THROWAWAY Ubuntu 22.04/24.04 cloud VM (>= 4 vCPU, 16 GB RAM,
# 40 GB disk) with NOTHING preinstalled. It is the honest launch gate: it does
# exactly what a stranger who found the repo on HN/LinkedIn would do, from zero,
# and reports where it breaks. It touches nothing on your dev machine.
#
#   scp clean-vm-quickstart.sh root@<vm-ip>:/root/
#   ssh root@<vm-ip> 'bash /root/clean-vm-quickstart.sh'
#
# It installs Docker + rustup (a stranger needs both), clones the public repo,
# then runs the README quickstart verbatim and times each step.
# ============================================================================
set -uo pipefail

REPO_URL="${REPO_URL:-https://github.com/RunAlphaLoop/verity.git}"
WORK="${WORK:-$HOME/verity-cleanroom}"
FAILED=0
step() { printf '\n\033[1;36m=== %s ===\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m[PASS]\033[0m %s\n' "$*"; }
bad()  { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*"; FAILED=1; }
timed(){ local t0 t1; t0=$(date +%s); "$@"; local rc=$?; t1=$(date +%s); printf '   (%ds)\n' "$((t1-t0))"; return $rc; }

step "0. Environment"
uname -a; nproc; free -h 2>/dev/null | head -2; df -h / | tail -1

step "1. Prerequisites a stranger must install (build toolchain + Docker + rustup)"
# A fresh Ubuntu has NO C linker; rustup does not ship one. Without this the
# from-source build dies immediately at: error: linker `cc` not found.
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq git build-essential pkg-config libssl-dev cmake curl \
  && ok "build toolchain present (git, cc, pkg-config, libssl, cmake)" \
  || bad "apt install of build toolchain failed"
if ! command -v docker >/dev/null; then
  curl -fsSL https://get.docker.com | sh || bad "Docker install failed"
fi
docker --version && ok "docker present" || bad "docker missing"
docker compose version >/dev/null 2>&1 && ok "compose v2 present" || bad "compose v2 missing (README assumes 'docker compose', not 'docker-compose')"
if ! command -v cargo >/dev/null; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y || bad "rustup install failed"
  # shellcheck disable=SC1091
  . "$HOME/.cargo/env"
fi
cargo --version && ok "cargo present (README never states a Rust version — the repo's rust-toolchain.toml pins it)" || bad "cargo missing"

step "2. Clone (exactly what the README implies)"
rm -rf "$WORK"; git clone "$REPO_URL" "$WORK" || bad "clone failed"
cd "$WORK" || { bad "cannot cd into checkout"; exit 1; }
git log --oneline -1
# Confirm the pin auto-resolves (this is the whole point of rust-toolchain.toml):
rustup show active-toolchain 2>/dev/null | grep -q rust-toolchain.toml \
  && ok "rust-toolchain.toml pin auto-resolved" \
  || bad "toolchain pin did NOT auto-resolve"

step "3. quickstart step 1: build + bring up the dev stack (the ~15 min claim)"
echo "This builds the workspace from source (fresh target/) AND cold-pulls the"
echo "docker images AND downloads the embedding model. Timing it honestly:"
# `dev` blocks until healthy then returns; run it and capture the wall time.
# PIPESTATUS[0] is the cargo/dev exit code (tee would otherwise mask a failure).
timed cargo run --release -p verity-cli -- dev 2>&1 | tee dev.log
DEV_RC=${PIPESTATUS[0]}
# Real readiness: dev exited 0 AND the server answers /healthz. A build failure
# leaves stale/absent state and MUST fail here (not match a stray log word).
if [ "$DEV_RC" -eq 0 ] && curl -fsS http://localhost:7717/healthz >/dev/null 2>&1; then
  ok "dev came up (exit 0, /healthz OK)"
else
  bad "dev did NOT come up (exit $DEV_RC, /healthz unreachable) — see dev.log"
fi
echo "--- containers actually running (expect 3-4: postgres, spicedb, minio[, minio-init]) ---"
docker ps --format '{{.Names}}\t{{.Status}}'
running() { docker ps --format '{{.Names}}' | grep -qx "$1"; }
CORE_OK=true;  for c in verity-postgres verity-spicedb verity-minio; do running "$c" || CORE_OK=false; done
SCALE_LEAK=false; for c in verity-temporal verity-qdrant; do running "$c" && SCALE_LEAK=true; done
CNT=$(docker ps --format '{{.Names}}' | grep -c '^verity-')
if $CORE_OK && ! $SCALE_LEAK; then
  ok "lean default stack: core 3 up (postgres/spicedb/minio), temporal+qdrant correctly absent ($CNT total)"
else
  bad "stack wrong: core_up=$CORE_OK scale_leaked=$SCALE_LEAK ($CNT verity-* running) — 0 = nothing started"
fi

step "4. quickstart steps 2-4: ingest, recall, webhook"
mkdir -p ./docs && printf 'Our Q3 pricing is usage-based at \$0.002 per token.\n' > ./docs/pricing.md
# `if timed cmd` keys off the command's real exit code (not a piped tail's).
if timed cargo run --release -p verity-cli -- add ./docs --visibility 1 > add.log 2>&1; then
  ok "add ran"; else tail -5 add.log; bad "add failed"; fi
OUT=$(cargo run --release -p verity-cli -- query "what do we know about pricing?" 2>&1)
echo "$OUT" | tail -8
echo "$OUT" | grep -qi pricing && ok "recall returned the ingested doc" || bad "recall did NOT return the doc (the headline demo)"
if timed cargo run --release -p verity-cli -- webhook mint my-system --visibility 1 > webhook.log 2>&1; then
  ok "webhook mint ran"; else tail -5 webhook.log; bad "webhook mint failed"; fi

step "SUMMARY"
if [ "$FAILED" -eq 0 ]; then
  printf '\033[1;32mALL GREEN — a stranger can go from zero to a working recall.\033[0m\n'
else
  printf '\033[1;31mFAILURES ABOVE — fix before launch. Logs: %s/{dev,build}.log\033[0m\n' "$WORK"
fi
echo "Tear down the VM when done; nothing here needs to persist."
exit $FAILED
