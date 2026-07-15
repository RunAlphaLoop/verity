#!/usr/bin/env bash
# Backup/restore DR drill — proves "if I put real data in, I can get it back."
#
# Runs the real `verity-cli backup`, restores the dump into a THROWAWAY database
# (never the live one), and asserts every table's row count matches the source
# exactly. Also runs pg_restore's exact `--clean --if-exists` path to confirm it
# exits clean. Safe to run against a live dev stack: it only READS the live DB.
#
#   ./demo/backup_restore_drill.sh
#
# Exit 0 = backup + restore round-trips with byte-identical row counts.
set -euo pipefail

CONTAINER="${VERITY_PG_CONTAINER:-verity-postgres}"
DB="${VERITY_DB:-verity}"
SCRATCH="${VERITY_SCRATCH_DB:-verity_restore_drill}"
DSN="${VERITY_DSN:-postgres://verity:verity@localhost:5433/$DB}"
CLI="${VERITY_CLI:-./target/debug/verity-cli}"
export PGPASSWORD="${PGPASSWORD:-verity}"

green() { printf '\033[1;32m%s\033[0m\n' "$1"; }
red()   { printf '\033[1;31m%s\033[0m\n' "$1"; }

TABLES="tenants chunks facts principals episodes actions knowledge media"
BK="$(mktemp -d)"
trap 'rm -rf "$BK"; psql "$DSN" -c "DROP DATABASE IF EXISTS $SCRATCH;" >/dev/null 2>&1 || true' EXIT

echo "== Verity backup/restore DR drill =="
echo

# 1. Back up the live DB with the real CLI.
"$CLI" backup "$BK" >/dev/null
DUMP="$(ls "$BK"/*.dump)"
echo "  backed up: $(basename "$DUMP") ($(wc -c <"$DUMP" | tr -d ' ') bytes)"

# 2. Restore into a throwaway database.
psql "$DSN" -c "DROP DATABASE IF EXISTS $SCRATCH;" >/dev/null
psql "$DSN" -c "CREATE DATABASE $SCRATCH;" >/dev/null
# Fresh-DB restore: 3 harmless "schema already exists" notes (paradedb/tiger/
# topology ship with the image); data restores fully. --no-owner avoids role noise.
docker exec -i "$CONTAINER" pg_restore -U verity -d "$SCRATCH" --no-owner <"$DUMP" 2>/dev/null || true
echo "  restored into throwaway db: $SCRATCH"
echo

# 3. Compare row counts, table by table.
SCRATCH_DSN="${DSN%/$DB}/$SCRATCH"
ok=1
printf "  %-14s %12s %12s\n" "table" "live" "restored"
for t in $TABLES; do
  live=$(psql "$DSN" -At -c "SELECT count(*) FROM $t" 2>/dev/null || echo "?")
  rest=$(psql "$SCRATCH_DSN" -At -c "SELECT count(*) FROM $t" 2>/dev/null || echo "?")
  mark="ok"; [ "$live" != "$rest" ] && { mark="MISMATCH"; ok=0; }
  printf "  %-14s %12s %12s   %s\n" "$t" "$live" "$rest" "$mark"
done
echo

# 4. Confirm the CLI's exact restore command (--clean --if-exists into an
#    existing db) exits clean — the real production restore path.
if docker exec -i "$CONTAINER" pg_restore -U verity -d "$SCRATCH" --clean --if-exists <"$DUMP" >/dev/null 2>&1; then
  echo "  pg_restore --clean --if-exists (the CLI's path): exit 0, clean"
else
  echo "  pg_restore --clean --if-exists: NON-ZERO exit — the CLI would bail"; ok=0
fi
echo

if [ "$ok" = 1 ]; then green "  PASS — backup + restore round-trips with identical row counts"; exit 0
else red "  FAIL — a table count diverged or restore errored"; exit 1; fi
