#!/usr/bin/env bash
#
# demo-folder-watch.sh — drip the folder-watch demo fixtures into a watched
# folder one at a time, so you can WATCH memories appear in the console's
# "Sources & Freshness" panel (source "folder:<name>") one by one.
#
# This does NOT start the watcher or the server — it just copies files into a
# folder you have already pointed a Verity folder-watch at (via the console's
# Sources & Freshness panel, or the FTUE "watch a local folder" choice). The
# server-side watcher notices each new file, extracts it, and turns it into
# memory scoped to whoever you said "can see it".
#
# Usage:
#   scripts/demo-folder-watch.sh <target-folder> [delay-seconds]
#
# Example:
#   # 1. In the console, add a folder watch pointing at ./verity-inbox,
#   #    visibility = user:jordan + group:sales (matches the sample cast).
#   # 2. Then drip the fixtures in:
#   scripts/demo-folder-watch.sh ./verity-inbox 4
#
# Defaults: delay = 4 seconds between files (longer than the ~500ms-1s watcher
# debounce, so each file lands as its own visible event).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURES="$HERE/../examples/watch-demo"

TARGET="${1:-}"
DELAY="${2:-4}"

if [[ -z "$TARGET" ]]; then
  echo "usage: $0 <target-folder> [delay-seconds]" >&2
  echo "  <target-folder>  a folder you have configured a Verity watch on" >&2
  exit 2
fi

if [[ ! -d "$FIXTURES" ]]; then
  echo "error: fixtures dir not found at $FIXTURES" >&2
  exit 1
fi

mkdir -p "$TARGET"

# Regenerate the binary fixtures if they are missing (the .md/.txt/.csv are
# committed; the .xlsx/.pptx/.pdf are produced by the generator).
if [[ ! -f "$FIXTURES/acme-renewal-risk.pdf" ]]; then
  echo "binary fixtures missing — generating them..."
  python3 "$FIXTURES/generate-binaries.py" || \
    echo "  (generator failed; plain-text fixtures will still drop)"
fi

# Order: lead with the human-readable notes so the story reads top-to-bottom,
# then the structured/binary formats that exercise Tier-1 extraction.
FILES=(
  "acme-renewal-risk.md"
  "acme-notes.txt"
  "acme-fleet.csv"
  "acme-renewal-pricing.xlsx"
  "acme-renewal-review.pptx"
  "acme-renewal-risk.pdf"
)

echo "Dripping folder-watch demo fixtures into: $TARGET"
echo "(delay ${DELAY}s between files — watch Sources & Freshness for source 'folder:$(basename "$TARGET")')"
echo

for f in "${FILES[@]}"; do
  src="$FIXTURES/$f"
  if [[ ! -f "$src" ]]; then
    echo "  [skip]  $f (not present)"
    continue
  fi
  cp "$src" "$TARGET/$f"
  echo "  [drop]  $f  ->  $TARGET/$f"
  sleep "$DELAY"
done

echo
echo "Done. All fixtures dropped. Now query in the Playground / CLI, e.g.:"
echo "    what is the renewal risk at Acme Freight?"
echo "    what did we quote for the Acme renewal?"
echo "Both should return the dropped memories, resolved to account:acme-freight."
