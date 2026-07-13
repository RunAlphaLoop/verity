# Folder-watch demo fixtures

A small set of droppable files that demo Verity's **local folder watch**: point
Verity at a folder, drop these files in, wait a few seconds, then query them
back. They tell a coherent story with the built-in **Acme Freight sample cast**
(`account:acme-freight`, `user:jordan` / `group:sales`, the renewal-risk deal),
so a query like *"what is the renewal risk at Acme Freight?"* returns them and
they resolve to the same seeded entity as the sample data.

## The files

| File | Format | Extraction path | What it says |
|------|--------|-----------------|--------------|
| `acme-renewal-risk.md` | Markdown (text) | passes through as text | The renewal-risk assessment: HIGH risk, $48k→$61k, $52k competitor, $58k floor |
| `acme-notes.txt` | Plain text | passes through as text | Renewal-call notes: pricing pushback, revised quote by Friday, 120 trucks |
| `acme-fleet.csv` | CSV (text) | passes through as text | Structured fleet + pricing metrics keyed to `account:acme-freight` |
| `acme-renewal-pricing.xlsx` | Excel | Tier-1 `calamine` (`extract.rs::extract_sheet`) | Renewal pricing sheet: prior/revised/competitor/floor amounts |
| `acme-renewal-review.pptx` | PowerPoint | Tier-1 `zip`+`quick-xml` (`extract.rs::extract_pptx`) | One-slide renewal review deck |
| `acme-renewal-risk.pdf` | PDF | Tier-1 `pdf-extract` (`extract.rs::extract_pdf`) | Renewal-risk one-pager |

The three text files are committed and always work. The three binary files
(`.xlsx`/`.pptx`/`.pdf`) are produced by `generate-binaries.py` (see below) so
the repo does not have to carry opaque binaries — but they are small, valid, and
verified to extract cleanly (`file` reports the right Office/PDF magic;
`pdftotext` and `openpyxl` round-trip them). Every file is well under the 200 KB
Tier-1 extraction cap.

### Why these numbers (ties to the sample cast)

The sample cast (`crates/verity-server/src/ui/sample_cast.js`) seeds Acme Freight
with: renewal amount revised **$48k → $61k** after a pricing review, a **$52k**
rumored competitor quote, a **$58k/yr** deal-desk floor, **120 trucks**, dispatch
integration **live since March**, and a **95%** on-time tracking target. Every
fixture here reuses those exact facts, so the dropped files reinforce (never
contradict) the seeded story and land on the same `account:acme-freight` entity.

## Regenerate the binary fixtures

```sh
cd examples/watch-demo
python3 generate-binaries.py
```

Requires `openpyxl` for the `.xlsx` (`pip install openpyxl`); the `.pptx` and
`.pdf` use only the Python standard library. If `openpyxl` is absent the script
skips the `.xlsx` with a clear message and everything else still generates —
`acme-fleet.csv` is the plain-text stand-in for the pricing sheet, so the demo
never depends on the generator succeeding.

## Demo — the fast path (drip script)

Point a watch at a folder in the console, then drip the fixtures in one at a time
so you can watch memories appear one-by-one in **Sources & Freshness** (the watch
registers as source `folder:<name>`):

```sh
# 1. In the console → Sources & Freshness → add a folder watch:
#      folder:   ./verity-inbox
#      who can see it (visibility):  user:jordan  +  group:sales
#    (matches the sample cast; there is NO default visibility — you must choose.)
#
# 2. Drip the fixtures in (4s between files, longer than the watcher debounce):
scripts/demo-folder-watch.sh ./verity-inbox 4
```

Each `[drop]` line corresponds to one new memory landing. Watch the
`folder:verity-inbox` row in Sources & Freshness update its item count and
last-seen time as each file is ingested.

## Demo — the manual path

```sh
# Configure the watch as above, then just copy files in yourself:
cp examples/watch-demo/acme-renewal-risk.md   ./verity-inbox/
cp examples/watch-demo/acme-notes.txt         ./verity-inbox/
cp examples/watch-demo/acme-fleet.csv         ./verity-inbox/
cp examples/watch-demo/acme-renewal-*.xlsx    ./verity-inbox/
cp examples/watch-demo/acme-renewal-*.pptx    ./verity-inbox/
cp examples/watch-demo/acme-renewal-*.pdf     ./verity-inbox/
# wait a few seconds for the watcher to pick them up
```

## Query them back

In the Playground (as `user:jordan` or any key in `group:sales`, since that is
the visibility we set), or via the CLI, ask:

```
what is the renewal risk at Acme Freight?
what did we quote for the Acme renewal?
what is Acme's deal-desk floor?
how big is Acme's fleet?
```

### Expected memories

- **Renewal risk is HIGH** — driven by the price gap ($61k revised quote vs a
  rumored $52k competitor) plus an active competitor (from
  `acme-renewal-risk.md`, `acme-renewal-risk.pdf`, `acme-renewal-review.pptx`).
- **We quoted $61k**, revised up from $48k after the pricing review; do not
  commit below the **$58k** deal-desk floor (from `acme-fleet.csv`,
  `acme-renewal-pricing.xlsx`).
- **Fleet is 120 trucks**, dispatch integration live since March, tracking above
  the 95% target (from `acme-notes.txt`, `acme-fleet.csv`).

All resolve to `account:acme-freight` — the same entity the sample cast seeds —
so these dropped files and the seeded CRM/notes memories answer as one coherent
account history.

## Fail-closed note

A folder watch **must** be configured with "who can see these files" at setup —
there is no permissive default (SPEC §5e). In this demo we chose
`user:jordan + group:sales`, which is why `user:sample-blind` (the guaranteed-
blind key) still sees nothing when it queries: that is the permission model
working, not a bug.
