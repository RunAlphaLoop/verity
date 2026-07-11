"""Metric #5 offline harness — the probabilistic entity tagger (SPEC §7d).

Entity tagging on unstructured content is *probabilistic*: a chunk mentions an
account, and the tagger decides which tenant-lexicon entities to attach. SPEC §7d
lists "tagger recall" as SRB metric #5 but it has been *defined-not-reported*.
This harness closes that gap for the shipped v0 tagger.

What is measured
----------------
For each labeled example we hand the **real** shipped tag logic — the
``DeterministicExtractor``'s entity-name echo in
``verity_ingest.consolidation`` — the example's content plus the tenant lexicon
(the union of the expected tags and the distractor entities), and read back the
``tag_suggestions`` it emits. We do NOT reimplement the echo: we build a
``LeasedEpisode`` whose single chunk carries the content and whose provenance
``entities`` are the lexicon, then call ``DeterministicExtractor().extract`` —
the same public seam the consolidation worker uses in production. Predicted tags
= the set of suggested tags.

We then compare the predicted set to the labeled ``expected_tags`` and report,
per example and in aggregate:

- **precision** — of the tags the tagger suggested, how many were correct. A
  false tag is the *costly* error here, exactly like a false merge in metric #6:
  wrongly attaching an entity **widens a memory's scope** to an account it does
  not concern, leaking it into that account's recall surface. Precision dominates.
- **recall** — of the tags that SHOULD have been suggested, how many were.
- **F1** — the harmonic mean.
- **distractor false-positive rate** — of the distractor entities (present in the
  lexicon but NOT in the content), how many were wrongly tagged. This is the
  confusion the corpus is built to stress (common-word names, pronoun-only
  mentions, substring collisions).

The deterministic echo is precision-first by construction (exact bare-name
substring match), so we expect **high precision, lower recall** — it misses
abbreviated/paraphrased mentions. That is the honest v0 baseline and the
motivation for the probabilistic (LLM) ``AnthropicExtractor`` tagger, which would
lift recall at the same precision but is shape-only here (no API key).

Run standalone to print the table and write the dated report:

    python -m verity_ingest.tagger_eval [path-to-tagger-eval.jsonl]
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from verity_ingest.consolidation import (
    DeterministicExtractor,
    LeasedChunk,
    LeasedEpisode,
)

_BENCH_DIR = Path(__file__).resolve().parents[2] / "docs" / "benchmark"
DEFAULT_CORPUS = _BENCH_DIR / "tagger-eval.jsonl"


def predict_tags(
    content: str,
    lexicon: list[str],
    extractor: DeterministicExtractor | None = None,
) -> set[str]:
    """Predicted entity tags for one snippet under a tenant lexicon.

    Reuses the SHIPPED tag logic: build the smallest ``LeasedEpisode`` the
    ``DeterministicExtractor`` accepts — one chunk holding the content, the
    lexicon supplied as provenance ``entities`` — and read back the tags it
    suggests. No reimplementation of the echo; this is the same seam the worker
    calls. ``payload.observation`` is left unset so the extractor reads the chunk
    content (its normal path) rather than a payload override."""
    ext = extractor or DeterministicExtractor()
    episode = LeasedEpisode(
        episode_id="tagger-eval",
        source="agent",
        source_entity=None,
        kind="observation",
        # entities = the tenant lexicon; observation absent so text() falls to
        # the chunk content, which is where the echo scans for names anyway.
        payload={"entities": list(lexicon)},
        chunks=[LeasedChunk(chunk_id="tagger-eval", content=content, entity_tags=[])],
    )
    extraction = ext.extract(episode)
    return {t.tag for t in extraction.tag_suggestions}


@dataclass
class Confusion:
    """Tag-level confusion. TP/FP/FN are counted over the SET of tags per
    example (a tag is correct iff it is in expected). TN is not meaningful for a
    multi-label suggest task, so we track the distractor confusion separately."""

    tp: int = 0
    fp: int = 0
    fn: int = 0
    # distractor confusion: how many distractor entities were (not) tagged.
    distractor_total: int = 0
    distractor_tagged: int = 0  # false positives against the distractor set

    def observe(self, predicted: set[str], expected: set[str], distractors: set[str]) -> None:
        self.tp += len(predicted & expected)
        self.fp += len(predicted - expected)
        self.fn += len(expected - predicted)
        self.distractor_total += len(distractors)
        self.distractor_tagged += len(predicted & distractors)

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return 1.0 if d == 0 else self.tp / d

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return 1.0 if d == 0 else self.tp / d

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 0.0 if p + r == 0 else 2 * p * r / (p + r)

    @property
    def distractor_fp_rate(self) -> float:
        d = self.distractor_total
        return 0.0 if d == 0 else self.distractor_tagged / d


@dataclass
class ExampleResult:
    id: str
    category: str
    content: str
    expected: list[str]
    predicted: list[str]
    false_tags: list[str] = field(default_factory=list)  # predicted but not expected
    missed_tags: list[str] = field(default_factory=list)  # expected but not predicted

    @property
    def exact(self) -> bool:
        return not self.false_tags and not self.missed_tags


def evaluate(corpus_path: Path | None = None) -> dict:
    """Score the corpus with the shipped DeterministicExtractor tag echo."""
    path = corpus_path or DEFAULT_CORPUS
    extractor = DeterministicExtractor()
    c = Confusion()
    per_category: dict[str, Confusion] = {}
    results: list[ExampleResult] = []
    n_none = 0

    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        d = json.loads(line)
        expected = set(d["expected_tags"])
        distractors = set(d["distractor_entities"])
        lexicon = sorted(expected | distractors)
        predicted = predict_tags(d["content"], lexicon, extractor)

        c.observe(predicted, expected, distractors)
        cat = d.get("category", "uncategorized")
        per_category.setdefault(cat, Confusion()).observe(predicted, expected, distractors)
        if not expected:
            n_none += 1

        results.append(
            ExampleResult(
                id=d["id"],
                category=cat,
                content=d["content"],
                expected=sorted(expected),
                predicted=sorted(predicted),
                false_tags=sorted(predicted - expected),
                missed_tags=sorted(expected - predicted),
            )
        )

    false_tag_examples = [
        {"id": r.id, "category": r.category, "content": r.content, "false_tags": r.false_tags}
        for r in results
        if r.false_tags
    ]
    missed_examples = [
        {"id": r.id, "category": r.category, "content": r.content, "missed_tags": r.missed_tags}
        for r in results
        if r.missed_tags
    ]

    return {
        "corpus": {
            "total": len(results),
            "expected_tags_total": c.tp + c.fn,
            "distractors_total": c.distractor_total,
            "examples_with_no_expected_tag": n_none,
            "by_category": {k: _category_stats(v) for k, v in sorted(per_category.items())},
        },
        "confusion": {"tp": c.tp, "fp": c.fp, "fn": c.fn},
        "precision": c.precision,
        "recall": c.recall,
        "f1": c.f1,
        "distractor_fp_rate": c.distractor_fp_rate,
        "distractor_tagged": c.distractor_tagged,
        "exact_examples": sum(1 for r in results if r.exact),
        "false_tag_examples": false_tag_examples,
        "missed_examples": missed_examples,
    }


def _category_stats(c: Confusion) -> dict:
    return {
        "tp": c.tp,
        "fp": c.fp,
        "fn": c.fn,
        "precision": round(c.precision, 4),
        "recall": round(c.recall, 4),
        "f1": round(c.f1, 4),
        "distractor_fp_rate": round(c.distractor_fp_rate, 4),
    }


# ---------------------------------------------------------------------------
# Report writers (mirror the consolidation harness's dated JSON+MD emit)
# ---------------------------------------------------------------------------


def _report_md(r: dict, corpus_path: Path) -> str:
    c, cf = r["corpus"], r["confusion"]
    lines: list[str] = []
    lines.append("# SRB metric #5 — tagger recall (deterministic v0 baseline)")
    lines.append("")
    lines.append(f"Corpus: `{corpus_path}` — **{c['total']} examples**, "
                 f"{c['expected_tags_total']} expected tags, "
                 f"{c['distractors_total']} distractor entities, "
                 f"{c['examples_with_no_expected_tag']} examples with NO expected tag.")
    lines.append("")
    lines.append("Tagger: `DeterministicExtractor` entity-name echo "
                 "(exact bare-name substring match over chunk content, confidence 0.95).")
    lines.append("")
    lines.append("## Aggregate")
    lines.append("")
    lines.append("| metric | value |")
    lines.append("|---|---|")
    lines.append(f"| precision | **{r['precision']:.4f}** |")
    lines.append(f"| recall | **{r['recall']:.4f}** |")
    lines.append(f"| F1 | {r['f1']:.4f} |")
    lines.append(f"| tag confusion (TP/FP/FN) | {cf['tp']} / {cf['fp']} / {cf['fn']} |")
    lines.append(f"| distractor false-positive rate | {r['distractor_fp_rate']:.4f} "
                 f"({r['distractor_tagged']}/{c['distractors_total']}) |")
    lines.append(f"| exact-match examples | {r['exact_examples']}/{c['total']} |")
    lines.append("")
    lines.append("**Precision-first framing.** A false entity tag is a "
                 "*scope-widening* error: it attaches a memory to an account the "
                 "content does not concern, leaking that memory into the wrong "
                 "account's recall surface — the tagging analogue of a false merge. "
                 "So precision (and the distractor false-positive rate) is the "
                 "load-bearing number; recall is what the probabilistic tagger buys later.")
    lines.append("")
    lines.append("## Per category")
    lines.append("")
    lines.append("| category | n(examples) | precision | recall | F1 | distractor-FP-rate |")
    lines.append("|---|---|---|---|---|---|")
    # count examples per category from the corpus block
    for cat, s in c["by_category"].items():
        n_ex = _count_category(corpus_path, cat)
        lines.append(f"| {cat} | {n_ex} | {s['precision']:.4f} | {s['recall']:.4f} | "
                     f"{s['f1']:.4f} | {s['distractor_fp_rate']:.4f} |")
    lines.append("")
    if r["false_tag_examples"]:
        lines.append(f"## False tags ({len(r['false_tag_examples'])}) — the costly error")
        lines.append("")
        for e in r["false_tag_examples"]:
            lines.append(f"- `{e['id']}` [{e['category']}] {e['false_tags']} "
                         f"in: {e['content']!r}")
        lines.append("")
    else:
        lines.append("## False tags")
        lines.append("")
        lines.append("**None.** No distractor or out-of-content entity was tagged — "
                     "precision 1.0 on this corpus.")
        lines.append("")
    if r["missed_examples"]:
        lines.append(f"## Missed tags ({len(r['missed_examples'])}) — the recall gap")
        lines.append("")
        lines.append("These are the mentions the exact-name echo cannot reach "
                     "(abbreviations, partial names). The probabilistic "
                     "`AnthropicExtractor` tagger is the intended fix.")
        lines.append("")
        for e in r["missed_examples"]:
            lines.append(f"- `{e['id']}` [{e['category']}] missed {e['missed_tags']} "
                         f"in: {e['content']!r}")
        lines.append("")
    lines.append("## The AnthropicExtractor tagger (defined, not run here)")
    lines.append("")
    lines.append("The `AnthropicExtractor` (consolidation.py, active only behind "
                 "`ANTHROPIC_API_KEY`) is the probabilistic tagger: its prompt asks "
                 "for tag suggestions with a confidence, *preferring recall* — it "
                 "would catch the abbreviated/partial mentions the echo misses, "
                 "lifting recall. It is **shape-only here** (no key), so this report "
                 "is the DETERMINISTIC baseline. With this run, metric #5 is "
                 "**defined AND baseline-reported**, closing the 'defined-not-reported' gap.")
    lines.append("")
    return "\n".join(lines)


def _count_category(corpus_path: Path, category: str) -> int:
    n = 0
    for line in corpus_path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        if json.loads(line).get("category") == category:
            n += 1
    return n


def write_reports(r: dict, corpus_path: Path, out_dir: Path, on: date | None = None) -> tuple[Path, Path]:
    on = on or date.today()
    stamp = on.isoformat()
    json_path = out_dir / f"RESULTS-tagger-{stamp}.json"
    md_path = out_dir / f"RESULTS-tagger-{stamp}.md"
    json_path.write_text(json.dumps(r, indent=2) + "\n")
    md_path.write_text(_report_md(r, corpus_path))
    return json_path, md_path


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    corpus = Path(argv[0]) if argv else DEFAULT_CORPUS
    r = evaluate(corpus)
    c, cf = r["corpus"], r["confusion"]

    print(f"tagger recall (SRB metric #5) — DeterministicExtractor echo over {corpus}")
    print(
        f"  corpus: {c['total']} examples "
        f"({c['expected_tags_total']} expected tags, "
        f"{c['distractors_total']} distractors, "
        f"{c['examples_with_no_expected_tag']} no-tag)"
    )
    print(f"  tag confusion: TP {cf['tp']}  FP {cf['fp']}  FN {cf['fn']}")
    print(
        f"  precision {r['precision']:.4f}  recall {r['recall']:.4f}  F1 {r['f1']:.4f}"
    )
    print(
        f"  distractor false-positive rate {r['distractor_fp_rate']:.4f} "
        f"({r['distractor_tagged']}/{c['distractors_total']})"
    )
    print(f"  exact-match examples: {r['exact_examples']}/{c['total']}")
    print("  per category:")
    for cat, s in c["by_category"].items():
        print(
            f"    {cat:20s} P {s['precision']:.3f}  R {s['recall']:.3f}  "
            f"F1 {s['f1']:.3f}  distractor-FP {s['distractor_fp_rate']:.3f}"
        )
    if r["false_tag_examples"]:
        print(f"  FALSE TAGS ({len(r['false_tag_examples'])}) — scope-widening errors:")
        for e in r["false_tag_examples"]:
            print(f"    - {e['id']} {e['false_tags']} in {e['content']!r}")

    json_path, md_path = write_reports(r, corpus, _BENCH_DIR)
    print(f"  wrote {json_path}")
    print(f"  wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
