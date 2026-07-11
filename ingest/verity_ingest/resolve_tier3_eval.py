"""Measured-eval harness for the ER Tier-3 unstructured-MENTION producer.

The knowledge-merge cascade has a measured judge eval (``consolidation_eval.py``)
and Tier-2 has a measured sameness eval (``resolve_tier2_eval.py``). Tier-3 — the
one irreducibly probabilistic surface (cross-source-entity-resolution.md §5) — is
graded on a DIFFERENT axis: not "same/not-same" but the TWO-DECISION outcome per
mention (nil / abstain_margin / reviewer_hint / tag). This harness mirrors the
Tier-2 harness structure (load the fixture, run the SHIPPED decision, report a
confusion-style breakdown + a dated JSON+MD sidecar), retargeted to the Tier-3
outcome taxonomy.

What is measured
----------------
For each labeled CHUNK in
``ingest/tests/fixtures/entity_resolution/mention_cases.json`` (an unstructured
Drive/Linear body + a per-case gazetteer ``catalog`` + the EXPECTED outcome per
candidate canonical), we run the SHIPPED Tier-3 pipeline
(``resolve_tier3.plan_tier3`` with the DETERMINISTIC default detector — NO API
key) and compare each mention's outcome to the label. We report:

  - **decision accuracy**: outcome matches the label, per mention.
  - the **abstain-safety** numbers, the load-bearing ones (§5): an AMBIGUOUS
    mention (two catalog candidates) must NEVER resolve to a ``tag`` — that would
    mis-file content into a real customer's scope. We count ``ambiguous_tags``
    (must be 0) and ``nil_or_abstain`` coverage of the ambiguous cases.
  - the **tag precision** proxy: every emitted ``tag`` in the labeled set was
    expected to be a ``tag`` (no chunk tagged for the wrong entity).

There is no live seam on the default path: the deterministic detector needs no
key. An ``anthropic`` NER backstop exists (``--detector anthropic``) but is
constructed LAZILY and ONLY when explicitly selected; a plain run never touches
it, so no key is needed or read for the default path. This harness never embeds,
prints, reads-from-a-literal, or otherwise handles a key.

Run standalone to print the metrics table and write a dated JSON+MD sidecar:

    python -m verity_ingest.resolve_tier3_eval                 # deterministic (no key)
    python -m verity_ingest.resolve_tier3_eval --detector anthropic   # live NER backstop
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from verity_ingest.resolve_tier3 import (
    CatalogEntity,
    Chunk,
    Gazetteer,
    MentionDetector,
    NullMentionDetector,
    Tier3Config,
    Tier3Outcome,
    plan_tier3,
)

# The labeled set lives with the other ingest test fixtures.
DEFAULT_CASES = (
    Path(__file__).resolve().parents[1]
    / "tests"
    / "fixtures"
    / "entity_resolution"
    / "mention_cases.json"
)

_BENCH_DIR = Path(__file__).resolve().parents[2] / "docs" / "benchmark"

TENANT = "00000000-0000-0000-0000-0000000000e3"


def load_cases(cases_path: Path | None = None) -> list[dict]:
    """Load the labeled mention-case set. Accepts the fixture's ``{"cases": [...]}``
    shape (keys other than ``cases`` are metadata and ignored)."""
    path = cases_path or DEFAULT_CASES
    doc = json.loads(path.read_text())
    return list(doc["cases"])


def _gazetteer(case: dict) -> Gazetteer:
    return Gazetteer(
        CatalogEntity(
            canonical=c["canonical"],
            name=c.get("name", ""),
            aliases=tuple(c.get("aliases", [])),
            domains=tuple(c.get("domains", [])),
            is_canonical=bool(c.get("is_canonical", True)),
        )
        for c in case["catalog"]
    )


def _chunk(case: dict) -> Chunk:
    ch = case["chunk"]
    return Chunk(
        chunk_ref=ch["chunk_ref"],
        text=ch["text"],
        chunk_domains=tuple(ch.get("chunk_domains", [])),
        acl_domains=tuple(ch.get("acl_domains", [])),
        human_confirmed_canonicals=frozenset(ch.get("human_confirmed_canonicals", [])),
    )


def _config(case: dict) -> Tier3Config:
    over = case.get("config", {})
    base = Tier3Config()
    return Tier3Config(
        tau_nil=over.get("tau_nil", base.tau_nil),
        margin_delta=over.get("margin_delta", base.margin_delta),
        auto_link_tier3=over.get("auto_link_tier3", base.auto_link_tier3),
    )


@dataclass
class MentionScore:
    """Per-mention grade: the case/candidate it belongs to, the expected vs
    predicted outcome, and whether it matched."""

    case_id: str
    canonical: str
    expected: str
    predicted: str
    correct: bool
    ambiguous: bool


@dataclass
class Tier3Report:
    total_mentions: int = 0
    correct: int = 0
    ambiguous_tags: int = 0  # LOAD-BEARING: must be 0 (no guess on an ambiguous mention)
    tag_false_positives: int = 0  # a `tag` where the label was NOT a tag
    outcome_counts: Counter = field(default_factory=Counter)
    per_mention: list[MentionScore] = field(default_factory=list)
    # cases whose mentions all matched their labels.
    cases_all_correct: int = 0
    total_cases: int = 0

    @property
    def accuracy(self) -> float:
        return 1.0 if self.total_mentions == 0 else self.correct / self.total_mentions


def evaluate(cases: list[dict], detector: MentionDetector | None = None) -> Tier3Report:
    """Score the labeled set with the SHIPPED Tier-3 pipeline. ``detector``
    defaults to the LLM-free ``NullMentionDetector`` (gazetteer-only, no key)."""
    detector = detector or NullMentionDetector()
    rep = Tier3Report()

    for case in cases:
        rep.total_cases += 1
        gaz = _gazetteer(case)
        chunk = _chunk(case)
        cfg = _config(case)
        expected: dict[str, str] = dict(case.get("expect", {}))
        ambiguous = case.get("kind") == "margin_abstain"

        result = plan_tier3(TENANT, [chunk], gaz, cfg, detector=detector)

        # Map each decision to a per-canonical outcome. For a resolved decision
        # (TAG / REVIEWER_HINT) only the CHOSEN top canonical is scored. For an
        # ABSTAIN_MARGIN / NIL decision NO entity was chosen, so the abstain
        # outcome applies to EVERY plausible candidate the mention surfaced — that
        # is the whole point of the gate (both Acmes were abstained on, not one).
        # A candidate-less NIL has no canonical and leaves the case empty.
        predicted: dict[str, str] = {}
        for d in result.decisions:
            if d.outcome in (Tier3Outcome.TAG, Tier3Outcome.REVIEWER_HINT):
                if d.top is not None:
                    predicted[d.top.entity.canonical] = d.outcome.value
            else:  # NIL / ABSTAIN_MARGIN — no entity chosen; applies to all candidates
                for c in d.candidates:
                    predicted[c.entity.canonical] = d.outcome.value

        case_ok = True
        # Grade every expected canonical.
        keys = set(expected) | set(predicted)
        for canonical in sorted(keys):
            exp = expected.get(canonical, "nil")  # unexpected prediction => should've been nil
            pred = predicted.get(canonical, "nil")  # missing prediction => effectively nil
            correct = exp == pred
            case_ok = case_ok and correct
            rep.total_mentions += 1
            if correct:
                rep.correct += 1
            rep.outcome_counts[pred] += 1
            if ambiguous and pred == Tier3Outcome.TAG.value:
                rep.ambiguous_tags += 1
            if pred == Tier3Outcome.TAG.value and exp != Tier3Outcome.TAG.value:
                rep.tag_false_positives += 1
            rep.per_mention.append(
                MentionScore(
                    case_id=case["id"],
                    canonical=canonical,
                    expected=exp,
                    predicted=pred,
                    correct=correct,
                    ambiguous=ambiguous,
                )
            )
        # An expected-empty case (no mentions at all) is correct iff nothing was
        # emitted for any catalog canonical.
        if not keys:
            case_ok = not result.to_emit
        if case_ok:
            rep.cases_all_correct += 1

    return rep


# ---------------------------------------------------------------------------
# Report writers (mirror the resolve_tier2_eval dated JSON+MD emit)
# ---------------------------------------------------------------------------


def _report_md(rep: Tier3Report, detector_name: str, cases_path: Path) -> str:
    lines: list[str] = []
    lines.append(f"# ER Tier-3 unstructured-mention producer — measured eval ({detector_name})")
    lines.append("")
    lines.append(
        f"Eval set: `{cases_path}` — **{rep.total_cases} labeled chunks**, "
        f"**{rep.total_mentions} graded mention-decisions**."
    )
    lines.append("")
    lines.append(
        "Pipeline: `resolve_tier3.plan_tier3` (detect -> retrieve -> disambiguate) "
        f"with the `{detector_name}` detector. Graded on the TWO-DECISION outcome "
        "taxonomy (nil / abstain_margin / reviewer_hint / tag), not same/not-same "
        "(cross-source-entity-resolution.md §5)."
    )
    lines.append("")
    lines.append("## Result")
    lines.append("")
    lines.append("| metric | value |")
    lines.append("|---|---|")
    lines.append(f"| decision accuracy | **{rep.accuracy:.4f}** |")
    lines.append(f"| cases fully correct | {rep.cases_all_correct}/{rep.total_cases} |")
    lines.append(
        f"| **ambiguous-mention tags** (must be 0) | **{rep.ambiguous_tags}** |"
    )
    lines.append(f"| tag false-positives (tagged wrong outcome) | {rep.tag_false_positives} |")
    oc = rep.outcome_counts
    lines.append(
        f"| outcome mix (nil/abstain/hint/tag) | "
        f"{oc.get('nil',0)} / {oc.get('abstain_margin',0)} / "
        f"{oc.get('reviewer_hint',0)} / {oc.get('tag',0)} |"
    )
    lines.append("")
    lines.append(
        "**Abstain-as-security framing.** Decision B (WHICH entity) is precision-"
        "first: tagging the wrong 'Acme' mis-files content into a real customer's "
        "scope. So **`ambiguous-mention tags` is the load-bearing number — it must "
        "be 0**: a mention with two plausible candidates must resolve to NIL / "
        "abstain, never a guess. Tier-3 is non-authoritative: it never forms an "
        "edge or widens a scope on its own (§5)."
    )
    lines.append("")
    wrong = [m for m in rep.per_mention if not m.correct]
    if wrong:
        lines.append(f"## Mismatches ({len(wrong)})")
        lines.append("")
        for m in wrong:
            lines.append(
                f"- `{m.case_id}` {m.canonical}: expected `{m.expected}`, got `{m.predicted}`"
            )
        lines.append("")
    else:
        lines.append("## Mismatches")
        lines.append("")
        lines.append(
            "**None.** Every labeled mention-decision matched: co-signed confident "
            "mentions TAG, uncorroborated confident mentions are REVIEWER_HINTs, "
            "ambiguous mentions ABSTAIN, and unknown/weak mentions NIL. No ambiguous "
            "mention was ever tagged."
        )
        lines.append("")
    return "\n".join(lines) + "\n"


def write_reports(
    rep: Tier3Report, detector_name: str, cases_path: Path, out_dir: Path, on: date | None = None
) -> tuple[Path, Path]:
    on = on or date.today()
    stamp = on.isoformat()
    json_path = out_dir / f"RESULTS-resolve-tier3-{detector_name}-{stamp}.json"
    md_path = out_dir / f"RESULTS-resolve-tier3-{detector_name}-{stamp}.md"
    sidecar = {
        "date": stamp,
        "metric": "tier3_mention_decision_accuracy",
        "detector": detector_name,
        "eval_set": str(cases_path),
        "result": {
            "total_cases": rep.total_cases,
            "total_mentions": rep.total_mentions,
            "accuracy": rep.accuracy,
            "cases_all_correct": rep.cases_all_correct,
            "ambiguous_tags": rep.ambiguous_tags,
            "tag_false_positives": rep.tag_false_positives,
            "outcome_counts": dict(rep.outcome_counts),
        },
    }
    json_path.write_text(json.dumps(sidecar, indent=2, sort_keys=True) + "\n")
    md_path.write_text(_report_md(rep, detector_name, cases_path))
    return json_path, md_path


def _build_detector(detector_name: str) -> MentionDetector:
    """Construct the requested detector. The live ``anthropic`` NER backstop is
    imported and constructed LAZILY and ONLY when explicitly asked, so the default
    (deterministic) path never imports the live seam and never needs a key."""
    if detector_name == "null":
        return NullMentionDetector()
    if detector_name == "anthropic":
        from verity_ingest.resolve_tier3 import AnthropicMentionDetector

        return AnthropicMentionDetector()
    raise ValueError(f"unknown detector {detector_name!r}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Measured eval for the ER Tier-3 unstructured-mention producer"
    )
    parser.add_argument(
        "--detector",
        choices=["null", "anthropic"],
        default="null",
        help="null (LLM-free gazetteer-only, NO key — the default) or anthropic "
        "(live NER backstop; reads ANTHROPIC_API_KEY from the operator's environment)",
    )
    parser.add_argument(
        "--cases",
        type=Path,
        default=DEFAULT_CASES,
        help="path to the labeled mention-case set (default: the checked-in fixture)",
    )
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="print the table only; do not write the dated JSON+MD sidecar",
    )
    args = parser.parse_args(argv)

    cases = load_cases(args.cases)
    detector = _build_detector(args.detector)
    rep = evaluate(cases, detector)

    print(f"ER Tier-3 mention producer ({args.detector}) over {args.cases}")
    print(f"  cases: {rep.total_cases}  mentions graded: {rep.total_mentions}")
    print(f"  decision accuracy: {rep.accuracy:.4f}  cases fully correct: "
          f"{rep.cases_all_correct}/{rep.total_cases}")
    oc = rep.outcome_counts
    print(
        f"  outcomes: nil {oc.get('nil',0)}  abstain {oc.get('abstain_margin',0)}  "
        f"hint {oc.get('reviewer_hint',0)}  tag {oc.get('tag',0)}"
    )
    print(f"  AMBIGUOUS-MENTION TAGS (must be 0): {rep.ambiguous_tags}")
    if rep.ambiguous_tags:
        print("  *** ABSTAIN GATE BREACH: an ambiguous mention was tagged ***")

    if not args.no_report:
        json_path, md_path = write_reports(rep, args.detector, args.cases, _BENCH_DIR)
        print(f"  wrote {json_path}")
        print(f"  wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
