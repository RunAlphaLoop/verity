"""Measured-eval harness for the ER Tier-2 entity-resolution JUDGE.

The knowledge-merge cascade has a measured judge eval (``consolidation_eval.py``,
SRB metric #6). Entity resolution has the SAME precision-as-security posture — a
false merge here UNIONS two customers' scopes (a leak, not a data nit;
resolve_tier2.py §3.2) — but its sameness judge had no measured eval. This closes
that gap, mirroring the knowledge-merge harness structure and metrics exactly.

What is measured
----------------
For each labeled entity PAIR in the fixture
``ingest/tests/fixtures/entity_resolution/entity_pairs.json`` (two business
entities each, name + optional domain + source ref, labeled ``same`` true/false),
we run the SHIPPED Tier-2 sameness decision — an ``EntityJudge`` from
``resolve_tier2`` — and compare its verdict to the label. We report the confusion
matrix (TP/FP/TN/FN), precision, recall, F1, and the **false-merge rate**
``FP/(FP+TN)`` — the load-bearing number, since a false merge is a scope leak.

Two judges plug in behind the SAME seam (``--judge``), exactly like the
consolidation harness:

  - ``deterministic`` — ``EntityDeterministicJudge``, LLM-FREE, needs NO API key.
    The honest oracle every test uses. Precision-first: exact shared registrable
    domain + agreeing names => SAME; anything softer/ambiguous => NOT SAME.
  - ``anthropic`` — ``EntityAnthropicJudge``, the LIVE seam. It is constructed
    ONLY when explicitly selected (``--judge anthropic``); a plain run never
    touches it, so no key is needed or read for the default (deterministic) path.
    The live judge reads ``ANTHROPIC_API_KEY`` from the OPERATOR's environment at
    construction time (inherited verbatim from ``consolidation.AnthropicJudge``);
    this harness never embeds, prints, reads-from-a-literal, or otherwise handles
    a key.

Upstream denylist (fail-closed pre-filter)
------------------------------------------
Free-mail / webmail / placeholder domains (gmail.com, outlook.com, ...) carry NO
company identity: two records sharing gmail.com are co-tenants, not the same
company. In production these are denylisted UPSTREAM of the judge (see
``EntityDeterministicJudge``'s docstring: "free-mail domains are denylisted
upstream"). The harness models that pre-filter deterministically: a pair whose
shared domain is free-mail is treated as having NO usable domain signal before
the judge sees it, so the judge cannot fuse on a co-tenant domain. This is a
precision guard, never a permissive one — it only ever REMOVES a spurious merge
signal, never adds one.

Run standalone to print the metrics table and write a dated JSON+MD sidecar:

    python -m verity_ingest.resolve_tier2_eval               # deterministic (no key)
    python -m verity_ingest.resolve_tier2_eval --judge anthropic   # live (operator key)
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from verity_ingest.resolve_tier2 import (
    Entity,
    EntityDeterministicJudge,
    EntityJudge,
    normalize_domain,
)

# The labeled set lives with the other ingest test fixtures.
DEFAULT_PAIRS = (
    Path(__file__).resolve().parents[1]
    / "tests"
    / "fixtures"
    / "entity_resolution"
    / "entity_pairs.json"
)

_BENCH_DIR = Path(__file__).resolve().parents[2] / "docs" / "benchmark"

# Free-mail / webmail / placeholder domains that carry NO company identity. A
# pair sharing one of these is co-tenancy, not co-company; it must never be a
# merge signal. Denylisted upstream in production; modeled here as a pre-filter.
FREEMAIL_DOMAINS = frozenset(
    {
        "gmail.com",
        "googlemail.com",
        "yahoo.com",
        "ymail.com",
        "hotmail.com",
        "outlook.com",
        "live.com",
        "msn.com",
        "aol.com",
        "icloud.com",
        "me.com",
        "mac.com",
        "proton.me",
        "protonmail.com",
        "gmx.com",
        "mail.com",
        "zoho.com",
        "yandex.com",
        "fastmail.com",
        "example.com",
    }
)


def is_freemail(domain: str) -> bool:
    """True iff the (normalized) domain is a free-mail/webmail/placeholder host
    that carries no company identity."""
    return normalize_domain(domain) in FREEMAIL_DOMAINS


def _denylist_domain(ent: Entity) -> Entity:
    """Blank an entity's domain if it is free-mail — the upstream denylist. This
    strips a spurious identity signal BEFORE the judge, so a shared co-tenant
    domain (two people @gmail.com) can never be read as one company. It only ever
    weakens evidence (fail closed), never strengthens it."""
    if ent.domain and is_freemail(ent.domain):
        return Entity(ref=ent.ref, name=ent.name, domain="")
    return ent


@dataclass
class Confusion:
    """Pair-level confusion for the sameness decision. Mirrors
    ``consolidation_eval.Confusion`` byte-for-byte (same metric definitions) so
    the two harnesses are directly comparable."""

    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    def observe(self, predicted_merge: bool, truth_same: bool) -> None:
        if predicted_merge and truth_same:
            self.tp += 1
        elif predicted_merge and not truth_same:
            self.fp += 1
        elif not predicted_merge and not truth_same:
            self.tn += 1
        else:
            self.fn += 1

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return 1.0 if d == 0 else self.tp / d

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return 0.0 if d == 0 else self.tp / d

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 0.0 if p + r == 0 else 2 * p * r / (p + r)

    @property
    def false_merge_rate(self) -> float:
        d = self.fp + self.tn
        return 0.0 if d == 0 else self.fp / d


def _entity(side: dict) -> Entity:
    return Entity(
        ref=side["ref"],
        name=side.get("name", ""),
        domain=side.get("domain", ""),
    )


def load_pairs(pairs_path: Path | None = None) -> list[dict]:
    """Load the labeled entity-pair set. Accepts the fixture's ``{"pairs": [...]}``
    object shape (keys other than ``pairs`` are metadata and ignored)."""
    path = pairs_path or DEFAULT_PAIRS
    doc = json.loads(path.read_text())
    return list(doc["pairs"])


def decide_same(judge: EntityJudge, left: Entity, right: Entity) -> bool:
    """The Tier-2 sameness decision for one pair as the given judge renders it,
    AFTER the upstream free-mail denylist pre-filter. This is exactly what the
    producer's blocker->judge cascade would decide for the pair (the blocker only
    reduces what reaches the judge; here we score the judge directly, so the
    comparison across judges is apples-to-apples — same as the consolidation
    harness scores the judge decision directly)."""
    return judge.judge(_denylist_domain(left), _denylist_domain(right)).same


def evaluate(judge: EntityJudge, pairs: list[dict]) -> dict:
    """Score the labeled set with ``judge``. Returns precision/recall/F1/
    false_merge_rate + confusion counts, plus the corpus breakdown and the
    false-merge / missed example lists (for the honesty section of the report).

    ``judge`` is any ``EntityJudge`` — pass ``EntityDeterministicJudge()`` for the
    offline oracle (no key) or ``EntityAnthropicJudge()`` for the live seam."""
    c = Confusion()
    n_pos = n_hard = n_easy = 0
    false_merges: list[dict] = []
    missed: list[dict] = []

    for p in pairs:
        left, right = _entity(p["left"]), _entity(p["right"])
        truth = bool(p["same"])
        predicted = decide_same(judge, left, right)
        c.observe(predicted, truth)

        if truth:
            n_pos += 1
        elif p.get("kind") == "easy_negative":
            n_easy += 1
        else:
            n_hard += 1

        if predicted and not truth:
            false_merges.append(
                {
                    "id": p.get("id"),
                    "left": [left.name, left.domain],
                    "right": [right.name, right.domain],
                    "rationale": p.get("rationale", ""),
                }
            )
        if not predicted and truth:
            missed.append(
                {
                    "id": p.get("id"),
                    "left": [left.name, left.domain],
                    "right": [right.name, right.domain],
                }
            )

    return {
        "corpus": {
            "total": c.tp + c.fp + c.tn + c.fn,
            "positives": n_pos,
            "hard_negatives": n_hard,
            "easy_negatives": n_easy,
            "negatives": n_hard + n_easy,
        },
        "confusion": {"tp": c.tp, "fp": c.fp, "tn": c.tn, "fn": c.fn},
        "precision": c.precision,
        "recall": c.recall,
        "f1": c.f1,
        "false_merge_rate": c.false_merge_rate,
        "false_merges": false_merges,
        "missed_examples": missed,
    }


# ---------------------------------------------------------------------------
# Report writers (mirror the consolidation/tagger dated JSON+MD emit)
# ---------------------------------------------------------------------------


def _report_md(r: dict, judge_name: str, pairs_path: Path) -> str:
    c, cf = r["corpus"], r["confusion"]
    lines: list[str] = []
    lines.append(f"# ER Tier-2 entity-resolution judge — measured eval ({judge_name})")
    lines.append("")
    lines.append(
        f"Eval set: `{pairs_path}` — **{c['total']} labeled entity pairs** "
        f"({c['positives']} positives, {c['hard_negatives']} hard negatives, "
        f"{c['easy_negatives']} easy negatives)."
    )
    lines.append("")
    lines.append(
        "Judge: `%s` from `ingest/verity_ingest/resolve_tier2.py`, scored exactly "
        "as the Tier-2 producer's blocker->judge cascade decides a pair "
        "(pairwise \"same entity?\", strict, fail-closed), after the upstream "
        "free-mail denylist pre-filter. Mirrors the knowledge-merge judge eval "
        "(`consolidation_eval.py`, SRB metric #6) — directly comparable." % judge_name
    )
    lines.append("")
    lines.append("## Result")
    lines.append("")
    lines.append("| metric | value |")
    lines.append("|---|---|")
    lines.append(f"| precision | **{r['precision']:.4f}** |")
    lines.append(f"| recall | {r['recall']:.4f} |")
    lines.append(f"| F1 | {r['f1']:.4f} |")
    lines.append(f"| **false-merge rate** (FP/(FP+TN)) | **{r['false_merge_rate']:.4f}** |")
    lines.append(
        f"| confusion (TP/FP/TN/FN) | {cf['tp']} / {cf['fp']} / {cf['tn']} / {cf['fn']} |"
    )
    lines.append("")
    lines.append(
        "**Precision-as-security framing.** A false merge unions two customers' "
        "data scopes — a leak, not a data nit (resolve_tier2.py §3.2). So the "
        "**false-merge rate is the load-bearing number**; recall is the capability "
        "the live judge buys. Under-merge is safe (a missed review candidate); a "
        "wrong merge is not."
    )
    lines.append("")
    if r["false_merges"]:
        lines.append(f"## FALSE MERGES ({len(r['false_merges'])}) — the failure this forbids")
        lines.append("")
        for e in r["false_merges"]:
            lines.append(
                f"- `{e['id']}` {e['left']} == {e['right']} — {e['rationale']}"
            )
        lines.append("")
    else:
        lines.append("## False merges")
        lines.append("")
        lines.append(
            "**None.** No hard or easy negative was fused — false-merge rate 0.0 on "
            "this set. Every confusable-but-distinct company (Acme Corp vs Acme "
            "Freight, Delta Air Lines vs Delta Faucet, parent vs distinct subsidiary, "
            "free-mail co-tenants) stayed apart."
        )
        lines.append("")
    if r["missed_examples"]:
        lines.append(f"## Missed merges ({len(r['missed_examples'])}) — the recall gap")
        lines.append("")
        lines.append(
            "True cross-source dups the judge called \"not same\" — the ACCEPTABLE "
            "failure (a missed review candidate, not a leak). For the deterministic "
            "oracle these are the same-company pairs lacking a clean shared domain; "
            "the live `EntityAnthropicJudge` is the intended fix, lifting recall "
            "without lowering precision."
        )
        lines.append("")
        for e in r["missed_examples"]:
            lines.append(f"- `{e['id']}` {e['left']} == {e['right']}")
        lines.append("")
    return "\n".join(lines) + "\n"


def write_reports(
    r: dict, judge_name: str, pairs_path: Path, out_dir: Path, on: date | None = None
) -> tuple[Path, Path]:
    on = on or date.today()
    stamp = on.isoformat()
    json_path = out_dir / f"RESULTS-resolve-tier2-{judge_name}-{stamp}.json"
    md_path = out_dir / f"RESULTS-resolve-tier2-{judge_name}-{stamp}.md"
    sidecar = {
        "date": stamp,
        "metric": "entity_resolution_judge_precision_recall",
        "judge": judge_name,
        "eval_set": str(pairs_path),
        "result": r,
    }
    json_path.write_text(json.dumps(sidecar, indent=2, sort_keys=True) + "\n")
    md_path.write_text(_report_md(r, judge_name, pairs_path))
    return json_path, md_path


def _build_judge(judge_name: str) -> EntityJudge:
    """Construct the requested judge. The live ``anthropic`` judge is imported and
    constructed LAZILY and ONLY when explicitly asked, so the default
    (deterministic) path never imports the live seam and never needs a key."""
    if judge_name == "deterministic":
        return EntityDeterministicJudge()
    if judge_name == "anthropic":
        # Lazy: only reached when the operator explicitly opts in. Construction
        # reads ANTHROPIC_API_KEY from the operator's environment (inherited from
        # consolidation.AnthropicJudge); this module never touches the key.
        from verity_ingest.resolve_tier2 import EntityAnthropicJudge

        return EntityAnthropicJudge()
    raise ValueError(f"unknown judge {judge_name!r}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Measured eval for the ER Tier-2 entity-resolution judge"
    )
    parser.add_argument(
        "--judge",
        choices=["deterministic", "anthropic"],
        default="deterministic",
        help="deterministic (LLM-free oracle, NO key — the default) or anthropic "
        "(live seam; reads ANTHROPIC_API_KEY from the operator's environment)",
    )
    parser.add_argument(
        "--pairs",
        type=Path,
        default=DEFAULT_PAIRS,
        help="path to the labeled entity-pair set (default: the checked-in fixture)",
    )
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="print the table only; do not write the dated JSON+MD sidecar",
    )
    args = parser.parse_args(argv)

    pairs = load_pairs(args.pairs)
    judge = _build_judge(args.judge)
    r = evaluate(judge, pairs)
    c, cf = r["corpus"], r["confusion"]

    print(f"ER Tier-2 entity-resolution judge ({args.judge}) over {args.pairs}")
    print(
        f"  corpus: {c['total']} pairs "
        f"({c['positives']} positives, {c['hard_negatives']} hard negs, "
        f"{c['easy_negatives']} easy negs)"
    )
    print(f"  confusion: TP {cf['tp']}  FP {cf['fp']}  TN {cf['tn']}  FN {cf['fn']}")
    print(
        f"  precision {r['precision']:.4f}  recall {r['recall']:.4f}  "
        f"F1 {r['f1']:.4f}  false-merge-rate {r['false_merge_rate']:.4f}"
    )
    if r["false_merges"]:
        print(f"  FALSE MERGES ({len(r['false_merges'])}) — scope leaks:")
        for e in r["false_merges"]:
            print(f"    - {e['id']}  {e['left']}  ==  {e['right']}")
    else:
        print("  FALSE MERGES: none (false-merge rate 0.0)")

    if not args.no_report:
        json_path, md_path = write_reports(r, args.judge, args.pairs, _BENCH_DIR)
        print(f"  wrote {json_path}")
        print(f"  wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
