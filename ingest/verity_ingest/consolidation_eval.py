"""Metric #6 offline harness for the DeterministicJudge cascade.

Runs the Phase-2 merge cascade's DECISION (as the DeterministicJudge makes it)
over the labeled statement-pair eval set at docs/benchmark/consolidation-pairs.jsonl
and reports precision / recall / false-merge-rate — the same metric the Rust
`verity-bench` harness reports for the *cosine* baseline, so the two are directly
comparable.

What is measured (knowledge-merge-tuning.md §4): for each labeled pair (a, b) we
reproduce the cascade's same-generalization decision the DeterministicJudge would
render — canonical-exact OR the conservative structural rule (same required
artifact + same gate) — and compare to the `same_generalization` label. We report
the confusion matrix, precision, recall, F1, and the false-merge rate FP/(FP+TN),
which the trust contract caps at <= 1%.

This is the DeterministicJudge, LLM-free. The AnthropicJudge would beat this on
recall (it catches paraphrases the canonicalizer does not fully align) while
holding the same precision — but it needs a live key, so it is not run here.

Run standalone to print the numbers:

    python -m verity_ingest.consolidation_eval [path-to-pairs.jsonl]
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

from verity_ingest.consolidation import (
    DeterministicJudge,
    JudgeExisting,
    KnowledgeCandidate,
)

DEFAULT_PAIRS = (
    Path(__file__).resolve().parents[2] / "docs" / "benchmark" / "consolidation-pairs.jsonl"
)


@dataclass
class Confusion:
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


def _decide_same(judge: DeterministicJudge, a: str, b: str) -> bool:
    """The cascade's same-generalization decision for one unordered pair, as the
    DeterministicJudge renders it. Canonicalization happens inside the candidate;
    the judge applies canonical-exact OR the structural rule."""
    proposed = KnowledgeCandidate(a)
    existing = JudgeExisting(knowledge_id="x", statement=b)
    return judge.judge(proposed, existing).same


def evaluate(pairs_path: Path | None = None) -> dict:
    """Score the eval set with the DeterministicJudge cascade decision."""
    path = pairs_path or DEFAULT_PAIRS
    judge = DeterministicJudge()
    c = Confusion()
    n_pos = n_hard = n_easy = 0
    false_merges: list[tuple[str, str]] = []
    missed: list[tuple[str, str]] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        d = json.loads(line)
        truth = bool(d["same_generalization"])
        predicted = _decide_same(judge, d["a"], d["b"])
        c.observe(predicted, truth)
        if truth:
            n_pos += 1
        elif d.get("kind") == "easy_negative":
            n_easy += 1
        else:
            n_hard += 1
        if predicted and not truth:
            false_merges.append((d["a"], d["b"]))
        if not predicted and truth:
            missed.append((d["a"], d["b"]))
    return {
        "corpus": {
            "total": c.tp + c.fp + c.tn + c.fn,
            "positives": n_pos,
            "hard_negatives": n_hard,
            "easy_negatives": n_easy,
        },
        "confusion": {"tp": c.tp, "fp": c.fp, "tn": c.tn, "fn": c.fn},
        "precision": c.precision,
        "recall": c.recall,
        "f1": c.f1,
        "false_merge_rate": c.false_merge_rate,
        "false_merges": false_merges,
        "missed_examples": missed[:5],
    }


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    path = Path(argv[0]) if argv else DEFAULT_PAIRS
    r = evaluate(path)
    c, cf = r["corpus"], r["confusion"]
    print(f"DeterministicJudge cascade — metric #6 over {path}")
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
        print(f"  FALSE MERGES ({len(r['false_merges'])}):")
        for a, b in r["false_merges"]:
            print(f"    - {a!r}  ==  {b!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
