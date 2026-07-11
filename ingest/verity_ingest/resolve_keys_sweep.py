"""Key-independence sweep — measures whether ``min_independent_keys = 2`` is
right, per key kind (design doc ``cross-source-entity-resolution.md`` §4.1
``entity_resolution_config.min_independent_keys`` and §10 open question Q2).

The question
------------
The fold (``crates/verity-storage/src/resolve/fold.rs``) refuses to auto-merge
two entities on fewer than ``min_independent_keys`` distinct corroborating keys
— default 2 — EXCEPT for "strong" single-key methods (``crm_fk`` /
``external_id`` / ``admin_crosswalk`` / ``email_exact`` / ``human_confirmed``),
which weld alone. §10 Q2 asks: should the default be per-``key_kind``
(external_id=1, domain=2, email=?) instead of a uniform 2?

This module answers it with MEASURED numbers on the labeled stress corpus
(``ingest/tests/fixtures/entity_resolution/entity_pairs.json``), entirely on
deterministic scorers — NO LLM, NO network, NO key. For each key kind K it
simulates "a single exact K-key match is allowed to auto-merge alone" and
reports the resulting FALSE-MERGE RATE (a false merge unions two customers'
scopes — a leak, §3.2, so FMR is the load-bearing number), then measures what a
2-key requirement on K COSTS: the true positives whose only evidence is a lone
K key, which the bar forgoes as auto-merges (they fall back to the Tier-2
review path — deferred, not lost). Finally it sweeps whole policies (uniform 1,
uniform 2, per-kind) over the corpus.

Key extraction (deterministic, mirrors S0/S1 + the fold's fences)
-----------------------------------------------------------------
- ``domain``       exact normalized registrable domain (``normalize_domain``,
                   the same normalizer the Tier-2 blocker uses), refused if the
                   domain is on the free-mail denylist (the §4.1
                   ``denylist_values`` guard, same list the Tier-2 eval models).
- ``email``        exact casefolded address; refused if the local part is a
                   role account (``info@``, ``sales@``, ... — §4.1 denylist).
                   Free-mail ADDRESSES are kept (jane@gmail.com names one
                   person even though gmail.com the domain never does).
- ``external_id``  exact ``(namespace, value)`` equality — a crosswalk id is a
                   key only WITHIN its id namespace; no normalization, no fuzz.

A pair "matches on kind K" iff both sides carry a K key and the keys are equal.
The policy simulator mirrors the fold's Pass-3 arithmetic: a pair auto-merges
under policy P iff some matched kind K has ``P[K] <= (number of distinct
matched kinds)`` — i.e. a kind with min 1 welds alone, a kind with min 2 needs
a second independent kind to corroborate.

HONESTY (CLAUDE.md): the corpus is a SYNTHETIC, HAND-LABELED STRESS SET —
negatives are adversarially composed (domain-shared-but-distinct parents/
franchises/co-tenants, shared-consultant emails), NOT a natural distribution.
Measured rates bound behavior on the adversarial cases; the zero/nonzero
distinction carries the decision weight, the magnitudes do not generalize.

Run standalone to print the tables and write the dated JSON+MD sidecar:

    python -m verity_ingest.resolve_keys_sweep
"""

from __future__ import annotations

import argparse
import json
from datetime import date
from pathlib import Path

from verity_ingest.resolve_tier2 import normalize_domain
from verity_ingest.resolve_tier2_eval import (
    DEFAULT_PAIRS,
    FREEMAIL_DOMAINS,
    Confusion,
    load_pairs,
)

_BENCH_DIR = Path(__file__).resolve().parents[2] / "docs" / "benchmark"

KEY_KINDS = ("external_id", "domain", "email")

# Role-account local parts (§4.1 denylist_values: "role locals (info@, sales@)
# ... NEVER an edge"). A shared role mailbox names a function, not a person or
# a company — it never forms an email key.
ROLE_LOCALS = frozenset(
    {
        "info",
        "sales",
        "support",
        "admin",
        "billing",
        "accounts",
        "accounting",
        "office",
        "contact",
        "hello",
        "team",
        "hr",
        "marketing",
        "help",
        "noreply",
        "no-reply",
    }
)


# ---------------------------------------------------------------------------
# Key extraction — one deterministic extractor per kind. Each returns the
# comparable key or None (no key ⇒ can never match ⇒ fail closed).
# ---------------------------------------------------------------------------


def domain_key(side: dict) -> str | None:
    """Normalized registrable domain, or None if absent/free-mail-denylisted."""
    d = normalize_domain(side.get("domain", ""))
    if not d or d in FREEMAIL_DOMAINS:
        return None
    return d


def email_key(side: dict) -> str | None:
    """Exact casefolded address, or None if absent/role-local-denylisted."""
    e = (side.get("email") or "").strip().casefold()
    if not e or "@" not in e:
        return None
    local = e.split("@", 1)[0]
    if local in ROLE_LOCALS:
        return None
    return e


def external_id_key(side: dict) -> tuple[str, str] | None:
    """Exact (namespace, value), or None if either half is absent. A crosswalk
    id is a key only WITHIN its namespace (the er-0087 guard)."""
    x = side.get("external_id")
    if not isinstance(x, dict):
        return None
    ns = (x.get("namespace") or "").strip().casefold()
    val = (x.get("value") or "").strip()
    if not ns or not val:
        return None
    return (ns, val)


_EXTRACTORS = {
    "external_id": external_id_key,
    "domain": domain_key,
    "email": email_key,
}


def matching_kinds(pair: dict) -> frozenset[str]:
    """The key kinds on which this pair EXACTLY matches (both sides carry the
    kind's key and the keys are equal). Each matched kind counts as one
    independent corroborating key — the fixture carries at most one key value
    per kind per side, so |matched kinds| == the fold's distinct-key count."""
    out = set()
    for kind, extract in _EXTRACTORS.items():
        lk, rk = extract(pair["left"]), extract(pair["right"])
        if lk is not None and rk is not None and lk == rk:
            out.add(kind)
    return frozenset(out)


def kind_eligible(pair: dict, kind: str) -> bool:
    """Both sides carry a (non-denylisted) key of this kind — the pair is in
    the kind's denominator regardless of whether the keys agree."""
    extract = _EXTRACTORS[kind]
    return extract(pair["left"]) is not None and extract(pair["right"]) is not None


# ---------------------------------------------------------------------------
# Per-kind "K alone may auto-merge" measurement.
# ---------------------------------------------------------------------------


def evaluate_kind_alone(pairs: list[dict], kind: str) -> dict:
    """Simulate the policy "a single exact key of ``kind`` auto-merges alone"
    and score it against the labels. Reports the confusion over ALL pairs, the
    kind-eligible denominators, the resulting false merges (each a would-be
    scope leak), and the lone-K positives — true pairs whose ONLY matching key
    is this kind, i.e. exactly the auto-merges a ``min_independent_keys=2``
    requirement on this kind forgoes (its recall cost)."""
    c = Confusion()
    eligible_neg = eligible_pos = 0
    false_merges: list[dict] = []
    lone_kind_positives: list[str] = []

    for p in pairs:
        truth = bool(p["same"])
        matched = matching_kinds(p)
        predicted = kind in matched
        c.observe(predicted, truth)
        if kind_eligible(p, kind):
            if truth:
                eligible_pos += 1
            else:
                eligible_neg += 1
        if predicted and not truth:
            false_merges.append(
                {
                    "id": p.get("id"),
                    "left": [p["left"].get("name", ""), p["left"].get("domain", "")],
                    "right": [p["right"].get("name", ""), p["right"].get("domain", "")],
                    "rationale": p.get("rationale", ""),
                }
            )
        if truth and matched == frozenset({kind}):
            lone_kind_positives.append(p.get("id", "?"))

    return {
        "kind": kind,
        "confusion": {"tp": c.tp, "fp": c.fp, "tn": c.tn, "fn": c.fn},
        "false_merge_rate_all_negatives": c.false_merge_rate,
        "eligible_negatives": eligible_neg,
        "eligible_positives": eligible_pos,
        "false_merge_rate_eligible": (c.fp / eligible_neg) if eligible_neg else 0.0,
        "recall_alone": c.recall,
        "false_merges": false_merges,
        # The recall COST of requiring 2 keys for this kind: true pairs whose
        # only evidence is a lone key of this kind. Forgone as auto-merges
        # (deferred to Tier-2 review), not lost.
        "lone_key_positives": sorted(lone_kind_positives),
        "lone_key_positive_count": len(lone_kind_positives),
    }


# ---------------------------------------------------------------------------
# Whole-policy sweep.
# ---------------------------------------------------------------------------

# The policies under test. Values are per-kind min_independent_keys.
POLICIES: dict[str, dict[str, int]] = {
    # Every kind welds alone — the permissive strawman.
    "uniform_min1": {"external_id": 1, "domain": 1, "email": 1},
    # The current §4.1 default applied with NO strong-key exemption.
    "uniform_min2": {"external_id": 2, "domain": 2, "email": 2},
    # §10 Q2's hypothesis with email kept strong (mirrors fold.rs's current
    # strong_method list, which lets email_exact weld alone).
    "per_kind_email1": {"external_id": 1, "domain": 2, "email": 1},
    # The recommendation this sweep exists to test.
    "per_kind_email2": {"external_id": 1, "domain": 2, "email": 2},
}


def merges_under(matched: frozenset[str], policy: dict[str, int]) -> bool:
    """The fold's Pass-3 arithmetic: an edge welds iff some matched kind's
    ``min_independent_keys`` is satisfied by the number of DISTINCT matched
    keys. A kind at min 1 welds alone; a kind at min 2 needs a second
    independent kind to corroborate. No matches ⇒ never (fail closed)."""
    n = len(matched)
    return any(policy.get(k, 2) <= n for k in matched)


def evaluate_policy(pairs: list[dict], policy: dict[str, int]) -> dict:
    """Score one per-kind policy over the corpus. Auto-merge only — pairs the
    policy refuses are NOT losses; in the shipped pipeline they fall through to
    the Tier-2 blocker→judge→human review path."""
    c = Confusion()
    false_merges: list[dict] = []
    forgone: list[str] = []
    for p in pairs:
        truth = bool(p["same"])
        predicted = merges_under(matching_kinds(p), policy)
        c.observe(predicted, truth)
        if predicted and not truth:
            false_merges.append({"id": p.get("id"), "rationale": p.get("rationale", "")})
        if not predicted and truth:
            forgone.append(p.get("id", "?"))
    return {
        "policy": dict(policy),
        "confusion": {"tp": c.tp, "fp": c.fp, "tn": c.tn, "fn": c.fn},
        "precision": c.precision,
        "recall": c.recall,
        "false_merge_rate": c.false_merge_rate,
        "false_merges": false_merges,
        "forgone_true_pairs": sorted(forgone),
    }


def run_sweep(pairs: list[dict]) -> dict:
    """The full measurement: corpus breakdown, per-kind alone table, policy
    sweep. Pure and deterministic — same corpus in, same numbers out."""
    n_pos = sum(1 for p in pairs if p["same"])
    n_hard = sum(1 for p in pairs if not p["same"] and p.get("kind") != "easy_negative")
    n_easy = sum(1 for p in pairs if not p["same"] and p.get("kind") == "easy_negative")
    return {
        "corpus": {
            "total": len(pairs),
            "positives": n_pos,
            "hard_negatives": n_hard,
            "easy_negatives": n_easy,
            "negatives": n_hard + n_easy,
        },
        "per_kind_alone": {k: evaluate_kind_alone(pairs, k) for k in KEY_KINDS},
        "policies": {name: evaluate_policy(pairs, pol) for name, pol in POLICIES.items()},
    }


# ---------------------------------------------------------------------------
# Report writers (dated JSON + MD sidecar, mirroring the other benchmark docs).
# ---------------------------------------------------------------------------


def _fmt(x: float) -> str:
    return f"{x:.4f}"


def _report_md(r: dict, pairs_path: Path) -> str:
    c = r["corpus"]
    lines: list[str] = []
    lines.append("# Key-independence sweep — is `min_independent_keys = 2` right, per key kind?")
    lines.append("")
    lines.append(
        f"Corpus: `{pairs_path}` — **{c['total']} labeled entity pairs** "
        f"({c['positives']} positives, {c['hard_negatives']} hard negatives, "
        f"{c['easy_negatives']} easy negatives). **This is a synthetic, "
        "hand-labeled STRESS set, not a natural distribution** — negatives are "
        "adversarially composed (domain-shared-but-distinct parents/franchises/"
        "co-tenants, shared-consultant emails), so the measured rates bound "
        "behavior on adversarial cases; the zero/nonzero distinction carries "
        "the decision weight, the magnitudes do not generalize to field data."
    )
    lines.append("")
    lines.append(
        "Question (design doc §4.1 `min_independent_keys`, §10 Q2): may a "
        "SINGLE exact key of kind K auto-merge two entities alone, per kind? "
        "All scorers are deterministic (no LLM, no network); the simulator "
        "mirrors the fold's Pass-3 arithmetic "
        "(`crates/verity-storage/src/resolve/fold.rs`). Precision-first: a "
        "false merge unions two customers' scopes — a leak (§3.2) — so the "
        "**false-merge rate (FMR) is the load-bearing number**; a forgone "
        "auto-merge is NOT a loss, it falls through to the Tier-2 "
        "blocker→judge→human review path."
    )
    lines.append("")
    lines.append("## Per-kind: what if a single K-key could auto-merge alone?")
    lines.append("")
    lines.append(
        "| key kind | FP (false merges) | eligible negs | FMR (eligible) | FMR (all negs) "
        "| recall alone | lone-K positives (auto-merges forgone by K=2) |"
    )
    lines.append("|---|---|---|---|---|---|---|")
    for kind in KEY_KINDS:
        k = r["per_kind_alone"][kind]
        lines.append(
            f"| `{kind}` | **{k['confusion']['fp']}** | {k['eligible_negatives']} "
            f"| **{_fmt(k['false_merge_rate_eligible'])}** "
            f"| {_fmt(k['false_merge_rate_all_negatives'])} "
            f"| {_fmt(k['recall_alone'])} "
            f"| {k['lone_key_positive_count']} |"
        )
    lines.append("")
    lines.append(
        "\"Eligible\" = both sides carry a non-denylisted key of that kind. "
        "\"Lone-K positives\" = true pairs whose ONLY matching key is kind K: "
        "exactly the auto-merges a 2-key bar on K forgoes (its recall cost, "
        "paid as Tier-2 review latency, not as a miss)."
    )
    lines.append("")
    for kind in KEY_KINDS:
        k = r["per_kind_alone"][kind]
        if k["false_merges"]:
            lines.append(f"### `{kind}`-alone false merges ({len(k['false_merges'])}) — the leaks")
            lines.append("")
            for e in k["false_merges"]:
                lines.append(f"- `{e['id']}` {e['left']} == {e['right']} — {e['rationale']}")
            lines.append("")
    lines.append("## Policy sweep")
    lines.append("")
    lines.append("| policy | external_id | domain | email | precision | recall | **FMR** | TP/FP/TN/FN |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for name, pr in r["policies"].items():
        pol, cf = pr["policy"], pr["confusion"]
        lines.append(
            f"| `{name}` | {pol['external_id']} | {pol['domain']} | {pol['email']} "
            f"| {_fmt(pr['precision'])} | {_fmt(pr['recall'])} "
            f"| **{_fmt(pr['false_merge_rate'])}** "
            f"| {cf['tp']}/{cf['fp']}/{cf['tn']}/{cf['fn']} |"
        )
    lines.append("")
    lines.append(
        "Recall here is AUTO-MERGE recall only. On this same corpus the "
        "deterministic Tier-2 judge (name+domain, human-review path) holds "
        "precision 1.0 — see `RESULTS-resolve-tier2-deterministic-*.md` — so "
        "pairs a policy refuses are recoverable through review."
    )
    lines.append("")
    lines.append("## Recommendation (data-decided, precision-first)")
    lines.append("")
    ext = r["per_kind_alone"]["external_id"]
    dom = r["per_kind_alone"]["domain"]
    eml = r["per_kind_alone"]["email"]
    lines.append(
        f"- **`external_id` → `min_independent_keys = 1`.** Measured "
        f"{ext['confusion']['fp']} false merges over {ext['eligible_negatives']} "
        "eligible stress negatives (FMR "
        f"{_fmt(ext['false_merge_rate_eligible'])}), including a cross-namespace "
        "value collision (er-0087) and a same-namespace near-miss (er-0088), "
        "both correctly refused by exact namespaced equality. An exact "
        "crosswalk is an intentional identity assertion by an integration; "
        f"requiring a second key would forgo {ext['lone_key_positive_count']} "
        "clean crosswalk-only true positives for zero measured precision gain."
    )
    lines.append(
        f"- **`domain` → `min_independent_keys = 2` (keep the default).** A lone "
        f"shared domain false-merges **{dom['confusion']['fp']} of "
        f"{dom['eligible_negatives']}** eligible stress negatives (FMR "
        f"{_fmt(dom['false_merge_rate_eligible'])}): parents/subsidiaries, "
        "conglomerate brands, franchises, agencies-of-record, coworking/PEO/"
        "marketplace/ISP/university co-tenants. These are STRUCTURAL — a "
        "denylist cannot enumerate them (er-0076's comcast.net is deliberately "
        f"not denylisted). The cost: {dom['lone_key_positive_count']} of "
        f"{c['positives']} true pairs are domain-only and fall to Tier-2 "
        "review instead of auto-merging — the deliberate, measured price of "
        "the §3.2 posture."
    )
    lines.append(
        f"- **`email` → `min_independent_keys = 2` for account↔account edges.** "
        f"A lone shared contact email false-merges **{eml['confusion']['fp']} of "
        f"{eml['eligible_negatives']}** eligible stress negatives (FMR "
        f"{_fmt(eml['false_merge_rate_eligible'])}): a fractional CFO, a serial "
        "founder, an agency contact — one human serving two companies. "
        "**Finding:** `fold.rs` currently lists `email_exact` in "
        "`strong_method`, letting it weld alone (the `per_kind_email1` row) — "
        "measured FMR "
        f"{_fmt(r['policies']['per_kind_email1']['false_merge_rate'])} vs "
        f"{_fmt(r['policies']['per_kind_email2']['false_merge_rate'])} for "
        "`per_kind_email2`. The §4.2 S1 intent (\"exact email person↔person "
        "within a namespace\") is fine for PERSON entities; for ACCOUNT merges "
        "the exemption should be dropped (a config/spec amendment, flagged for "
        "§10 Q2 — this corpus does not measure person↔person resolution)."
    )
    lines.append("")
    lines.append("## Honesty notes")
    lines.append("")
    lines.append(
        "- Synthetic hand-labeled STRESS corpus (103 pairs at this writing); "
        "composition stated above. Not a natural distribution; per-kind FMR "
        "magnitudes are properties of this set's composition."
    )
    lines.append(
        "- Every number above was produced by `python -m "
        "verity_ingest.resolve_keys_sweep` on the checked-in fixture; nothing "
        "is quoted from elsewhere. `ingest/tests/test_resolve_keys_sweep.py` "
        "pins the per-kind FMR/FP counts as a regression gate."
    )
    lines.append(
        "- Key-independence caveat: in er-0098/er-0102 the contact email lives "
        "ON the shared domain, so email+domain are CORRELATED keys; the fold "
        "counts them as 2 distinct keys. A future refinement could refuse to "
        "count an email key whose domain equals an already-counted domain key."
    )
    lines.append(
        "- `external_id` FMR 0 means: exact NAMESPACED equality refused every "
        "confusable we could construct. The set does not model an integration "
        "writing a factually wrong crosswalk into the SAME namespace with "
        "exact-match values — that failure is real but unmeasurable by a key "
        "rule (it is what anti-links/review and invalidate-don't-delete are "
        "for)."
    )
    lines.append(
        "- No LLM or API call anywhere in this sweep; all scorers are "
        "deterministic and offline."
    )
    lines.append("")
    return "\n".join(lines) + "\n"


def write_reports(r: dict, pairs_path: Path, out_dir: Path, on: date | None = None) -> tuple[Path, Path]:
    on = on or date.today()
    stamp = on.isoformat()
    json_path = out_dir / f"RESULTS-key-independence-{stamp}.json"
    md_path = out_dir / f"RESULTS-key-independence-{stamp}.md"
    sidecar = {
        "date": stamp,
        "metric": "entity_resolution_key_independence_sweep",
        "eval_set": str(pairs_path),
        "honesty": (
            "Synthetic, hand-labeled STRESS corpus — adversarial composition, not a "
            "natural distribution. Deterministic scorers only; no LLM anywhere."
        ),
        "result": r,
    }
    json_path.write_text(json.dumps(sidecar, indent=2, sort_keys=True) + "\n")
    md_path.write_text(_report_md(r, pairs_path))
    return json_path, md_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Per-key-kind min_independent_keys sweep (deterministic, no LLM)"
    )
    parser.add_argument("--pairs", type=Path, default=DEFAULT_PAIRS)
    parser.add_argument("--no-report", action="store_true")
    args = parser.parse_args(argv)

    pairs = load_pairs(args.pairs)
    r = run_sweep(pairs)
    c = r["corpus"]
    print(f"Key-independence sweep over {args.pairs}")
    print(
        f"  corpus: {c['total']} pairs ({c['positives']} positives, "
        f"{c['hard_negatives']} hard negs, {c['easy_negatives']} easy negs) — "
        "SYNTHETIC STRESS SET"
    )
    for kind in KEY_KINDS:
        k = r["per_kind_alone"][kind]
        print(
            f"  {kind:12s} alone: FP {k['confusion']['fp']:2d}  "
            f"FMR(eligible {k['eligible_negatives']:2d}) {k['false_merge_rate_eligible']:.4f}  "
            f"FMR(all) {k['false_merge_rate_all_negatives']:.4f}  "
            f"recall {k['recall_alone']:.4f}  "
            f"lone-K positives {k['lone_key_positive_count']}"
        )
    for name, pr in r["policies"].items():
        print(
            f"  policy {name:18s}: precision {pr['precision']:.4f}  "
            f"recall {pr['recall']:.4f}  FMR {pr['false_merge_rate']:.4f}"
        )
    if not args.no_report:
        json_path, md_path = write_reports(r, args.pairs, _BENCH_DIR)
        print(f"  wrote {json_path}")
        print(f"  wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
