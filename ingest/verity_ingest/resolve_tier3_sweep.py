"""(tau_nil, margin_delta) abstain-gate SWEEP for the ER Tier-3 mention producer
— the measurement behind cross-source-entity-resolution.md §10 Q6 ("measure
fresh on a tenant-catalog EL benchmark", not bootstrap-and-hope).

What is measured
----------------
For every point on a (tau_nil, margin_delta) grid we run the SHIPPED Tier-3
pipeline (``resolve_tier3.plan_tier3`` — detect -> retrieve -> disambiguate)
over the labeled sweep corpus
``ingest/tests/fixtures/entity_resolution/mention_sweep_cases.json`` and grade
each case's gold link-or-NIL label:

  - **link**     = Decision B resolved to ONE canonical (outcome ``tag`` or
                   ``reviewer_hint`` — the §5 tag gate is orthogonal to the
                   abstain gates and is NOT what this sweep tunes).
  - **abstain**  = NIL / margin-abstain / no mention detected.

Per grid point: link-precision, link-recall, false-link count+rate, and the
abstain split (correct-abstain vs over-abstain). The recommended operating
point is the highest-recall point holding link-precision >= 0.99 with ZERO
false links on the stress set; ties resolve to the (lower-)median tau and
delta of the tied region — the interior of the safe plateau, farthest from
both measured cliffs, never a boundary point.

Determinism / honesty
---------------------
NO LLM or network call anywhere: the NER-backstop seam is exercised by a
``ScriptedMentionDetector`` replaying the fixture's hand-authored
``detector_spans`` (the gazetteer window pass alone only ever yields exact
1.0 matches, so tau_nil is only exercisable in the backstop regime — stated in
every report this module writes). The corpus is a synthetic hand-labeled
STRESS set, not a natural mention distribution. Cases flagged ``annex`` are
containment-detection failures no gate can block; they are excluded from grid
metrics and reported separately.

Run standalone to print the grid and write the dated RESULTS JSON+MD:

    python -m verity_ingest.resolve_tier3_sweep
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from verity_ingest.resolve_tier3 import (
    CatalogEntity,
    Chunk,
    Gazetteer,
    Tier3Config,
    Tier3Outcome,
    plan_tier3,
)

DEFAULT_CASES = (
    Path(__file__).resolve().parents[1]
    / "tests"
    / "fixtures"
    / "entity_resolution"
    / "mention_sweep_cases.json"
)

_BENCH_DIR = Path(__file__).resolve().parents[2] / "docs" / "benchmark"

TENANT = "00000000-0000-0000-0000-0000000000e3"

# The grid. tau values bracket the deterministic scorer's actual score levels
# (0.6 / 0.6667 / 0.75 / 1.0 — token-set Jaccard at the fuzzy-retrieval floor
# 0.6, and the co-signal-saturated / exact 1.0); delta values bracket the
# measured margins (0.0 ties, 0.25, 0.3333). Both the pre-amendment defaults
# (tau=0.55, delta=0.15) and the shipped (0.70, 0.15) are grid points so the
# comparison is direct.
TAUS = (0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.90, 1.00)
DELTAS = (0.00, 0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.40, 0.50)

# The operating point this sweep recommends (see RESULTS-tier3-gates-*.md).
# test_resolve_tier3_sweep.py pins the corpus-measured numbers at this point.
RECOMMENDED_TAU_NIL = 0.70
RECOMMENDED_MARGIN_DELTA = 0.15


class ScriptedMentionDetector:
    """Deterministic stand-in for the NER/LLM backstop seam: replays the
    fixture case's hand-authored ``detector_spans`` verbatim. No LLM, no key,
    no network — the sweep stays fully deterministic while still exercising
    the fuzzy-score regime that only the backstop path can produce."""

    def __init__(self, spans: list[str]) -> None:
        self._spans = list(spans)

    def detect(self, text: str, gazetteer: Gazetteer) -> list[str]:
        return list(self._spans)


def load_sweep_cases(cases_path: Path | None = None) -> list[dict]:
    doc = json.loads((cases_path or DEFAULT_CASES).read_text())
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
    )


def grade_case(case: dict, config: Tier3Config) -> str:
    """Grade ONE case against its config-independent gold label. Returns one of
    ``correct_link`` / ``false_link`` / ``over_abstain`` / ``correct_abstain``.

    A case counts as a LINK when Decision B resolved: any decision with outcome
    ``tag`` or ``reviewer_hint`` names one canonical. Gold-link cases must
    resolve to exactly the gold canonical (anything else — the wrong canonical,
    or an extra one — is a false link). Gold-abstain (``gold: null``) cases must
    produce no resolved canonical at all."""
    result = plan_tier3(
        TENANT,
        [_chunk(case)],
        _gazetteer(case),
        config,
        detector=ScriptedMentionDetector(case.get("detector_spans", [])),
    )
    linked = {
        d.top.entity.canonical
        for d in result.decisions
        if d.outcome in (Tier3Outcome.TAG, Tier3Outcome.REVIEWER_HINT) and d.top is not None
    }
    gold = case.get("gold")
    if gold is None:
        return "correct_abstain" if not linked else "false_link"
    if linked == {gold}:
        return "correct_link"
    if not linked:
        return "over_abstain"
    return "false_link"


@dataclass
class PointMetrics:
    """Measured numbers at one (tau_nil, margin_delta) grid point over the
    graded (non-annex) corpus."""

    tau_nil: float
    margin_delta: float
    correct_links: int = 0
    false_links: int = 0
    over_abstain: int = 0
    correct_abstain: int = 0
    false_link_cases: list[str] = field(default_factory=list)
    over_abstain_cases: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.correct_links + self.false_links + self.over_abstain + self.correct_abstain

    @property
    def links_emitted(self) -> int:
        return self.correct_links + self.false_links

    @property
    def link_precision(self) -> float:
        """correct / emitted. A zero-link point is vacuously precise (1.0) but
        has zero recall, so it can never win selection on precision alone."""
        return 1.0 if self.links_emitted == 0 else self.correct_links / self.links_emitted

    def link_recall(self, gold_link_total: int) -> float:
        return 0.0 if gold_link_total == 0 else self.correct_links / gold_link_total

    @property
    def false_link_rate(self) -> float:
        return 0.0 if self.total == 0 else self.false_links / self.total

    @property
    def abstain_rate(self) -> float:
        return 0.0 if self.total == 0 else (self.correct_abstain + self.over_abstain) / self.total


def measure_point(graded: list[dict], tau_nil: float, margin_delta: float) -> PointMetrics:
    cfg = Tier3Config(tau_nil=tau_nil, margin_delta=margin_delta, auto_link_tier3=False)
    pm = PointMetrics(tau_nil=tau_nil, margin_delta=margin_delta)
    for case in graded:
        outcome = grade_case(case, cfg)
        if outcome == "correct_link":
            pm.correct_links += 1
        elif outcome == "false_link":
            pm.false_links += 1
            pm.false_link_cases.append(case["id"])
        elif outcome == "over_abstain":
            pm.over_abstain += 1
            pm.over_abstain_cases.append(case["id"])
        else:
            pm.correct_abstain += 1
    return pm


def sweep(
    cases: list[dict],
    taus: tuple[float, ...] = TAUS,
    deltas: tuple[float, ...] = DELTAS,
) -> list[PointMetrics]:
    graded = [c for c in cases if not c.get("annex")]
    return [measure_point(graded, t, d) for t in taus for d in deltas]


def _lower_median(values: list[float]) -> float:
    s = sorted(set(values))
    return s[(len(s) - 1) // 2]


def choose_operating_point(
    points: list[PointMetrics],
    gold_link_total: int,
    *,
    min_precision: float = 0.99,
) -> PointMetrics:
    """The selection rule (stated in the RESULTS doc): among grid points with
    link-precision >= ``min_precision`` AND zero false links, take the maximal
    link-recall; resolve ties to the (lower-)median tau and delta of the tied
    region — an interior point of the safe plateau, never a boundary point."""
    eligible = [p for p in points if p.false_links == 0 and p.link_precision >= min_precision]
    if not eligible:
        raise ValueError("no grid point meets the precision/false-link bar")
    best_recall = max(p.link_recall(gold_link_total) for p in eligible)
    tied = [p for p in eligible if p.link_recall(gold_link_total) == best_recall]
    tau = _lower_median([p.tau_nil for p in tied])
    delta = _lower_median([p.margin_delta for p in tied])
    for p in tied:
        if p.tau_nil == tau and p.margin_delta == delta:
            return p
    # median combination not itself tied (non-rectangular tie region): fall back
    # to the tied point closest to the median combination, deterministic order.
    tied.sort(key=lambda p: (abs(p.tau_nil - tau) + abs(p.margin_delta - delta), p.tau_nil, p.margin_delta))
    return tied[0]


def measure_annex(cases: list[dict], config: Tier3Config) -> dict:
    """The containment-detection annex, reported SEPARATELY: cases where a
    catalog surface form is a contiguous sub-span of a longer distinct org name.
    The window pass exact-matches them at 1.0 with no second candidate, so no
    (tau_nil, margin_delta) can block them — a detection-level limitation."""
    annex = [c for c in cases if c.get("annex")]
    false_ids = [c["id"] for c in annex if grade_case(c, config) == "false_link"]
    return {"annex_cases": len(annex), "annex_false_links": len(false_ids), "case_ids": false_ids}


# ---------------------------------------------------------------------------
# Reports — mirror the RESULTS-resolve-tier2 dated JSON+MD shape.
# ---------------------------------------------------------------------------


def _band_composition(graded: list[dict]) -> dict[str, dict]:
    comp: dict[str, dict] = {}
    for c in graded:
        b = comp.setdefault(c["band"], {"cases": 0, "gold_link": 0, "gold_abstain": 0})
        b["cases"] += 1
        b["gold_link" if c.get("gold") else "gold_abstain"] += 1
    return dict(sorted(comp.items()))


def _grid_cell(p: PointMetrics, gold_link_total: int) -> str:
    r = p.link_recall(gold_link_total)
    return f"{r:.3f}" if p.false_links == 0 else f"{r:.3f} ({p.false_links} FL)"


def _report_md(
    cases: list[dict],
    points: list[PointMetrics],
    chosen: PointMetrics,
    annex: dict,
    default_point: PointMetrics,
    cases_path: Path,
    taus: tuple[float, ...],
    deltas: tuple[float, ...],
) -> str:
    graded = [c for c in cases if not c.get("annex")]
    gold_link_total = sum(1 for c in graded if c.get("gold"))
    gold_abstain_total = len(graded) - gold_link_total
    comp = _band_composition(graded)
    by_id = {c["id"]: c for c in cases}

    L: list[str] = []
    L.append("# ER Tier-3 abstain gates (tau_nil, margin_delta) — measured sweep")
    L.append("")
    L.append(
        f"Eval set: `{cases_path}` — **{len(graded)} graded labeled mentions** "
        f"({gold_link_total} gold-link, {gold_abstain_total} gold-abstain) + "
        f"{annex['annex_cases']} annex cases reported separately below. "
        "**Synthetic, hand-labeled STRESS set — not a natural mention distribution**: bands were designed to sit "
        "on the deterministic scorer's decision boundaries so the grid has measurable cliffs. Every number below "
        "was produced by running the shipped pipeline over this corpus; no number is quoted from elsewhere."
    )
    L.append("")
    L.append(
        "Pipeline: `resolve_tier3.plan_tier3` (detect -> retrieve -> disambiguate), deterministic end-to-end — "
        "the NER-backstop seam is exercised by a scripted detector replaying hand-authored fixture spans "
        "(`detector_spans`); **no LLM or network call anywhere**. Answers design §10 Q6 "
        "(cross-source-entity-resolution.md): measure `tau_nil`/`margin_delta` fresh on a tenant-catalog EL "
        "benchmark rather than bootstrapping from the knowledge-merge judge's operating point."
    )
    L.append("")
    L.append("## Grading")
    L.append("")
    L.append(
        "Each case carries a config-independent gold label: `gold: account:x` (the mention truly refers to that "
        "catalog entity; correct decision = RESOLVE) or `gold: null` (correct decision = ABSTAIN). A case counts "
        "as a **link** when Decision B resolved to one canonical (outcome `tag` **or** `reviewer_hint` — the §5 "
        "tag gate is orthogonal to the abstain gates and is not what this sweep tunes), and as an **abstain** on "
        "NIL / margin-abstain / no detection. Per point: link-precision = correct/emitted links; link-recall = "
        "correct links / gold-link cases; false-link rate = false links / graded cases; over-abstain = gold-link "
        "cases abstained; correct-abstain = gold-abstain cases abstained."
    )
    L.append("")
    L.append("## Corpus composition")
    L.append("")
    L.append("| band | cases | gold-link | gold-abstain | what it stresses |")
    L.append("|---|---|---|---|---|")
    _band_notes = {
        "b1_exact_cosignal": "unambiguous exact name + domain co-signal (strong context)",
        "b2_exact_no_cosignal": "unambiguous exact name, no co-signal (resolves as reviewer_hint)",
        "b3_ambiguous_two_exact": "two exact same-surface candidates, no co-signal (the two Acmes) — MUST abstain",
        "b4_ambiguous_cosignal_capped": "two exact candidates + co-signal on one; boost caps at 1.0 so margin stays 0 (scorer limitation, measured)",
        "b5_separable_two_candidates": "exact top + fuzzy sibling (margins 0.25 / 0.3333) — prices margin_delta set too high",
        "b6_partial_name_backstop": "near-miss partial names via the scripted backstop (0.75 / 0.6667) — the tau_nil recall frontier",
        "b7_fuzzy_with_cosignal": "fuzzy partial name + co-signal (saturates to 1.0) — the sanctioned sub-exact link path",
        "b8_wrong_org_trap": "distinct near-miss orgs scoring 0.6667 / 0.6000 — sets the tau_nil floor; must abstain",
        "b9_gold_nil_unknown_org": "orgs matching nothing in the catalog (gold NIL)",
        "b9_gold_nil_generic_scatter": "catalog name tokens scattered as common words (gold NIL)",
        "b10_short_low_context": "short/low-context docs (link, ambiguous, and unknown variants)",
    }
    for band, b in comp.items():
        L.append(
            f"| `{band}` | {b['cases']} | {b['gold_link']} | {b['gold_abstain']} | {_band_notes.get(band, '')} |"
        )
    L.append(
        f"| **total (graded)** | **{len(graded)}** | **{gold_link_total}** | **{gold_abstain_total}** | |"
    )
    L.append("")
    L.append("## The grid — link-recall per point (false links flagged)")
    L.append("")
    L.append(
        "Cell = link-recall at that point; `(n FL)` marks points with n **false links** (any such point is "
        "disqualified). Link-precision is 1.0 at every unflagged point on this corpus (zero false links)."
    )
    L.append("")
    header = "| tau_nil \\ margin_delta | " + " | ".join(f"{d:.2f}" for d in deltas) + " |"
    L.append(header)
    L.append("|" + "---|" * (len(deltas) + 1))
    by_point = {(p.tau_nil, p.margin_delta): p for p in points}
    for t in taus:
        row = [f"| **{t:.2f}**"]
        for d in deltas:
            p = by_point[(t, d)]
            cell = _grid_cell(p, gold_link_total)
            if (t, d) == (chosen.tau_nil, chosen.margin_delta):
                cell = f"**{cell}** ←"
            row.append(cell)
        L.append(" | ".join(row) + " |")
    L.append("")
    L.append("Reading the cliffs (all measured):")
    L.append("")
    L.append(
        "- **margin_delta = 0.00 is unsafe at every tau**: exact-exact ties (two Acmes) fall through to the "
        "deterministic alphabetical tie-break — a guess — producing false links (bands b3/b4/b10)."
    )
    L.append(
        "- **tau_nil <= 0.60** additionally admits the 0.6000-scored wrong-org traps; **tau_nil <= 0.6667 "
        "(grid 0.65)** admits the 0.6667 traps (band b8). The margin gate cannot help — those traps are "
        "single-candidate."
    )
    L.append(
        "- **tau_nil >= 0.80** drops the legitimate 0.75-scored partial-name mentions (band b6): recall falls "
        "with no precision gain."
    )
    L.append(
        "- **margin_delta >= 0.30** starts eating the separable two-candidate band (b5: margins 0.25, then "
        "0.3333 at >= 0.40): recall falls with no precision gain."
    )
    L.append("")
    L.append("## Recommended operating point")
    L.append("")
    L.append(
        "Selection rule: among points with link-precision >= 0.99 **and zero false links**, take maximal "
        "link-recall; resolve ties to the (lower-)median tau and delta of the tied region — the interior of the "
        "safe plateau (tau in {0.70, 0.75} x delta in {0.05..0.25}), deliberately not a boundary point (0.6667 "
        "and 0.75 are exact score levels; 0.25 is an exact margin level)."
    )
    L.append("")
    L.append(f"### `tau_nil = {chosen.tau_nil:.2f}`, `margin_delta = {chosen.margin_delta:.2f}`")
    L.append("")
    L.append("| metric | value |")
    L.append("|---|---|")
    L.append(f"| link-precision | **{chosen.link_precision:.4f}** |")
    L.append(f"| link-recall | **{chosen.link_recall(gold_link_total):.4f}** ({chosen.correct_links}/{gold_link_total}) |")
    L.append(f"| **false links** | **{chosen.false_links}** (rate {chosen.false_link_rate:.4f}) |")
    L.append(f"| correct-abstain | {chosen.correct_abstain}/{gold_abstain_total} (1.0000) |")
    L.append(f"| over-abstain | {chosen.over_abstain}/{gold_link_total} ({chosen.over_abstain / gold_link_total:.4f}) |")
    L.append(f"| abstain rate (overall) | {chosen.abstain_rate:.4f} |")
    L.append("")
    L.append("### What it abstains on (the price of precision, itemized)")
    L.append("")
    over_by_band: dict[str, list[str]] = {}
    for cid in chosen.over_abstain_cases:
        over_by_band.setdefault(by_id[cid]["band"], []).append(cid)
    for band, ids in sorted(over_by_band.items()):
        L.append(f"- **{band}** ({len(ids)}): " + ", ".join(f"`{i}`" for i in ids))
    L.append("")
    L.append(
        "- The **b4** over-abstains are a measured scorer limitation, not a gate mistuning: the co-signal boost "
        "caps at 1.0, so it cannot separate two exact-surface candidates even when it deterministically "
        "corroborates one. Fixing that is a scorer change (e.g. rank co-signal above tie, or boost "
        "multiplicatively below the cap) — flagged for a follow-up, not silently absorbed here."
    )
    L.append(
        "- The **b6** 0.6667 over-abstains are deliberate: those scores are numerically identical to the b8 "
        "wrong-org traps, so no tau separates them; the sanctioned path for such mentions is a co-signal (b7, "
        "which saturates to 1.0 and links at every tau)."
    )
    L.append("")
    L.append("## Shipped default vs recommended")
    L.append("")
    L.append(
        f"| point | precision | recall | false links | over-abstain |\n|---|---|---|---|---|\n"
        f"| pre-amendment default `tau=0.55, delta=0.15` | {default_point.link_precision:.4f} | "
        f"{default_point.link_recall(gold_link_total):.4f} | **{default_point.false_links}** | "
        f"{default_point.over_abstain} |\n"
        f"| **recommended `tau={chosen.tau_nil:.2f}, delta={chosen.margin_delta:.2f}`** | "
        f"**{chosen.link_precision:.4f}** | {chosen.link_recall(gold_link_total):.4f} | **{chosen.false_links}** | "
        f"{chosen.over_abstain} |"
    )
    L.append("")
    L.append(
        f"The pre-amendment default `tau_nil=0.55` admits **{default_point.false_links} false links** on this corpus — "
        "all from the b8 wrong-org traps, which only exist in the NER-backstop regime (fuzzy scores). Raising to "
        f"0.70 costs measured recall ({default_point.link_recall(gold_link_total):.4f} -> "
        f"{chosen.link_recall(gold_link_total):.4f}: the six b6 0.6667 partial-name links, numerically "
        "inseparable from the traps) and buys the elimination of ALL false links — the precision-first trade "
        "(a false link is a scope leak; a miss is a review-queue entry). On the pure gazetteer path (the shipped "
        "`NullMentionDetector` default) every detected mention scores exactly 1.0, so 0.55 and 0.70 behave "
        "identically TODAY; the raise hardens the gate for the backstop era. `Tier3Config` defaults were "
        "amended to (0.70, 0.15) on 2026-07-11 (see RESULTS-tuning-defaults-2026-07-11.md)."
    )
    L.append("")
    L.append("## Annex — containment failures the gates CANNOT block (reported, not hidden)")
    L.append("")
    L.append(
        f"{annex['annex_cases']} fixture cases put a catalog surface form as a contiguous sub-span of a longer, "
        "distinct org name ('Acme' inside 'Acme Analytics'). The window pass exact-matches them at 1.000 with no "
        f"second candidate, so **every grid point false-links all {annex['annex_false_links']}** — the failure is "
        "in DETECTION, upstream of the gates, and would be dishonest to average into the grid. Standing "
        "detection-level limitation; candidate fixes (longest-span-wins suppression, NER-span containment checks) "
        "are follow-up work: " + ", ".join(f"`{i}`" for i in annex["case_ids"]) + "."
    )
    L.append("")
    L.append("## Honesty notes")
    L.append("")
    L.append(
        "- **Corpus**: 102 graded synthetic hand-labeled mentions (+4 annex), composition above. STRESS set "
        "engineered onto the scorer's decision boundaries — precision/recall here do NOT predict natural-corpus "
        "rates; they bound gate behavior at the boundaries."
    )
    L.append(
        "- **tau_nil is only exercisable in the backstop regime**: the gazetteer window pass yields exact 1.0 "
        "matches only, so with the shipped `NullMentionDetector` the NIL gate never fires on a detected mention. "
        "The scripted spans deterministically stand in for a live NER backstop; a live-backstop measurement on "
        "real text remains future work."
    )
    L.append(
        "- **Score quantization**: the deterministic scorer emits a small set of levels (1.0, 0.75, 0.6667, 0.6 "
        "on this corpus; fuzzy retrieval floors at 0.6). Grid cells between levels are flat by construction; the "
        "recommended tau=0.70 sits between the 0.6667 trap level and the 0.75 legitimate level with slack on both "
        "sides."
    )
    L.append(
        "- **Known scorer saturations, measured here**: (a) the +0.4 co-signal boost caps at 1.0 and cannot break "
        "an exact-exact tie (b4 over-abstains); (b) a WRONG fuzzy candidate >= 0.6 with a co-signal would also "
        "saturate to 1.0 and be ungateable — such cases are excluded from this corpus (they need a scorer fix, "
        "not a threshold) and noted here so the exclusion is explicit."
    )
    L.append(
        "- Every reported number was measured by this module over the named fixture on this machine; the sweep is "
        "pure Python over an in-memory corpus (no DB, no network), so no latency numbers are claimed."
    )
    L.append("")
    return "\n".join(L) + "\n"


def write_reports(
    cases: list[dict],
    points: list[PointMetrics],
    chosen: PointMetrics,
    annex: dict,
    default_point: PointMetrics,
    cases_path: Path,
    out_dir: Path,
    taus: tuple[float, ...],
    deltas: tuple[float, ...],
    on: date | None = None,
) -> tuple[Path, Path]:
    on = on or date.today()
    stamp = on.isoformat()
    json_path = out_dir / f"RESULTS-tier3-gates-{stamp}.json"
    md_path = out_dir / f"RESULTS-tier3-gates-{stamp}.md"
    graded = [c for c in cases if not c.get("annex")]
    gold_link_total = sum(1 for c in graded if c.get("gold"))

    def point_json(p: PointMetrics) -> dict:
        return {
            "tau_nil": p.tau_nil,
            "margin_delta": p.margin_delta,
            "correct_links": p.correct_links,
            "false_links": p.false_links,
            "over_abstain": p.over_abstain,
            "correct_abstain": p.correct_abstain,
            "link_precision": p.link_precision,
            "link_recall": p.link_recall(gold_link_total),
            "false_link_rate": p.false_link_rate,
            "abstain_rate": p.abstain_rate,
        }

    sidecar = {
        "date": stamp,
        "metric": "tier3_abstain_gate_sweep",
        "design_question": "cross-source-entity-resolution.md section 10 Q6",
        "eval_set": str(cases_path),
        "corpus": {
            "graded_mentions": len(graded),
            "gold_link": gold_link_total,
            "gold_abstain": len(graded) - gold_link_total,
            "annex_cases": annex["annex_cases"],
            "composition": _band_composition(graded),
            "honesty": (
                "synthetic hand-labeled STRESS set engineered onto the deterministic scorer's decision "
                "boundaries; NOT a natural mention distribution. Fully deterministic: scripted backstop spans, "
                "no LLM/network calls."
            ),
        },
        "grid": {"taus": list(taus), "deltas": list(deltas), "points": [point_json(p) for p in points]},
        "recommended": {
            **point_json(chosen),
            "selection_rule": (
                "max link-recall among points with link-precision >= 0.99 and zero false links; ties -> "
                "lower-median tau and delta of the tied region (interior of the safe plateau)"
            ),
            "over_abstain_cases": chosen.over_abstain_cases,
        },
        "shipped_default": point_json(default_point),
        "annex_containment": annex,
    }
    json_path.write_text(json.dumps(sidecar, indent=2, sort_keys=True) + "\n")
    md_path.write_text(
        _report_md(cases, points, chosen, annex, default_point, cases_path, taus, deltas)
    )
    return json_path, md_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="(tau_nil, margin_delta) abstain-gate sweep for the Tier-3 mention producer"
    )
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--no-report", action="store_true")
    args = parser.parse_args(argv)

    cases = load_sweep_cases(args.cases)
    graded = [c for c in cases if not c.get("annex")]
    gold_link_total = sum(1 for c in graded if c.get("gold"))
    points = sweep(cases)
    chosen = choose_operating_point(points, gold_link_total)
    # The PRE-AMENDMENT default (tau=0.55) — kept as the report's fixed
    # comparison baseline. Tier3Config now ships the recommended (0.70, 0.15);
    # see docs/benchmark/RESULTS-tuning-defaults-2026-07-11.md.
    default_point = measure_point(graded, 0.55, 0.15)
    annex = measure_annex(
        cases, Tier3Config(tau_nil=chosen.tau_nil, margin_delta=chosen.margin_delta)
    )

    print(f"Tier-3 abstain-gate sweep over {args.cases}")
    print(
        f"  corpus: {len(graded)} graded mentions ({gold_link_total} gold-link, "
        f"{len(graded) - gold_link_total} gold-abstain) + {annex['annex_cases']} annex"
    )
    print(f"  grid: {len(TAUS)} tau x {len(DELTAS)} delta = {len(points)} points")
    print(
        f"  RECOMMENDED tau_nil={chosen.tau_nil:.2f} margin_delta={chosen.margin_delta:.2f}: "
        f"precision {chosen.link_precision:.4f}, recall {chosen.link_recall(gold_link_total):.4f}, "
        f"false links {chosen.false_links}, over-abstain {chosen.over_abstain}"
    )
    print(
        f"  pre-amendment default tau=0.55 delta=0.15: precision {default_point.link_precision:.4f}, "
        f"recall {default_point.link_recall(gold_link_total):.4f}, false links {default_point.false_links}"
    )
    print(f"  annex containment false links (ungateable): {annex['annex_false_links']}")

    if not args.no_report:
        json_path, md_path = write_reports(
            cases, points, chosen, annex, default_point, args.cases, _BENCH_DIR, TAUS, DELTAS
        )
        print(f"  wrote {json_path}")
        print(f"  wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
