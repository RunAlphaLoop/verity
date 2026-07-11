# Consolidation precision/recall — SRB metric 6, 2026-07-10

**Machine:** Apple M3 Pro · 36 GB · Darwin 23.6.0 arm64.

**CI gate:** false-merge-rate target ≤ 0.0100; measured 0.0000 at the shipped threshold.

## Metric 6 — consolidation precision/recall (knowledge-merge decision)

**Encoder:** sentence-transformers/all-MiniLM-L6-v2 (384-d). **Operating threshold:** 0.85 (VERITY_KNOWLEDGE_MERGE_THRESHOLD (default 0.85)). **Eval set:** `docs/benchmark/consolidation-pairs.jsonl` — 206 pairs (94 positives, 90 hard negatives, 22 easy negatives).

This metric mirrors the shipped merge decision: crates/verity-server/src/consolidation.rs propose_or_merge (lines 373-405), merge predicate lines 381-397; normalize_term lines 56-61; threshold DEFAULT_MERGE_THRESHOLD line 52. It measures — it changes nothing.

### Operating point at the shipped threshold (0.85)

| | predicted merge | predicted distinct |
|---|---|---|
| **actually same** | TP 0 | FN 94 |
| **actually distinct** | FP 0 | TN 112 |

**precision 1.0000 · recall 0.0000 · F1 0.0000 · false-merge-rate 0.0000**

### The ≥99%-precision frontier

Lowest threshold holding precision ≥ 0.99 (false-merge rate ≤ 1%): **threshold 0.73** → precision 1.0000, **recall 0.1064** (FP 0, FN 84). *That recall is the capability disclosure: at the precision the trust contract requires, this is how much true paraphrase the current cosine-only decision can catch.*

### PR curve (threshold sweep)

| threshold | TP | FP | TN | FN | precision | recall | F1 | false-merge-rate |
|---|---|---|---|---|---|---|---|---|
| 0.30 | 90 | 66 | 46 | 4 | 0.5769 | 0.9574 | 0.7200 | 0.5893 |
| 0.35 | 89 | 47 | 65 | 5 | 0.6544 | 0.9468 | 0.7739 | 0.4196 |
| 0.40 | 83 | 35 | 77 | 11 | 0.7034 | 0.8830 | 0.7830 | 0.3125 |
| 0.45 | 71 | 22 | 90 | 23 | 0.7634 | 0.7553 | 0.7594 | 0.1964 |
| 0.50 | 62 | 15 | 97 | 32 | 0.8052 | 0.6596 | 0.7251 | 0.1339 |
| 0.55 | 46 | 9 | 103 | 48 | 0.8364 | 0.4894 | 0.6174 | 0.0804 |
| 0.60 | 34 | 8 | 104 | 60 | 0.8095 | 0.3617 | 0.5000 | 0.0714 |
| 0.65 | 23 | 5 | 107 | 71 | 0.8214 | 0.2447 | 0.3770 | 0.0446 |
| 0.70 | 15 | 2 | 110 | 79 | 0.8824 | 0.1596 | 0.2703 | 0.0179 |
| 0.75 | 10 | 0 | 112 | 84 | 1.0000 | 0.1064 | 0.1923 | 0.0000 |
| 0.80 | 4 | 0 | 112 | 90 | 1.0000 | 0.0426 | 0.0816 | 0.0000 |
| 0.85 | 0 | 0 | 112 | 94 | 1.0000 | 0.0000 | 0.0000 | 0.0000 |
| 0.90 | 0 | 0 | 112 | 94 | 1.0000 | 0.0000 | 0.0000 | 0.0000 |
| 0.95 | 0 | 0 | 112 | 94 | 1.0000 | 0.0000 | 0.0000 | 0.0000 |
| 1.00 | 0 | 0 | 112 | 94 | 1.0000 | 0.0000 | 0.0000 | 0.0000 |

**Hardest false pair (highest cosine, genuinely distinct):** 0.7249
- A: the deepest discounts are offered at the end of the quarter
- B: the deepest discounts are offered for large volume commitments

**Hardest true paraphrase (lowest cosine, same generalization):** 0.2396
- A: SMB accounts are the first to leave after a rate hike
- B: small businesses cancel quickly when prices are raised
