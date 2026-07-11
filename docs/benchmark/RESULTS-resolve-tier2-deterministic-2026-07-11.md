# ER Tier-2 entity-resolution judge — measured eval (deterministic)

Eval set: `/Users/mattfleming/agent-memory/ingest/tests/fixtures/entity_resolution/entity_pairs.json` — **68 labeled entity pairs** (33 positives, 32 hard negatives, 3 easy negatives).

Judge: `deterministic` from `ingest/verity_ingest/resolve_tier2.py`, scored exactly as the Tier-2 producer's blocker->judge cascade decides a pair (pairwise "same entity?", strict, fail-closed), after the upstream free-mail denylist pre-filter. Mirrors the knowledge-merge judge eval (`consolidation_eval.py`, SRB metric #6) — directly comparable.

## Result

| metric | value |
|---|---|
| precision | **1.0000** |
| recall | 0.9394 |
| F1 | 0.9688 |
| **false-merge rate** (FP/(FP+TN)) | **0.0000** |
| confusion (TP/FP/TN/FN) | 31 / 0 / 35 / 2 |

**Precision-as-security framing.** A false merge unions two customers' data scopes — a leak, not a data nit (resolve_tier2.py §3.2). So the **false-merge rate is the load-bearing number**; recall is the capability the live judge buys. Under-merge is safe (a missed review candidate); a wrong merge is not.

## False merges

**None.** No hard or easy negative was fused — false-merge rate 0.0 on this set. Every confusable-but-distinct company (Acme Corp vs Acme Freight, Delta Air Lines vs Delta Faucet, parent vs distinct subsidiary, free-mail co-tenants) stayed apart.

## Missed merges (2) — the recall gap

True cross-source dups the judge called "not same" — the ACCEPTABLE failure (a missed review candidate, not a leak). For the deterministic oracle these are the same-company pairs lacking a clean shared domain; the live `EntityAnthropicJudge` is the intended fix, lifting recall without lowering precision.

- `er-0057` ['Globex Corporation', ''] == ['Globex', 'globex.io']
- `er-0061` ["Chotchkie's", 'chotchkies.com'] == ['Chotchkies', 'chotchkies.com']

