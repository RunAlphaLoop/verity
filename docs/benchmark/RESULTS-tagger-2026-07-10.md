# SRB metric #5 — tagger recall (deterministic v0 baseline)

Corpus: `docs/benchmark/tagger-eval.jsonl` — **118 examples**, 100 expected tags, 188 distractor entities, 40 examples with NO expected tag.

Tagger: `DeterministicExtractor` entity-name echo (exact bare-name substring match over chunk content, confidence 0.95).

## Aggregate

| metric | value |
|---|---|
| precision | **0.8495** |
| recall | **0.7900** |
| F1 | 0.8187 |
| tag confusion (TP/FP/FN) | 79 / 14 / 21 |
| distractor false-positive rate | 0.0745 (14/188) |
| exact-match examples | 87/118 |

**Precision-first framing.** A false entity tag is a *scope-widening* error: it attaches a memory to an account the content does not concern, leaking that memory into the wrong account's recall surface — the tagging analogue of a false merge. So precision (and the distractor false-positive rate) is the load-bearing number; recall is what the probabilistic tagger buys later.

## Per category

| category | n(examples) | precision | recall | F1 | distractor-FP-rate |
|---|---|---|---|---|---|
| common_word | 10 | 0.1818 | 1.0000 | 0.3077 | 0.5000 |
| multi_entity | 18 | 1.0000 | 0.9000 | 0.9474 | 0.0000 |
| none | 23 | 1.0000 | 1.0000 | 1.0000 | 0.0000 |
| partial_name | 12 | 1.0000 | 0.0000 | 0.0000 | 0.0000 |
| pronoun_only | 7 | 1.0000 | 1.0000 | 1.0000 | 0.0000 |
| single_entity | 44 | 1.0000 | 0.8864 | 0.9398 | 0.0000 |
| substring_collision | 4 | 0.2857 | 1.0000 | 0.4444 | 0.8333 |

## False tags (11) — the costly error

- `tg-0045` [common_word] ['account:box'] in: 'We shipped the fix on Monday and the box turned green in CI.'
- `tg-0046` [common_word] ['account:apple'] in: "The apple of the sales team's eye this quarter is the enterprise segment."
- `tg-0047` [common_word] ['account:priority'] in: 'Support gave the ticket top priority and closed it within the hour.'
- `tg-0048` [common_word] ['account:general'] in: 'There was a general consensus that pricing needs a rework.'
- `tg-0049` [common_word] ['account:summit'] in: 'The buyer wants a summit with our exec team before signing.'
- `tg-0050` [common_word] ['account:bridge'] in: 'We need a bridge call to align both sides before the renewal.'
- `tg-0068` [substring_collision] ['account:data', 'account:meta'] in: 'Metadata pipeline is healthy; no issues to report this week.'
- `tg-0069` [substring_collision] ['account:cat', 'account:log'] in: 'The catalog sync ran clean overnight across all regions.'
- `tg-0071` [substring_collision] ['account:star'] in: "Northstar's contract is signed; the north star metric is activation."
- `tg-0116` [common_word] ['account:stake'] in: 'We put a stake in the ground on the Q3 targets today.'
- `tg-0117` [common_word] ['account:north', 'account:south'] in: 'The North team hit quota; the South team is trailing.'

## Missed tags (20) — the recall gap

These are the mentions the exact-name echo cannot reach (abbreviations, partial names). The probabilistic `AnthropicExtractor` tagger is the intended fix.

- `tg-0015` [single_entity] missed ['account:massive-dynamic'] in: 'Massive Dynamic escalated a billing dispute over the March invoice.'
- `tg-0016` [single_entity] missed ['account:pied-piper'] in: "Pied Piper needs a middle-out compression benchmark before they'll expand."
- `tg-0017` [single_entity] missed ['account:dunder-mifflin'] in: "Dunder Mifflin's regional managers want a demo of the new dashboard."
- `tg-0019` [single_entity] missed ['account:blue-sun'] in: 'Blue Sun reported degraded sync performance across three integrations.'
- `tg-0026` [multi_entity] missed ['account:blue-sun', 'account:pied-piper'] in: "Pied Piper is migrating off Blue Sun's legacy stack onto ours."
- `tg-0027` [multi_entity] missed ['account:dunder-mifflin'] in: 'Both Dunder Mifflin and Prestige Worldwide asked for the same case study.'
- `tg-0028` [multi_entity] missed ['account:massive-dynamic'] in: 'Soylent flagged the bug; Massive Dynamic hit the same one an hour later.'
- `tg-0053` [partial_name] missed ['account:international-business-machines'] in: "IBM's procurement team wants a volume discount for 10k seats."
- `tg-0054` [partial_name] missed ['account:general-electric'] in: "GE flagged a compliance requirement we haven't seen before."
- `tg-0055` [partial_name] missed ['account:hewlett-packard'] in: "HP is consolidating vendors and we're on the shortlist."
- `tg-0056` [partial_name] missed ['account:massive-dynamic'] in: "MassDyn wants a QBR before they'll discuss the expansion."
- `tg-0057` [partial_name] missed ['account:vandelay-industries'] in: 'Vandelay Ind. is late on the March invoice; AR is following up.'
- `tg-0058` [partial_name] missed ['account:dunder-mifflin-paper'] in: "DM Paper's Scranton branch is the most active on the platform."
- `tg-0059` [partial_name] missed ['account:prestige-worldwide'] in: 'PWW signed but wants the contract restated with the full legal name.'
- `tg-0060` [partial_name] missed ['account:cyberdyne-systems'] in: 'Cyberdyne Sys escalated the SSO outage to their CISO.'
- `tg-0099` [single_entity] missed ['account:blue-sun'] in: 'Blue Sun asked whether we support customer-managed encryption keys.'
- `tg-0112` [partial_name] missed ['account:jpmorgan-chase'] in: "JPMC's risk team needs an on-prem option before they'll proceed."
- `tg-0113` [partial_name] missed ['account:procter-gamble'] in: 'P&G is standardizing tooling globally and wants a master agreement.'
- `tg-0114` [partial_name] missed ['account:american-express'] in: 'AmEx flagged a PCI requirement for the payments integration.'
- `tg-0115` [partial_name] missed ['account:department-of-defense'] in: 'The DoD contract requires FedRAMP; sending our authorization docs.'

## The AnthropicExtractor tagger (defined, not run here)

The `AnthropicExtractor` (consolidation.py, active only behind `ANTHROPIC_API_KEY`) is the probabilistic tagger: its prompt asks for tag suggestions with a confidence, *preferring recall* — it would catch the abbreviated/partial mentions the echo misses, lifting recall. It is **shape-only here** (no key), so this report is the DETERMINISTIC baseline. With this run, metric #5 is **defined AND baseline-reported**, closing the 'defined-not-reported' gap.
