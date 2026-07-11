-- 0024 — measured entity-resolution tuning defaults (append-only; 0022 is not
-- edited). Sets column defaults on entity_resolution_config to the MEASURED
-- operating points so DB-created rows agree with
-- EntityResolutionConfig::defaults in verity-core. Numbers are measured on
-- synthetic hand-labeled STRESS sets (not natural distributions); see
-- docs/benchmark/RESULTS-tuning-defaults-2026-07-11.md (consolidated) and the
-- three detailed docs it links.
--
-- Existing rows are untouched: these are INSERT-time defaults only, and every
-- current writer binds all columns explicitly.

-- Tier-3 abstain gates: (0.70, 0.15) is the max-recall grid point with
-- link-precision 1.0000 and ZERO false links on the 106-case mention sweep
-- (RESULTS-tier3-gates-2026-07-11.md). The former code default 0.55 admits 10
-- false links in the fuzzy-backstop regime; margin_delta = 0 is unsafe at
-- every tau (21+ false links from alphabetical tie-break guesses).
ALTER TABLE entity_resolution_config
    ALTER COLUMN tau_nil SET DEFAULT 0.70;
ALTER TABLE entity_resolution_config
    ALTER COLUMN margin_delta SET DEFAULT 0.15;

-- min_independent_keys keeps its column default of 2 (0022): domain-alone
-- false-merge rate measured 0.2745 on eligible negatives, email-alone 3/4 —
-- both need a second independent key. The measured external_id = 1 exception
-- (FMR 0/3 eligible negatives; RESULTS-key-independence-2026-07-11.md) is
-- per-key_kind and cannot be a single column default; it lives in
-- EntityResolutionConfig::defaults and per-tenant rows.
