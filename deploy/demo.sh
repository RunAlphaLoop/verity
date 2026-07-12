#!/usr/bin/env bash
# The Verity launch demo (SPEC §13): two agents, one shared memory, provable
# scoping. Requires a running server (default http://127.0.0.1:7717) and jq.
set -euo pipefail

VERITY="${VERITY_URL:-http://127.0.0.1:7717}"
say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
show() { printf '   %s\n' "$*"; }

curl -sf "$VERITY/healthz" >/dev/null || { echo "verity not reachable at $VERITY"; exit 1; }

TENANT=$(curl -s -X POST "$VERITY/v1/admin/tenants" -H 'content-type: application/json' \
  -d "{\"name\":\"demo-$(date +%s)\"}" | jq -r .tenant_id)
say "Demo tenant: $TENANT"

mint() { # principals entity actor -> handle
  curl -s -X POST "$VERITY/v1/scopes" -H 'content-type: application/json' -d "{
    \"tenant_id\":\"$TENANT\",\"principals\":$1,\"entity_scope\":$2,
    \"actor_sub\":\"user:demo\",\"actor_azp\":\"$3\"}" | jq -r .scope_handle
}
SALES=$(mint '[11]' '["account:acme"]'  'agent:sales-bot')
SUPPORT=$(mint '[11]' '["account:acme"]' 'agent:support-bot')
EVE=$(mint '[11]' '["account:globex"]'  'agent:eve-bot')
show "sales-bot + support-bot scoped to account:acme; eve-bot scoped to account:globex"
show "(all three share the same org-level principal — entity scope is the only difference)"

say "1) CRM change -> both agents see it live (Debezium CDC envelope)"
NOW_MS=$(($(date +%s) * 1000))
cdc() { curl -s -X POST "$VERITY/v1/ingest/debezium?tenant_id=$TENANT" \
  -H 'content-type: application/json' -d "$1" >/dev/null; }
cdc "{\"payload\":{\"after\":{\"id\":\"opp-1\",\"amount\":50000,\"stage\":\"negotiation\"},
  \"source\":{\"connector\":\"postgresql\",\"db\":\"crm\",\"table\":\"opportunities\",\"ts_ms\":$((NOW_MS-60000))},\"op\":\"c\"}}"
T0=$(python3 -c 'import time; print(time.time())')
cdc "{\"payload\":{\"after\":{\"id\":\"opp-1\",\"amount\":84000,\"stage\":\"negotiation\"},
  \"source\":{\"connector\":\"postgresql\",\"db\":\"crm\",\"table\":\"opportunities\",\"ts_ms\":$NOW_MS},\"op\":\"u\"}}"
REC="$VERITY/v1/records/postgresql:crm.opportunities/opp-1/amount"
for BOT in "sales-bot:$SALES" "support-bot:$SUPPORT"; do
  VAL=$(curl -s "$REC?scope_handle=${BOT#*:}" | jq -r .value)
  show "${BOT%%:*} reads amount = \$$VAL"
done
python3 -c "import time; print(f'   CDC update -> both agents queryable: {(time.time()-$T0)*1000:.0f}ms')"
show "history intact: $(curl -s "$REC?scope_handle=$SALES&as_of=$(date -u -v-30S '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '30 seconds ago' '+%Y-%m-%dT%H:%M:%SZ')" | jq -r '"\(.value) (superseded)"')"

say "2) Cross-agent awareness: sales acts, support sees it before answering"
curl -s -X POST "$VERITY/v1/actions" -H 'content-type: application/json' -d "{
  \"scope_handle\":\"$SALES\",\"action_id\":\"demo-q1\",\"action_type\":\"quote.issued\",
  \"summary\":\"Issued renewal quote at \$84,000 (12mo, net-30).\",
  \"payload\":{\"amount\":84000},\"outcome\":\"succeeded\",
  \"occurred_at\":\"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\"}" >/dev/null
curl -s "$VERITY/v1/briefs/account:acme?scope_handle=$SUPPORT" \
  | jq -r '.recent_activity[] | "   support-bot sees: \(.actor_azp) \(.action_type) — \(.summary)"'

say "3) Shared semantic memory across agents"
curl -s -X POST "$VERITY/v1/episodes" -H 'content-type: application/json' -d "{
  \"scope_handle\":\"$SUPPORT\",
  \"observation\":\"Acme confirmed the renewal decision moves to their Q4 board meeting.\"}" >/dev/null
curl -s -X POST "$VERITY/v1/recall" -H 'content-type: application/json' -d "{
  \"scope_handle\":\"$SALES\",\"text\":\"when is acme deciding on renewal?\",\"k\":1}" \
  | jq -r '.[] | "   sales-bot recalls support-bot'\''s note: \"\(.content)\""'

say "4) Provable scoping: eve-bot (scoped to globex) attacks acme's data"
HITS=$(curl -s -X POST "$VERITY/v1/recall" -H 'content-type: application/json' \
  -d "{\"scope_handle\":\"$EVE\",\"text\":\"acme renewal quote amount\",\"k\":8}" | jq length)
show "recall for acme's quote     -> $HITS results (out-of-scope memory never reaches the model)"
BRIEF=$(curl -s "$VERITY/v1/briefs/account:acme?scope_handle=$EVE" | jq '.recent_memory + .recent_activity | length')
show "brief of account:acme       -> $BRIEF items"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$VERITY/v1/actions" -H 'content-type: application/json' -d "{
  \"scope_handle\":\"$EVE\",\"action_id\":\"demo-x\",\"action_type\":\"email.sent\",
  \"entities\":[\"account:acme\"],\"summary\":\"x\",\"outcome\":\"succeeded\",
  \"occurred_at\":\"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\"}")
show "write tagged to acme        -> HTTP $CODE"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$VERITY/v1/recall" \
  -H 'content-type: application/json' -d "{\"scope_handle\":\"${EVE}00\",\"text\":\"x\"}")
show "tampered scope handle       -> HTTP $CODE"

say "Done. Same memory, three agents: live truth in milliseconds, awareness of each other's actions, and scoping enforced in the index — not in the prompt."

say "5) v0.1 additions: webhook source, file drop, forget"
WH=$(curl -s -X POST "$VERITY/v1/webhooks" -H 'content-type: application/json' \
  -d "{\"tenant_id\":\"$TENANT\",\"name\":\"demo-system\",\"visibility\":[11]}" | jq -r .url)
curl -s -X POST "$VERITY$WH" -H 'content-type: application/json' \
  -d '{"content":"Acme signed the pilot agreement for the fall rollout.","entities":["account:acme"]}' >/dev/null
WH_HIT=$(curl -s -X POST "$VERITY/v1/recall" -H 'content-type: application/json' \
  -d "{\"scope_handle\":\"$SALES\",\"text\":\"pilot agreement\",\"k\":1}" | jq -r '.[0].content' | cut -c1-60)
show "webhook-minted source posted a memory -> $WH_HIT"
EPI=$(curl -s -X POST "$VERITY/v1/episodes" -H 'content-type: application/json' \
  -d "{\"scope_handle\":\"$SALES\",\"observation\":\"Temporary note: wrong pricing quoted, please disregard.\"}" | jq -r .episode_id)
curl -s -X POST "$VERITY/v1/forget" -H 'content-type: application/json' \
  -d "{\"scope_handle\":\"$SALES\",\"ref\":{\"kind\":\"episode\",\"id\":\"$EPI\"},\"reason\":\"retracted\"}" >/dev/null
HITS=$(curl -s -X POST "$VERITY/v1/recall" -H 'content-type: application/json' \
  -d "{\"scope_handle\":\"$SALES\",\"text\":\"wrong pricing disregard\",\"k\":5}" | jq '[.[] | select(.content | contains("disregard"))] | length')
show "forget(episode) -> retracted note now returns $HITS results"

say "6) Entity resolution: two CRMs, one company — and a fuzzy pair held for human review"
cdc_src() { # connector table after_json — one CDC upsert from a named source
  curl -s -X POST "$VERITY/v1/ingest/debezium?tenant_id=$TENANT" -H 'content-type: application/json' \
    -d "{\"payload\":{\"after\":$3,\"source\":{\"connector\":\"$1\",\"db\":\"crm\",\"table\":\"$2\",\"ts_ms\":$NOW_MS},\"op\":\"c\"}}" >/dev/null
}
cdc_src salesforce accounts  '{"id":"sf-1001","name":"Vandelay Industries","Website":"https://vandelay.example","duns":"081466849"}'
cdc_src hubspot    companies '{"id":"hs-77","name":"Vandelay Industries Inc","domain":"vandelay.example","duns":"081466849"}'
show "salesforce + hubspot each hold the same company; both carry DUNS 081466849 (a strong crosswalk key)"
cdc_src salesforce accounts  '{"id":"sf-2002","name":"Initech LLC","Website":"https://initech.example"}'
cdc_src hubspot    companies '{"id":"hs-88","name":"Initech","domain":"initech.example"}'
show "a second pair shares only a similar name/domain — no strong key, so Tier-1 must NOT weld it"
curl -s -X POST "$VERITY/v1/admin/entity-evidence" -H 'content-type: application/json' -d "{
  \"tenant_id\":\"$TENANT\",\"left_ref\":\"hubspot:crm.companies:hs-88\",
  \"right_ref\":\"salesforce:crm.accounts:sf-2002\",\"tier\":2,\"method\":\"name_domain_fuzzy\",
  \"score\":0.9,
  \"evidence_l0_ref\":\"demo: fuzzy name+domain similarity — needs a human decision\"}" >/dev/null
RUN=$(curl -s -X POST "$VERITY/v1/admin/entity-resolution/run" -H 'content-type: application/json' \
  -d "{\"tenant_id\":\"$TENANT\"}")
show "$(echo "$RUN" | jq -r '"resolution run -> \(.evidence_produced) new Tier-1 evidence, \(.canonicals) canonical(s) welded — the weak pair did NOT weld"')"
REVIEW=$(curl -s "$VERITY/v1/admin/entity-resolution/review-queue?tenant_id=$TENANT" | jq length)
show "human review queue -> $REVIEW candidate(s): Tier-2 never auto-merges; confirm/reject stays a human verb"

say "7) Knowledge: the same lesson observed by three scoped agents -> candidates, never auto-published"
INITECH=$(mint '[11]' '["account:initech"]' 'agent:ops-bot')
LESSON="Renewal conversations stall unless pricing is confirmed before the quarterly board review."
observe() { curl -s -X POST "$VERITY/v1/episodes" -H 'content-type: application/json' \
  -d "{\"scope_handle\":\"$1\",\"observation\":\"$2\"}" | jq -r .episode_id; }
E1=$(observe "$SALES"   "Renewal stalled again until pricing was confirmed ahead of the board review.")
E2=$(observe "$SUPPORT" "Ticket resolved only after pricing confirmation unblocked the renewal discussion.")
E3=$(observe "$INITECH" "Procurement said the renewal waits for the quarterly board review either way.")
propose() { curl -s -X POST "$VERITY/v1/knowledge" -H 'content-type: application/json' -d "{
  \"scope_handle\":\"$1\",\"statement\":\"$LESSON\",\"categories\":[\"sales-process\"],\"evidence\":[\"$2\"]}" >/dev/null; }
propose "$SALES" "$E1"; propose "$SUPPORT" "$E2"; propose "$INITECH" "$E3"
KN=$(curl -s "$VERITY/v1/knowledge?tenant_id=$TENANT" | jq '[.items[] | select(.status=="candidate")] | length')
show "knowledge queue -> $KN candidate(s) of the same statement from three writers; publish stays a human gate"

say "8) Operability: a connector heartbeat, and a payload nobody can map"
TS=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
curl -s -X POST "$VERITY/v1/admin/connector-status" -H 'content-type: application/json' -d "{
  \"tenant_id\":\"$TENANT\",\"source\":\"salesforce:crm.accounts\",\"cursor\":\"$TS\",
  \"items_synced\":2,\"last_event_at\":\"$TS\"}" >/dev/null
HB=$(curl -s "$VERITY/v1/admin/connector-status?tenant_id=$TENANT" | jq length)
show "connector heartbeat posted -> $HB source(s) reporting"
QFLAG=$(curl -s -X POST "$VERITY$WH" -H 'content-type: application/json' \
  -d '{"schema":"vendor-x/lead.v2","rows":[["hot",42]]}' | jq -r .quarantined)
QN=$(curl -s "$VERITY/v1/admin/quarantine?tenant_id=$TENANT" | jq length)
show "unmappable webhook payload -> quarantined=$QFLAG ($QN item(s) await triage; never indexed permissively)"

say "Open the console — everything above is inspectable"
CONSOLE_HANDLE=$(mint '[11]' '[]' 'agent:console-operator')
show "console   $VERITY/ui"
show "tenant    $TENANT"
show "handle    $CONSOLE_HANDLE"
show "paste the handle into the console's Scope panel at $VERITY/ui to decode it and run scoped"
show "recalls as this principal; the tenant id above unlocks the admin panels."
