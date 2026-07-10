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
