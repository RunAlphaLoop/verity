# Verity demos

Runnable, self-contained proofs of the core guarantees. Each stands up a
throwaway demo space, proves something live, and tears it down — so they double
as regression protection and as things you can run in front of someone.

## Prerequisites

- The dev stack up **with SpiceDB** (identity resolution needs it):
  `verity-cli dev` (it wires SpiceDB when the container is healthy).
- The repo built: `cargo build --release` (the demos use `target/release/verity-mcp`).
- Local Postgres reachable at the dev DSN (for teardown).

Overridable via env: `VERITY_URL`, `VERITY_MCP_BIN`, `VERITY_DSN`.

## `two_agent_trust.py` — "agent A can never see agent B's data"

```
python3 demo/two_agent_trust.py
```

The whole thesis in one script. `all-staff ⊃ engineering ⊃ alice`; **Bob** is in
neither; a confidential doc is shared with `all-staff`. Two agents connect over
the **real MCP interface**, each naming only *who* it is (a subject) — never
what powers it holds:

- **Alice's agent recalls the doc** — Verity resolves `alice → engineering →
  all-staff` server-side (SPEC §6/§9a) and the doc is shared with `all-staff`.
  Nested-group ACL inheritance, live.
- **Bob's agent is provably dark** — on a normal query *and* under a
  prompt-injection attempt. The scope is a signed pre-filter; a prompt can't
  argue past it.

No principal token is ever handed to an agent. Exit code `0` = the boundary
held. Idempotent — safe to re-run.
