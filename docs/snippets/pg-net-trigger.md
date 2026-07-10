# Postgres → Verity with a pg_net trigger (CDC-lite)

One copy-paste trigger that POSTs row changes to a minted Verity webhook URL.
Works on Supabase (pg_net ships preinstalled — enable it under Database →
Extensions) or any Postgres with [pg_net](https://github.com/supabase/pg_net)
installed. This is the convenience lane: no replication slot, no Kafka, no
connector process — the database itself pushes. For whole-database CDC with
ordering, snapshots, and gap recovery, use the Debezium lane at the bottom.

The payload uses Verity's native `facts` shape, so rows land as deterministic,
bi-temporal L1 facts keyed `(source, entity_id, field)` — zero mapping, no
quarantine detour, queryable seconds after commit.

## 1. Mint the webhook URL

```sh
verity-cli webhook mint pg:orders --visibility 1
```

Visibility is bound into the URL at mint time — every row this trigger pushes
is readable by exactly those principal tokens, and the payload can never widen
that set. The URL is shown once; the token in it IS the credential. Paste it
into the function below.

## 2. Enable pg_net

```sql
create extension if not exists pg_net;
```

## 3. The trigger

Substitute the minted URL, your table name (`orders` below), and its primary
key column (the trigger argument, `'id'` below).

```sql
create or replace function verity_row_to_facts()
returns trigger
language plpgsql
as $$
declare
  -- Paste the URL minted by `verity-cli webhook mint` (shown exactly once).
  verity_url constant text := 'https://verity.example.com/wh/<token>';
  pk_column  constant text := tg_argv[0];
  row_new    jsonb := to_jsonb(new);
  -- CASE guarantees OLD is only touched on UPDATE (it is unassigned on INSERT).
  row_old    jsonb := case when tg_op = 'UPDATE' then to_jsonb(old) end;
  facts      jsonb;
begin
  select jsonb_agg(jsonb_build_object(
           'source',     'pg:' || tg_table_name,
           'entity_id',  row_new ->> pk_column,
           'field',      kv.key,
           'value',      kv.value,
           'valid_from', now()
         ))
    into facts
    from jsonb_each(row_new) as kv
   where kv.key <> pk_column
     -- On UPDATE, send only the columns that actually changed.
     and (row_old is null or kv.value is distinct from row_old -> kv.key);

  if facts is not null then
    perform net.http_post(
      url     := verity_url,
      body    := jsonb_build_object('facts', facts),
      headers := '{"Content-Type": "application/json"}'::jsonb
    );
  end if;
  return null; -- AFTER trigger: the return value is ignored
end;
$$;

create trigger verity_cdc
  after insert or update on orders
  for each row execute function verity_row_to_facts('id');
```

Then watch it land:

```sql
insert into orders (id, status, amount) values (1042, 'paid', 99.00);
```

```sh
verity-cli query "order 1042"
```

## What lands, exactly

- One fact per column, keyed `(source = "pg:orders", entity_id = <pk>, field = <column>)`.
  Re-sending an unchanged value is a no-op; a changed value supersedes the old
  row bi-temporally (`valid_to` + `superseded_by` — never UPDATE-in-place).
- `valid_from` is the transaction's `now()`, so validity tracks commit time,
  not delivery time.
- INSERTs send every column; UPDATEs send only what changed.

## Honest limits (why the Debezium lane exists)

- **Fire-and-forget.** `net.http_post` is async and does not fail your
  transaction. Delivery failures are visible in `net._http_response`, but
  nothing retries in order — gaps are possible.
- **No DELETEs.** Verity invalidates rather than deletes; a row-level tombstone
  needs the CDC envelope below, which retires the entity's facts properly.
- **No backfill.** Triggers see changes "from now on", not history.

## Alternative: the Debezium envelope (the truth lane)

Already running CDC, or need ordering, snapshots (backfill), and deletes?
Verity accepts Debezium change-event envelopes as first-class input — no
trigger, no mapping:

```
POST /v1/ingest/debezium?tenant_id=<uuid>&pk=id
```

Point a [Debezium Server](https://debezium.io/documentation/reference/stable/operations/debezium-server.html)
HTTP sink (or a small Kafka consumer) at that endpoint; it accepts a single
envelope or a JSON array, upserts row facts through the same bi-temporal path,
and handles `op: "d"` by retiring the entity's facts. The endpoint is an admin
surface — send the server's `VERITY_ADMIN_TOKEN` as a bearer token when one is
configured. See SPEC §5 (Ingestion & Freshness, push lane) for the contract.
