"""Create/update Temporal Schedules for the enabled connectors.

    python -m verity_ingest.orchestration.schedules            # dry-run: print the plan
    python -m verity_ingest.orchestration.schedules --apply    # create/update for real

One Schedule per connector in ``VERITY_CONNECTORS`` (override with
``--connectors``), id ``verity-sync-<connector>``, firing every
``VERITY_SYNC_INTERVAL[_<CONNECTOR>]`` seconds with **overlap policy SKIP**.

Why a Schedule at all, when ``ConnectorSyncWorkflow`` already loops forever
via continue-as-new? The Schedule is the supervisor: it starts the workflow
the first time and re-starts it if the chain is ever terminated or fails
past its retry policy. While the workflow chain is alive, every tick is
skipped (SKIP + a fixed workflow id ``connector-sync-<connector>``), so there
is never more than one sync chain per connector. A restarted chain begins
with ``cursor=None`` — connector-default resume semantics (HubSpot/Salesforce
replay from epoch into keyed upserts; Drive re-arms the change feed and the
reconciliation crawl covers the gap) — at-least-once, never silent loss.
"""

from __future__ import annotations

import argparse
import asyncio
from datetime import timedelta
from typing import Any, Sequence

from temporalio.client import (
    Client,
    Schedule,
    ScheduleActionStartWorkflow,
    ScheduleAlreadyRunningError,
    ScheduleIntervalSpec,
    ScheduleOverlapPolicy,
    SchedulePolicy,
    ScheduleSpec,
    ScheduleUpdate,
)

from verity_ingest.orchestration import config
from verity_ingest.orchestration.shared import ConnectorSyncInput

WORKFLOW_NAME = "ConnectorSyncWorkflow"


def schedule_id_for(connector: str) -> str:
    return f"verity-sync-{connector}"


def workflow_id_for(connector: str) -> str:
    return f"connector-sync-{connector}"


def build_schedule(connector: str, interval_seconds: float) -> Schedule:
    return Schedule(
        action=ScheduleActionStartWorkflow(
            WORKFLOW_NAME,
            ConnectorSyncInput(
                connector=connector,
                interval_seconds=interval_seconds,
                resolve_debounce_seconds=config.resolve_debounce_seconds(),
            ),
            id=workflow_id_for(connector),
            task_queue=config.task_queue(),
        ),
        spec=ScheduleSpec(
            intervals=[ScheduleIntervalSpec(every=timedelta(seconds=interval_seconds))]
        ),
        policy=SchedulePolicy(overlap=ScheduleOverlapPolicy.SKIP),
    )


async def apply_schedules(client: Any, connectors: Sequence[str]) -> dict[str, str]:
    """Create each connector's Schedule; if it already exists, update it in
    place (interval/config changes take effect without deleting history).
    Returns ``{connector: "created" | "updated"}``. ``client`` is duck-typed
    (``create_schedule`` / ``get_schedule_handle``) so tests need no server."""
    results: dict[str, str] = {}
    for connector in connectors:
        schedule = build_schedule(connector, config.interval_seconds(connector))
        try:
            await client.create_schedule(schedule_id_for(connector), schedule)
            results[connector] = "created"
        except ScheduleAlreadyRunningError:
            handle = client.get_schedule_handle(schedule_id_for(connector))
            await handle.update(lambda _in, s=schedule: ScheduleUpdate(schedule=s))
            results[connector] = "updated"
    return results


async def _run(connectors: Sequence[str], apply: bool) -> int:
    if not connectors:
        print("nothing to do: no connectors enabled (set VERITY_CONNECTORS or --connectors)")
        return 1
    if not apply:
        for connector in connectors:
            interval = config.interval_seconds(connector)
            print(
                f"[dry-run] would apply schedule {schedule_id_for(connector)}: "
                f"{WORKFLOW_NAME}({connector}) every {interval:g}s, overlap=SKIP "
                f"on task queue {config.task_queue()!r}"
            )
        print("re-run with --apply to create/update")
        return 0
    client = await Client.connect(config.temporal_address(), namespace=config.temporal_namespace())
    results = await apply_schedules(client, connectors)
    for connector, outcome in results.items():
        print(f"{schedule_id_for(connector)}: {outcome}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m verity_ingest.orchestration.schedules",
        description=__doc__.split("\n", 1)[0],
    )
    parser.add_argument(
        "--apply", action="store_true", help="create/update the schedules (default: dry-run)"
    )
    parser.add_argument(
        "--connectors",
        default=None,
        help="comma list overriding VERITY_CONNECTORS, e.g. hubspot,gdrive",
    )
    args = parser.parse_args(argv)
    if args.connectors is not None:
        connectors = [t.strip().lower() for t in args.connectors.split(",") if t.strip()]
    else:
        connectors = config.enabled_connectors()
    return asyncio.run(_run(connectors, apply=args.apply))


if __name__ == "__main__":
    raise SystemExit(main())
