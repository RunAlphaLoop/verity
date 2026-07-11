"""Worker entrypoint: ``python -m verity_ingest.orchestration.worker``.

Connects to Temporal (``TEMPORAL_ADDRESS``/``TEMPORAL_NAMESPACE``), registers
``ConnectorSyncWorkflow`` + the poll-cycle activity on ``VERITY_TASK_QUEUE``,
and runs until interrupted. Scale horizontally by running more workers on the
same task queue.

Connector enablement (``VERITY_CONNECTORS``) is a *schedules* concern — see
:mod:`.schedules` — but the worker logs it at startup so an operator can see
at a glance whether the env it inherited matches what they meant to sync.
"""

from __future__ import annotations

import asyncio
import logging

from temporalio.client import Client
from temporalio.worker import Worker

from verity_ingest.orchestration import config
from verity_ingest.orchestration.activities import (
    run_connector_poll_cycle,
    trigger_entity_resolution,
)
from verity_ingest.orchestration.workflows import ConnectorSyncWorkflow

logger = logging.getLogger(__name__)


async def run_worker() -> None:
    client = await Client.connect(config.temporal_address(), namespace=config.temporal_namespace())
    logger.info(
        "verity-ingest worker: temporal=%s namespace=%s task_queue=%s connectors=%s",
        config.temporal_address(),
        config.temporal_namespace(),
        config.task_queue(),
        ",".join(config.enabled_connectors()) or "(none enabled — set VERITY_CONNECTORS)",
    )
    worker = Worker(
        client,
        task_queue=config.task_queue(),
        workflows=[ConnectorSyncWorkflow],
        activities=[run_connector_poll_cycle, trigger_entity_resolution],
    )
    await worker.run()


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        asyncio.run(run_worker())
    except KeyboardInterrupt:
        logger.info("worker interrupted; shutting down")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
