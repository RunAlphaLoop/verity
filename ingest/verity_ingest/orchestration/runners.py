"""Poll-cycle runners: the seam between Temporal activities and the EXISTING
connector classes.

A runner owns exactly one truth-lane cycle: build the connector from env,
``poll(cursor)``, deliver through the connector's own sink, and return the
next cursor. The connectors and sinks are used as-is (wrap, don't modify);
the only thing that changes vs. the ad-hoc ``--once`` runners is where the
cursor lives — Temporal workflow state instead of ``.verity/*_cursor`` files.

At-least-once invariant (load-bearing, tested): the next cursor is returned
ONLY after sink delivery succeeded. A delivery failure raises out of
``run_cycle``, the activity fails, and Temporal retries the SAME cursor —
the window replays into deterministic keyed upserts, which is safe; a lost
window would not be.
"""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Protocol

HeartbeatFn = Callable[..., None]


class RunnerConfigError(RuntimeError):
    """Missing/invalid operator config (env). Non-retryable: retrying cannot
    conjure a visibility policy or a credential."""


class UnknownConnectorError(RunnerConfigError):
    """The workflow named a connector this worker has no runner for."""


@dataclass
class CycleOutcome:
    next_cursor: str | None
    events_delivered: int
    #: The tenant this cycle wrote into. The runner is the only layer that
    #: knows it (env or connector config); the workflow needs it to fire the
    #: post-ingest resolution hook. ``None`` = tenant unknown → hook skipped.
    tenant_id: str | None = None


class PollCycleRunner(Protocol):
    async def run_cycle(self, cursor: str | None, heartbeat: HeartbeatFn) -> CycleOutcome: ...


def _visibility_from_env(env_var: str) -> list[int]:
    """Admin-assigned visibility policy for tier-C-style connectors: required,
    no default (fail closed — SPEC §5e.2), comma-separated int tokens."""
    raw = os.environ.get(env_var, "")
    try:
        policy = [int(token) for token in raw.split(",") if token.strip()]
    except ValueError as exc:
        raise RunnerConfigError(
            f"{env_var} must be comma-separated integers, e.g. 1,2 (got {raw!r})"
        ) from exc
    if not policy:
        raise RunnerConfigError(
            f"{env_var} must name at least one principal token (fail closed, no default)"
        )
    return policy


# ---------------------------------------------------------------------------
# FactEvent connectors (HubSpot, Salesforce) → VerityDebeziumSink
# ---------------------------------------------------------------------------


class DebeziumPollRunner:
    """One cycle for the structured CRM connectors: async ``poll`` on the
    connector, then one batched ``VerityDebeziumSink.post`` (which also fires
    the best-effort connector-status heartbeat, cursor included)."""

    def __init__(
        self,
        connector_factory: Callable[[], Any],
        sink_factory: Callable[[], Any],
    ) -> None:
        self._connector_factory = connector_factory
        self._sink_factory = sink_factory

    async def run_cycle(self, cursor: str | None, heartbeat: HeartbeatFn) -> CycleOutcome:
        connector = self._connector_factory()
        heartbeat(f"polling from cursor={cursor!r}")
        try:
            events, next_cursor = await connector.poll(cursor)
        finally:
            aclose = getattr(connector, "aclose", None)
            if aclose is not None:
                await aclose()
        heartbeat(f"delivering {len(events)} event(s)")
        sink = self._sink_factory()
        # sink.post is synchronous httpx; keep the activity's event loop (and
        # its heartbeats) responsive.
        await asyncio.to_thread(sink.post, list(events), next_cursor)
        # The VerityDebeziumSink carries the tenant (VERITY_TENANT_ID); surface
        # it so the workflow can fire the post-ingest resolution hook.
        return CycleOutcome(
            next_cursor=next_cursor,
            events_delivered=len(events),
            tenant_id=getattr(sink, "tenant_id", None),
        )


def _hubspot_runner() -> DebeziumPollRunner:
    from verity_ingest.connectors.hubspot import HubSpotConnector, VerityDebeziumSink

    policy = _visibility_from_env("HUBSPOT_VISIBILITY")
    # from_env demands the heartbeat source explicitly: idle beats key the
    # server's per-source freshness gate and must never ride a default.
    return DebeziumPollRunner(
        connector_factory=lambda: HubSpotConnector(policy),
        sink_factory=lambda: VerityDebeziumSink.from_env("hubspot"),
    )


def _salesforce_runner() -> DebeziumPollRunner:
    from verity_ingest.connectors.hubspot import VerityDebeziumSink
    from verity_ingest.connectors.salesforce import SalesforceConnector

    policy = _visibility_from_env("SALESFORCE_VISIBILITY")
    # The shared sink defaults its heartbeat source to HubSpot's; an idle
    # Salesforce cycle heartbeating as "hubspot" would silently mis-key the
    # server's per-source freshness gate — make it explicit.
    return DebeziumPollRunner(
        connector_factory=lambda: SalesforceConnector(policy),
        sink_factory=lambda: VerityDebeziumSink.from_env("salesforce"),
    )


# ---------------------------------------------------------------------------
# DocumentEvent connector (Google Drive) → VerityDocumentSink
# ---------------------------------------------------------------------------


class GDrivePollRunner:
    """One cycle for the Drive connector: poll the change feed, build each
    document request through the connector module's fail-closed ladder,
    deliver one-by-one (heartbeating progress), then the telemetry heartbeat.

    Delivery failure mid-batch raises with the batch partially delivered —
    the retry replays the whole window against the same content-addressed
    document ids, which the server dedupes (at-least-once, not exactly-once).
    """

    def __init__(
        self,
        connector_factory: Callable[[], Any],
        registry_factory: Callable[[], Any],
        sink_factory: Callable[[], Any],
    ) -> None:
        self._connector_factory = connector_factory
        self._registry_factory = registry_factory
        self._sink_factory = sink_factory

    async def run_cycle(self, cursor: str | None, heartbeat: HeartbeatFn) -> CycleOutcome:
        from verity_ingest.connectors.gdrive import build_document_request

        connector = self._connector_factory()
        heartbeat(f"polling from cursor={cursor!r}")
        events, next_cursor = await connector.poll(cursor)
        registry = self._registry_factory()
        sink = self._sink_factory()
        tenant_id = connector.config.tenant_id
        for index, event in enumerate(events, start=1):
            request = build_document_request(event, registry, tenant_id)
            await asyncio.to_thread(sink.deliver, request)
            heartbeat(f"delivered {index}/{len(events)}")
        telemetry = getattr(sink, "heartbeat", None)
        if telemetry is not None:  # best-effort connector-status heartbeat
            await asyncio.to_thread(telemetry, next_cursor)
        return CycleOutcome(
            next_cursor=next_cursor,
            events_delivered=len(events),
            tenant_id=tenant_id,
        )


def _gdrive_runner() -> GDrivePollRunner:
    from verity_ingest.connectors.gdrive import (
        GDriveConfig,
        GDriveConnector,
        HttpDriveTransport,
        HttpRegistry,
        StaticRegistry,
        VerityDocumentSink,
        load_service_account_credentials,
    )

    verity_url = os.environ.get("VERITY_URL", "http://localhost:8080")
    api_key = os.environ.get("VERITY_API_KEY")
    config = GDriveConfig(
        tenant_id=os.environ.get("VERITY_TENANT_ID", "default"),
        anyone_maps_to=os.environ.get("GDRIVE_ANYONE_MAPS_TO"),
        delegated_subject=os.environ.get("GDRIVE_DELEGATED_SUBJECT"),
    )

    def connector_factory() -> GDriveConnector:
        credentials = load_service_account_credentials(delegated_subject=config.delegated_subject)
        return GDriveConnector(HttpDriveTransport(credentials), config)

    def registry_factory() -> Any:
        principal_map = os.environ.get("GDRIVE_PRINCIPAL_MAP")
        if principal_map:
            return StaticRegistry(json.loads(Path(principal_map).read_text()))
        return HttpRegistry(verity_url, api_key=api_key)

    def sink_factory() -> VerityDocumentSink:
        sink = VerityDocumentSink(verity_url, api_key=api_key)
        # Same wiring as the module main: a cycle that delivered NOTHING still
        # needs a tenant + source to key its idle heartbeat row, or the beat is
        # silently skipped and the server's per-source freshness gate reads a
        # healthy-but-quiet Drive connector as stalled.
        sink.alarm_tenant_id = config.tenant_id
        sink.default_source = "gdrive"
        return sink

    return GDrivePollRunner(
        connector_factory=connector_factory,
        registry_factory=registry_factory,
        sink_factory=sink_factory,
    )


# ---------------------------------------------------------------------------
# Registry (test seam: tests register mock factories here)
# ---------------------------------------------------------------------------

RUNNER_FACTORIES: dict[str, Callable[[], PollCycleRunner]] = {
    "hubspot": _hubspot_runner,
    "salesforce": _salesforce_runner,
    "gdrive": _gdrive_runner,
}


def get_runner(connector: str) -> PollCycleRunner:
    factory = RUNNER_FACTORIES.get(connector)
    if factory is None:
        raise UnknownConnectorError(
            f"no runner for connector {connector!r} (known: {sorted(RUNNER_FACTORIES)})"
        )
    return factory()
