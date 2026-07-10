"""Env-driven orchestration config: which connectors, how often, where Temporal is.

Everything is environment-first so the worker container needs no config file:

- ``TEMPORAL_ADDRESS``   (default ``localhost:7233``)
- ``TEMPORAL_NAMESPACE`` (default ``default``)
- ``VERITY_TASK_QUEUE``  (default ``verity-ingest``)
- ``VERITY_CONNECTORS``  comma list of enabled connectors, e.g.
  ``hubspot,salesforce,gdrive``. Default EMPTY: nothing syncs unless an
  operator says so (fail closed, same doctrine as visibility policies).
- ``VERITY_SYNC_INTERVAL``            default poll interval in seconds (300)
- ``VERITY_SYNC_INTERVAL_<CONNECTOR>`` per-connector override, e.g.
  ``VERITY_SYNC_INTERVAL_HUBSPOT=60``

Connector credentials/policies ride on the connectors' own env contract
(``HUBSPOT_PRIVATE_APP_TOKEN``, ``SF_*``, ``GOOGLE_APPLICATION_CREDENTIALS``,
``VERITY_TENANT_ID`` …); see :mod:`.runners`.
"""

from __future__ import annotations

import os

DEFAULT_ADDRESS = "localhost:7233"
DEFAULT_NAMESPACE = "default"
DEFAULT_TASK_QUEUE = "verity-ingest"
DEFAULT_INTERVAL_SECONDS = 300.0

CONNECTORS_ENV = "VERITY_CONNECTORS"
INTERVAL_ENV = "VERITY_SYNC_INTERVAL"


def temporal_address() -> str:
    return os.environ.get("TEMPORAL_ADDRESS", DEFAULT_ADDRESS)


def temporal_namespace() -> str:
    return os.environ.get("TEMPORAL_NAMESPACE", DEFAULT_NAMESPACE)


def task_queue() -> str:
    return os.environ.get("VERITY_TASK_QUEUE", DEFAULT_TASK_QUEUE)


def enabled_connectors() -> list[str]:
    """Connectors named in ``VERITY_CONNECTORS`` (deduplicated, order kept).
    Empty/unset means none — enabling a sync is an explicit operator act."""
    raw = os.environ.get(CONNECTORS_ENV, "")
    seen: list[str] = []
    for token in raw.split(","):
        name = token.strip().lower()
        if name and name not in seen:
            seen.append(name)
    return seen


def interval_seconds(connector: str) -> float:
    """Poll interval for one connector: per-connector env override, then the
    global default. Non-positive/garbage values are rejected loudly."""
    raw = os.environ.get(f"{INTERVAL_ENV}_{connector.upper()}") or os.environ.get(INTERVAL_ENV)
    if raw is None:
        return DEFAULT_INTERVAL_SECONDS
    try:
        value = float(raw)
    except ValueError as exc:
        raise RuntimeError(f"invalid sync interval {raw!r} for {connector}") from exc
    if value <= 0:
        raise RuntimeError(f"sync interval for {connector} must be positive, got {value}")
    return value
