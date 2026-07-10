"""Verity BaseStore for LangGraph — a great sink, never a loader (SPEC §5e.4)."""

from ._client import VISIBILITY_TEACHING, VerityClient
from .store import VerityStore, namespace_tag

__all__ = [
    "VISIBILITY_TEACHING",
    "VerityClient",
    "VerityStore",
    "namespace_tag",
]
