"""Verity Session backend for the OpenAI Agents SDK — a great sink, never a
loader (SPEC §5e.4, §9c)."""

from ._client import VISIBILITY_TEACHING, VerityClient
from .session import ITEM_KIND, RECALL_WINDOW, VeritySession, session_tag

__all__ = [
    "ITEM_KIND",
    "RECALL_WINDOW",
    "VISIBILITY_TEACHING",
    "VerityClient",
    "VeritySession",
    "session_tag",
]
