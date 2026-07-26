"""Verity sink for LangChain — a great sink, never a loader (SPEC §5e.4)."""

from ._client import VISIBILITY_TEACHING, VerityClient
from .vector_store import (
    ENTITIES_METADATA_KEY,
    VerityRetriever,
    VeritySubjectRetriever,
    VerityVectorStore,
)

__all__ = [
    "ENTITIES_METADATA_KEY",
    "VISIBILITY_TEACHING",
    "VerityClient",
    "VerityRetriever",
    "VeritySubjectRetriever",
    "VerityVectorStore",
]
