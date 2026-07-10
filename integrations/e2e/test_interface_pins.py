"""Interface-pin canary: assert each framework's exact plug point still exists
and our class still satisfies it (runtime protocol isinstance checks, required
constructor/method signatures via ``inspect``, field pins for every attribute
our adapters read).

Designed to FAIL WITH A MESSAGE naming the framework and what moved — the
CrewAI-1.0-style breakage detector (``ExternalMemory`` vanished in the 1.0
unified-memory rewrite; these pins turn the next such rewrite into a red weekly
canary run instead of a user bug report). No live server needed: adapters are
constructed against a dummy URL (no network happens before the first call).
"""

from __future__ import annotations

import importlib
import inspect

import pytest

pytestmark = pytest.mark.e2e

DUMMY = dict(verity_url="http://pin.invalid", tenant_id="pin-tenant", visibility_policy=[1])


def _pin(framework: str, condition: bool, moved: str) -> None:
    assert condition, (
        f"[{framework}] interface pin broken: {moved}. "
        f"The framework-side plug point changed shape — update the "
        f"integrations/verity-* adapter (and its pyproject floor) for the new "
        f"{framework} interface."
    )


def _import(framework: str, module: str):
    try:
        return importlib.import_module(module)
    except Exception as exc:  # ImportError or transitive breakage
        pytest.fail(
            f"[{framework}] plug-point module {module!r} no longer imports: {exc!r}. "
            f"The framework moved or removed it — update the adapter."
        )


def _params(func) -> list[str]:
    return list(inspect.signature(func).parameters)


def _not_abstract(framework: str, cls: type) -> None:
    _pin(
        framework,
        not inspect.isabstract(cls),
        f"{cls.__name__} became abstract — the base class grew new abstract "
        f"methods our adapter does not implement: "
        f"{sorted(getattr(cls, '__abstractmethods__', set()))}",
    )


# ---------- LlamaIndex: BasePydanticVectorStore ----------


def test_llamaindex_vector_store_pin():
    fw = "llama-index-core"
    types_mod = _import(fw, "llama_index.core.vector_stores.types")
    _import(fw, "llama_index.core.schema")
    from verity_llamaindex import VerityVectorStore

    base = types_mod.BasePydanticVectorStore
    _pin(fw, issubclass(VerityVectorStore, base), "BasePydanticVectorStore is no longer our base")
    _not_abstract(fw, VerityVectorStore)

    store = VerityVectorStore(**DUMMY)
    _pin(fw, isinstance(store, base), "constructed store no longer isinstance of the base")
    _pin(fw, store.stores_text is True, "stores_text attribute moved")
    _pin(fw, "nodes" in _params(store.add), "VectorStore.add(nodes) signature moved")
    _pin(fw, "query" in _params(store.query), "VectorStore.query(query) signature moved")
    _pin(fw, "ref_doc_id" in _params(store.delete), "VectorStore.delete(ref_doc_id) moved")

    query_fields = set(types_mod.VectorStoreQuery.__dataclass_fields__)
    for field in ("query_str", "query_embedding", "similarity_top_k", "filters"):
        _pin(fw, field in query_fields, f"VectorStoreQuery.{field} field moved")
    result_fields = set(types_mod.VectorStoreQueryResult.__dataclass_fields__)
    for field in ("nodes", "similarities", "ids"):
        _pin(fw, field in result_fields, f"VectorStoreQueryResult.{field} field moved")


# ---------- LangChain: VectorStore + BaseRetriever ----------


def test_langchain_vector_store_and_retriever_pin():
    fw = "langchain-core"
    vs_mod = _import(fw, "langchain_core.vectorstores")
    retr_mod = _import(fw, "langchain_core.retrievers")
    _import(fw, "langchain_core.documents")
    from verity_langchain import VerityRetriever, VerityVectorStore

    _pin(fw, issubclass(VerityVectorStore, vs_mod.VectorStore), "VectorStore base moved")
    _not_abstract(fw, VerityVectorStore)
    store = VerityVectorStore(**DUMMY)

    retriever = store.as_retriever(search_kwargs={"k": 3})
    _pin(
        fw,
        isinstance(retriever, retr_mod.BaseRetriever),
        "as_retriever() no longer a BaseRetriever",
    )
    _pin(fw, isinstance(retriever, VerityRetriever), "as_retriever() no longer our retriever")
    _pin(fw, callable(getattr(retriever, "invoke", None)), "BaseRetriever.invoke entry point moved")
    _pin(
        fw,
        {"query", "run_manager"} <= set(_params(VerityRetriever._get_relevant_documents)),
        "BaseRetriever._get_relevant_documents(query, run_manager) hook moved",
    )
    _pin(fw, "texts" in _params(store.add_texts), "VectorStore.add_texts(texts) moved")
    _pin(fw, "query" in _params(store.similarity_search), "VectorStore.similarity_search moved")


# ---------- LangGraph: BaseStore + the op tuples ----------


def test_langgraph_base_store_pin():
    fw = "langgraph-checkpoint"
    base_mod = _import(fw, "langgraph.store.base")
    from verity_langgraph import VerityStore

    _pin(fw, issubclass(VerityStore, base_mod.BaseStore), "BaseStore base moved")
    _not_abstract(fw, VerityStore)
    store = VerityStore(**DUMMY)

    for entry in ("put", "get", "search", "batch", "abatch"):
        _pin(fw, callable(getattr(store, entry, None)), f"BaseStore.{entry} entry point moved")

    # The op tuples batch() dispatches on, and every field we read from them.
    for op_name, fields in (
        ("GetOp", {"namespace", "key"}),
        ("PutOp", {"namespace", "key", "value"}),
        ("SearchOp", {"namespace_prefix", "query", "filter", "limit", "offset"}),
    ):
        op_cls = getattr(base_mod, op_name, None)
        _pin(fw, op_cls is not None, f"{op_name} moved out of langgraph.store.base")
        _pin(
            fw,
            fields <= set(op_cls._fields),
            f"{op_name} lost fields {fields - set(op_cls._fields)}",
        )

    for item_name, fields in (
        ("Item", {"value", "key", "namespace", "created_at", "updated_at"}),
        ("SearchItem", {"namespace", "key", "value", "created_at", "updated_at", "score"}),
    ):
        item_cls = getattr(base_mod, item_name, None)
        _pin(fw, item_cls is not None, f"{item_name} moved out of langgraph.store.base")
        missing = fields - set(_params(item_cls.__init__))
        _pin(fw, not missing, f"{item_name}.__init__ lost parameters {sorted(missing)}")


# ---------- CrewAI: StorageBackend protocol + unified Memory wiring ----------


def test_crewai_storage_backend_pin():
    fw = "crewai"
    backend_mod = _import(fw, "crewai.memory.storage.backend")
    types_mod = _import(fw, "crewai.memory.types")
    memory_mod = _import(fw, "crewai.memory")
    from verity_crewai import VerityStorage

    protocol = backend_mod.StorageBackend
    storage = VerityStorage(**DUMMY)
    _pin(
        fw,
        isinstance(storage, protocol),
        "VerityStorage no longer satisfies the StorageBackend runtime protocol "
        "(a protocol method was added or renamed)",
    )
    _pin(
        fw,
        {"query_embedding", "scope_prefix", "limit", "min_score"} <= set(_params(storage.search)),
        "StorageBackend.search signature moved",
    )
    _pin(fw, "records" in _params(storage.save), "StorageBackend.save(records) moved")

    # Every MemoryRecord field our envelope codec reads/writes.
    record_fields = {
        "id",
        "content",
        "scope",
        "categories",
        "metadata",
        "importance",
        "created_at",
        "last_accessed",
        "source",
        "private",
    }
    missing = record_fields - set(types_mod.MemoryRecord.model_fields)
    _pin(fw, not missing, f"MemoryRecord lost fields {sorted(missing)}")

    # The Memory(storage=..., embedder=...) wiring we document and e2e-test.
    memory_cls = memory_mod.Memory
    for field in ("storage", "embedder"):
        _pin(fw, field in memory_cls.model_fields, f"Memory.{field} field moved")
    _pin(
        fw,
        {"scope", "categories", "importance"} <= set(_params(memory_cls.remember)),
        "Memory.remember explicit-field parameters moved (the zero-LLM save path)",
    )
    _pin(fw, "depth" in _params(memory_cls.recall), "Memory.recall(depth=...) parameter moved")


# ---------- Google ADK: BaseMemoryService + Session/Event shapes ----------


def test_adk_memory_service_pin():
    fw = "google-adk"
    memory_mod = _import(fw, "google.adk.memory")
    base_mod = _import(fw, "google.adk.memory.base_memory_service")
    entry_mod = _import(fw, "google.adk.memory.memory_entry")
    sessions_mod = _import(fw, "google.adk.sessions")
    events_mod = _import(fw, "google.adk.events")
    from verity_adk import VerityMemoryService

    _pin(
        fw,
        issubclass(VerityMemoryService, memory_mod.BaseMemoryService),
        "BaseMemoryService base moved",
    )
    _not_abstract(fw, VerityMemoryService)
    service = VerityMemoryService(**DUMMY)

    _pin(
        fw,
        "session" in _params(service.add_session_to_memory),
        "BaseMemoryService.add_session_to_memory(session) moved",
    )
    _pin(
        fw,
        {"app_name", "user_id", "query"} <= set(_params(service.search_memory)),
        "BaseMemoryService.search_memory(app_name, user_id, query) moved",
    )
    _pin(
        fw,
        callable(getattr(base_mod, "SearchMemoryResponse", None))
        and "memories" in base_mod.SearchMemoryResponse.model_fields,
        "SearchMemoryResponse.memories moved",
    )
    entry_missing = {"content", "author", "timestamp"} - set(entry_mod.MemoryEntry.model_fields)
    _pin(fw, not entry_missing, f"MemoryEntry lost fields {sorted(entry_missing)}")

    session_missing = {"id", "app_name", "user_id", "events"} - set(
        sessions_mod.Session.model_fields
    )
    _pin(fw, not session_missing, f"Session lost fields {sorted(session_missing)}")
    event_missing = {"id", "author", "timestamp", "content"} - set(events_mod.Event.model_fields)
    _pin(fw, not event_missing, f"Event lost fields {sorted(event_missing)}")


# ---------- OpenAI Agents SDK: the Session runtime protocol ----------


def test_openai_agents_session_pin():
    fw = "openai-agents"
    session_mod = _import(fw, "agents.memory.session")
    items_mod = _import(fw, "agents.items")
    from verity_openai_agents import VeritySession

    protocol = session_mod.Session
    _pin(
        fw,
        getattr(protocol, "_is_runtime_protocol", False),
        "agents.memory.session.Session is no longer a runtime-checkable protocol",
    )
    session = VeritySession("pin-thread", **DUMMY)
    _pin(
        fw,
        isinstance(session, protocol),
        "VeritySession no longer satisfies the Session runtime protocol "
        "(a protocol method was added or renamed)",
    )
    _pin(fw, "limit" in _params(session.get_items), "Session.get_items(limit) moved")
    _pin(fw, "items" in _params(session.add_items), "Session.add_items(items) moved")
    for method in ("pop_item", "clear_session"):
        _pin(fw, callable(getattr(session, method, None)), f"Session.{method} moved")
    _pin(
        fw,
        hasattr(items_mod, "TResponseInputItem"),
        "agents.items.TResponseInputItem type alias moved",
    )
