"""Knowledge index over two namespaces: internal secure code and OWASP guidance.

Backed by Pinecone in live mode and LangChain's `InMemoryVectorStore` offline. Both are
LangChain `VectorStore`s; the only difference is the metadata-filter dialect, which this
module translates from one small, backend-neutral filter shape.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping, Sequence
from typing import Literal

from langchain_core.documents import Document
from langchain_core.vectorstores import VectorStore

from remediation_rag.domain import Chunk, SourceKind

logger = logging.getLogger(__name__)

# {"vuln_class": "sql_injection", "language": ["python", "any"]}
#   str  -> equality, list -> membership. Keys are ANDed.
MetadataFilter = Mapping[str, str | Sequence[str]]
FilterDialect = Literal["pinecone", "callable"]


def to_pinecone_filter(filters: MetadataFilter) -> dict[str, object] | None:
    clauses: dict[str, object] = {}
    for key, value in filters.items():
        clauses[key] = {"$eq": value} if isinstance(value, str) else {"$in": list(value)}
    return clauses or None


def to_callable_filter(filters: MetadataFilter) -> Callable[[Document], bool] | None:
    if not filters:
        return None

    def predicate(doc: Document) -> bool:
        for key, value in filters.items():
            actual = doc.metadata.get(key)
            if isinstance(value, str):
                if actual != value:
                    return False
            elif actual not in value:
                return False
        return True

    return predicate


def document_to_chunk(doc: Document, similarity: float) -> Chunk:
    meta = doc.metadata
    return Chunk(
        id=str(meta["chunk_id"]),
        source=SourceKind(meta["source"]),
        text=doc.page_content,
        vuln_class=str(meta.get("vuln_class", "")),
        language=str(meta.get("language", "any")),
        framework=str(meta.get("framework", "any")),
        kind=str(meta.get("kind", "guidance")),
        source_path=str(meta.get("source_path", "")),
        title=str(meta.get("title", "")),
        similarity=round(float(similarity), 4),
    )


class KnowledgeIndex:
    def __init__(
        self, stores: Mapping[SourceKind, VectorStore], dialect: FilterDialect, *, label: str
    ) -> None:
        missing = set(SourceKind) - set(stores)
        if missing:
            raise ValueError(f"missing vector stores for {sorted(missing)}")
        self._stores = dict(stores)
        self._dialect = dialect
        self.label = label

    async def search(
        self, source: SourceKind, query: str, k: int, filters: MetadataFilter
    ) -> list[Chunk]:
        store = self._stores[source]
        native = (
            to_pinecone_filter(filters)
            if self._dialect == "pinecone"
            else to_callable_filter(filters)
        )
        results = await store.asimilarity_search_with_score(query, k=k, filter=native)
        return [document_to_chunk(doc, score) for doc, score in results]

    async def upsert(self, source: SourceKind, documents: list[Document]) -> int:
        if not documents:
            return 0
        ids = [str(doc.metadata["chunk_id"]) for doc in documents]
        await self._stores[source].aadd_documents(documents, ids=ids)
        return len(documents)
