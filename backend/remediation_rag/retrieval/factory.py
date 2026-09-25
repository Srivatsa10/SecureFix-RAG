"""Construct the KnowledgeIndex for the configured mode."""

from __future__ import annotations

import logging

from langchain_core.embeddings import Embeddings
from langchain_core.vectorstores import InMemoryVectorStore

from remediation_rag.config import Settings
from remediation_rag.domain import SourceKind
from remediation_rag.retrieval.index import KnowledgeIndex

logger = logging.getLogger(__name__)


def ensure_pinecone_index(settings: Settings) -> None:
    """Create the serverless index if it does not exist (dimension = embedding size)."""
    from pinecone import Pinecone, ServerlessSpec

    assert settings.pinecone_api_key is not None
    client = Pinecone(api_key=settings.pinecone_api_key.get_secret_value())
    if client.has_index(settings.pinecone_index_name):
        return
    logger.info("creating Pinecone index %s", settings.pinecone_index_name)
    client.create_index(
        name=settings.pinecone_index_name,
        dimension=settings.bedrock_embedding_dimensions,
        metric="cosine",
        spec=ServerlessSpec(cloud=settings.pinecone_cloud, region=settings.pinecone_region),
    )


def build_pinecone_index(settings: Settings, embeddings: Embeddings) -> KnowledgeIndex:
    from langchain_pinecone import PineconeVectorStore
    from pinecone import Pinecone

    assert settings.pinecone_api_key is not None
    client = Pinecone(api_key=settings.pinecone_api_key.get_secret_value())
    index = client.Index(settings.pinecone_index_name)
    namespaces = {
        SourceKind.INTERNAL: settings.pinecone_namespace_internal,
        SourceKind.OWASP: settings.pinecone_namespace_owasp,
    }
    stores = {
        kind: PineconeVectorStore(index=index, embedding=embeddings, namespace=namespace)
        for kind, namespace in namespaces.items()
    }
    return KnowledgeIndex(stores, "pinecone", label=f"pinecone:{settings.pinecone_index_name}")


def build_memory_index(embeddings: Embeddings) -> KnowledgeIndex:
    stores = {kind: InMemoryVectorStore(embeddings) for kind in SourceKind}
    return KnowledgeIndex(stores, "callable", label="in-memory (offline)")
