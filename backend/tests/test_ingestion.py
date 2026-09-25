from pathlib import Path

from langchain_core.documents import Document

from remediation_rag.clients.offline import HashingEmbeddings
from remediation_rag.domain import SourceKind, VulnClass
from remediation_rag.ingestion.pipeline import build_plan, chunk_internal_snippets, ingest
from remediation_rag.ingestion.sources import SNIPPETS_DIR, fetch_guidance, load_manifest
from remediation_rag.retrieval.factory import build_memory_index
from remediation_rag.retrieval.index import to_callable_filter, to_pinecone_filter

REQUIRED_METADATA = {
    "chunk_id",
    "source",
    "source_path",
    "vuln_class",
    "language",
    "framework",
    "kind",
}


def test_manifest_files_exist_and_cover_three_languages():
    manifest = load_manifest()
    assert {s.language for s in manifest.snippets} >= {"python", "javascript", "java"}
    for entry in manifest.snippets:
        assert (SNIPPETS_DIR / entry.path).is_file(), entry.path


def test_internal_chunks_carry_filterable_metadata():
    docs = chunk_internal_snippets()
    assert docs
    ids = [d.metadata["chunk_id"] for d in docs]
    assert len(ids) == len(set(ids)), "chunk ids must be unique for idempotent upserts"
    for doc in docs:
        assert doc.metadata.keys() >= REQUIRED_METADATA
        assert doc.metadata["source"] == SourceKind.INTERNAL.value


def test_offline_guidance_uses_digest_when_cache_is_empty(tmp_path: Path):
    guides = fetch_guidance(VulnClass.SQL_INJECTION, tmp_path, offline=True)
    assert len(guides) == 1 and guides[0].is_digest


def test_offline_guidance_prefers_cache(tmp_path: Path):
    for slug in ("sql-injection-prevention", "query-parameterization"):
        (tmp_path / f"{slug}.md").write_text("## Defense\n" + "Use prepared statements. " * 10)
    guides = fetch_guidance(VulnClass.SQL_INJECTION, tmp_path, offline=True)
    assert [g.is_digest for g in guides] == [False, False]


def test_filter_translation():
    filters = {"vuln_class": "sql_injection", "language": ["python", "any"]}
    assert to_pinecone_filter(filters) == {
        "vuln_class": {"$eq": "sql_injection"},
        "language": {"$in": ["python", "any"]},
    }
    predicate = to_callable_filter(filters)
    assert predicate is not None
    assert predicate(
        Document(page_content="", metadata={"vuln_class": "sql_injection", "language": "any"})
    )
    assert not predicate(
        Document(page_content="", metadata={"vuln_class": "sql_injection", "language": "java"})
    )
    assert to_pinecone_filter({}) is None and to_callable_filter({}) is None


async def test_memory_index_filters_by_language(tmp_path: Path):
    index = build_memory_index(HashingEmbeddings())
    counts = await ingest(index, build_plan(tmp_path, offline=True))
    assert counts["internal"] > 0 and counts["owasp"] > 0

    hits = await index.search(
        SourceKind.INTERNAL,
        "PreparedStatement setString executeQuery",
        k=3,
        filters={"vuln_class": "sql_injection", "language": "java"},
    )
    assert hits and all(h.language == "java" for h in hits)
    assert hits[0].framework == "jdbc"
