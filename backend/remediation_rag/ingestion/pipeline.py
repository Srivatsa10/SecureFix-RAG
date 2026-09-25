"""Ingestion: load -> chunk (with metadata) -> embed -> upsert into two namespaces.

uv run remediation-ingest --dry-run          # chunk + print stats, no credentials needed
uv run remediation-ingest                    # embed with Bedrock Titan, upsert to Pinecone
uv run remediation-ingest --offline-guidance # use the local digest instead of fetching OWASP
"""

from __future__ import annotations

import argparse
import asyncio
import logging
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from langchain_core.documents import Document
from langchain_text_splitters import (
    Language,
    MarkdownHeaderTextSplitter,
    RecursiveCharacterTextSplitter,
)

from remediation_rag.domain import SourceKind, VulnClass
from remediation_rag.ingestion.sources import (
    SNIPPETS_DIR,
    GuidanceDocument,
    fetch_guidance,
    load_manifest,
    supported_vuln_classes,
)
from remediation_rag.retrieval.index import KnowledgeIndex

logger = logging.getLogger(__name__)

CODE_CHUNK_SIZE = 1_600
CODE_CHUNK_OVERLAP = 200
GUIDANCE_CHUNK_SIZE = 1_400
GUIDANCE_CHUNK_OVERLAP = 150

_SPLITTER_LANGUAGE = {
    "python": Language.PYTHON,
    "javascript": Language.JS,
    "typescript": Language.TS,
    "java": Language.JAVA,
}


def chunk_internal_snippets(snippets_dir: Path = SNIPPETS_DIR) -> list[Document]:
    manifest = load_manifest(snippets_dir)
    documents: list[Document] = []
    for entry in manifest.snippets:
        source = (snippets_dir / entry.path).read_text(encoding="utf-8")
        language = _SPLITTER_LANGUAGE.get(entry.language)
        splitter = (
            RecursiveCharacterTextSplitter.from_language(
                language, chunk_size=CODE_CHUNK_SIZE, chunk_overlap=CODE_CHUNK_OVERLAP
            )
            if language
            else RecursiveCharacterTextSplitter(
                chunk_size=CODE_CHUNK_SIZE, chunk_overlap=CODE_CHUNK_OVERLAP
            )
        )
        for i, text in enumerate(splitter.split_text(source)):
            documents.append(
                Document(
                    page_content=text,
                    metadata={
                        "chunk_id": f"internal:{entry.path}#{i}",
                        "source": SourceKind.INTERNAL.value,
                        "source_repo": manifest.repository,
                        "source_path": entry.path,
                        "title": entry.title,
                        "vuln_class": entry.vuln_class.value,
                        "language": entry.language,
                        "framework": entry.framework,
                        "kind": entry.kind,
                    },
                )
            )
    return documents


def chunk_guidance(guides: list[GuidanceDocument]) -> list[Document]:
    header_splitter = MarkdownHeaderTextSplitter(
        headers_to_split_on=[("#", "h1"), ("##", "h2"), ("###", "h3")], strip_headers=False
    )
    size_splitter = RecursiveCharacterTextSplitter(
        chunk_size=GUIDANCE_CHUNK_SIZE, chunk_overlap=GUIDANCE_CHUNK_OVERLAP
    )
    documents: list[Document] = []
    for guide in guides:
        sections = size_splitter.split_documents(header_splitter.split_text(guide.markdown))
        for i, section in enumerate(sections):
            heading = " > ".join(section.metadata[h] for h in ("h2", "h3") if h in section.metadata)
            if len(section.page_content.strip()) < 80:
                continue  # skip heading-only / link-only fragments
            documents.append(
                Document(
                    page_content=section.page_content,
                    metadata={
                        "chunk_id": f"owasp:{guide.slug}#{i}",
                        "source": SourceKind.OWASP.value,
                        "source_path": guide.url,
                        "title": f"{guide.title} - {heading}" if heading else guide.title,
                        "vuln_class": guide.vuln_class.value,
                        "language": "any",
                        "framework": "any",
                        "kind": "digest" if guide.is_digest else "guidance",
                    },
                )
            )
    return documents


@dataclass(frozen=True)
class IngestionPlan:
    internal: list[Document]
    guidance: list[Document]
    used_digest: bool


def build_plan(
    cache_dir: Path, vuln_classes: set[VulnClass] | None = None, *, offline: bool = False
) -> IngestionPlan:
    classes = vuln_classes or supported_vuln_classes()
    internal = [d for d in chunk_internal_snippets() if d.metadata["vuln_class"] in classes]
    guides = [g for vc in sorted(classes) for g in fetch_guidance(vc, cache_dir, offline=offline)]
    return IngestionPlan(
        internal=internal,
        guidance=chunk_guidance(guides),
        used_digest=any(g.is_digest for g in guides),
    )


async def ingest(index: KnowledgeIndex, plan: IngestionPlan) -> dict[str, int]:
    return {
        SourceKind.INTERNAL.value: await index.upsert(SourceKind.INTERNAL, plan.internal),
        SourceKind.OWASP.value: await index.upsert(SourceKind.OWASP, plan.guidance),
    }


def describe(plan: IngestionPlan) -> str:
    by_lang = Counter(d.metadata["language"] for d in plan.internal)
    by_kind = Counter(d.metadata["kind"] for d in plan.internal)
    lines = [
        f"internal snippet chunks: {len(plan.internal)}",
        f"  by language: {dict(by_lang)}",
        f"  by kind:     {dict(by_kind)}",
        f"guidance chunks: {len(plan.guidance)} "
        f"({'offline digest' if plan.used_digest else 'live OWASP cheat sheets'})",
    ]
    for doc in plan.guidance[:5]:
        lines.append(f"  - {doc.metadata['chunk_id']}: {doc.metadata['title'][:80]}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> None:
    from remediation_rag.clients.bedrock import build_embeddings
    from remediation_rag.config import get_settings
    from remediation_rag.retrieval.factory import build_pinecone_index, ensure_pinecone_index

    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--dry-run", action="store_true", help="chunk and report; do not upsert")
    parser.add_argument(
        "--offline-guidance",
        action="store_true",
        help="no network: use cached cheat sheets, else the local digest",
    )
    parser.add_argument(
        "--vuln-class", action="append", type=VulnClass, help="limit to these classes"
    )
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    settings = get_settings()
    plan = build_plan(
        settings.data_cache_dir / "owasp",
        set(args.vuln_class) if args.vuln_class else None,
        offline=args.offline_guidance,
    )
    print(describe(plan))
    if args.dry_run:
        return

    if settings.pinecone_api_key is None:
        raise SystemExit("PINECONE_API_KEY is required to upsert (use --dry-run to preview)")
    ensure_pinecone_index(settings)
    index = build_pinecone_index(settings, build_embeddings(settings))
    counts = asyncio.run(ingest(index, plan))
    print(f"upserted: {counts} into {index.label}")


if __name__ == "__main__":
    main()
