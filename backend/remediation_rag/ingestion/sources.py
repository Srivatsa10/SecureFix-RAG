"""Knowledge sources: the internal snippet manifest and the OWASP guidance registry.

Adding a vulnerability class = add a `VulnClass` member, one `OWASP_SOURCES` entry,
(optionally) an offline digest file, and tag the relevant internal snippets in
`seed/snippets/manifest.yaml`. Nothing else in the pipeline is class-specific.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

import httpx
import yaml
from pydantic import BaseModel

from remediation_rag.domain import VulnClass

logger = logging.getLogger(__name__)

SEED_DIR = Path(__file__).resolve().parent / "seed"
SNIPPETS_DIR = SEED_DIR / "snippets"
DIGEST_DIR = SEED_DIR / "owasp_digest"

_CHEATSHEETS = "https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/cheatsheets"


@dataclass(frozen=True)
class GuidanceSource:
    slug: str
    title: str
    url: str


OWASP_SOURCES: dict[VulnClass, tuple[GuidanceSource, ...]] = {
    VulnClass.SQL_INJECTION: (
        GuidanceSource(
            slug="sql-injection-prevention",
            title="OWASP SQL Injection Prevention Cheat Sheet",
            url=f"{_CHEATSHEETS}/SQL_Injection_Prevention_Cheat_Sheet.md",
        ),
        GuidanceSource(
            slug="query-parameterization",
            title="OWASP Query Parameterization Cheat Sheet",
            url=f"{_CHEATSHEETS}/Query_Parameterization_Cheat_Sheet.md",
        ),
    ),
}


def supported_vuln_classes() -> set[VulnClass]:
    return set(OWASP_SOURCES)


class SnippetEntry(BaseModel):
    path: str
    title: str
    vuln_class: VulnClass
    language: str
    framework: str
    kind: str


class SnippetManifest(BaseModel):
    repository: str
    snippets: list[SnippetEntry]


def load_manifest(snippets_dir: Path = SNIPPETS_DIR) -> SnippetManifest:
    raw = yaml.safe_load((snippets_dir / "manifest.yaml").read_text(encoding="utf-8"))
    return SnippetManifest.model_validate(raw)


@dataclass(frozen=True)
class GuidanceDocument:
    vuln_class: VulnClass
    slug: str
    title: str
    url: str
    markdown: str
    is_digest: bool


def fetch_guidance(
    vuln_class: VulnClass, cache_dir: Path, *, offline: bool = False, timeout: float = 15.0
) -> list[GuidanceDocument]:
    """Return the OWASP cheat sheets for `vuln_class`.

    Order of preference: on-disk cache -> live fetch (unless `offline`) -> project digest.
    """
    sources = OWASP_SOURCES.get(vuln_class, ())
    documents: list[GuidanceDocument] = []
    for source in sources:
        cached = cache_dir / f"{source.slug}.md"
        if not cached.exists():
            if offline:
                break
            try:
                response = httpx.get(source.url, timeout=timeout, follow_redirects=True)
                response.raise_for_status()
            except httpx.HTTPError as exc:
                logger.warning("could not fetch %s (%s); using digest", source.url, exc)
                break
            cache_dir.mkdir(parents=True, exist_ok=True)
            cached.write_text(response.text, encoding="utf-8")
        documents.append(
            GuidanceDocument(
                vuln_class=vuln_class,
                slug=source.slug,
                title=source.title,
                url=source.url,
                markdown=cached.read_text(encoding="utf-8"),
                is_digest=False,
            )
        )
    if sources and len(documents) == len(sources):
        return documents

    digest = DIGEST_DIR / f"{vuln_class.value}.md"
    if not digest.exists():
        raise FileNotFoundError(f"no guidance available offline for {vuln_class}")
    return [
        GuidanceDocument(
            vuln_class=vuln_class,
            slug=f"{vuln_class.value}-digest",
            title=f"{vuln_class.value} remediation digest (project-authored)",
            url=f"file://{digest.name}",
            markdown=digest.read_text(encoding="utf-8"),
            is_digest=True,
        )
    ]
