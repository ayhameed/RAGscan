"""
Finding embedder using OpenAI text-embedding-3-small (1536 dims).
Serialises a Finding to a structured text representation before embedding.
"""
from langchain_openai import OpenAIEmbeddings
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.models import Finding, FindingEmbedding

_embedder = None


def _get_embedder() -> OpenAIEmbeddings:
    global _embedder
    if _embedder is None:
        _embedder = OpenAIEmbeddings(
            model=settings.embedding_model,
            openai_api_key=settings.openai_api_key,
        )
    return _embedder


def embedder():
    return _get_embedder()


def finding_to_text(f: Finding) -> str:
    kev_status = "YES - actively exploited" if f.cisa_kev else "no"
    epss = f"{f.epss_score:.4f}" if f.epss_score is not None else "N/A"
    return (
        f"ID: {f.id} | CVE: {f.cve_id or 'N/A'} | Severity: {f.severity_label.upper()} | "
        f"CVSS: {f.cvss3_score or 'N/A'} | EPSS: {epss} | "
        f"KEV: {kev_status} | Risk Score: {f.risk_score or 'N/A'} | "
        f"Host: {f.hostname or 'N/A'} ({f.host_ip or 'N/A'}) | "
        f"Title: {f.title} | "
        f"Description: {(f.description or '')[:500]} | "
        f"Solution: {(f.solution or '')[:300]}"
    )


async def embed_finding(finding: Finding, session: AsyncSession) -> None:
    text = finding_to_text(finding)
    vector = _get_embedder().embed_query(text)

    existing = await session.get(FindingEmbedding, finding.id)
    if existing:
        existing.embedding = vector
    else:
        session.add(FindingEmbedding(finding_id=finding.id, embedding=vector))
    await session.flush()


async def embed_batch(findings: list[Finding], session: AsyncSession) -> None:
    texts = [finding_to_text(f) for f in findings]
    vectors = _get_embedder().embed_documents(texts)
    for finding, vector in zip(findings, vectors):
        existing = await session.get(FindingEmbedding, finding.id)
        if existing:
            existing.embedding = vector
        else:
            session.add(FindingEmbedding(finding_id=finding.id, embedding=vector))
    await session.flush()
