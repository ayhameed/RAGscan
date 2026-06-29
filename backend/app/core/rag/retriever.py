"""
pgvector cosine similarity retriever.
Returns top-k findings ordered by semantic similarity to the query.
"""
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.rag.embedder import _get_embedder
from app.models.models import Finding


async def retrieve(
    query: str,
    session: AsyncSession,
    k: int = None,
    severity_filter: str | None = None,
    host_filter: str | None = None,
    report_ids: list[str] | None = None,
) -> list[Finding]:
    k = k or settings.retrieval_k
    query_vec = _get_embedder().embed_query(query)
    vec_str = "[" + ",".join(str(x) for x in query_vec) + "]"

    where_clauses = ["1=1"]
    params: dict[str, str | int] = {"vec": vec_str, "k": k}
    if severity_filter:
        where_clauses.append("f.severity_label = :severity_filter")
        params["severity_filter"] = severity_filter
    if host_filter:
        where_clauses.append("(f.host_ip = :host_filter OR f.hostname = :host_filter)")
        params["host_filter"] = host_filter
    if report_ids:
        placeholders: list[str] = []
        for idx, rid in enumerate(report_ids):
            key = f"report_id_{idx}"
            placeholders.append(f":{key}")
            params[key] = str(rid)
        where_clauses.append(f"f.upload_id IN ({', '.join(placeholders)})")
    where = " AND ".join(where_clauses)

    sql = text(f"""
        SELECT f.*, 1 - (fe.embedding <=> CAST(:vec AS vector)) AS similarity
        FROM finding_embeddings fe
        JOIN findings f ON f.id = fe.finding_id
        WHERE {where}
        ORDER BY fe.embedding <=> CAST(:vec AS vector)
        LIMIT :k
    """)

    result = await session.execute(sql, params)
    rows = result.mappings().all()
    return [dict(r) for r in rows]
