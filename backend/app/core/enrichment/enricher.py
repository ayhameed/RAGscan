"""
Enrichment service: NVD CVSS, FIRST EPSS, CISA KEV.

Checks enrichment_cache first. All three external APIs are called
concurrently on a cache miss. KEV is loaded from a pre-downloaded
in-memory set refreshed every 24 hours via a background task.
"""
import asyncio
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.models import EnrichmentCache, Finding
from app.schemas.schemas import FindingCreate

log = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# In-memory KEV set — loaded at startup, refreshed every 24 hours
_kev_cves: set[str] = set()
_kev_loaded_at: Optional[datetime] = None


async def load_kev(client: httpx.AsyncClient) -> None:
    global _kev_cves, _kev_loaded_at
    try:
        resp = await client.get(KEV_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        _kev_cves = {v["cveID"] for v in data.get("vulnerabilities", [])}
        _kev_loaded_at = datetime.now(timezone.utc)
        log.info("KEV loaded: %d entries", len(_kev_cves))
    except Exception as exc:
        log.warning("KEV load failed: %s", exc)


def is_kev(cve_id: str) -> bool:
    return cve_id.upper() in _kev_cves


async def _fetch_nvd(cve_id: str, client: httpx.AsyncClient) -> dict:
    params = {"cveId": cve_id}
    headers = {}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key
    try:
        resp = await client.get(NVD_URL, params=params, headers=headers, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return {}
        metrics = vulns[0].get("cve", {}).get("metrics", {})
        cvss_v31 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
        cvss_v30 = metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
        score = cvss_v31.get("baseScore") or cvss_v30.get("baseScore")
        return {"cvssV3Score": score, "raw": vulns[0].get("cve", {})}
    except Exception as exc:
        log.debug("NVD fetch failed for %s: %s", cve_id, exc)
        return {}


async def _fetch_epss(cve_id: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(EPSS_URL, params={"cve": cve_id}, timeout=10)
        resp.raise_for_status()
        data = resp.json().get("data", [])
        if not data:
            return {}
        return {"epss": float(data[0].get("epss", 0)), "percentile": float(data[0].get("percentile", 0))}
    except Exception as exc:
        log.debug("EPSS fetch failed for %s: %s", cve_id, exc)
        return {}


async def _get_cache(cve_id: str, session: AsyncSession) -> Optional[dict]:
    row = await session.get(EnrichmentCache, cve_id)
    if row is None:
        return None
    return {
        "cvss3_score": row.nvd_data.get("cvssV3Score") if row.nvd_data else None,
        "epss_score": row.epss_score,
        "epss_percentile": row.epss_percentile,
        "cisa_kev": row.cisa_kev,
    }


async def _save_cache(cve_id: str, result: dict, session: AsyncSession) -> None:
    existing = await session.get(EnrichmentCache, cve_id)
    if existing:
        existing.nvd_data = {"cvssV3Score": result.get("cvss3_score")}
        existing.epss_score = result.get("epss_score")
        existing.epss_percentile = result.get("epss_percentile")
        existing.cisa_kev = result.get("cisa_kev", False)
        existing.cached_at = datetime.now(timezone.utc)
    else:
        session.add(EnrichmentCache(
            cve_id=cve_id,
            nvd_data={"cvssV3Score": result.get("cvss3_score")},
            epss_score=result.get("epss_score"),
            epss_percentile=result.get("epss_percentile"),
            cisa_kev=result.get("cisa_kev", False),
            cached_at=datetime.now(timezone.utc),
        ))
    await session.commit()


async def enrich_cve(cve_id: str, client: httpx.AsyncClient, session: AsyncSession) -> dict:
    cached = await _get_cache(cve_id, session)
    if cached:
        return cached

    nvd, epss = await asyncio.gather(
        _fetch_nvd(cve_id, client),
        _fetch_epss(cve_id, client),
    )
    result = {
        "cvss3_score": nvd.get("cvssV3Score"),
        "epss_score": epss.get("epss"),
        "epss_percentile": epss.get("percentile"),
        "cisa_kev": is_kev(cve_id),
    }
    await _save_cache(cve_id, result, session)
    return result


async def enrich_finding(finding: Finding, client: httpx.AsyncClient, session: AsyncSession) -> None:
    if not finding.cve_id:
        return
    data = await enrich_cve(finding.cve_id, client, session)
    finding.cvss3_score = data.get("cvss3_score")
    finding.epss_score = data.get("epss_score")
    finding.epss_percentile = data.get("epss_percentile")
    finding.cisa_kev = data.get("cisa_kev", False)
    finding.enriched_at = datetime.now(timezone.utc)
