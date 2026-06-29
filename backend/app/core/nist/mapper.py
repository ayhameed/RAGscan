"""
NIST CSF and ISO 27001 compliance gap mapper.

Mapping is deterministic (static JSON table). The LLM is not in the loop
here — it only writes narrative sections around the gaps detected.

Severity-based fallback for findings without a CWE ID:
  critical/high -> DE.CM-7 (detection), PR.IP-12 (vuln mgmt)
  medium        -> PR.IP-12
  low           -> PR.IP-12
"""
import json
import logging
from pathlib import Path
from typing import Literal

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete

from app.config import settings
from app.models.models import Finding, NistMapping, ComplianceGap

log = logging.getLogger(__name__)

Framework = Literal["nist_csf", "iso27001"]

_MAPPINGS_PATH = Path(__file__).parent / "cwe_nist_mappings.json"

_SEV_FALLBACK: dict[str, list[tuple[str, str, str, str]]] = {
    "critical": [
        ("nist_csf", "DE", "DE.CM-7", "Monitoring for unauthorized activity"),
        ("nist_csf", "PR", "PR.IP-12", "Vulnerability management plan"),
        ("iso27001", "A.8", "A.8.8", "Management of technical vulnerabilities"),
    ],
    "high": [
        ("nist_csf", "PR", "PR.IP-12", "Vulnerability management plan"),
        ("iso27001", "A.8", "A.8.8", "Management of technical vulnerabilities"),
    ],
    "medium": [
        ("nist_csf", "PR", "PR.IP-12", "Vulnerability management plan"),
        ("iso27001", "A.8", "A.8.8", "Management of technical vulnerabilities"),
    ],
    "low": [
        ("nist_csf", "PR", "PR.IP-12", "Vulnerability management plan"),
    ],
}


def _load_raw_mappings() -> list[dict]:
    with open(_MAPPINGS_PATH) as f:
        return json.load(f)


async def seed_mappings(session: AsyncSession) -> None:
    """Seed nist_mappings table from JSON on startup (idempotent)."""
    count = (await session.execute(select(NistMapping).limit(1))).first()
    if count:
        return
    for row in _load_raw_mappings():
        session.add(NistMapping(
            cwe_id=row["cwe_id"],
            framework=row["framework"],
            control_family=row["family"],
            control_id=row["control_id"],
            description=row["description"],
        ))
    await session.commit()
    log.info("NIST/ISO 27001 mappings seeded")


def _map_by_cwe(cwe_id: str, framework: Framework) -> list[dict]:
    for row in _load_raw_mappings():
        if row["cwe_id"] == cwe_id and row["framework"] == framework:
            yield row


def _map_by_severity(severity: str, framework: Framework) -> list[dict]:
    fallbacks = _SEV_FALLBACK.get(severity, [])
    for fb_framework, family, control_id, desc in fallbacks:
        if fb_framework == framework:
            yield {"control_id": control_id, "family": family, "description": desc}


def get_controls(cwe_id: str | None, severity: str, framework: Framework) -> list[dict]:
    if cwe_id:
        controls = list(_map_by_cwe(cwe_id, framework))
        if controls:
            return controls
    return list(_map_by_severity(severity, framework))


def _gap_level(risk_score: float | None) -> str:
    s = risk_score or 0
    if s >= 70:
        return "critical"
    if s >= 40:
        return "significant"
    return "minor"


async def compute_and_store_gaps(
    findings: list[Finding],
    framework: Framework,
    session: AsyncSession,
) -> dict[str, list[str]]:
    """
    Map each finding to framework controls, persist ComplianceGap rows,
    and return {control_id: [finding_ids]}.
    """
    await session.execute(
        delete(ComplianceGap).where(ComplianceGap.framework == framework)
    )

    gaps: dict[str, list[str]] = {}
    for f in findings:
        if (f.risk_score or 0) < settings.risk_gap_threshold:
            continue
        controls = get_controls(f.cwe_id, f.severity_label, framework)
        for ctrl in controls:
            ctrl_id = ctrl["control_id"]
            gaps.setdefault(ctrl_id, []).append(str(f.id))
            session.add(ComplianceGap(
                finding_id=f.id,
                framework=framework,
                control_id=ctrl_id,
                gap_level=_gap_level(f.risk_score),
            ))

    await session.commit()
    return gaps
