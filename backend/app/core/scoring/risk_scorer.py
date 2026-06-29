"""
Composite risk score: (CVSS * 0.4) + (EPSS * 0.4) + (KEV * 0.2), scaled 0-100.

Findings without a CVE fall back to severity-derived CVSS equivalents.
"""
from app.config import settings
from app.models.models import Finding

_SEV_CVSS_FALLBACK = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.5,
}


def compute_risk_score(cvss3: float | None, epss: float | None, kev: bool) -> float:
    cvss_n = (5.0 if cvss3 is None else cvss3) / 10.0
    epss_n = min(epss or 0.0, 1.0)
    kev_n = 1.0 if kev else 0.0
    raw = (
        cvss_n * settings.weight_cvss
        + epss_n * settings.weight_epss
        + kev_n * settings.weight_kev
    )
    return round(raw * 100, 1)


def score_finding(finding: Finding) -> float:
    cvss = finding.cvss3_score or _SEV_CVSS_FALLBACK.get(finding.severity_label, 5.0)
    score = compute_risk_score(cvss, finding.epss_score, finding.cisa_kev)
    finding.risk_score = score
    return score
