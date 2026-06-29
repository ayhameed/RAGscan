"""
OpenSCAP XCCDF XML parser.
Handles XCCDF 1.2 benchmark result files produced by oscap / OpenSCAP.
Only 'fail' rule-results are ingested as findings.
"""
import re
from lxml import etree
from app.schemas.schemas import FindingCreate

_XCCDF_NS = [
    "http://checklists.nist.gov/xccdf/1.2",
    "http://checklists.nist.gov/xccdf/1.1",
    "",
]

_SEV_MAP = {"critical": "critical", "high": "high", "medium": "medium",
            "low": "low", "info": "info", "unknown": "info"}

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
_CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)


def _q(tag: str, ns: str) -> str:
    return f"{{{ns}}}{tag}" if ns else tag


def _find(el: etree._Element, tag: str):
    for ns in _XCCDF_NS:
        found = el.find(_q(tag, ns))
        if found is not None:
            return found
    return None


def _findall(el: etree._Element, tag: str) -> list:
    results = []
    for ns in _XCCDF_NS:
        results.extend(el.findall(_q(tag, ns)))
    return results


def _iterall(root: etree._Element, tag: str):
    for ns in _XCCDF_NS:
        yield from root.iter(_q(tag, ns))


def parse_openscap(file_bytes: bytes) -> list[FindingCreate]:
    root = etree.fromstring(file_bytes)

    rule_meta: dict[str, dict] = {}
    for rule in _iterall(root, "Rule"):
        rid = rule.get("id", "")
        if not rid:
            continue
        severity = _SEV_MAP.get(rule.get("severity", "unknown"), "info")

        title_el = _find(rule, "title")
        desc_el = _find(rule, "description")
        fix_el = _find(rule, "fixtext") or _find(rule, "fix")

        cve_ids, cwe_ids = [], []
        for ref in _iterall(rule, "reference"):
            text = (ref.text or "") + " " + (ref.get("href", ""))
            cve_ids.extend(_CVE_RE.findall(text))
            cwe_ids.extend(_CWE_RE.findall(text))
        for ident in _iterall(rule, "ident"):
            text = (ident.text or "").strip()
            cve_ids.extend(_CVE_RE.findall(text))
            cwe_ids.extend(_CWE_RE.findall(text))

        rule_meta[rid] = {
            "severity": severity,
            "title": title_el.text if title_el is not None else rid,
            "description": desc_el.text if desc_el is not None else None,
            "solution": fix_el.text if fix_el is not None else None,
            "cve_id": cve_ids[0].upper() if cve_ids else None,
            "cwe_id": f"CWE-{cwe_ids[0]}" if cwe_ids else None,
        }

    findings: list[FindingCreate] = []
    seen: set[str] = set()

    for result in _iterall(root, "TestResult"):
        target_el = _find(result, "target")
        hostname = target_el.text if target_el is not None else "unknown"
        target_addr = _find(result, "target-address")
        ip = target_addr.text if target_addr is not None else hostname

        for rr in _iterall(result, "rule-result"):
            outcome_el = _find(rr, "result")
            if outcome_el is None or outcome_el.text != "fail":
                continue
            rid = rr.get("idref", "")
            if rid in seen:
                continue
            seen.add(rid)

            meta = rule_meta.get(rid, {})
            rr_sev = rr.get("severity", "")
            severity_label = _SEV_MAP.get(rr_sev, None) or meta.get("severity", "info")
            findings.append(
                FindingCreate(
                    source="openscap",
                    cve_id=meta.get("cve_id"),
                    cwe_id=meta.get("cwe_id"),
                    plugin_id=rid,
                    title=meta.get("title", rid),
                    description=meta.get("description"),
                    solution=meta.get("solution"),
                    severity_label=severity_label,
                    host_ip=ip,
                    hostname=hostname,
                    raw_data={"rule_id": rid, "result": "fail"},
                )
            )

    return findings
