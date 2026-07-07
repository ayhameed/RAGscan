import re
from collections.abc import Iterable

from lxml import etree

from app.schemas.schemas import FindingCreate

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SEV_RE = re.compile(r"\b(critical|high|medium|low|info|informational)\b", re.IGNORECASE)

_CANDIDATE_TAGS = {
    "vulnerability",
    "vuln",
    "finding",
    "issue",
    "alert",
    "result",
    "item",
    "entry",
    "host",
    "port",
    "service",
}


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower() if tag else ""


def _collapse_text(values: Iterable[str]) -> str:
    text = " ".join((v or "") for v in values)
    return re.sub(r"\s+", " ", text).strip()


def _severity_from(node: etree._Element, text: str) -> str:
    for key in ("severity", "risk", "threat", "impact"):
        if key in node.attrib and node.attrib[key]:
            val = str(node.attrib[key]).lower()
            if "crit" in val:
                return "critical"
            if "high" in val:
                return "high"
            if "med" in val:
                return "medium"
            if "low" in val:
                return "low"
            if "info" in val:
                return "info"
    match = _SEV_RE.search(text)
    if not match:
        return "medium"
    val = match.group(1).lower()
    if val == "informational":
        return "info"
    return val


def _first_child_text(node: etree._Element, tags: set[str]) -> str | None:
    for child in node.iterchildren():
        if _local_name(child.tag) in tags:
            val = _collapse_text(child.itertext())
            if val:
                return val
    return None


def parse_generic_xml(content: bytes, source_hint: str = "generic_xml") -> list[FindingCreate]:
    parser = etree.XMLParser(recover=True, huge_tree=True)
    root = etree.fromstring(content, parser=parser)

    findings: list[FindingCreate] = []
    seen: set[tuple[str, str, str]] = set()

    for idx, node in enumerate(root.iter()):
        if idx > 15000:
            break

        tag = _local_name(node.tag)
        has_signal_attr = any(k in node.attrib for k in ("severity", "risk", "threat", "cve", "cvss"))
        if tag not in _CANDIDATE_TAGS and not has_signal_attr:
            continue

        text = _collapse_text(node.itertext())
        if len(text) < 20 and not has_signal_attr:
            continue

        title = (
            node.attrib.get("pluginName")
            or node.attrib.get("title")
            or node.attrib.get("name")
            or _first_child_text(node, {"title", "name", "summary", "synopsis"})
            or (text[:120] if text else "XML Finding")
        )
        description = _first_child_text(node, {"description", "details", "detail", "desc", "message"}) or text[:800]
        solution = _first_child_text(node, {"solution", "remediation", "fix", "recommendation", "resolution"})

        cve_matches = _CVE_RE.findall(text + " " + _collapse_text(node.attrib.values()))
        cve_id = cve_matches[0].upper() if cve_matches else None

        cwe_matches = _CWE_RE.findall(text)
        cwe_id = f"CWE-{cwe_matches[0]}" if cwe_matches else None

        host_ip = (
            node.attrib.get("host")
            or node.attrib.get("ip")
            or node.attrib.get("address")
            or (_IPV4_RE.search(text).group(0) if _IPV4_RE.search(text) else None)
        )
        hostname = node.attrib.get("hostname") or node.attrib.get("fqdn") or host_ip

        port = None
        for key in ("port", "portid"):
            if key in node.attrib:
                try:
                    port = int(str(node.attrib[key]))
                except Exception:
                    port = None
                break

        severity = _severity_from(node, text)

        key = (cve_id or "", title[:120], host_ip or "")
        if key in seen:
            continue
        seen.add(key)

        # Keep only rows with meaningful signal.
        if not cve_id and len(title.strip()) < 6 and len(description.strip()) < 30:
            continue

        findings.append(
            FindingCreate(
                source=source_hint,
                cve_id=cve_id,
                cwe_id=cwe_id,
                plugin_id=node.attrib.get("id") or node.attrib.get("pluginID") or tag,
                title=title.strip(),
                description=description.strip() if description else None,
                solution=solution.strip() if solution else None,
                severity_label=severity,
                host_ip=host_ip,
                hostname=hostname,
                port=port,
                protocol=node.attrib.get("protocol"),
                raw_data={"element": tag, "attributes": {k: str(v) for k, v in node.attrib.items()}},
            )
        )

    if findings:
        return findings

    # Very last fallback: each discovered CVE becomes a minimal finding.
    root_text = _collapse_text(root.itertext())
    cves = sorted(set(cve.upper() for cve in _CVE_RE.findall(root_text)))
    for cve in cves:
        findings.append(
            FindingCreate(
                source=source_hint,
                cve_id=cve,
                title=f"Detected {cve} in XML input",
                description="Generic parser fallback extracted CVE from unrecognized XML schema.",
                severity_label="medium",
            )
        )

    return findings
