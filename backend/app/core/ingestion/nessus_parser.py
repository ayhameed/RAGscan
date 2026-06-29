"""
Nessus XML parser (.nessus format).
Parses ReportHost / ReportItem elements using lxml for performance.
"""
from lxml import etree
from app.schemas.schemas import FindingCreate

_SEV_MAP = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}


def _sev(n: int) -> str:
    return _SEV_MAP.get(min(n, 4), "info")


def _el_to_dict(el: etree._Element) -> dict:
    return {child.tag: child.text for child in el}


def parse_nessus(file_bytes: bytes) -> list[FindingCreate]:
    root = etree.fromstring(file_bytes)
    findings: list[FindingCreate] = []

    for host in root.iter("ReportHost"):
        hostname = host.get("name")
        ip_tag = host.find('.//tag[@name="host-ip"]')
        ip = ip_tag.text if ip_tag is not None else hostname

        for item in host.iter("ReportItem"):
            sev_int = int(item.get("severity", 0))
            if sev_int == 0:
                continue  # skip informational by default

            cve_id = item.findtext("cve")
            cwe_el = item.find("cwe")
            cwe_id = f"CWE-{cwe_el.text}" if cwe_el is not None and cwe_el.text else None

            findings.append(
                FindingCreate(
                    source="nessus",
                    cve_id=cve_id,
                    cwe_id=cwe_id,
                    plugin_id=item.get("pluginID"),
                    title=item.get("pluginName", "Unknown"),
                    description=item.findtext("description"),
                    solution=item.findtext("solution"),
                    severity_label=_sev(sev_int),
                    host_ip=ip,
                    hostname=hostname,
                    port=int(item.get("port", 0)) or None,
                    protocol=item.get("protocol"),
                    raw_data=_el_to_dict(item),
                )
            )

    return findings
