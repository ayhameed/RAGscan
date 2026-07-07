from dataclasses import dataclass

from lxml import etree


@dataclass
class DetectionResult:
    tool: str
    source: str
    confidence: float
    reason: str


def _local_name(tag: str) -> str:
    if not tag:
        return ""
    return tag.rsplit("}", 1)[-1].lower()


def detect_scan_tool(filename: str, content: bytes) -> DetectionResult:
    fname = (filename or "").lower()

    if fname.endswith(".nessus"):
        return DetectionResult(tool="nessus", source="nessus", confidence=0.99, reason="filename extension .nessus")

    try:
        root = etree.fromstring(content)
    except Exception:
        return DetectionResult(tool="unknown_xml", source="generic_xml", confidence=0.2, reason="xml parse failed")

    root_name = _local_name(root.tag)
    tags = set()
    for idx, node in enumerate(root.iter()):
        if idx > 3000:
            break
        tags.add(_local_name(node.tag))

    ns_values = [str(item or "").lower() for item in root.nsmap.values()]

    if root_name in {"nessusclientdata_v2", "nessusclientdata"} or {"reporthost", "reportitem"}.issubset(tags):
        return DetectionResult(tool="nessus", source="nessus", confidence=0.95, reason="nessus structural markers")

    has_xccdf_ns = any("xccdf" in item for item in ns_values)
    has_xccdf_tags = {"benchmark", "rule", "rule-result", "testresult"} & tags
    if has_xccdf_ns or (root_name == "benchmark" and has_xccdf_tags):
        return DetectionResult(tool="openscap", source="openscap", confidence=0.92, reason="xccdf namespace/tags")

    if root_name == "nmaprun" or "nmaprun" in tags:
        return DetectionResult(tool="nmap", source="nmap_xml", confidence=0.85, reason="nmap root tag")

    if "oval_definitions" in tags or root_name == "oval_definitions":
        return DetectionResult(tool="oval", source="oval_xml", confidence=0.8, reason="oval definition markers")

    return DetectionResult(tool="unknown_xml", source="generic_xml", confidence=0.35, reason="fallback generic xml parser")
