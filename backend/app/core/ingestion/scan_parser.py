from dataclasses import dataclass, field

from app.core.ingestion.detector import DetectionResult, detect_scan_tool
from app.core.ingestion.generic_xml_parser import parse_generic_xml
from app.core.ingestion.nessus_parser import parse_nessus
from app.core.ingestion.openscap_parser import parse_openscap
from app.schemas.schemas import FindingCreate


@dataclass
class ParseResult:
    findings: list[FindingCreate]
    detected_tool: str
    parser_used: str
    source: str
    fallback_used: bool = False
    parse_warnings: list[str] = field(default_factory=list)


def parse_scan_file(content: bytes, filename: str) -> ParseResult:
    detection: DetectionResult = detect_scan_tool(filename, content)

    parser_used = detection.tool
    fallback_used = False
    warnings: list[str] = []

    try:
        if detection.tool == "nessus":
            findings = parse_nessus(content)
        elif detection.tool == "openscap":
            findings = parse_openscap(content)
        else:
            parser_used = "generic_xml"
            findings = parse_generic_xml(content, source_hint=detection.source)
            fallback_used = True
            warnings.append(f"No dedicated parser for tool={detection.tool}; used generic parser")
    except Exception as exc:
        parser_used = "generic_xml"
        fallback_used = True
        warnings.append(f"Primary parser failed ({detection.tool}): {exc}")
        findings = parse_generic_xml(content, source_hint=detection.source)

    return ParseResult(
        findings=findings,
        detected_tool=detection.tool,
        parser_used=parser_used,
        source=detection.source,
        fallback_used=fallback_used,
        parse_warnings=warnings,
    )
