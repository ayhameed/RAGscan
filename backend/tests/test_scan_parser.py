from app.core.ingestion.detector import detect_scan_tool
from app.core.ingestion.generic_xml_parser import parse_generic_xml
from app.core.ingestion.scan_parser import parse_scan_file
from tests.conftest import SAMPLE_NESSUS, SAMPLE_OPENSCAP


def test_detect_nessus_by_structure():
    result = detect_scan_tool("something.xml", SAMPLE_NESSUS)
    assert result.tool == "nessus"
    assert result.source == "nessus"


def test_detect_openscap_by_xccdf_markers():
    result = detect_scan_tool("scan.xml", SAMPLE_OPENSCAP)
    assert result.tool == "openscap"
    assert result.source == "openscap"


def test_generic_parser_extracts_minimal_finding_from_unknown_xml():
    sample = b"""<?xml version='1.0'?>
    <scan tool='custom'>
      <host ip='10.10.10.20'>
        <issue severity='high' id='abc-1'>
          <title>Weak TLS ciphers enabled</title>
          <description>Host exposes weak ciphers and references CVE-2020-12345.</description>
          <solution>Disable weak cipher suites.</solution>
        </issue>
      </host>
    </scan>
    """
    findings = parse_generic_xml(sample, source_hint="custom_xml")
    assert len(findings) >= 1
    first = findings[0]
    assert first.source == "custom_xml"
    assert first.severity_label in {"high", "critical", "medium", "low", "info"}


def test_scan_parser_falls_back_to_generic_for_unknown_tool():
    sample = b"""<?xml version='1.0'?><root><finding severity='medium'><title>Example</title></finding></root>"""
    result = parse_scan_file(sample, "unknown.xml")
    assert result.parser_used == "generic_xml"
    assert result.fallback_used is True
    assert len(result.findings) >= 1
