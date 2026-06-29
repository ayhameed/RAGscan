from app.core.ingestion.openscap_parser import parse_openscap
from tests.conftest import SAMPLE_OPENSCAP


def test_parse_openscap_only_fails():
    findings = parse_openscap(SAMPLE_OPENSCAP)
    # Both rules in sample are 'fail' results
    assert len(findings) == 2


def test_parse_openscap_source():
    findings = parse_openscap(SAMPLE_OPENSCAP)
    assert all(f.source == "openscap" for f in findings)


def test_parse_openscap_cve():
    findings = parse_openscap(SAMPLE_OPENSCAP)
    cves = {f.cve_id for f in findings}
    assert "CVE-2023-38408" in cves


def test_parse_openscap_severity():
    findings = parse_openscap(SAMPLE_OPENSCAP)
    by_plugin = {f.plugin_id: f for f in findings}
    assert by_plugin["rule-sshd-disable-root"].severity_label == "high"


def test_parse_openscap_host():
    findings = parse_openscap(SAMPLE_OPENSCAP)
    assert all(f.hostname == "test-host" for f in findings)
