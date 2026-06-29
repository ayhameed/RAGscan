from app.core.ingestion.nessus_parser import parse_nessus
from tests.conftest import SAMPLE_NESSUS


def test_parse_nessus_finding_count():
    findings = parse_nessus(SAMPLE_NESSUS)
    assert len(findings) == 2


def test_parse_nessus_cve():
    findings = parse_nessus(SAMPLE_NESSUS)
    cves = {f.cve_id for f in findings}
    assert "CVE-2022-0778" in cves
    assert "CVE-2021-44228" in cves


def test_parse_nessus_severity():
    findings = parse_nessus(SAMPLE_NESSUS)
    by_cve = {f.cve_id: f for f in findings}
    assert by_cve["CVE-2022-0778"].severity_label == "high"
    assert by_cve["CVE-2021-44228"].severity_label == "critical"


def test_parse_nessus_host():
    findings = parse_nessus(SAMPLE_NESSUS)
    assert all(f.hostname == "web-server-01" for f in findings)
    assert all(f.host_ip == "192.168.1.10" for f in findings)


def test_parse_nessus_source():
    findings = parse_nessus(SAMPLE_NESSUS)
    assert all(f.source == "nessus" for f in findings)
