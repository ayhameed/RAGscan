from app.core.nist.mapper import get_controls


def test_cwe_89_maps_nist():
    controls = get_controls("CWE-89", "high", "nist_csf")
    ids = [c["control_id"] for c in controls]
    assert "PR.AC-1" in ids or "PR.DS-5" in ids


def test_cwe_89_maps_iso():
    controls = get_controls("CWE-89", "high", "iso27001")
    ids = [c["control_id"] for c in controls]
    assert any(c.startswith("A.") for c in ids)


def test_no_cwe_fallback():
    controls = get_controls(None, "critical", "nist_csf")
    assert len(controls) > 0
    ids = [c["control_id"] for c in controls]
    assert "DE.CM-7" in ids or "PR.IP-12" in ids


def test_unknown_cwe_fallback():
    controls = get_controls("CWE-9999", "high", "nist_csf")
    assert len(controls) > 0


def test_low_severity_fallback():
    controls = get_controls(None, "low", "nist_csf")
    assert len(controls) > 0
