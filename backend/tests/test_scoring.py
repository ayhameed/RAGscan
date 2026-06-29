from app.core.scoring.risk_scorer import compute_risk_score


def test_kev_boosts_score():
    score_kev = compute_risk_score(cvss3=7.0, epss=0.1, kev=True)
    score_no_kev = compute_risk_score(cvss3=7.0, epss=0.1, kev=False)
    assert score_kev > score_no_kev


def test_high_epss_boosts_score():
    low_epss = compute_risk_score(cvss3=7.0, epss=0.01, kev=False)
    high_epss = compute_risk_score(cvss3=7.0, epss=0.9, kev=False)
    assert high_epss > low_epss


def test_score_range():
    score = compute_risk_score(cvss3=10.0, epss=1.0, kev=True)
    assert 0 <= score <= 100


def test_none_cvss_fallback():
    score = compute_risk_score(cvss3=None, epss=0.0, kev=False)
    assert score == compute_risk_score(cvss3=5.0, epss=0.0, kev=False)


def test_perfect_score():
    score = compute_risk_score(cvss3=10.0, epss=1.0, kev=True)
    assert score == 100.0


def test_zero_score():
    score = compute_risk_score(cvss3=0.0, epss=0.0, kev=False)
    assert score == 0.0
