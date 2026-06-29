"""
Enrichment tests — mock HTTP calls and DB session.
Tests cache hit/miss paths and KEV detection.
"""
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from app.core.enrichment.enricher import is_kev, _kev_cves


def test_kev_hit():
    _kev_cves.add("CVE-2021-44228")
    assert is_kev("CVE-2021-44228") is True


def test_kev_miss():
    assert is_kev("CVE-9999-99999") is False


def test_kev_case_insensitive():
    _kev_cves.add("CVE-2021-44228")
    assert is_kev("cve-2021-44228") is True


@pytest.mark.asyncio
async def test_enrich_cve_cache_hit():
    from app.core.enrichment.enricher import enrich_cve

    mock_session = AsyncMock()
    mock_cache_row = MagicMock()
    mock_cache_row.nvd_data = {"cvssV3Score": 9.8}
    mock_cache_row.epss_score = 0.97
    mock_cache_row.epss_percentile = 0.99
    mock_cache_row.cisa_kev = True
    mock_session.get = AsyncMock(return_value=mock_cache_row)

    mock_client = AsyncMock()
    result = await enrich_cve("CVE-2021-44228", mock_client, mock_session)

    assert result["cvss3_score"] == 9.8
    assert result["epss_score"] == 0.97
    assert result["cisa_kev"] is True
    mock_client.get.assert_not_called()
