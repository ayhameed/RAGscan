"""
Agent routing tests — mock the LLM call to avoid API costs in CI.
"""
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from app.core.agents.supervisor import Intent, route


@pytest.mark.asyncio
@patch("app.core.agents.supervisor.llm")
async def test_routes_security(mock_llm):
    mock_result = MagicMock()
    mock_result.content = "security"
    mock_llm.ainvoke = AsyncMock(return_value=mock_result)

    with patch("app.core.agents.supervisor._ROUTER_PROMPT") as mock_prompt:
        mock_chain = MagicMock()
        mock_chain.__or__ = MagicMock(return_value=mock_chain)
        mock_chain.ainvoke = AsyncMock(return_value=mock_result)
        mock_prompt.__or__ = MagicMock(return_value=mock_chain)

        intent = await route("What are the critical CVEs on host 10.0.0.1?")
    assert intent == Intent.SECURITY


@pytest.mark.asyncio
@patch("app.core.agents.supervisor.llm")
async def test_routes_reporting(mock_llm):
    mock_result = MagicMock()
    mock_result.content = "reporting"
    mock_llm.ainvoke = AsyncMock(return_value=mock_result)

    with patch("app.core.agents.supervisor._ROUTER_PROMPT") as mock_prompt:
        mock_chain = MagicMock()
        mock_chain.__or__ = MagicMock(return_value=mock_chain)
        mock_chain.ainvoke = AsyncMock(return_value=mock_result)
        mock_prompt.__or__ = MagicMock(return_value=mock_chain)

        intent = await route("Generate a NIST CSF compliance gap report")
    assert intent == Intent.REPORTING


def test_intent_enum_values():
    assert Intent.SECURITY.value == "security"
    assert Intent.REPORTING.value == "reporting"
    assert Intent.GENERAL.value == "general"
