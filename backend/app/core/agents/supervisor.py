"""
Intent router. Classifies query intent and dispatches to the appropriate agent.
Not an autonomous loop — a named prompt role that routes in a single LLM call.
"""
from enum import Enum

from langchain_anthropic import ChatAnthropic
from langchain_core.prompts import ChatPromptTemplate

from app.config import settings


class Intent(str, Enum):
    SECURITY = "security"
    REPORTING = "reporting"
    GENERAL = "general"


_ROUTER_PROMPT = ChatPromptTemplate.from_messages([
    (
        "system",
        "Classify the intent of this security query into exactly one word.\n"
        "Reply with only one of: security | reporting | general\n"
        "- security: interpreting findings, explaining risk, CVSS/EPSS/KEV questions\n"
        "- reporting: generating reports, compliance gaps, NIST/ISO 27001 mappings\n"
        "- general: general security knowledge not tied to specific findings",
    ),
    ("human", "{query}"),
])

_llm = None


def _get_llm():
    global _llm
    if _llm is None:
        _llm = ChatAnthropic(
            model=settings.llm_model,
            temperature=0.0,
            anthropic_api_key=settings.anthropic_api_key,
        )
    return _llm


async def route(query: str) -> Intent:
    result = await (_ROUTER_PROMPT | _get_llm()).ainvoke({"query": query})
    text = result.content.strip().lower().split()[0] if result.content.strip() else "general"
    return Intent(text) if text in Intent._value2member_map_ else Intent.GENERAL
