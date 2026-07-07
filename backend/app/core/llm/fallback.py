from dataclasses import dataclass

from langchain_anthropic import ChatAnthropic
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI

from app.config import settings


@dataclass
class LLMTextResult:
    text: str
    provider: str
    fallback_used: bool = False
    fallback_reason: str | None = None


def _is_credit_or_quota_error(exc: Exception) -> bool:
    text = str(exc).lower()
    markers = (
        "insufficient_quota",
        "quota",
        "credit",
        "billing",
        "payment",
        "exceeded your current quota",
    )
    return any(marker in text for marker in markers)


def _anthropic_chain(prompt: ChatPromptTemplate):
    if not settings.anthropic_api_key:
        return None
    llm = ChatAnthropic(
        model=settings.llm_model,
        temperature=0.1,
        anthropic_api_key=settings.anthropic_api_key,
    )
    return prompt | llm | StrOutputParser()


def _github_open_chain(prompt: ChatPromptTemplate):
    if not settings.github_models_api_key:
        return None
    llm = ChatOpenAI(
        model=settings.github_fallback_model,
        api_key=settings.github_models_api_key,
        base_url=settings.github_models_base_url,
        temperature=0.1,
    )
    return prompt | llm | StrOutputParser()


async def invoke_text_with_fallback(prompt: ChatPromptTemplate, payload: dict) -> LLMTextResult:
    primary = _anthropic_chain(prompt)
    github = _github_open_chain(prompt)

    # If Anthropic is not configured, use GitHub model directly when available.
    if primary is None and github is not None:
        text = await github.ainvoke(payload)
        return LLMTextResult(
            text=text,
            provider="github-open-model",
            fallback_used=True,
            fallback_reason="anthropic_not_configured",
        )

    if primary is None and github is None:
        raise RuntimeError(
            "No LLM provider is configured. Set ANTHROPIC_API_KEY or GITHUB_MODELS_API_KEY."
        )

    try:
        text = await primary.ainvoke(payload)
        return LLMTextResult(text=text, provider="anthropic")
    except Exception as exc:
        if github is not None and _is_credit_or_quota_error(exc):
            text = await github.ainvoke(payload)
            return LLMTextResult(
                text=text,
                provider="github-open-model",
                fallback_used=True,
                fallback_reason="anthropic_credit_or_quota",
            )
        raise