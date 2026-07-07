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


def _is_unknown_model_error(exc: Exception) -> bool:
    text = str(exc).lower()
    return "unknown_model" in text or "unknown model" in text


def _anthropic_chain(prompt: ChatPromptTemplate):
    if not settings.anthropic_api_key:
        return None
    llm = ChatAnthropic(
        model=settings.llm_model,
        temperature=0.1,
        anthropic_api_key=settings.anthropic_api_key,
    )
    return prompt | llm | StrOutputParser()


def _github_open_chain(prompt: ChatPromptTemplate, model: str):
    if not settings.github_models_api_key:
        return None
    llm = ChatOpenAI(
        model=model,
        api_key=settings.github_models_api_key,
        base_url=settings.github_models_base_url,
        temperature=0.1,
    )
    return prompt | llm | StrOutputParser()


def _github_model_candidates() -> list[str]:
    candidates: list[str] = []

    if settings.github_fallback_model.strip():
        candidates.append(settings.github_fallback_model.strip())

    if settings.github_fallback_models.strip():
        candidates.extend(
            model.strip()
            for model in settings.github_fallback_models.split(",")
            if model.strip()
        )

    # Built-in fallbacks for GitHub Models OpenAI-compatible endpoint.
    candidates.extend([
        "openai/gpt-oss-20b",
        "openai/gpt-oss-120b",
        "meta/Meta-Llama-3.1-70B-Instruct",
    ])

    deduped: list[str] = []
    seen: set[str] = set()
    for item in candidates:
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


async def _invoke_github_with_model_fallback(prompt: ChatPromptTemplate, payload: dict) -> tuple[str, str]:
    last_error: Exception | None = None
    for model in _github_model_candidates():
        try:
            chain = _github_open_chain(prompt, model)
            if chain is None:
                break
            text = await chain.ainvoke(payload)
            return str(text), model
        except Exception as exc:
            last_error = exc
            if _is_unknown_model_error(exc):
                continue
            raise

    if last_error is not None:
        raise RuntimeError(
            "GitHub model fallback failed. Configure a valid GITHUB_FALLBACK_MODEL "
            "or GITHUB_FALLBACK_MODELS list for your endpoint. "
            f"Last error: {last_error}"
        ) from last_error

    raise RuntimeError("GitHub model fallback is not configured")


async def invoke_text_with_fallback(prompt: ChatPromptTemplate, payload: dict) -> LLMTextResult:
    primary = _anthropic_chain(prompt)
    github_configured = bool(settings.github_models_api_key)

    # If Anthropic is not configured, use GitHub model directly when available.
    if primary is None and github_configured:
        text, model = await _invoke_github_with_model_fallback(prompt, payload)
        return LLMTextResult(
            text=text,
            provider=f"github-open-model:{model}",
            fallback_used=True,
            fallback_reason="anthropic_not_configured",
        )

    if primary is None and not github_configured:
        raise RuntimeError(
            "No LLM provider is configured. Set ANTHROPIC_API_KEY or GITHUB_MODELS_API_KEY."
        )

    try:
        text = await primary.ainvoke(payload)
        return LLMTextResult(text=text, provider="anthropic")
    except Exception as exc:
        if github_configured and _is_credit_or_quota_error(exc):
            text, model = await _invoke_github_with_model_fallback(prompt, payload)
            return LLMTextResult(
                text=text,
                provider=f"github-open-model:{model}",
                fallback_used=True,
                fallback_reason="anthropic_credit_or_quota",
            )
        raise