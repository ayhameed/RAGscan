from dataclasses import dataclass
import httpx

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


def _fallback_chain(prompt: ChatPromptTemplate, model: str):
    if not settings.fallback_llm_api_key:
        return None
    llm = ChatOpenAI(
        model=model,
        api_key=settings.fallback_llm_api_key,
        base_url=settings.fallback_llm_base_url,
        temperature=0.1,
    )
    return prompt | llm | StrOutputParser()


def _fallback_model_candidates() -> list[str]:
    candidates: list[str] = []

    if settings.fallback_llm_model.strip():
        candidates.append(settings.fallback_llm_model.strip())

    if settings.fallback_llm_models.strip():
        candidates.extend(
            model.strip()
            for model in settings.fallback_llm_models.split(",")
            if model.strip()
        )

    # Built-in defaults for Groq's OpenAI-compatible endpoint, always appended as a
    # last resort so an empty FALLBACK_LLM_MODEL(S) env var can never zero out the list.
    candidates.extend([
        "openai/gpt-oss-20b",
        "openai/gpt-oss-120b",
        "llama-3.3-70b-versatile",
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


async def _discover_endpoint_models() -> list[str]:
    if not settings.fallback_llm_api_key:
        return []

    base = settings.fallback_llm_base_url.rstrip("/")
    url = f"{base}/models"
    headers = {
        "Authorization": f"Bearer {settings.fallback_llm_api_key}",
    }

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            res = await client.get(url, headers=headers)
        if res.status_code != 200:
            return []
        data = res.json()
        rows = data.get("data") if isinstance(data, dict) else None
        if not isinstance(rows, list):
            return []
        ids: list[str] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            mid = str(row.get("id") or "").strip()
            if mid:
                ids.append(mid)
        return ids
    except Exception:
        return []


def _rank_discovered_models(models: list[str]) -> list[str]:
    if not models:
        return []

    preferred_markers = (
        "gpt-oss",
        "llama",
        "mistral",
        "qwen",
        "deepseek",
        "gemma",
    )

    ranked = sorted(
        models,
        key=lambda model: (
            0 if any(marker in model.lower() for marker in preferred_markers) else 1,
            len(model),
            model.lower(),
        ),
    )
    return ranked


async def _invoke_fallback_with_model_fallback(prompt: ChatPromptTemplate, payload: dict) -> tuple[str, str]:
    last_error: Exception | None = None
    candidates = _fallback_model_candidates()
    discovered = _rank_discovered_models(await _discover_endpoint_models())
    for model in discovered:
        if model.lower() not in {item.lower() for item in candidates}:
            candidates.append(model)

    for model in candidates:
        try:
            chain = _fallback_chain(prompt, model)
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
            "LLM fallback failed. Configure a valid FALLBACK_LLM_MODEL "
            "or FALLBACK_LLM_MODELS list for your endpoint. "
            f"Last error: {last_error}"
        ) from last_error

    raise RuntimeError("LLM fallback is not configured")


async def invoke_text_with_fallback(prompt: ChatPromptTemplate, payload: dict) -> LLMTextResult:
    primary = _anthropic_chain(prompt)
    fallback_configured = bool(settings.fallback_llm_api_key)

    # If Anthropic is not configured, use the fallback provider directly when available.
    if primary is None and fallback_configured:
        text, model = await _invoke_fallback_with_model_fallback(prompt, payload)
        return LLMTextResult(
            text=text,
            provider=f"fallback-llm:{model}",
            fallback_used=True,
            fallback_reason="anthropic_not_configured",
        )

    if primary is None and not fallback_configured:
        raise RuntimeError(
            "No LLM provider is configured. Set ANTHROPIC_API_KEY or FALLBACK_LLM_API_KEY."
        )

    try:
        text = await primary.ainvoke(payload)
        return LLMTextResult(text=text, provider="anthropic")
    except Exception as exc:
        if fallback_configured and _is_credit_or_quota_error(exc):
            text, model = await _invoke_fallback_with_model_fallback(prompt, payload)
            return LLMTextResult(
                text=text,
                provider=f"fallback-llm:{model}",
                fallback_used=True,
                fallback_reason="anthropic_credit_or_quota",
            )
        raise