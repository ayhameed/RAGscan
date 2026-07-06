"""Optional LLM-judged faithfulness eval tests.

These tests are marked with `eval` and are skipped by default unless explicitly
selected with `pytest -m eval`.

Guardrail:
The answer generator uses Claude. The DeepEval judge model must be a different
model family (default GPT-class via EVAL_JUDGE_MODEL) to reduce self-preference
bias.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import uuid
from dataclasses import dataclass
from pathlib import Path

import pytest
from sqlalchemy import select

from app.config import settings
from app.core.rag.chain import format_findings, query as grounded_answer
from app.models.models import Finding
from app.core.rag.retriever import retrieve
from app.db.session import AsyncSessionLocal, engine

ROOT = Path(__file__).resolve().parents[2]
DATASET = ROOT / "sample_data" / "eval_cases.jsonl"


@dataclass
class EvalCase:
    question: str
    expected_finding_ids: list[str]
    report_ids: list[str]


_CITATION_BLOCK_RE = re.compile(r"\[Finding:[^\]]+\]")


def _load_cases(path: Path) -> list[EvalCase]:
    cases: list[EvalCase] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            cases.append(
                EvalCase(
                    question=str(row["question"]),
                    expected_finding_ids=[str(item) for item in row.get("expected_finding_ids", [])],
                    report_ids=[str(item) for item in row.get("report_ids", [])],
                )
            )
    return cases


def _extract_free_text(answer: str) -> str:
    text = _CITATION_BLOCK_RE.sub("", answer)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(coro)
    finally:
        try:
            loop.run_until_complete(engine.dispose())
        except Exception:
            pass
        try:
            loop.run_until_complete(loop.shutdown_asyncgens())
        except Exception:
            pass
        loop.close()
        asyncio.set_event_loop(None)


async def _load_expected_context_texts(expected_ids: list[str]) -> list[str]:
    if not expected_ids:
        return []

    uuids: list[uuid.UUID] = []
    for item in expected_ids:
        try:
            uuids.append(uuid.UUID(item))
        except ValueError:
            continue

    if not uuids:
        return []

    async with AsyncSessionLocal() as session:
        rows = (await session.execute(select(Finding).where(Finding.id.in_(uuids)))).scalars().all()

    return [
        format_findings(
            [
                {
                    "id": row.id,
                    "cve_id": row.cve_id,
                    "cwe_id": row.cwe_id,
                    "title": row.title,
                    "description": row.description,
                    "solution": row.solution,
                    "severity_label": row.severity_label,
                    "cvss3_score": row.cvss3_score,
                    "epss_score": row.epss_score,
                    "cisa_kev": row.cisa_kev,
                    "risk_score": row.risk_score,
                    "hostname": row.hostname,
                    "host_ip": row.host_ip,
                }
            ]
        )
        for row in rows
    ]


async def _evaluate_case(case: EvalCase) -> tuple[str, str, list[str], list[str]]:
    async with AsyncSessionLocal() as session:
        retrieved = await retrieve(case.question, session, report_ids=case.report_ids)
    answer = await grounded_answer(case.question, retrieved)
    free_text = _extract_free_text(answer)
    retrieval_context = [format_findings([item]) for item in retrieved]
    expected_context = await _load_expected_context_texts(case.expected_finding_ids)
    return free_text, answer, retrieval_context, expected_context


async def _evaluate_cases(cases: list[EvalCase]) -> list[tuple[str, str, list[str], list[str]]]:
    results: list[tuple[str, str, list[str], list[str]]] = []
    for case in cases:
        results.append(await _evaluate_case(case))
    return results


@pytest.mark.eval
def test_faithfulness_eval_threshold():
    pytest.importorskip("deepeval")

    if not settings.anthropic_api_key:
        pytest.skip("ANTHROPIC_API_KEY is required for grounded generation")
    if not settings.openai_api_key:
        pytest.skip("OPENAI_API_KEY is required for DeepEval judge")

    judge_model = str(getattr(settings, "eval_judge_model", "gpt-4.1-mini") or "gpt-4.1-mini")
    assert "claude" not in judge_model.lower(), "EVAL_JUDGE_MODEL must be non-Claude"

    from deepeval.metrics import FaithfulnessMetric  # type: ignore
    from deepeval.test_case import LLMTestCase  # type: ignore

    threshold = float(os.getenv("EVAL_FAITHFULNESS_THRESHOLD", "0.7"))
    max_cases = int(os.getenv("EVAL_MAX_CASES", "5"))
    cases = _load_cases(DATASET)[:max_cases]
    assert cases, "No eval cases found in sample_data/eval_cases.jsonl"
    evaluated_cases = _run(_evaluate_cases(cases))

    scores: list[float] = []
    for case, evaluated in zip(cases, evaluated_cases):
        free_text, answer, retrieval_context, expected_context = evaluated
        assert answer, f"Grounded answer was empty for question: {case.question}"
        test_case = LLMTestCase(
            input=case.question,
            actual_output=free_text,
            retrieval_context=retrieval_context,
            expected_context=expected_context,
            expected_output="Narrative answer should remain grounded in retrieval context.",
        )

        metric = FaithfulnessMetric(threshold=threshold, model=judge_model, include_reason=True, async_mode=False)
        metric.measure(test_case)
        scores.append(float(metric.score or 0.0))

    avg_score = sum(scores) / len(scores)
    assert avg_score >= threshold, f"Average faithfulness {avg_score:.3f} is below threshold {threshold:.3f}"
