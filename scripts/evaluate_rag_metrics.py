#!/usr/bin/env python3
"""Evaluate grounded chat quality on a labeled JSONL dataset.

Per response, the evaluator computes:
- retrieval precision@10
- citation accuracy
- hallucination rate
- NIST/ISO mapping fidelity
- risk score correlation proxy

Optional (flagged):
- LLM-judged free-text faithfulness and contextual precision/recall via DeepEval

DeepEval scope guardrail:
- DeepEval is used only for free-text grounding checks and is never used for
    deterministic structured metrics (citations, mapping fidelity, structured
    retrieval checks).
- The generator model is Claude (`settings.llm_model`), so the DeepEval judge
    must use a different model family. Configure `EVAL_JUDGE_MODEL` (default:
    GPT-family) and keep it non-Claude to reduce self-preference bias.

Usage:
- Deterministic only (default):
    python scripts/evaluate_rag_metrics.py sample_data/eval_cases.jsonl
- Deterministic + DeepEval free-text section:
    python scripts/evaluate_rag_metrics.py sample_data/eval_cases.jsonl --with-deepeval

It also writes a compact HTML report and a PDF report so the results can be shared
in a paper, slide deck, or appendix.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from statistics import mean
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from langchain_anthropic import ChatAnthropic  # type: ignore
from langchain_core.output_parsers import StrOutputParser  # type: ignore
from langchain_core.prompts import ChatPromptTemplate  # type: ignore
from reportlab.lib import colors  # type: ignore
from reportlab.lib.pagesizes import A4  # type: ignore
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet  # type: ignore
from reportlab.lib.units import mm  # type: ignore
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle  # type: ignore
from sqlalchemy import select  # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession  # type: ignore

from app.config import settings  # type: ignore
from app.core.rag.chain import format_findings, query as grounded_answer  # type: ignore
from app.core.rag.retriever import retrieve  # type: ignore
from app.db.session import AsyncSessionLocal  # type: ignore
from app.models.models import Finding  # type: ignore
from app.models.models import ScanUpload  # type: ignore

FINDING_CITATION_RE = re.compile(r"\[Finding:\s*([0-9a-fA-F-]{8,})\s*,\s*CVE:")
FINDING_CITATION_BLOCK_RE = re.compile(r"\[Finding:[^\]]+\]")
_TOKEN_RE = re.compile(r"[a-z0-9]{3,}")
_STOPWORDS = {
    "the", "and", "for", "with", "that", "this", "from", "are", "was", "were", "have", "has",
    "had", "you", "your", "their", "they", "them", "into", "over", "under", "than", "then", "not",
    "but", "can", "may", "might", "will", "would", "should", "could", "all", "any", "its", "our",
    "out", "use", "using", "used", "via", "per", "one", "two", "three", "also", "most", "more",
    "less", "high", "low", "medium", "critical", "risk", "finding", "findings", "cve", "host", "port",
}

_UNGROUNDED_PROMPT = ChatPromptTemplate.from_messages(
    [
        (
            "system",
            "You are a cybersecurity assistant. Answer the question directly without using retrieved findings. "
            "Do not cite findings because you have no evidence. Be concise.",
        ),
        ("human", "Question: {question}"),
    ]
)

_ungrounded_chain = None


@dataclass
class EvalCase:
    question: str
    expected_finding_ids: list[str]
    report_ids: list[str]
    gold_citation_ids: list[str]
    expected_controls: list[str]
    expected_risk_score: float | None
    framework: str


def _load_cases(path: Path) -> list[EvalCase]:
    cases: list[EvalCase] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            expected = [str(item) for item in row.get("expected_finding_ids", [])]
            gold = [str(item) for item in row.get("gold_citation_ids", expected)]
            cases.append(
                EvalCase(
                    question=str(row["question"]),
                    expected_finding_ids=expected,
                    report_ids=[str(item) for item in row.get("report_ids", [])],
                    gold_citation_ids=gold,
                    expected_controls=[str(item) for item in row.get("expected_controls", [])],
                    expected_risk_score=(float(row["expected_risk_score"]) if row.get("expected_risk_score") is not None else None),
                    framework=str(row.get("framework", "nist_csf")),
                )
            )
    return cases


def _precision_at_10(retrieved_ids: list[str], expected_ids: list[str]) -> float:
    if not retrieved_ids:
        return 0.0
    top10 = retrieved_ids[:10]
    expected = set(expected_ids)
    return sum(1 for item in top10 if item in expected) / 10.0


def _normalized_precision_at_10(retrieved_ids: list[str], expected_ids: list[str]) -> float:
    if not retrieved_ids or not expected_ids:
        return 0.0
    top10 = retrieved_ids[:10]
    expected = set(expected_ids)
    hits = sum(1 for item in top10 if item in expected)
    denom = min(10, len(expected))
    if denom == 0:
        return 0.0
    return hits / denom


def _recall_at_10(retrieved_ids: list[str], expected_ids: list[str]) -> float:
    if not expected_ids:
        return 0.0
    top10 = retrieved_ids[:10]
    expected = set(expected_ids)
    hits = sum(1 for item in top10 if item in expected)
    return hits / len(expected)


def _citation_accuracy(answer: str, gold_ids: list[str]) -> float:
    cited = FINDING_CITATION_RE.findall(answer)
    if not cited:
        return 0.0
    gold = set(gold_ids)
    return sum(1 for item in cited if item in gold) / len(cited)


def _tokenize(text: str) -> set[str]:
    tokens = set(_TOKEN_RE.findall(text.lower()))
    return {token for token in tokens if token not in _STOPWORDS}


def _finding_evidence_tokens(finding: dict[str, Any]) -> set[str]:
    parts = [
        str(finding.get("title") or ""),
        str(finding.get("description") or ""),
        str(finding.get("solution") or ""),
        str(finding.get("severity_label") or ""),
        str(finding.get("cve_id") or ""),
    ]
    return _tokenize(" ".join(parts))


def _semantic_supported(sentence: str, evidence_tokens: list[set[str]]) -> bool:
    sentence_tokens = _tokenize(sentence)
    if not sentence_tokens:
        return True
    best_overlap = 0.0
    best_hits = 0
    for tokens in evidence_tokens:
        if not tokens:
            continue
        hits = len(sentence_tokens & tokens)
        overlap = hits / max(1, len(sentence_tokens))
        if overlap > best_overlap:
            best_overlap = overlap
            best_hits = hits
    return best_overlap >= 0.18 or best_hits >= 3


def _hallucination_rate(answer: str, retrieved_findings: list[dict[str, Any]]) -> float:
    sentences = [part.strip() for part in re.split(r"(?<=[.!?])\s+", answer) if part.strip()]
    if not sentences:
        return 0.0
    evidence_tokens = [_finding_evidence_tokens(item) for item in retrieved_findings]
    unsupported = sum(1 for sentence in sentences if not _semantic_supported(sentence, evidence_tokens))
    return unsupported / len(sentences)


def _mapping_fidelity(retrieved_findings: list[dict[str, Any]], expected_controls: list[str], framework: str) -> float:
    if not expected_controls:
        return 0.0
    try:
        from app.core.nist.mapper import get_controls  # type: ignore
    except Exception:
        return 0.0

    predicted_controls: set[str] = set()
    for finding in retrieved_findings:
        controls = get_controls(finding.get("cwe_id"), finding.get("severity_label", ""), framework)  # type: ignore[arg-type]
        for control in controls:
            predicted_controls.add(str(control.get("control_id", "")))

    if not predicted_controls:
        return 0.0
    expected = set(expected_controls)
    return len(predicted_controls & expected) / len(expected)


def _risk_score_proxy(retrieved_findings: list[dict[str, Any]]) -> float | None:
    scores = [float(item["risk_score"]) for item in retrieved_findings if item.get("risk_score") is not None]
    if not scores:
        return None
    return max(scores)


def _pearson(xs: list[float], ys: list[float]) -> float:
    if len(xs) != len(ys) or len(xs) < 2:
        return 0.0
    mean_x = mean(xs)
    mean_y = mean(ys)
    num = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    den_x = sum((x - mean_x) ** 2 for x in xs)
    den_y = sum((y - mean_y) ** 2 for y in ys)
    if den_x == 0 or den_y == 0:
        return 0.0
    return num / ((den_x ** 0.5) * (den_y ** 0.5))


def _get_ungrounded_chain():
    global _ungrounded_chain
    if _ungrounded_chain is None:
        llm = ChatAnthropic(
            model=settings.llm_model,
            temperature=0.1,
            anthropic_api_key=settings.anthropic_api_key,
        )
        _ungrounded_chain = _UNGROUNDED_PROMPT | llm | StrOutputParser()
    return _ungrounded_chain


async def _fetch_scope(session: AsyncSession, report_ids: list[str]) -> list[str]:
    if report_ids:
        rows = (await session.execute(select(ScanUpload.id).where(ScanUpload.id.in_(report_ids)))).scalars().all()
        return [str(item) for item in rows]
    rows = (await session.execute(select(ScanUpload.id))).scalars().all()
    return [str(item) for item in rows]


def _extract_free_text(answer: str) -> str:
    # Remove explicit structured citation blocks to focus the judge on narrative grounding.
    text = FINDING_CITATION_BLOCK_RE.sub("", answer)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _row_to_chain_finding(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row.get("id"),
        "cve_id": row.get("cve_id"),
        "cwe_id": row.get("cwe_id"),
        "title": row.get("title"),
        "description": row.get("description"),
        "solution": row.get("solution"),
        "severity_label": row.get("severity_label"),
        "cvss3_score": row.get("cvss3_score"),
        "epss_score": row.get("epss_score"),
        "cisa_kev": row.get("cisa_kev"),
        "risk_score": row.get("risk_score"),
        "hostname": row.get("hostname"),
        "host_ip": row.get("host_ip"),
    }


def _model_to_chain_finding(item: Finding) -> dict[str, Any]:
    return {
        "id": item.id,
        "cve_id": item.cve_id,
        "cwe_id": item.cwe_id,
        "title": item.title,
        "description": item.description,
        "solution": item.solution,
        "severity_label": item.severity_label,
        "cvss3_score": item.cvss3_score,
        "epss_score": item.epss_score,
        "cisa_kev": item.cisa_kev,
        "risk_score": item.risk_score,
        "hostname": item.hostname,
        "host_ip": item.host_ip,
    }


def _validate_eval_judge_model() -> str:
    judge_model = str(getattr(settings, "eval_judge_model", "gpt-4.1-mini") or "gpt-4.1-mini").strip()
    # Guardrail: avoid same-family self-judging against Claude-generated answers.
    if "claude" in judge_model.lower():
        raise SystemExit(
            "EVAL_JUDGE_MODEL must be a non-Claude model family (for example GPT-4-class) to avoid self-preference bias"
        )
    return judge_model


async def _load_expected_context_texts(session: AsyncSession, expected_ids: list[str]) -> list[str]:
    if not expected_ids:
        return []
    uuids: list[uuid.UUID] = []
    for item in expected_ids:
        try:
            uuids.append(uuid.UUID(str(item)))
        except ValueError:
            continue
    if not uuids:
        return []

    rows = (await session.execute(select(Finding).where(Finding.id.in_(uuids)))).scalars().all()
    texts: list[str] = []
    for row in rows:
        texts.append(format_findings([_model_to_chain_finding(row)]))
    return texts


async def _evaluate_deepeval_case(case: EvalCase, judge_model: str, faithfulness_threshold: float) -> dict[str, Any]:
    from deepeval.metrics import ContextualPrecisionMetric, ContextualRecallMetric, FaithfulnessMetric  # type: ignore
    from deepeval.test_case import LLMTestCase  # type: ignore

    async with AsyncSessionLocal() as session:
        scope_ids = await _fetch_scope(session, case.report_ids)
        retrieved = await retrieve(case.question, session, report_ids=scope_ids)
        grounded_text = await grounded_answer(case.question, retrieved)
        expected_context = await _load_expected_context_texts(session, case.expected_finding_ids)

    retrieval_context = [format_findings([_row_to_chain_finding(item)]) for item in retrieved]
    free_text_output = _extract_free_text(grounded_text)

    test_case = LLMTestCase(
        input=case.question,
        actual_output=free_text_output,
        retrieval_context=retrieval_context,
        expected_context=expected_context,
        expected_output="Narrative answer must remain grounded in retrieved scan evidence.",
    )

    faithfulness_metric = FaithfulnessMetric(
        threshold=faithfulness_threshold,
        model=judge_model,
        include_reason=True,
        async_mode=False,
    )
    contextual_precision_metric = ContextualPrecisionMetric(
        threshold=0.0,
        model=judge_model,
        include_reason=True,
        async_mode=False,
    )
    contextual_recall_metric = ContextualRecallMetric(
        threshold=0.0,
        model=judge_model,
        include_reason=True,
        async_mode=False,
    )

    faithfulness_metric.measure(test_case)
    contextual_precision_metric.measure(test_case)
    contextual_recall_metric.measure(test_case)

    return {
        "question": case.question,
        "faithfulness_score": float(faithfulness_metric.score or 0.0),
        "faithfulness_passed": bool(faithfulness_metric.is_successful()),
        "faithfulness_reason": str(getattr(faithfulness_metric, "reason", "") or ""),
        "contextual_precision_score": float(contextual_precision_metric.score or 0.0),
        "contextual_recall_score": float(contextual_recall_metric.score or 0.0),
    }


async def _evaluate_with_deepeval(cases: list[EvalCase], faithfulness_threshold: float) -> dict[str, Any]:
    judge_model = _validate_eval_judge_model()
    rows = [await _evaluate_deepeval_case(case, judge_model, faithfulness_threshold) for case in cases]
    avg_faithfulness = mean(item["faithfulness_score"] for item in rows) if rows else 0.0
    pass_rate = (
        sum(1 for item in rows if item["faithfulness_passed"]) / len(rows)
        if rows
        else 0.0
    )
    avg_contextual_precision = mean(item["contextual_precision_score"] for item in rows) if rows else 0.0
    avg_contextual_recall = mean(item["contextual_recall_score"] for item in rows) if rows else 0.0
    return {
        "judge_model": judge_model,
        "faithfulness_threshold": faithfulness_threshold,
        "rows": rows,
        "summary": {
            "avg_faithfulness": avg_faithfulness,
            "faithfulness_pass_rate": pass_rate,
            "avg_contextual_precision": avg_contextual_precision,
            "avg_contextual_recall": avg_contextual_recall,
        },
    }


async def _evaluate_case(case: EvalCase) -> dict[str, Any]:
    async with AsyncSessionLocal() as session:
        scope_ids = await _fetch_scope(session, case.report_ids)
        retrieved = await retrieve(case.question, session, report_ids=scope_ids)
        retrieved_ids = [str(item.get("id", "")) for item in retrieved if item.get("id")]

        grounded_text = await grounded_answer(case.question, retrieved)
        ungrounded_text = await _get_ungrounded_chain().ainvoke({"question": case.question})

        grounded_metrics = {
            "precision_at_10": _precision_at_10(retrieved_ids, case.expected_finding_ids),
            "normalized_precision_at_10": _normalized_precision_at_10(retrieved_ids, case.expected_finding_ids),
            "recall_at_10": _recall_at_10(retrieved_ids, case.expected_finding_ids),
            "citation_accuracy": _citation_accuracy(grounded_text, case.gold_citation_ids),
            "hallucination_rate": _hallucination_rate(grounded_text, retrieved),
            "mapping_fidelity": _mapping_fidelity(retrieved, case.expected_controls, case.framework),
            "predicted_risk_score": _risk_score_proxy(retrieved),
            "expected_risk_score": case.expected_risk_score,
        }
        baseline_metrics = {
            "citation_accuracy": _citation_accuracy(ungrounded_text, case.gold_citation_ids),
            "hallucination_rate": _hallucination_rate(ungrounded_text, []),
        }

        return {"question": case.question, "grounded": grounded_metrics, "baseline": baseline_metrics}


def _print_summary(rows: list[dict[str, Any]], deepeval: dict[str, Any] | None = None) -> None:
    grounded_p10 = mean(row["grounded"]["precision_at_10"] for row in rows)
    grounded_np10 = mean(row["grounded"]["normalized_precision_at_10"] for row in rows)
    grounded_r10 = mean(row["grounded"]["recall_at_10"] for row in rows)
    grounded_citation = mean(row["grounded"]["citation_accuracy"] for row in rows)
    grounded_hallucination = mean(row["grounded"]["hallucination_rate"] for row in rows)
    grounded_mapping_fidelity = mean(row["grounded"]["mapping_fidelity"] for row in rows)
    baseline_citation = mean(row["baseline"]["citation_accuracy"] for row in rows)
    baseline_hallucination = mean(row["baseline"]["hallucination_rate"] for row in rows)

    predicted_scores = [
        row["grounded"]["predicted_risk_score"]
        for row in rows
        if row["grounded"]["predicted_risk_score"] is not None and row["grounded"]["expected_risk_score"] is not None
    ]
    expected_scores = [
        row["grounded"]["expected_risk_score"]
        for row in rows
        if row["grounded"]["predicted_risk_score"] is not None and row["grounded"]["expected_risk_score"] is not None
    ]
    risk_score_corr = _pearson(predicted_scores, expected_scores) if predicted_scores and expected_scores else 0.0

    print("RAGScan evaluation summary")
    print(f"Cases: {len(rows)}")
    print(f"Retrieval precision@10: {grounded_p10:.3f}")
    print(f"Retrieval normalized precision@10: {grounded_np10:.3f}")
    print(f"Retrieval recall@10: {grounded_r10:.3f}")
    print(f"Citation accuracy: {grounded_citation:.3f}")
    print(f"Hallucination rate: {grounded_hallucination:.3f}")
    print(f"NIST/ISO mapping fidelity: {grounded_mapping_fidelity:.3f}")
    print(f"Risk score correlation: {risk_score_corr:.3f}")
    print(f"Ungrounded baseline citation accuracy: {baseline_citation:.3f}")
    print(f"Ungrounded baseline hallucination rate: {baseline_hallucination:.3f}")

    if deepeval is not None:
        summary = deepeval["summary"]
        print()
        print("LLM-judged (free-text) summary")
        print(f"Judge model: {deepeval['judge_model']}")
        print(f"Faithfulness threshold: {deepeval['faithfulness_threshold']:.2f}")
        print(f"Faithfulness (avg): {summary['avg_faithfulness']:.3f}")
        print(f"Faithfulness pass rate: {summary['faithfulness_pass_rate']:.3f}")
        print(f"Contextual precision (avg): {summary['avg_contextual_precision']:.3f}")
        print(f"Contextual recall (avg): {summary['avg_contextual_recall']:.3f}")

    print()
    print("Per-case metrics")
    for row in rows:
        print(json.dumps({"question": row["question"], "grounded": row["grounded"], "baseline": row["baseline"]}, ensure_ascii=True))


def _escape_html(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _render_html(path: Path, rows: list[dict[str, Any]], deepeval: dict[str, Any] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    grounded_p10 = mean(row["grounded"]["precision_at_10"] for row in rows)
    grounded_np10 = mean(row["grounded"]["normalized_precision_at_10"] for row in rows)
    grounded_r10 = mean(row["grounded"]["recall_at_10"] for row in rows)
    grounded_citation = mean(row["grounded"]["citation_accuracy"] for row in rows)
    grounded_hallucination = mean(row["grounded"]["hallucination_rate"] for row in rows)
    grounded_mapping_fidelity = mean(row["grounded"]["mapping_fidelity"] for row in rows)

    html_rows: list[str] = []
    for row in rows:
        g = row["grounded"]
        b = row["baseline"]
        risk_proxy = g["predicted_risk_score"]
        risk_proxy_text = f"{risk_proxy:.1f}" if risk_proxy is not None else "N/A"
        html_rows.append(
            "<tr>"
            f"<td>{_escape_html(row['question'])}</td>"
            f"<td>{g['precision_at_10']:.3f}</td>"
            f"<td>{g['normalized_precision_at_10']:.3f}</td>"
            f"<td>{g['recall_at_10']:.3f}</td>"
            f"<td>{g['citation_accuracy']:.3f}</td>"
            f"<td>{g['hallucination_rate']:.3f}</td>"
            f"<td>{g['mapping_fidelity']:.3f}</td>"
            f"<td>{risk_proxy_text}</td>"
            f"<td>{b['hallucination_rate']:.3f}</td>"
            "</tr>"
        )

    html = f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>RAGScan Evaluation Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 32px; color: #111827; }}
    h1 {{ margin-bottom: 4px; }}
    .meta {{ color: #6b7280; margin-bottom: 18px; }}
    .cards {{ display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 12px; margin: 18px 0 24px; }}
    .card {{ border: 1px solid #d1d5db; border-radius: 10px; padding: 12px; background: #f9fafb; }}
    .card .label {{ font-size: 12px; color: #6b7280; text-transform: uppercase; letter-spacing: .06em; }}
    .card .value {{ font-size: 22px; font-weight: 700; margin-top: 4px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th, td {{ border: 1px solid #e5e7eb; padding: 8px 10px; vertical-align: top; }}
    th {{ background: #111827; color: white; text-align: left; }}
    .small {{ font-size: 12px; color: #6b7280; }}
  </style>
</head>
<body>
  <h1>RAGScan Evaluation Report</h1>
  <div class=\"meta\">Grounded RAG vs ungrounded baseline · {len(rows)} cases</div>
  <div class=\"cards\">
    <div class=\"card\"><div class=\"label\">Precision@10</div><div class=\"value\">{grounded_p10:.3f}</div></div>
        <div class="card"><div class="label">Norm Precision@10</div><div class="value">{grounded_np10:.3f}</div></div>
        <div class="card"><div class="label">Recall@10</div><div class="value">{grounded_r10:.3f}</div></div>
    <div class=\"card\"><div class=\"label\">Citation Accuracy</div><div class=\"value\">{grounded_citation:.3f}</div></div>
    <div class=\"card\"><div class=\"label\">Hallucination Rate</div><div class=\"value\">{grounded_hallucination:.3f}</div></div>
    <div class=\"card\"><div class=\"label\">Mapping Fidelity</div><div class=\"value\">{grounded_mapping_fidelity:.3f}</div></div>
  </div>
  <p class=\"small\">Ground truth format: JSONL rows with question, expected_finding_ids, optional gold_citation_ids, optional expected_controls, optional expected_risk_score, optional framework.</p>
  <table>
    <thead>
      <tr>
        <th>Question</th>
        <th>P@10</th>
        <th>Norm P@10</th>
        <th>R@10</th>
        <th>Citation Acc.</th>
        <th>Hallucination</th>
        <th>Mapping Fidelity</th>
        <th>Risk Score Proxy</th>
        <th>Baseline Hallucination</th>
      </tr>
    </thead>
    <tbody>
      {''.join(html_rows)}
    </tbody>
  </table>
</body>
</html>"""

    llm_section = ""

    if deepeval is not None:
        summary = deepeval["summary"]
        llm_rows: list[str] = []
        for item in deepeval["rows"]:
            llm_rows.append(
                "<tr>"
                f"<td>{_escape_html(item['question'])}</td>"
                f"<td>{item['faithfulness_score']:.3f}</td>"
                f"<td>{'yes' if item['faithfulness_passed'] else 'no'}</td>"
                f"<td>{item['contextual_precision_score']:.3f}</td>"
                f"<td>{item['contextual_recall_score']:.3f}</td>"
                f"<td>{_escape_html(item['faithfulness_reason'])}</td>"
                "</tr>"
            )

        llm_section = f"""
    <h2>LLM-judged (free-text)</h2>
    <p class=\"small\">Judge model: {_escape_html(deepeval['judge_model'])}. These metrics grade narrative grounding only; deterministic structured metrics remain authoritative.</p>
    <div class=\"cards\">
        <div class=\"card\"><div class=\"label\">Faithfulness Avg</div><div class=\"value\">{summary['avg_faithfulness']:.3f}</div></div>
        <div class=\"card\"><div class=\"label\">Faithfulness Pass Rate</div><div class=\"value\">{summary['faithfulness_pass_rate']:.3f}</div></div>
        <div class=\"card\"><div class=\"label\">Contextual Precision</div><div class=\"value\">{summary['avg_contextual_precision']:.3f}</div></div>
        <div class=\"card\"><div class=\"label\">Contextual Recall</div><div class=\"value\">{summary['avg_contextual_recall']:.3f}</div></div>
    </div>
    <table>
        <thead>
            <tr>
                <th>Question</th>
                <th>Faithfulness</th>
                <th>Pass</th>
                <th>Contextual Precision</th>
                <th>Contextual Recall</th>
                <th>Judge Reason</th>
            </tr>
        </thead>
        <tbody>
            {''.join(llm_rows)}
        </tbody>
    </table>
"""
    if llm_section:
        html = html.replace("</body>", f"{llm_section}\n</body>")

    path.write_text(html, encoding="utf-8")


def _render_pdf(path: Path, rows: list[dict[str, Any]], deepeval: dict[str, Any] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    styles = getSampleStyleSheet()
    title = ParagraphStyle("EvalTitle", parent=styles["Title"], fontSize=18, spaceAfter=10)
    body = ParagraphStyle("EvalBody", parent=styles["Normal"], fontSize=9, spaceAfter=4)
    doc = SimpleDocTemplate(
        str(path),
        pagesize=A4,
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
    )

    grounded_p10 = mean(row["grounded"]["precision_at_10"] for row in rows)
    grounded_np10 = mean(row["grounded"]["normalized_precision_at_10"] for row in rows)
    grounded_r10 = mean(row["grounded"]["recall_at_10"] for row in rows)
    grounded_citation = mean(row["grounded"]["citation_accuracy"] for row in rows)
    grounded_hallucination = mean(row["grounded"]["hallucination_rate"] for row in rows)
    grounded_mapping_fidelity = mean(row["grounded"]["mapping_fidelity"] for row in rows)

    story = [
        Paragraph("RAGScan Evaluation Report", title),
        Paragraph(f"Grounded RAG vs ungrounded baseline | {len(rows)} cases", body),
        Spacer(1, 4 * mm),
    ]

    summary_table = Table(
        [
            ["Metric", "Value"],
            ["Precision@10", f"{grounded_p10:.3f}"],
            ["Normalized Precision@10", f"{grounded_np10:.3f}"],
            ["Recall@10", f"{grounded_r10:.3f}"],
            ["Citation Accuracy", f"{grounded_citation:.3f}"],
            ["Hallucination Rate", f"{grounded_hallucination:.3f}"],
            ["Mapping Fidelity", f"{grounded_mapping_fidelity:.3f}"],
        ],
        colWidths=[60 * mm, 40 * mm],
    )
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ]
        )
    )
    story.extend([summary_table, Spacer(1, 5 * mm)])

    rows_data = [["Question", "P@10", "Norm P@10", "R@10", "Citation", "Hallucination", "Mapping", "Risk proxy", "Baseline hallucination"]]
    for row in rows:
        g = row["grounded"]
        b = row["baseline"]
        risk_proxy = g["predicted_risk_score"]
        rows_data.append(
            [
                Paragraph(_escape_html(row["question"]), body),
                f"{g['precision_at_10']:.3f}",
                f"{g['normalized_precision_at_10']:.3f}",
                f"{g['recall_at_10']:.3f}",
                f"{g['citation_accuracy']:.3f}",
                f"{g['hallucination_rate']:.3f}",
                f"{g['mapping_fidelity']:.3f}",
                f"{risk_proxy:.1f}" if risk_proxy is not None else "N/A",
                f"{b['hallucination_rate']:.3f}",
            ]
        )

    detail_table = Table(rows_data, colWidths=[50 * mm, 12 * mm, 14 * mm, 12 * mm, 14 * mm, 16 * mm, 14 * mm, 16 * mm, 18 * mm])
    detail_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#374151")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(detail_table)

    if deepeval is not None:
        summary = deepeval["summary"]
        story.extend([Spacer(1, 6 * mm), Paragraph("LLM-judged (free-text)", styles["Heading2"])])
        story.append(
            Paragraph(
                f"Judge model: {deepeval['judge_model']}. These scores apply only to narrative free-text grounding.",
                body,
            )
        )

        llm_summary_table = Table(
            [
                ["Metric", "Value"],
                ["Faithfulness avg", f"{summary['avg_faithfulness']:.3f}"],
                ["Faithfulness pass rate", f"{summary['faithfulness_pass_rate']:.3f}"],
                ["Contextual precision avg", f"{summary['avg_contextual_precision']:.3f}"],
                ["Contextual recall avg", f"{summary['avg_contextual_recall']:.3f}"],
            ],
            colWidths=[60 * mm, 40 * mm],
        )
        llm_summary_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ]
            )
        )
        story.extend([llm_summary_table, Spacer(1, 4 * mm)])

        llm_rows_data = [["Question", "Faithfulness", "Pass", "Ctx Precision", "Ctx Recall", "Judge reason"]]
        for item in deepeval["rows"]:
            llm_rows_data.append(
                [
                    Paragraph(_escape_html(item["question"]), body),
                    f"{item['faithfulness_score']:.3f}",
                    "yes" if item["faithfulness_passed"] else "no",
                    f"{item['contextual_precision_score']:.3f}",
                    f"{item['contextual_recall_score']:.3f}",
                    Paragraph(_escape_html(item["faithfulness_reason"]), body),
                ]
            )

        llm_detail_table = Table(llm_rows_data, colWidths=[42 * mm, 18 * mm, 10 * mm, 18 * mm, 18 * mm, 54 * mm])
        llm_detail_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#374151")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(llm_detail_table)

    doc.build(story)


async def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate grounded retrieval quality and hallucination rate.")
    parser.add_argument("dataset", type=Path, help="JSONL file with evaluation cases")
    default_reports_dir = ROOT / "reports" / "evaluations"
    parser.add_argument("--html-out", type=Path, default=default_reports_dir / "eval_report.html", help="Where to write the HTML report")
    parser.add_argument("--pdf-out", type=Path, default=default_reports_dir / "eval_report.pdf", help="Where to write the PDF report")
    parser.add_argument("--with-deepeval", action="store_true", help="Run optional LLM-judged free-text metrics (DeepEval)")
    parser.add_argument("--faithfulness-threshold", type=float, default=0.7, help="Pass threshold for DeepEval faithfulness metric")
    args = parser.parse_args()

    cases = _load_cases(args.dataset)
    if not cases:
        raise SystemExit("No evaluation cases found in dataset")

    if not settings.anthropic_api_key:
        raise SystemExit("ANTHROPIC_API_KEY is required for the grounded and baseline answer comparison")

    rows = [await _evaluate_case(case) for case in cases]
    deepeval_results: dict[str, Any] | None = None
    if args.with_deepeval:
        if not settings.openai_api_key:
            raise SystemExit("OPENAI_API_KEY is required when using --with-deepeval")
        try:
            import deepeval  # type: ignore  # noqa: F401
        except Exception as exc:
            raise SystemExit("DeepEval is not installed. Install backend requirements to use --with-deepeval.") from exc
        deepeval_results = await _evaluate_with_deepeval(cases, args.faithfulness_threshold)
        if args.html_out == (default_reports_dir / "eval_report.html"):
            args.html_out = default_reports_dir / "eval_report_deepeval.html"
        if args.pdf_out == (default_reports_dir / "eval_report.pdf"):
            args.pdf_out = default_reports_dir / "eval_report_deepeval.pdf"

    _print_summary(rows, deepeval=deepeval_results)
    _render_html(args.html_out, rows, deepeval=deepeval_results)
    _render_pdf(args.pdf_out, rows, deepeval=deepeval_results)
    print(f"HTML report written to: {args.html_out.resolve()}")
    print(f"PDF report written to: {args.pdf_out.resolve()}")


def _run_async_entrypoint(coro: Any) -> Any:
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(coro)
    finally:
        try:
            loop.run_until_complete(loop.shutdown_asyncgens())
        except Exception:
            pass
        loop.close()
        asyncio.set_event_loop(None)


if __name__ == "__main__":
    _run_async_entrypoint(main())
