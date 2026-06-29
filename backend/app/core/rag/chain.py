"""
LangChain LCEL chain for grounded vulnerability Q&A.

All answers are strictly anchored to retrieved findings.
The LLM is instructed to cite finding IDs and CVEs in every response.
Temperature = 0.1 for deterministic, auditable outputs.
"""
import re

from langchain_anthropic import ChatAnthropic
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate

from app.config import settings

SYSTEM_PROMPT = """You are RAGScan, a security intelligence assistant.

Rules you must follow:
1. Answer ONLY using the vulnerability findings provided below.
2. Cite the finding ID and CVE for every claim you make, e.g. [Finding: <id>, CVE: <cve>].
3. If the answer is not contained in the provided findings, say exactly: "This information is not in the retrieved findings."
4. Do not speculate, guess, or add context not present in the findings.
5. Prioritise findings with higher risk scores and CISA KEV status.
6. Do not use emojis, markdown headings, bullet lists, tables, or code fences.
7. Write plain text only, using short paragraphs.

Respond in clear, structured paragraphs. Be specific and concise."""

prompt = ChatPromptTemplate.from_messages([
    ("system", SYSTEM_PROMPT),
    ("human", "Findings:\n{context}\n\nQuestion: {question}"),
])

_chain = None


def _clean_answer(text: str) -> str:
    cleaned = text.strip()
    cleaned = re.sub(r"^\s{0,3}#{1,6}\s*", "", cleaned, flags=re.MULTILINE)
    cleaned = cleaned.replace("**", "").replace("__", "").replace("`", "")
    cleaned = re.sub(r"^\s*[-*+]\s+", "", cleaned, flags=re.MULTILINE)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    cleaned = re.sub(r"[ \t]{2,}", " ", cleaned)
    return cleaned.strip()


def _get_chain():
    global _chain
    if _chain is None:
        llm = ChatAnthropic(
            model=settings.llm_model,
            temperature=0.1,
            anthropic_api_key=settings.anthropic_api_key,
        )
        _chain = prompt | llm | StrOutputParser()
    return _chain


def format_findings(findings: list[dict]) -> str:
    if not findings:
        return "No findings retrieved."
    parts = []
    for f in findings:
        kev = "YES (CISA KEV)" if f.get("cisa_kev") else "no"
        parts.append(
            f"[Finding ID: {f.get('id')}]\n"
            f"  CVE: {f.get('cve_id') or 'N/A'} | Severity: {f.get('severity_label', '').upper()} | "
            f"Risk Score: {f.get('risk_score', 'N/A')}/100\n"
            f"  CVSS: {f.get('cvss3_score', 'N/A')} | EPSS: {f.get('epss_score', 'N/A')} | KEV: {kev}\n"
            f"  Host: {f.get('hostname', 'N/A')} ({f.get('host_ip', 'N/A')})\n"
            f"  Title: {f.get('title', 'N/A')}\n"
            f"  Description: {str(f.get('description') or '')[:400]}\n"
            f"  Solution: {str(f.get('solution') or '')[:300]}"
        )
    return "\n\n".join(parts)


async def query(question: str, findings: list[dict]) -> str:
    context = format_findings(findings)
    response = await _get_chain().ainvoke({"context": context, "question": question})
    return _clean_answer(response)
