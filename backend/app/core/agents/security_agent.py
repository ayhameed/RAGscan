"""
Security agent: interprets findings, explains risk, prioritises remediation.
Strictly cites finding IDs and CVEs. No speculation beyond retrieved data.
"""
import re

from langchain_anthropic import ChatAnthropic
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate

from app.config import settings
from app.core.rag.chain import format_findings

_SECURITY_PROMPT = ChatPromptTemplate.from_messages([
    (
        "system",
        """You are the RAGScan Security Agent.
Your role: interpret vulnerability findings for a security team and recommend remediation.

For each finding you discuss, address:
1. What the vulnerability is (plain English, one sentence)
2. Why it matters: reference the CVSS score, EPSS exploitation probability, and CISA KEV status
3. Which hosts are affected
4. Recommended action and priority

Rules:
- Always cite [Finding: <id>, CVE: <cve>] for every claim.
- Treat the provided findings as the primary evidence base.
- If supplemental internet context is provided, use it only as secondary context to explain or reinforce the findings.
- If supplemental context conflicts with the findings, trust the findings.
- Present findings in descending risk score order.
- If a finding is in the CISA KEV catalog, flag it prominently as an immediate priority.
- Do not add information not present in the provided findings and supplemental context.
- Be concise. Each finding should take 3-5 sentences maximum.
- Do not use emojis, markdown headings, bullet lists, tables, or code fences.
- Write plain text only, using short paragraphs.""",
    ),
    ("human", "Findings:\n{context}\n\nSupplemental context:\n{supplemental_context}\n\nQuestion: {question}"),
])

_llm = None
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
    global _llm, _chain
    if _chain is None:
        _llm = ChatAnthropic(
            model=settings.llm_model,
            temperature=0.1,
            anthropic_api_key=settings.anthropic_api_key,
        )
        _chain = _SECURITY_PROMPT | _llm | StrOutputParser()
    return _chain


async def analyse(question: str, findings: list[dict], supplemental_context: str | None = None) -> str:
    context = format_findings(findings)
    response = await _get_chain().ainvoke(
        {
            "context": context,
            "supplemental_context": supplemental_context or "None.",
            "question": question,
        }
    )
    return _clean_answer(response)
