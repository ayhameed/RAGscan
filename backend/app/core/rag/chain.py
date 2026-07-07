"""
LangChain LCEL chain for grounded vulnerability Q&A.

All answers are strictly anchored to retrieved findings.
The LLM is instructed to cite finding IDs and CVEs in every response.
Temperature = 0.1 for deterministic, auditable outputs.
"""
import re

from langchain_core.prompts import ChatPromptTemplate

from app.core.llm import LLMTextResult, invoke_text_with_fallback
from app.core.nist.mapper import get_controls

SYSTEM_PROMPT = """You are RAGScan, a security intelligence assistant.

Rules you must follow:
1. Treat the vulnerability findings as the primary evidence base.
2. Treat the compliance mappings included with each finding as part of the primary scan context.
3. If supplemental internet context is provided, use it only as secondary context to explain or reinforce the findings.
4. Never contradict the findings or their mapped controls. If findings and supplemental context differ, trust the findings.
5. Cite the finding ID and CVE for every claim grounded in a finding, e.g. [Finding: <id>, CVE: <cve>].
6. If the answer is not contained in the provided findings, say exactly: "This information is not in the retrieved findings."
7. Do not speculate or invent facts beyond the findings, their compliance mappings, and the supplemental context.
8. Prioritise findings with higher risk scores and CISA KEV status.
9. Do not use emojis, markdown headings, bullet lists, tables, or code fences.
10. Write plain text only, using short paragraphs.

Respond in clear, structured paragraphs. Be specific and concise."""

prompt = ChatPromptTemplate.from_messages([
    ("system", SYSTEM_PROMPT),
    ("human", "Findings:\n{context}\n\nSupplemental context:\n{supplemental_context}\n\nQuestion: {question}"),
])

def _clean_answer(text: str) -> str:
    cleaned = text.strip()
    cleaned = re.sub(r"^\s{0,3}#{1,6}\s*", "", cleaned, flags=re.MULTILINE)
    cleaned = cleaned.replace("**", "").replace("__", "").replace("`", "")
    cleaned = re.sub(r"^\s*[-*+]\s+", "", cleaned, flags=re.MULTILINE)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    cleaned = re.sub(r"[ \t]{2,}", " ", cleaned)
    return cleaned.strip()


def format_findings(findings: list[dict]) -> str:
    if not findings:
        return "No findings retrieved."
    parts = []
    for f in findings:
        kev = "YES (CISA KEV)" if f.get("cisa_kev") else "no"
        nist_controls = get_controls(f.get("cwe_id"), f.get("severity_label", ""), "nist_csf")
        iso_controls = get_controls(f.get("cwe_id"), f.get("severity_label", ""), "iso27001")
        nist_text = ", ".join(f"{item.get('control_id')}: {item.get('description')}" for item in nist_controls) or "None"
        iso_text = ", ".join(f"{item.get('control_id')}: {item.get('description')}" for item in iso_controls) or "None"
        parts.append(
            f"[Finding ID: {f.get('id')}]\n"
            f"  CVE: {f.get('cve_id') or 'N/A'} | Severity: {f.get('severity_label', '').upper()} | "
            f"Risk Score: {f.get('risk_score', 'N/A')}/100\n"
            f"  CVSS: {f.get('cvss3_score', 'N/A')} | EPSS: {f.get('epss_score', 'N/A')} | KEV: {kev}\n"
            f"  CWE: {f.get('cwe_id') or 'N/A'}\n"
            f"  Host: {f.get('hostname', 'N/A')} ({f.get('host_ip', 'N/A')})\n"
            f"  Title: {f.get('title', 'N/A')}\n"
            f"  Description: {str(f.get('description') or '')[:400]}\n"
            f"  Solution: {str(f.get('solution') or '')[:300]}\n"
            f"  NIST CSF mappings: {nist_text}\n"
            f"  ISO 27001 mappings: {iso_text}"
        )
    return "\n\n".join(parts)


async def query(question: str, findings: list[dict], supplemental_context: str | None = None) -> str:
    result = await query_with_meta(question, findings, supplemental_context)
    return result.text


async def query_with_meta(question: str, findings: list[dict], supplemental_context: str | None = None) -> LLMTextResult:
    context = format_findings(findings)
    response = await invoke_text_with_fallback(
        prompt,
        {
            "context": context,
            "supplemental_context": supplemental_context or "None.",
            "question": question,
        }
    )
    response.text = _clean_answer(response.text)
    return response
