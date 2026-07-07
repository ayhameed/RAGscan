"""
Reporting agent: generates narrative sections for compliance gap reports.

The report structure (tables, control lists, gap counts) is built in Python
by the report builder. This agent writes only the executive summary and
remediation narratives — strictly from the retrieved findings.
"""
from langchain_core.prompts import ChatPromptTemplate

from app.core.llm import LLMTextResult, invoke_text_with_fallback

_EXEC_SUMMARY_PROMPT = ChatPromptTemplate.from_messages([
    (
        "system",
        """You are the RAGScan Reporting Agent.
Write an executive summary paragraph (150-200 words) for a {framework} compliance gap report.

Base your summary strictly on the gap data provided. Mention:
- Total number of findings and critical/high count
- Number of gapped controls
- Top 2-3 most critical gaps with their control IDs
- Overall risk posture (one sentence)

Do not invent control IDs, CVEs, or statistics not present in the data.
 Cite controls as they appear in the gap data.
Output plain text only. Do not use markdown headings, bold markers, bullets, or code formatting.""",
    ),
    ("human", "Gap data:\n{gap_summary}\n\nFinding statistics:\n{stats}"),
])

_REMEDIATION_PROMPT = ChatPromptTemplate.from_messages([
    (
        "system",
        """You are the RAGScan Reporting Agent.
Write a remediation narrative (100-150 words) for the following {framework} control gap.

Rules:
- Reference the specific findings by their IDs that create this gap.
- State the recommended remediation action clearly.
- Estimate effort as: immediate (< 1 week) | short-term (1-4 weeks) | long-term (> 1 month).
- Do not add information not present in the findings.
Output plain text only. Do not use markdown headings, bold markers, bullets, or code formatting.""",
    ),
    ("human", "Control: {control_id}\nDescription: {control_desc}\n\nFindings:\n{findings_text}"),
])

async def write_executive_summary(framework: str, gap_summary: str, stats: str) -> str:
    result = await write_executive_summary_with_meta(framework, gap_summary, stats)
    return result.text


async def write_executive_summary_with_meta(framework: str, gap_summary: str, stats: str) -> LLMTextResult:
    return await invoke_text_with_fallback(_EXEC_SUMMARY_PROMPT, {
        "framework": framework,
        "gap_summary": gap_summary,
        "stats": stats,
    })


async def write_remediation(
    framework: str,
    control_id: str,
    control_desc: str,
    findings_text: str,
) -> str:
    result = await write_remediation_with_meta(framework, control_id, control_desc, findings_text)
    return result.text


async def write_remediation_with_meta(
    framework: str,
    control_id: str,
    control_desc: str,
    findings_text: str,
) -> LLMTextResult:
    return await invoke_text_with_fallback(_REMEDIATION_PROMPT, {
        "framework": framework,
        "control_id": control_id,
        "control_desc": control_desc,
        "findings_text": findings_text,
    })
