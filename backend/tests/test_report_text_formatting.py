"""Report text formatting tests.

These tests ensure LLM markdown artifacts are sanitized before PDF rendering.
"""

from app.core.reports.builder import _clean_llm_text


def test_clean_llm_text_removes_markdown_tokens():
    raw = "## Remediation Narrative\n**Critical** issue in `kernel` package."
    cleaned = _clean_llm_text(raw)

    assert "##" not in cleaned
    assert "**" not in cleaned
    assert "`" not in cleaned
    assert cleaned == "Remediation Narrative Critical issue in kernel package."


def test_clean_llm_text_collapses_wrapped_lines_and_keeps_paragraphs():
    raw = (
        "Findings **abc123** and **def456** indicate patch delays.\n"
        "Apply vendor updates immediately.\n\n"
        "Estimated effort: short-term (1-4 weeks)."
    )
    cleaned = _clean_llm_text(raw)

    assert "\n\n" in cleaned
    assert "Findings abc123 and def456 indicate patch delays. Apply vendor updates immediately." in cleaned
    assert "Estimated effort: short-term (1-4 weeks)." in cleaned


def test_clean_llm_text_handles_empty_input():
    assert _clean_llm_text("") == ""
