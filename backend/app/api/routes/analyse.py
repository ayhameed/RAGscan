import uuid
import subprocess
import sys
import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.background import BackgroundTasks
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth_utils import require_auth
from app.core.agents.security_agent import analyse
from app.core.rag.embedder import finding_to_text
from app.db.session import get_db
from app.models.models import Finding, User
from app.schemas.schemas import FindingOut

router = APIRouter(tags=["analyse"])


def _safe_unlink(path: str) -> None:
    try:
        Path(path).unlink(missing_ok=True)
    except Exception:
        pass


@router.get("/deepeval/download")
async def download_deepeval_pdf(
    background_tasks: BackgroundTasks,
    _: User = Depends(require_auth),
):
    repo_root = Path(__file__).resolve().parents[4]
    script_path = repo_root / "scripts" / "evaluate_rag_metrics.py"
    dataset_path = repo_root / "sample_data" / "eval_cases.jsonl"

    if not script_path.exists() or not dataset_path.exists():
        raise HTTPException(
            status_code=500,
            detail="DeepEval assets are not available on this runtime",
        )

    pdf_tmp = tempfile.NamedTemporaryFile(prefix="deepeval_", suffix=".pdf", delete=False)
    html_tmp = tempfile.NamedTemporaryFile(prefix="deepeval_", suffix=".html", delete=False)
    pdf_tmp.close()
    html_tmp.close()

    try:
        proc = subprocess.run(
            [
                sys.executable,
                str(script_path),
                str(dataset_path),
                "--with-deepeval",
                "--html-out",
                html_tmp.name,
                "--pdf-out",
                pdf_tmp.name,
            ],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception as exc:
        _safe_unlink(pdf_tmp.name)
        _safe_unlink(html_tmp.name)
        raise HTTPException(status_code=500, detail=f"Failed to run DeepEval: {exc}") from exc

    if proc.returncode != 0 or not Path(pdf_tmp.name).exists():
        _safe_unlink(pdf_tmp.name)
        _safe_unlink(html_tmp.name)
        error_text = (proc.stderr or proc.stdout or "DeepEval export failed").strip()
        raise HTTPException(status_code=500, detail=error_text)

    background_tasks.add_task(_safe_unlink, pdf_tmp.name)
    background_tasks.add_task(_safe_unlink, html_tmp.name)
    return FileResponse(
        pdf_tmp.name,
        media_type="application/pdf",
        filename="ragscan_deepeval_report.pdf",
    )


@router.get("/{finding_id}", response_model=dict)
async def analyse_finding(
    finding_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_auth),
):
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    question = f"Explain this vulnerability and provide remediation steps."
    findings_ctx = [{
        "id": str(finding.id),
        "cve_id": finding.cve_id,
        "title": finding.title,
        "description": finding.description,
        "solution": finding.solution,
        "severity_label": finding.severity_label,
        "cvss3_score": finding.cvss3_score,
        "epss_score": finding.epss_score,
        "cisa_kev": finding.cisa_kev,
        "risk_score": finding.risk_score,
        "hostname": finding.hostname,
        "host_ip": finding.host_ip,
    }]
    narrative = await analyse(question, findings_ctx)

    return {
        "finding": FindingOut.model_validate(finding),
        "analysis": narrative,
    }
