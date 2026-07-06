#!/usr/bin/env python3
"""Generate labeled evaluation cases from already-parsed scan findings.

Scope note:
The uploaded scan is ground truth for "does the answer faithfully represent
the scan," NOT for "is the vulnerability real on the host." Scanners can have
false positives. These cases validate faithfulness-to-retrieved-evidence only.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import uuid
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.db.session import AsyncSessionLocal  # type: ignore
from app.models.models import Finding, ScanUpload  # type: ignore


@dataclass
class EvalCase:
    question: str
    expected_finding_ids: list[str]
    report_ids: list[str]
    gold_citation_ids: list[str]
    expected_controls: list[str]
    expected_risk_score: float | None
    framework: str

    def to_json(self) -> str:
        return json.dumps(
            {
                "question": self.question,
                "expected_finding_ids": self.expected_finding_ids,
                "report_ids": self.report_ids,
                "gold_citation_ids": self.gold_citation_ids,
                "expected_controls": self.expected_controls,
                "expected_risk_score": self.expected_risk_score,
                "framework": self.framework,
            },
            ensure_ascii=True,
        )


def _sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    # Deterministic order: highest risk first, then UUID string.
    return sorted(
        findings,
        key=lambda item: (
            -(item.risk_score if item.risk_score is not None else -1.0),
            str(item.id),
        ),
    )


def _ids(findings: Iterable[Finding], cap: int | None = None) -> list[str]:
    ordered = _sort_findings(findings)
    if cap is not None:
        ordered = ordered[:cap]
    return [str(item.id) for item in ordered]


def _build_case(question: str, matched_ids: list[str], report_id: str, framework: str) -> EvalCase:
    # Guardrails:
    # - expected_controls must remain empty to avoid circular mapper self-grading.
    # - expected_risk_score must remain null to avoid self-validating stored/computed risk.
    return EvalCase(
        question=question,
        expected_finding_ids=matched_ids,
        report_ids=[report_id],
        gold_citation_ids=matched_ids,
        expected_controls=[],
        expected_risk_score=None,
        framework=framework,
    )


async def _resolve_upload(session: AsyncSession, report_id: str | None, user_id: str | None) -> ScanUpload:
    if report_id:
        try:
            report_uuid = uuid.UUID(report_id)
        except ValueError as exc:
            raise SystemExit(f"Invalid --report-id: {report_id}") from exc
        upload = await session.scalar(select(ScanUpload).where(ScanUpload.id == report_uuid))
        if upload is None:
            raise SystemExit(f"No scan upload found for report id: {report_id}")
        return upload

    stmt = select(ScanUpload)
    if user_id:
        try:
            user_uuid = uuid.UUID(user_id)
        except ValueError as exc:
            raise SystemExit(f"Invalid --user-id: {user_id}") from exc
        stmt = stmt.where(ScanUpload.user_id == user_uuid)

    upload = await session.scalar(stmt.order_by(ScanUpload.uploaded_at.desc()).limit(1))
    if upload is None:
        if user_id:
            raise SystemExit(f"No scan uploads found for user id: {user_id}")
        raise SystemExit("No scan uploads found. Ingest a scan first or pass --report-id.")
    return upload


async def _load_findings_for_upload(session: AsyncSession, upload_id: uuid.UUID) -> list[Finding]:
    rows = await session.scalars(select(Finding).where(Finding.upload_id == upload_id))
    findings = list(rows.all())
    if not findings:
        raise SystemExit(f"No findings found for upload id: {upload_id}")
    return findings


def _generate_cases(findings: list[Finding], report_id: str, framework: str, max_per_template: int) -> tuple[list[EvalCase], dict[str, int]]:
    cases: list[EvalCase] = []
    counts: dict[str, int] = defaultdict(int)

    kev_findings = [item for item in findings if bool(item.cisa_kev)]
    if kev_findings:
        matched_ids = _ids(kev_findings, cap=max_per_template)
        cases.append(_build_case("Which findings are in the CISA KEV catalog?", matched_ids, report_id, framework))
        counts["kev"] += 1

    for severity in ("critical", "high"):
        sev_findings = [
            item
            for item in findings
            if (item.severity_label or "").strip().lower() == severity
        ]
        if sev_findings:
            matched_ids = _ids(sev_findings, cap=max_per_template)
            cases.append(_build_case(f"What are the {severity}-severity findings?", matched_ids, report_id, framework))
            counts[f"severity_{severity}"] += 1

    by_host: dict[str, list[Finding]] = defaultdict(list)
    for item in findings:
        host_value = (item.hostname or "").strip() or (item.host_ip or "").strip()
        if host_value:
            by_host[host_value].append(item)
    for host in sorted(by_host):
        matched_ids = _ids(by_host[host], cap=max_per_template)
        if matched_ids:
            cases.append(_build_case(f"Which findings affect host {host}?", matched_ids, report_id, framework))
            counts["host"] += 1

    by_cve: dict[str, list[Finding]] = defaultdict(list)
    for item in findings:
        cve = (item.cve_id or "").strip()
        if cve:
            by_cve[cve].append(item)
    for cve in sorted(by_cve):
        matched_ids = _ids(by_cve[cve], cap=max_per_template)
        if matched_ids:
            cases.append(_build_case(f"List the findings for {cve}.", matched_ids, report_id, framework))
            counts["cve"] += 1

    no_cve = [item for item in findings if not (item.cve_id or "").strip()]
    if no_cve:
        matched_ids = _ids(no_cve, cap=max_per_template)
        cases.append(_build_case("Which findings have no associated CVE?", matched_ids, report_id, framework))
        counts["no_cve"] += 1

    with_risk = [item for item in findings if item.risk_score is not None]
    if with_risk:
        top_risk_id = _ids(with_risk, cap=1)
        cases.append(_build_case("Which finding has the highest risk score?", top_risk_id, report_id, framework))
        counts["highest_risk"] += 1

    with_epss = [item for item in findings if item.epss_score is not None]
    if with_epss:
        top_epss = sorted(with_epss, key=lambda item: (-(item.epss_score or -1.0), str(item.id)))[:1]
        top_epss_id = [str(top_epss[0].id)]
        cases.append(
            _build_case("Which finding has the highest EPSS exploit probability?", top_epss_id, report_id, framework)
        )
        counts["highest_epss"] += 1

    return cases, counts


def _write_cases(path: Path, cases: list[EvalCase]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for case in cases:
            handle.write(case.to_json())
            handle.write("\n")


def _print_summary(counts: dict[str, int], total: int, out_path: Path) -> None:
    rows = [
        ("kev", counts.get("kev", 0)),
        ("severity_critical", counts.get("severity_critical", 0)),
        ("severity_high", counts.get("severity_high", 0)),
        ("host", counts.get("host", 0)),
        ("cve", counts.get("cve", 0)),
        ("no_cve", counts.get("no_cve", 0)),
        ("highest_risk", counts.get("highest_risk", 0)),
        ("highest_epss", counts.get("highest_epss", 0)),
    ]
    print("Generated evaluation cases")
    print(f"Output: {out_path}")
    print(f"Total cases: {total}")
    print()
    print("template              count")
    print("--------------------  -----")
    for name, value in rows:
        print(f"{name:<20}  {value:>5}")


async def main() -> None:
    parser = argparse.ArgumentParser(description="Generate labeled eval JSONL cases from parsed scan findings.")
    parser.add_argument("--report-id", type=str, default=None, help="ScanUpload ID to scope evaluation generation")
    parser.add_argument("--user-id", type=str, default=None, help="User ID; used when --report-id is omitted")
    parser.add_argument("--out", type=Path, default=Path("sample_data/eval_cases.jsonl"), help="Output JSONL path")
    parser.add_argument("--max-per-template", type=int, default=5, help="Maximum gold findings per template case")
    parser.add_argument("--framework", type=str, default="nist_csf", help="Framework field value for generated rows")
    args = parser.parse_args()

    if args.max_per_template < 1:
        raise SystemExit("--max-per-template must be >= 1")

    async with AsyncSessionLocal() as session:
        upload = await _resolve_upload(session, args.report_id, args.user_id)
        findings = await _load_findings_for_upload(session, upload.id)

    report_id = str(upload.id)
    cases, counts = _generate_cases(
        findings=findings,
        report_id=report_id,
        framework=args.framework,
        max_per_template=args.max_per_template,
    )

    if not cases:
        raise SystemExit("No matching findings produced any template cases.")

    _write_cases(args.out, cases)
    print(f"Using upload_id={report_id} user_id={upload.user_id} filename={upload.filename}")
    _print_summary(counts, len(cases), args.out)


if __name__ == "__main__":
    asyncio.run(main())
