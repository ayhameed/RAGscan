# RAGScan

Retrieval-augmented vulnerability intelligence and compliance gap analysis.

RAGScan ingests XML scan data (Nessus, OpenSCAP XCCDF, and other XML schemas through a generic fallback parser), enriches every finding with live threat intelligence from NVD, FIRST EPSS, and the CISA KEV catalog, computes a composite risk score, stores findings in a pgvector embedding store, and exposes a LangChain-orchestrated agent that answers natural-language questions using retrieved scan findings as the primary context. Optional NVD/EPSS internet context can also be supplied as secondary context to help explain or reinforce those findings, but it does not override the scan evidence. A Next.js dashboard provides a browser interface for importing scans, viewing risk scores, and querying the agent. Hallucination is treated as a first-class failure mode.

## Architecture

Figure 1. RAGScan data pipeline

![Figure 1. RAGScan data pipeline](Figure_1%20RAGScan%20data%20pipeline.jpg)

Figure 2. RAGScan consumption paths

![Figure 2. RAGScan consumption paths](Figure_2%20RAGScan%20consumption%20paths.jpg)

## Prerequisites

**Runtime**
- Docker Desktop (or Docker Engine + Compose plugin)

**API keys**
- `ANTHROPIC_API_KEY` — Claude (required for `/query` and `/report`)
- `OPENAI_API_KEY` — text-embedding-3-small (required for RAG retrieval)
- `NVD_API_KEY` — optional; raises NVD rate limit from 5 to 50 req/30 s

> The `/ingest` and `/score` endpoints are fully functional without any API keys — enrichment via NVD, EPSS, and CISA KEV uses only HTTP calls.

## Quick start

### Docker Compose

```bash
# create the repo-root environment file and fill in your API keys
cp .env.example .env

docker compose up --build
```

The repo-root `.env` is the canonical local configuration file. The backend also reads this file when started directly from the repo root.

Open:

- Frontend: http://localhost:3000
- Backend API docs: http://localhost:8000/docs

Stop everything:

```bash
docker compose down
```

Reset database volume (fresh state):

```bash
docker compose down -v
```

Optional: load demo data (~200 findings)

```bash
python scripts/load_demo_data.py --url http://localhost:8000
```

## Using the application

1. Open `http://localhost:3000` and register an account.
2. If your account is pending, wait for an admin to approve it before login access is granted.
3. Go to **Import** and upload an XML scan file (`.nessus`, OpenSCAP `.xml`, or other XML scanner outputs), or click **Load Demo Data**.
4. Go to **Reports** to select an uploaded report and inspect scoped findings.
5. Go to **Guide** to understand risk score interpretation and prioritization bands.
6. Go to **Dashboard** for executive summary, live grounding metrics, compliance PDF export, and DeepEval PDF export.
7. Go to **Chat** to ask natural-language questions about your findings (requires `ANTHROPIC_API_KEY` and `OPENAI_API_KEY`).
8. Go to **Logs** to review activity history.
9. If you are an admin, use **Admin** to approve users, grant/revoke admin rights, and block/unblock accounts.

## Admin usage

RAGScan now uses approval-based access control.

- New registrations are created as `pending approval`.
- Blocked users cannot log in.
- Existing users are backfilled as approved during migration/init.
- The seeded admin account is `hameedyunusa@outlook.com`.

Admin workflow:

1. Sign in as an admin user.
2. Open **Admin** (`/admin`).
3. Review users list.
4. Click **Approve** to allow login.
5. Click **Make Admin** to grant admin rights.
6. Click **Block** to disable account access.

Operational notes:

- Non-admin users only see their own audit logs.
- Admin users can see all logs.
- Admins cannot block themselves or remove their own admin role.

## Screen guide

- **Landing (`/`)**: login/register.
- **Import (`/import`)**: drag-drop upload or demo load, plus upload log table.
- **Reports (`/reports`)**: report-scoped findings and risk summary cards.
- **Dashboard (`/dashboard`)**: summary cards, trend metrics, compliance export, DeepEval export.
- **Chat (`/chat`)**: scoped conversational analysis with citations, metrics, session export.
- **Logs (`/logs`)**: paginated activity log.
- **Guide (`/guide`)**: risk formula and severity interpretation.
- **Admin (`/admin`)**: user lifecycle controls (admin-only).

## API reference

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/register` | — | Register a user |
| POST | `/auth/login` | — | Obtain a JWT |
| GET | `/auth/me` | Bearer | Return current user profile and access flags |
| GET | `/auth/admin/users` | Bearer (admin) | List users for admin lifecycle management |
| PATCH | `/auth/admin/users/{user_id}` | Bearer (admin) | Update `is_admin`, `is_approved`, `is_blocked` |
| POST | `/ingest` | Bearer | Upload an XML scan file (known formats use dedicated parsers; unknown formats use generic fallback parsing) |
| POST | `/ingest/demo` | Bearer | Ingest bundled demo files in one click |
| GET | `/ingest/reports` | Bearer | List uploaded scan reports (file, uploader, timestamp, finding count) |
| DELETE | `/ingest/reports/{report_id}` | Bearer | Delete an uploaded report and associated findings |
| DELETE | `/ingest/reports` | Bearer | Purge all uploaded reports and associated findings for current user |
| GET | `/score` | Bearer | Findings ranked by risk score (`report_id` optional) |
| POST | `/query` | Bearer | Natural-language query over findings (`report_id`, `report_ids`, `finding_ids`, `session_id`, `include_internet_context` optional) |
| GET | `/query/sessions/{session_id}` | Bearer | Load stored conversation history |
| GET | `/query/sessions/{session_id}/download` | Bearer | Download conversation transcript as PDF |
| DELETE | `/query/sessions/{session_id}` | Bearer | Delete a stored chat session |
| GET | `/analyse/{id}` | Bearer | Deep analysis of a single finding |
| GET | `/analyse/deepeval/download` | Bearer | Generate and download DeepEval PDF on-demand (temp file) |
| POST | `/report` | Bearer | Generate NIST CSF or ISO 27001 gap report PDF |
| GET | `/report/{id}/download` | Bearer | Download generated report |
| GET | `/metrics/overview` | Bearer | Scope-aware average query grounding metrics |
| GET | `/metrics/trend` | Bearer | Scope-aware daily grounding metrics trend (`days` query param) |
| GET | `/audit` | Bearer | Activity log (paginated: `page`, `page_size`) |
| GET | `/health` | — | Liveness check |

`POST /ingest` response includes parser metadata:

- `detected_tool`: detector classification (for example `nessus`, `openscap`, `unknown_xml`).
- `parser_used`: parser actually used (`nessus`, `openscap`, or `generic_xml`).
- `fallback_used`: `true` when generic fallback parsing was used.
- `parse_warnings`: non-fatal parser/fallback warnings.

## Running tests

```bash
source venv/bin/activate
cd backend
pip install -r requirements.txt
pytest tests/ -v --tb=short
```

35 unit tests covering parsers, ingestion routing, enrichment, scoring, NIST mapping, and agent routing.

Optional LLM-judged faithfulness tests are marked `eval` and skipped by default:

```bash
source venv/bin/activate
cd backend
pytest -m eval -v
```

## Risk score formula

```
risk_score = ((cvss3 / 10.0) * 0.4 + epss * 0.4 + kev * 0.2) * 100
```

| Component | Value | Weight |
|-----------|-------|--------|
| `cvss3` | CVSS v3.1 base score (0-10); fallback 5.0 if no CVE | 40% |
| `epss` | FIRST EPSS exploitation probability (0-1) | 40% |
| `kev` | 1.0 if in CISA KEV catalog, else 0.0 | 20% |

Example scores from the E2E test:

| CVE | CVSS | EPSS | KEV | Risk |
|-----|------|------|-----|------|
| CVE-2014-6271 (Shellshock) | 9.8 | 100% | yes | **99.2** |
| CVE-2014-0160 (Heartbleed) | 7.5 | 100% | yes | **90.0** |
| CVE-2001-0572 (SSHv1) | — | 7% | no | **32.8** |
| no CVE (world-writable /tmp) | — | — | no | **20.0** |

This composite is motivated by Jacobs et al. (2021) and Spring et al. (2021), who show that combining CVSS with exploitation probability produces substantially better prioritisation than either metric alone.

## Hallucination mitigation

The LLM is given retrieved finding context as the primary evidence base for grounded answers.

When the chat toggle for internet context is enabled, the LLM may also receive supplemental NVD/EPSS context as a secondary input. The prompt explicitly instructs the model to trust the retrieved findings first and use internet context only to reinforce or explain them.

Runtime hallucination scoring uses semantic support against retrieved findings rather than citation-only checks:

1. Split the answer into sentences.
2. For each sentence, compare semantic token overlap with retrieved finding evidence (title, description, solution, severity, CVE).
3. Mark a sentence unsupported if it has weak overlap with all retrieved findings.
4. If a sentence cites finding IDs that are not in retrieved sources, mark it unsupported.

Hallucination rate is `unsupported_sentences / total_sentences`.

Citations are still strongly encouraged for traceability, but uncited factual statements can count as supported when semantically grounded in retrieved evidence.

Temperature is 0.1 (near-deterministic). This follows Lewis et al. (2020), who demonstrate that retrieval-grounded generation substantially reduces unsupported claims.

## Compliance mapping

CWE IDs are mapped to NIST CSF controls and ISO 27001:2022 controls via a static JSON table (`backend/app/core/nist/cwe_nist_mappings.json`, 42 entries). Findings without a CWE ID fall back to severity-based mappings (critical/high → DE.CM-7, PR.IP-12; medium → PR.IP-12). The LLM writes only the executive summary and per-control remediation narrative — control tables and gap counts are generated deterministically in Python.

## Project layout

```
backend/
  app/
    api/routes/         auth, ingest, query, score, report, analyse, metrics, audit
    core/
      ingestion/        tool detector, parser registry, Nessus/OpenSCAP parsers, generic XML fallback parser
      enrichment/       NVD, EPSS, CISA KEV clients with DB caching
      scoring/          composite risk score engine
      rag/              embedder, pgvector retriever, LangChain LCEL chain
      agents/           supervisor (intent router), security agent, reporting agent
      nist/             NIST CSF / ISO 27001 mapper and seed data (42 CWE mappings)
      reports/          ReportLab PDF builder
    db/                 SQLAlchemy 2.0 async session and init
    models/             ORM models (findings, embeddings, cache, gaps, reports, users)
    schemas/            Pydantic v2 request/response schemas
  alembic/              database migrations
  tests/                35 unit tests

frontend/
  app/
    page.tsx            login / register
    admin/              user approval/admin/block management
    dashboard/          risk stat cards + sortable findings table
    import/             drag-and-drop scan file upload
    logs/               audit log viewer
    reports/            report-scoped findings explorer
    guide/              risk formula and interpretation
    chat/               natural-language query interface with citations
  components/
    Nav.tsx             navigation bar
    AuthGuard.tsx       client-side JWT gate
  lib/
    api.ts              typed API client (fetch + localStorage token)

scripts/
  load_demo_data.py     seeds dev environment from DefectDojo sample scan
  evaluate_rag_metrics.py deterministic + optional DeepEval benchmark runner

sample_data/
  eval_cases.jsonl      evaluation dataset template

reports/
  evaluations/          generated evaluation HTML/PDF artifacts

docker-compose.yml
Dockerfile
```

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | Yes | `postgresql+asyncpg://user:pass@host/db` |
| `JWT_SECRET` | Yes | Random 256-bit string for JWT HS256 signing |
| `ANTHROPIC_API_KEY` | For chat/report | Claude LLM (claude-sonnet-4-6 by default) |
| `OPENAI_API_KEY` | For chat/report | Embeddings (text-embedding-3-small, 1536 dims) |
| `NVD_API_KEY` | No | Raises NVD rate limit from 5 to 50 req/30 s |
| `ENVIRONMENT` | No | `dev` (permissive CORS) or `prod` |

Put local environment variables in the repo-root `.env` file. The backend prefers `/.env` over `backend/.env`.

## Score Guide And Compliance Export

- Use the in-app **Guide** page (`/guide`) to understand the composite risk formula and score bands.
- Use **Dashboard -> Compliance PDF Export** to choose framework (`nist_csf`, `iso27001`, or `executive`) and generate a downloadable PDF.
- Export uses the currently selected report scope when provided.
- Use **Reports** to view uploaded files with uploader/date and delete selected uploaded reports.
- Use **Logs** (`/logs`) to view activity history including who performed each operation and when.

## Evaluation Metrics

To show retrieval quality and answer grounding, use a labeled JSONL evaluation set and run the metrics script:

```bash
source venv/bin/activate
cd backend
python ../scripts/evaluate_rag_metrics.py ../sample_data/eval_cases.jsonl --html-out ../reports/eval_report.html --pdf-out ../reports/eval_report.pdf
```

Deterministic (default) metrics in the script are:

- Retrieval precision@10
- Citation accuracy
- Hallucination rate
- Mapping fidelity
- Risk score correlation proxy

Optional LLM-judged metrics (free-text only) are available via DeepEval and are **off by default**:

```bash
source venv/bin/activate
cd backend
EVAL_JUDGE_MODEL=gpt-4.1-mini python ../scripts/evaluate_rag_metrics.py ../sample_data/eval_cases.jsonl --with-deepeval --html-out ../reports/eval_report.html --pdf-out ../reports/eval_report.pdf
```

DeepEval is used only for narrative grounding quality (faithfulness/contextual precision/contextual recall). Structured checks remain deterministic.

Judge-model guardrail:

- Generator model uses Claude (`LLM_MODEL` / `settings.llm_model`).
- DeepEval judge should use a **different model family** to reduce self-preference bias (set `EVAL_JUDGE_MODEL` to a GPT-4-class model).

Caveat: LLM-judged metrics are slower, cost money, and can vary slightly across runs. Keep deterministic metrics as the primary baseline.

The included `sample_data/eval_cases.jsonl` file is a template. Replace the placeholder IDs with labeled cases before using the output as a real benchmark.

Each JSONL row should look like this:

```json
{"question": "Which findings are KEV?", "expected_finding_ids": ["..."], "report_ids": ["..."], "expected_controls": ["PR.IP-12"], "expected_risk_score": 91.2, "gold_citation_ids": ["..."], "framework": "nist_csf"}
```

Recommended ground-truth file format:

- `question`: user query or evaluation prompt.
- `expected_finding_ids`: the finding IDs that should be retrieved for `precision@10`.
- `gold_citation_ids`: the finding IDs that should appear in the answer citations.
- `expected_controls`: the expected NIST/ISO control IDs for mapping fidelity.
- `expected_risk_score`: optional numeric reference for risk-score correlation.
- `framework`: `nist_csf` or `iso27001` when control mapping should be checked.

The script prints a summary for grounded RAG answers and an ungrounded baseline:

| Metric | What it measures |
|--------|------------------|
| Retrieval precision@10 | Relevant findings returned in the top 10 retrieved results divided by 10 |
| Citation accuracy | Share of cited finding IDs that are correct for the gold answer |
| Hallucination rate | Share of answer sentences that are not semantically supported by retrieved findings (with invalid cited IDs penalized) |
| Ungrounded baseline | Same question answered without retrieved findings, so you can compare grounding quality |

Recommended presentation format:

| Run | Precision@10 | Citation Accuracy | Hallucination Rate |
|-----|-------------:|------------------:|-------------------:|
| Grounded RAG | 0.82 | 0.91 | 0.08 |
| Ungrounded baseline | 0.00 | 0.12 | 0.74 |

If you want a stronger claim for hallucination rate, add a second-pass judge that labels each sentence as supported or unsupported by the retrieved findings.

Finding ID note:

- `findings.id` is the canonical identifier used in retrieval output and citations.
- `finding_embeddings` stores vectors keyed by `finding_id`, so each vector maps 1:1 to a finding row.

The dashboard also shows live grounding metrics for the current upload scope:

- Evidence Precision@10: how often the top retrieved sources are actually used in the answer.
- Citation Accuracy: how often cited finding IDs match retrieved sources.
- Hallucination Rate: semantically unsupported sentences divided by total sentences.

Chat controls:

- **Show internet context** toggle: enables/disables secondary NVD/EPSS context lookup and supplemental reasoning context per query.
- **Clear Session** button: clears local chat state and deletes the persisted backend session.

The offline HTML and PDF reports also include NIST/ISO mapping fidelity and risk score correlation when `expected_controls` and `expected_risk_score` are provided in the JSONL file.

Use the dashboard metrics for operational monitoring and the labeled JSONL benchmark for journal-style comparisons against an ungrounded baseline.

## References

Biesecker, C., et al. (2022). *CISA Known Exploited Vulnerabilities Catalog.* Cybersecurity and Infrastructure Security Agency. https://www.cisa.gov/known-exploited-vulnerabilities-catalog

Common Vulnerability Scoring System (CVSS) v3.1 specification. (2019). *FIRST.org.* https://www.first.org/cvss/specification-document

Deng, G., Liu, Y., Mayoral-Vilches, V., Liu, P., Li, Y., Xu, Y., Zhang, T., Liu, Y., Pinzger, M., & Rass, S. (2024). PentestGPT: An LLM-empowered automatic penetration testing tool. *arXiv.* https://doi.org/10.48550/arxiv.2308.06782

ISO/IEC 27001:2022. (2022). *Information security, cybersecurity and privacy protection — Information security management systems — Requirements.* International Organization for Standardization.

Jacobs, J., Romanosky, S., Adjerid, I., & Baker, W. (2021). Exploit prediction scoring system (EPSS). *Digital Threats: Research and Practice, 2*(3), 1-17. https://doi.org/10.1145/3436242

Lewis, P., Perez, E., Piktus, A., Petroni, F., Karpukhin, V., Goyal, N., Kuettler, H., Lewis, M., Yih, W., Rocktaeschel, T., Riedel, S., & Kiela, D. (2020). Retrieval-augmented generation for knowledge-intensive NLP tasks. *Advances in Neural Information Processing Systems, 33.* https://doi.org/10.48550/arxiv.2005.11401

National Institute of Standards and Technology. (2018). *Framework for Improving Critical Infrastructure Cybersecurity (NIST CSF) v1.1.* https://doi.org/10.6028/NIST.CSWP.04162018

National Vulnerability Database. (2024). *NVD CVE API v2.0.* NIST. https://nvd.nist.gov/developers/vulnerabilities

OpenSCAP Project. (2024). *SCAP Security Guide and XCCDF benchmark format.* Red Hat / NIST. https://www.open-scap.org

Spring, J., Hatleback, E., Householder, A., Manion, A., & Shick, D. (2021). Improving vulnerability remediation through better exploit prediction. *Journal of Cybersecurity, 7*(1). https://doi.org/10.1093/cybsec/tyaa015

## License

This project is licensed under the **Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0)** license.

- You may use, modify, and share this project for non-commercial purposes.
- You must provide attribution.
- Derivative works must be shared under the same license terms (copyleft/share-alike).
- **Commercial use is prohibited**, including use of this project in whole or in part within commercial applications or services.

Full license text: https://creativecommons.org/licenses/by-nc-sa/4.0/
