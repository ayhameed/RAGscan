# RAGScan

Retrieval-augmented vulnerability intelligence and compliance gap analysis.

RAGScan ingests structured scan data (Nessus XML, OpenSCAP XCCDF), enriches every finding with live threat intelligence from NVD, FIRST EPSS, and the CISA KEV catalog, computes a composite risk score, stores findings in a pgvector embedding store, and exposes a LangChain-orchestrated agent that answers natural-language questions grounded in retrieved findings. A Next.js dashboard provides a browser interface for importing scans, viewing risk scores, and querying the agent. All LLM responses are strictly anchored to retrieved findings with mandatory citations — hallucination is treated as a first-class failure mode.

## Architecture

```
Scan file (.nessus / OpenSCAP XCCDF XML)
          |
          v
  Ingestion layer (lxml parsers)
    - Nessus: ReportHost -> ReportItem, skips severity 0
    - OpenSCAP: XCCDF 1.1 + 1.2 namespaces, only 'fail' rule-results
          |
          v
  Enrichment service  (concurrent NVD + EPSS, DB-cached per CVE)
    NVD CVSS v3.1  +  FIRST EPSS  +  CISA KEV  (1629 entries, loaded at startup)
          |
          v
  Composite risk score  ->  pgvector embedding store (1536 dims)
          |
    +-----|------+
    |            |
    v            v
 /query       /report
 Security      NIST CSF /
 Agent         ISO 27001 gap
    |
    v
 FastAPI  (JWT HS256, slowapi rate limiting, audit log)
    |
    v
 Next.js frontend  (login, dashboard, import, chat)
```

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
# copy and fill in your API keys
cp .env.example .env

docker compose up --build
```

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
2. Go to **Import** and upload a `.nessus` or OpenSCAP `.xml` file.
3. Go to **Reports** to select an uploaded report and inspect scoped findings.
4. Go to **Guide** to understand risk score interpretation and prioritization bands.
5. Go to **Dashboard** for executive summary and to export framework-matched compliance PDFs.
6. Go to **Chat** to ask natural-language questions about your findings (requires `ANTHROPIC_API_KEY` and `OPENAI_API_KEY`).

## API reference

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/register` | — | Register a user |
| POST | `/auth/login` | — | Obtain a JWT |
| POST | `/ingest` | Bearer | Upload a Nessus or OpenSCAP file |
| GET | `/ingest/reports` | Bearer | List uploaded scan reports (file, uploader, timestamp, finding count) |
| DELETE | `/ingest/reports/{report_id}` | Bearer | Delete an uploaded report and associated findings |
| DELETE | `/ingest/reports` | Bearer | Purge all uploaded reports and associated findings for current user |
| GET | `/score` | Bearer | Findings ranked by risk score (`report_id` optional) |
| POST | `/query` | Bearer | Natural-language query over findings (`report_id` and `finding_ids` optional) |
| GET | `/analyse/{id}` | Bearer | Deep analysis of a single finding |
| POST | `/report` | Bearer | Generate NIST CSF or ISO 27001 gap report PDF |
| GET | `/report/{id}/download` | Bearer | Download generated report |
| GET | `/audit` | Bearer | Activity log (paginated: `page`, `page_size`) |
| GET | `/health` | — | Liveness check |

## Running tests

```bash
cd backend
pip install -r requirements.txt
pytest tests/ -v --tb=short
```

25 unit tests covering parsers, enrichment, scoring, NIST mapping, and agent routing.

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

The LLM is given only the retrieved finding context. The system prompt requires Claude to:

1. Cite every claim with `[Finding: <id>, CVE: <cve>]`.
2. State "This information is not in the retrieved findings" when the answer is absent.
3. Not speculate beyond the provided data.

Temperature is 0.1 (near-deterministic). This follows Lewis et al. (2020), who demonstrate that retrieval-grounded generation substantially reduces unsupported claims.

## Compliance mapping

CWE IDs are mapped to NIST CSF controls and ISO 27001:2022 controls via a static JSON table (`backend/app/core/nist/cwe_nist_mappings.json`, 42 entries). Findings without a CWE ID fall back to severity-based mappings (critical/high → DE.CM-7, PR.IP-12; medium → PR.IP-12). The LLM writes only the executive summary and per-control remediation narrative — control tables and gap counts are generated deterministically in Python.

## Project layout

```
backend/
  app/
    api/routes/         auth, ingest, query, score, report, analyse
    core/
      ingestion/        Nessus + OpenSCAP XCCDF parsers (lxml)
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
  tests/                25 unit tests

frontend/
  app/
    page.tsx            login / register
    dashboard/          risk stat cards + sortable findings table
    import/             drag-and-drop scan file upload
    chat/               natural-language query interface with citations
  components/
    Nav.tsx             navigation bar
    AuthGuard.tsx       client-side JWT gate
  lib/
    api.ts              typed API client (fetch + localStorage token)

scripts/
  load_demo_data.py     seeds dev environment from DefectDojo sample scan
docker-compose.yml
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

## Score Guide And Compliance Export

- Use the in-app **Guide** page (`/guide`) to understand the composite risk formula and score bands.
- Use **Dashboard -> Compliance PDF Export** to choose framework (`nist_csf`, `iso27001`, or `executive`) and generate a downloadable PDF.
- Export uses the currently selected report scope when provided.
- Use **Reports** to view uploaded files with uploader/date and delete selected uploaded reports.
- Use **Logs** (`/logs`) to view activity history including who performed each operation and when.

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
