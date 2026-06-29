Security teams increasingly rely on automated scanning tools,
yet raw outputs leave practitioners to manually interpret severity,
exploit likelihood, and regulatory exposure. While large language
models (LLMs) could bridge this gap, their propensity for hallu-
cination makes ungrounded use risky in security and compliance
contexts. This paper presents RAGScan, an open pipeline that
ingests structured vulnerability scan data (e.g., OpenSCAP XML
and network scans), normalizes findings, and enriches them with
public threat intelligence from the NVD (CVSS), FIRST EPSS,
and CISA KEV catalog. These signals are combined into a com-
posite risk score using a weighted formula to produce prioritized
remediation rankings. Enriched findings are stored in a pgvector
vector database and exposed via a LangChain-orchestrated agent
layer that supports natural-language querying and grounded ISO
27001 compliance gap analysis. All LLM-generated narratives are
strictly anchored to retrieved evidence with mandatory citations.
We evaluate RAGScan on public OpenSCAP datasets, measur-
ing retrieval precision@10, citation accuracy, hallucination rate
(versus ungrounded baselines), NIST/ISO mapping fidelity, and
correlation of the composite risk score with real-world exploit
likelihood. Results show significant reductions in unsupported
claims and meaningful alignment between the risk score and
actual exploitation probability. The full pipeline is released as
open source to enable reproducibility and community extensions.
***Keywords***: retrieval-augmented generation, vulnerability
management, large language models, EPSS, CVSS, CISA KEV,
ISO 27001, compliance automation, grounded AI
Index Terms—retrieval-augmented generation, vulnerability
analysis, LLMs, EPSS, CVSS, NIST CSF, compliance reporting
