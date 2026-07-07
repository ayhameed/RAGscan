import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field


class FindingCreate(BaseModel):
    source: str
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    plugin_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    solution: Optional[str] = None
    severity_label: str
    host_ip: Optional[str] = None
    hostname: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    raw_data: Optional[dict] = None


class FindingOut(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    source: str
    cve_id: Optional[str]
    title: str
    severity_label: str
    cvss3_score: Optional[float]
    epss_score: Optional[float]
    epss_percentile: Optional[float]
    cisa_kev: bool
    risk_score: Optional[float]
    host_ip: Optional[str]
    hostname: Optional[str]
    port: Optional[int]
    ingested_at: datetime


class IngestResponse(BaseModel):
    upload_id: uuid.UUID
    filename: str
    source: str
    uploaded_at: datetime
    ingested: int
    enriched: int
    skipped: int


class QueryRequest(BaseModel):
    question: str
    session_id: Optional[uuid.UUID] = None
    report_id: Optional[uuid.UUID] = None
    report_ids: list[uuid.UUID] = Field(default_factory=list)
    finding_ids: list[uuid.UUID] = Field(default_factory=list)
    include_internet_context: bool = True


class QueryMetricsOut(BaseModel):
    retrieval_precision_at_10: float
    citation_accuracy: float
    hallucination_rate: float
    source_count: int
    citation_count: int


class QueryResponse(BaseModel):
    answer: str
    sources: list[str]
    intent: str
    session_id: Optional[uuid.UUID] = None
    metrics: Optional[QueryMetricsOut] = None
    secondary_context: Optional[str] = None


class SessionMessage(BaseModel):
    role: str
    text: str
    ts: datetime


class SessionHistoryResponse(BaseModel):
    session_id: uuid.UUID
    history: list[SessionMessage]


class ReportRequest(BaseModel):
    framework: str = "nist_csf"  # nist_csf | iso27001 | executive
    report_id: Optional[uuid.UUID] = None
    report_ids: list[uuid.UUID] = Field(default_factory=list)


class ReportOut(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    report_type: str
    path: str
    created_at: datetime


class UserRegister(BaseModel):
    email: EmailStr
    password: str
    role: str = "analyst"


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class RegisterResponse(BaseModel):
    status: str
    message: str


class UserProfileOut(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    email: EmailStr
    role: str
    is_admin: bool
    is_approved: bool
    is_blocked: bool
    created_at: datetime
    approved_at: Optional[datetime]
    blocked_at: Optional[datetime]


class AdminUserUpdate(BaseModel):
    is_admin: Optional[bool] = None
    is_approved: Optional[bool] = None
    is_blocked: Optional[bool] = None


class AdminUserListOut(BaseModel):
    items: list[UserProfileOut]
    total: int


class ScoreSummary(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    kev_count: int
    avg_risk_score: float
    findings: list[FindingOut]


class ScanUploadOut(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    user_id: uuid.UUID
    filename: str
    source: str
    uploaded_at: datetime
    finding_count: int
    user_email: str


class ComplianceGapOut(BaseModel):
    control_id: str
    framework: str
    gap_level: str
    finding_ids: list[str]


class AuditLogOut(BaseModel):
    id: uuid.UUID
    user_id: Optional[uuid.UUID]
    user_email: Optional[str]
    action: str
    entity: str
    ts: datetime


class AuditLogPageOut(BaseModel):
    items: list[AuditLogOut]
    total: int
    page: int
    page_size: int


class MetricsOverviewOut(BaseModel):
    scope_key: str
    total_queries: int
    avg_retrieval_precision_at_10: float
    avg_citation_accuracy: float
    avg_hallucination_rate: float


class MetricsTrendPointOut(BaseModel):
    day: str
    queries: int
    avg_retrieval_precision_at_10: float
    avg_citation_accuracy: float
    avg_hallucination_rate: float


class MetricsTrendOut(BaseModel):
    scope_key: str
    days: int
    total_queries: int
    avg_retrieval_precision_at_10: float
    avg_citation_accuracy: float
    avg_hallucination_rate: float
    points: list[MetricsTrendPointOut]
