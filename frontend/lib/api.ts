const BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

function baseVariants(base: string): string[] {
  const variants = [base];
  if (base.includes("localhost")) {
    variants.push(base.replace("localhost", "127.0.0.1"));
  } else if (base.includes("127.0.0.1")) {
    variants.push(base.replace("127.0.0.1", "localhost"));
  }
  return Array.from(new Set(variants));
}

function getToken(): string {
  if (typeof window === "undefined") return "";
  return localStorage.getItem("ragscan_token") ?? "";
}

function setCurrentUser(user: UserProfile) {
  localStorage.setItem("ragscan_user", JSON.stringify(user));
}

export function getCurrentUser(): UserProfile | null {
  if (typeof window === "undefined") return null;
  const raw = localStorage.getItem("ragscan_user");
  if (!raw) return null;
  try {
    return JSON.parse(raw) as UserProfile;
  } catch {
    return null;
  }
}

export function setToken(token: string) {
  localStorage.setItem("ragscan_token", token);
}

export function clearToken() {
  localStorage.removeItem("ragscan_token");
  localStorage.removeItem("ragscan_user");
}

function buildReportScopeQuery(reportIds?: string[]): string {
  if (!reportIds || reportIds.length === 0) return "";
  const qs = new URLSearchParams();
  for (const id of reportIds) {
    qs.append("report_ids", id);
  }
  const q = qs.toString();
  return q ? `?${q}` : "";
}

function buildMetricsScopeQuery(reportIds?: string[]): string {
  if (!reportIds || reportIds.length === 0) return "";
  const qs = new URLSearchParams();
  for (const id of reportIds) {
    qs.append("report_ids", id);
  }
  const q = qs.toString();
  return q ? `?${q}` : "";
}

async function downloadPdf(path: string, filename: string): Promise<void> {
  const token = getToken();
  let res: Response | null = null;
  for (const base of baseVariants(BASE)) {
    try {
      res = await fetch(`${base}${path}`, {
        headers: {
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
      });
      break;
    } catch {
      // try next base variant
    }
  }
  if (!res) {
    throw new Error(`Failed to fetch API at ${BASE}. Ensure backend is running and reachable.`);
  }

  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(text || `HTTP ${res.status}`);
  }

  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

async function req<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const token = getToken();
  let res: Response | null = null;
  for (const base of baseVariants(BASE)) {
    try {
      res = await fetch(`${base}${path}`, {
        ...opts,
        headers: {
          ...(opts.headers ?? {}),
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
      });
      break;
    } catch {
      // try next base variant
    }
  }
  if (!res) {
    throw new Error(`Failed to fetch API at ${BASE}. Ensure backend is running and reachable.`);
  }
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(text || `HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  login: (email: string, password: string) =>
    req<{ access_token: string }>("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    }),

  register: (email: string, password: string) =>
    req<RegisterResponse>("/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password, role: "analyst" }),
    }),

  me: async () => {
    const user = await req<UserProfile>("/auth/me");
    setCurrentUser(user);
    return user;
  },

  adminUsers: () =>
    req<AdminUserListOut>("/auth/admin/users"),

  updateAdminUser: (userId: string, patch: AdminUserUpdate) =>
    req<UserProfile>(`/auth/admin/users/${encodeURIComponent(userId)}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(patch),
    }),

  score: (reportIds?: string[]) =>
    req<ScoreSummary>(`/score${buildReportScopeQuery(reportIds)}`),

  query: (
    question: string,
    reportIds: string[] = [],
    findingIds: string[] = [],
    sessionId?: string,
    includeInternetContext = true,
  ) =>
    req<QueryResponse>("/query", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        question,
        report_ids: reportIds,
        finding_ids: findingIds,
        session_id: sessionId ?? null,
        include_internet_context: includeInternetContext,
      }),
    }),

  chatSessionHistory: (sessionId: string) =>
    req<SessionHistoryResponse>(`/query/sessions/${encodeURIComponent(sessionId)}`),

  clearChatSession: async (sessionId: string) => {
    const token = getToken();
    const res = await fetch(`${BASE}/query/sessions/${encodeURIComponent(sessionId)}`, {
      method: "DELETE",
      headers: {
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
    });
    if (!res.ok) {
      const text = await res.text().catch(() => res.statusText);
      throw new Error(text || `HTTP ${res.status}`);
    }
  },

  downloadChatSession: async (sessionId: string) =>
    downloadPdf(`/query/sessions/${encodeURIComponent(sessionId)}/download`, `ragscan_chat_${sessionId}.pdf`),

  ingest: (file: File) => {
    const fd = new FormData();
    fd.append("file", file);
    return req<IngestResponse>("/ingest", { method: "POST", body: fd });
  },

  ingestDemoData: () =>
    req<DemoIngestResponse>("/ingest/demo", { method: "POST" }),

  uploadReports: () =>
    req<UploadReport[]>("/ingest/reports"),

  deleteUploadReport: async (reportId: string) => {
    const token = getToken();
    const res = await fetch(`${BASE}/ingest/reports/${encodeURIComponent(reportId)}`, {
      method: "DELETE",
      headers: {
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
    });
    if (!res.ok) {
      const text = await res.text().catch(() => res.statusText);
      throw new Error(text || `HTTP ${res.status}`);
    }
  },

  purgeUploadReports: async () => {
    const token = getToken();
    const res = await fetch(`${BASE}/ingest/reports`, {
      method: "DELETE",
      headers: {
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
    });
    if (!res.ok) {
      const text = await res.text().catch(() => res.statusText);
      throw new Error(text || `HTTP ${res.status}`);
    }
  },

  auditLogs: (page = 1, pageSize = 25) =>
    req<AuditLogPage>(`/audit?page=${encodeURIComponent(String(page))}&page_size=${encodeURIComponent(String(pageSize))}`),

  generateComplianceReport: (framework: "nist_csf" | "iso27001" | "executive", reportIds: string[] = []) =>
    req<ReportOut>("/report", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ framework, report_ids: reportIds }),
    }),

  downloadComplianceReport: async (reportId: string, filename = `ragscan_${reportId}.pdf`) =>
    downloadPdf(`/report/${encodeURIComponent(reportId)}/download`, filename),

  downloadDeepEvalPdf: async (filename = "ragscan_deepeval_report.pdf") =>
    downloadPdf("/analyse/deepeval/download", filename),

  metricsOverview: (reportIds?: string[]) =>
    req<MetricsOverviewResponse>(`/metrics/overview${buildMetricsScopeQuery(reportIds)}`),

  metricsTrend: (reportIds?: string[], days = 14) =>
    req<MetricsTrendResponse>(`/metrics/trend${buildMetricsScopeQuery(reportIds)}${buildMetricsScopeQuery(reportIds) ? "&" : "?"}days=${encodeURIComponent(String(days))}`),
};

export interface Finding {
  id: string;
  source: string;
  cve_id: string | null;
  title: string;
  severity_label: string;
  cvss3_score: number | null;
  epss_score: number | null;
  epss_percentile: number | null;
  cisa_kev: boolean;
  risk_score: number | null;
  host_ip: string | null;
  hostname: string | null;
  port: number | null;
  ingested_at: string;
}

export interface ScoreSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  kev_count: number;
  avg_risk_score: number;
  findings: Finding[];
}

export interface QueryResponse {
  answer: string;
  sources: string[];
  intent: string;
  session_id?: string | null;
  metrics?: QueryMetrics | null;
  secondary_context?: string | null;
}

export interface QueryMetrics {
  retrieval_precision_at_10: number;
  citation_accuracy: number;
  hallucination_rate: number;
  source_count: number;
  citation_count: number;
}

export interface SessionMessage {
  role: string;
  text: string;
  ts: string;
}

export interface SessionHistoryResponse {
  session_id: string;
  history: SessionMessage[];
}

export interface IngestResponse {
  upload_id: string;
  filename: string;
  source: string;
  uploaded_at: string;
  ingested: number;
  enriched: number;
  skipped: number;
}

export interface DemoIngestItem {
  filename: string;
  source: string | null;
  status: "ingested" | "failed" | "missing";
  detail: string | null;
  upload_id: string | null;
  uploaded_at: string | null;
  ingested: number;
  enriched: number;
  skipped: number;
}

export interface DemoIngestResponse {
  items: DemoIngestItem[];
}

export interface UploadReport {
  id: string;
  user_id: string;
  user_email: string;
  filename: string;
  source: string;
  uploaded_at: string;
  finding_count: number;
}

export interface ReportOut {
  id: string;
  report_type: string;
  path: string;
  created_at: string;
}

export interface AuditLogEntry {
  id: string;
  user_id: string | null;
  user_email: string | null;
  action: string;
  entity: string;
  ts: string;
}

export interface AuditLogPage {
  items: AuditLogEntry[];
  total: number;
  page: number;
  page_size: number;
}

export interface MetricsOverview {
  scope_key: string;
  total_queries: number;
  avg_retrieval_precision_at_10: number;
  avg_citation_accuracy: number;
  avg_hallucination_rate: number;
}

export type MetricsOverviewResponse = MetricsOverview;

export interface MetricsTrendPoint {
  day: string;
  queries: number;
  avg_retrieval_precision_at_10: number;
  avg_citation_accuracy: number;
  avg_hallucination_rate: number;
}

export interface MetricsTrendResponse {
  scope_key: string;
  days: number;
  total_queries: number;
  avg_retrieval_precision_at_10: number;
  avg_citation_accuracy: number;
  avg_hallucination_rate: number;
  points: MetricsTrendPoint[];
}

export interface RegisterResponse {
  status: "pending_approval" | "approved";
  message: string;
}

export interface UserProfile {
  id: string;
  email: string;
  role: string;
  is_admin: boolean;
  is_approved: boolean;
  is_blocked: boolean;
  created_at: string;
  approved_at: string | null;
  blocked_at: string | null;
}

export interface AdminUserUpdate {
  is_admin?: boolean;
  is_approved?: boolean;
  is_blocked?: boolean;
}

export interface AdminUserListOut {
  items: UserProfile[];
  total: number;
}
