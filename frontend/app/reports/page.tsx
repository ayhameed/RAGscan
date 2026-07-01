"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import Nav from "@/components/Nav";
import AuthGuard from "@/components/AuthGuard";
import { api, Finding, ScoreSummary, UploadReport } from "@/lib/api";

const TOP_5_PROMPT = "What are the top 5 highest-risk vulnerabilities?";

function SeverityPill({ value }: { value: string }) {
  const s = value.toLowerCase();
  const cls =
    s === "critical"
      ? "bg-red-500/25 text-white"
      : s === "high"
      ? "bg-orange-500/25 text-white"
      : s === "medium"
      ? "bg-yellow-500/25 text-white"
      : s === "low"
      ? "bg-green-500/25 text-white"
      : "bg-white/15 text-white";
  return <span className={`px-2 py-0.5 rounded text-xs font-medium ${cls}`}>{value}</span>;
}

function ScoreCard({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-lg border border-white/15 bg-white/10 px-3 py-2">
      <p className="text-[11px] text-white/70 uppercase tracking-wide">{label}</p>
      <p className="text-white font-semibold text-base">{value}</p>
    </div>
  );
}

export default function ReportsPage() {
  const router = useRouter();
  const [reports, setReports] = useState<UploadReport[]>([]);
  const [selectedReportId, setSelectedReportId] = useState<string>("");
  const [summary, setSummary] = useState<ScoreSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [deletingId, setDeletingId] = useState<string>("");
  const [purging, setPurging] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function refreshReports(nextSelectedId?: string) {
    const rows = await api.uploadReports();
    setReports(rows);
    const initial = nextSelectedId ?? rows[0]?.id ?? "";
    setSelectedReportId(initial);
    const s = await api.score(initial ? [initial] : []);
    setSummary(s);
  }

  useEffect(() => {
    setLoading(true);
    refreshReports()
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (!selectedReportId) {
      api.score([]).then(setSummary).catch((e: Error) => setError(e.message));
      return;
    }
    api.score([selectedReportId]).then(setSummary).catch((e: Error) => setError(e.message));
  }, [selectedReportId]);

  async function deleteReport(reportId: string, filename: string) {
    const ok = window.confirm(`Delete report ${filename}? This removes associated findings for this upload.`);
    if (!ok) return;
    setError(null);
    setDeletingId(reportId);
    try {
      await api.deleteUploadReport(reportId);
      const next = selectedReportId === reportId ? "" : selectedReportId;
      await refreshReports(next || undefined);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Delete failed");
    } finally {
      setDeletingId("");
    }
  }

  async function purgeAllReports() {
    const ok = window.confirm("Purge ALL uploaded reports and findings for your account?");
    if (!ok) return;
    setError(null);
    setPurging(true);
    try {
      await api.purgeUploadReports();
      await refreshReports("");
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Purge failed");
    } finally {
      setPurging(false);
    }
  }

  const findings: Finding[] = useMemo(() => {
    if (!summary) return [];
    return [...summary.findings].sort((a, b) => (b.risk_score ?? -1) - (a.risk_score ?? -1));
  }, [summary]);

  function openChatWithTop5() {
    const qs = new URLSearchParams();
    if (selectedReportId) qs.set("report_ids", selectedReportId);
    qs.set("prompt", TOP_5_PROMPT);
    router.push(`/chat?${qs.toString()}`);
  }

  function openChatWithReport() {
    const qs = new URLSearchParams();
    if (selectedReportId) qs.set("report_ids", selectedReportId);
    router.push(`/chat?${qs.toString()}`);
  }

  return (
    <AuthGuard>
      <Nav />
      <main className="max-w-7xl mx-auto w-full px-6 py-8">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6">
          <div>
            <h1 className="text-2xl font-semibold text-white">Reports</h1>
            <p className="text-white/70 text-sm mt-1">Select a report, inspect findings, then continue to chat.</p>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => refreshReports(selectedReportId || undefined).catch((e: Error) => setError(e.message))}
              className="px-4 py-2 rounded-lg border border-white/30 text-white hover:bg-white/10 text-sm"
            >
              Refresh
            </button>
            <button
              onClick={purgeAllReports}
              disabled={purging}
              className="px-4 py-2 rounded-lg border border-red-300/60 text-white hover:bg-red-500/25 text-sm disabled:opacity-50"
            >
              {purging ? "Purging..." : "Purge All"}
            </button>
            <button
              onClick={openChatWithReport}
              className="px-4 py-2 rounded-lg border border-white/30 text-white hover:bg-white/10 text-sm"
            >
              Open in Chat
            </button>
            <button
              onClick={openChatWithTop5}
              className="px-4 py-2 rounded-lg bg-[#cb156d] hover:bg-[#aa125c] text-white text-sm font-medium"
            >
              Ask Top 5 Risks
            </button>
          </div>
        </div>

        {error && (
          <div className="mb-4 rounded-lg border border-red-400/40 bg-red-500/20 text-white px-4 py-3 text-sm">
            {error}
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-[360px_1fr] gap-6">
          <section className="rounded-xl border border-white/15 bg-[rgba(34,17,38,0.8)] p-4">
            <h2 className="text-white font-medium mb-3">Uploaded Reports</h2>
            <div className="space-y-2 max-h-135 overflow-y-auto pr-1">
              <div
                onClick={() => setSelectedReportId("")}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    setSelectedReportId("");
                  }
                }}
                className={`w-full text-left rounded-lg border px-3 py-3 transition-colors cursor-pointer ${
                  selectedReportId === ""
                    ? "border-[#cb156d] bg-[#cb156d]/15"
                    : "border-white/10 bg-white/5 hover:bg-white/10"
                }`}
              >
                <p className="text-white text-sm font-medium">All Uploaded Reports</p>
                <p className="text-white/70 text-xs mt-1">Aggregate view across multiple uploaded reports</p>
              </div>

              {reports.map((r) => (
                <div
                  key={r.id}
                  onClick={() => setSelectedReportId(r.id)}
                  role="button"
                  tabIndex={0}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      setSelectedReportId(r.id);
                    }
                  }}
                  className={`w-full text-left rounded-lg border px-3 py-3 transition-colors cursor-pointer ${
                    selectedReportId === r.id
                      ? "border-[#cb156d] bg-[#cb156d]/15"
                      : "border-white/10 bg-white/5 hover:bg-white/10"
                  }`}
                >
                  <p className="text-white text-sm font-medium truncate">{r.filename}</p>
                  <p className="text-white/65 text-xs mt-1">{new Date(r.uploaded_at).toLocaleString()}</p>
                  <p className="text-white/80 text-xs mt-0.5">{r.user_email}</p>
                  <p className="text-white/75 text-xs mt-1">Findings: {r.finding_count}</p>
                  <div className="mt-2 flex justify-end">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        deleteReport(r.id, r.filename);
                      }}
                      disabled={deletingId === r.id}
                      className="text-xs px-2 py-1 rounded border border-red-300/50 text-white hover:bg-red-500/25 disabled:opacity-50"
                    >
                      {deletingId === r.id ? "Deleting..." : "Delete"}
                    </button>
                  </div>
                </div>
              ))}
              {reports.length === 0 && !loading && (
                <div className="rounded-lg border border-white/10 bg-white/5 p-3">
                  <p className="text-white/90 text-sm font-medium">No reports yet.</p>
                  <p className="text-white/70 text-xs mt-1">Upload from Import page, then click Refresh here.</p>
                </div>
              )}
            </div>
          </section>

          <section className="rounded-xl border border-white/15 bg-[rgba(34,17,38,0.8)] overflow-hidden">
            <div className="px-4 py-3 border-b border-white/10 flex items-center justify-between">
              <h2 className="text-white font-medium">Results</h2>
              {summary && <span className="text-white/70 text-xs">{summary.total} findings</span>}
            </div>

            {summary && (
              <div className="px-4 py-3 border-b border-white/10 grid grid-cols-3 md:grid-cols-7 gap-2">
                <ScoreCard label="Total" value={summary.total} />
                <ScoreCard label="Critical" value={summary.critical} />
                <ScoreCard label="High" value={summary.high} />
                <ScoreCard label="Medium" value={summary.medium} />
                <ScoreCard label="Low" value={summary.low} />
                <ScoreCard label="KEV" value={summary.kev_count} />
                <ScoreCard label="Avg Risk" value={summary.avg_risk_score.toFixed(1)} />
              </div>
            )}

            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-white/5 text-white/75 text-xs uppercase tracking-wide">
                  <tr>
                    <th className="px-4 py-3 text-left">CVE</th>
                    <th className="px-4 py-3 text-left">Title</th>
                    <th className="px-4 py-3 text-left">Severity</th>
                    <th className="px-4 py-3 text-right">Risk</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/10">
                  {findings.map((f) => (
                    <tr key={f.id} className="hover:bg-white/5">
                      <td className="px-4 py-3 text-xs font-mono text-white/90">{f.cve_id ?? "NO-CVE"}</td>
                      <td className="px-4 py-3 text-white/90 max-w-90 truncate" title={f.title}>
                        {f.title}
                      </td>
                      <td className="px-4 py-3">
                        <SeverityPill value={f.severity_label} />
                      </td>
                      <td className="px-4 py-3 text-right text-white font-semibold">
                        {f.risk_score != null ? f.risk_score.toFixed(1) : "-"}
                      </td>
                    </tr>
                  ))}
                  {findings.length === 0 && !loading && (
                    <tr>
                      <td colSpan={4} className="px-4 py-8 text-center text-white/60">
                        No results for selected report.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </div>
      </main>
    </AuthGuard>
  );
}
