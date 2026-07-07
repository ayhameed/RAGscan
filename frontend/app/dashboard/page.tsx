"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import Nav from "@/components/Nav";
import AuthGuard from "@/components/AuthGuard";
import LlmProviderStatus from "@/components/LlmProviderStatus";
import { api, ScoreSummary, UploadReport, MetricsTrendResponse } from "@/lib/api";

function StatCard({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <div className="bg-white rounded-xl border border-gray-200 p-5">
      <p className="text-sm text-gray-500 mb-1">{label}</p>
      <p className="text-3xl font-bold text-gray-900">{value}</p>
      {sub && <p className="text-xs text-gray-400 mt-1">{sub}</p>}
    </div>
  );
}

export default function DashboardPage() {
  const router = useRouter();
  const [data, setData] = useState<ScoreSummary | null>(null);
  const [metrics, setMetrics] = useState<{ total_queries: number; avg_retrieval_precision_at_10: number; avg_citation_accuracy: number; avg_hallucination_rate: number } | null>(null);
  const [trend, setTrend] = useState<MetricsTrendResponse | null>(null);
  const [reports, setReports] = useState<UploadReport[]>([]);
  const [selectedReportIds, setSelectedReportIds] = useState<string[]>([]);
  const [deletingId, setDeletingId] = useState<string>("");
  const [purging, setPurging] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [framework, setFramework] = useState<"nist_csf" | "iso27001" | "executive">("nist_csf");
  const [exporting, setExporting] = useState(false);
  const [exportingDeepEval, setExportingDeepEval] = useState(false);
  const [uploadsPage, setUploadsPage] = useState(1);
  const [trendPage, setTrendPage] = useState(1);
  const [detectionsPage, setDetectionsPage] = useState(1);

  const pageSize = 10;
  const uploadTotalPages = Math.max(1, Math.ceil(reports.length / pageSize));
  const pagedReports = reports.slice((uploadsPage - 1) * pageSize, uploadsPage * pageSize);
  const trendPoints = (trend?.points ?? []).slice().reverse();
  const trendTotalPages = Math.max(1, Math.ceil(trendPoints.length / pageSize));
  const pagedTrend = trendPoints.slice((trendPage - 1) * pageSize, trendPage * pageSize);
  const detections = data?.findings ?? [];
  const detectionsTotalPages = Math.max(1, Math.ceil(detections.length / pageSize));
  const pagedDetections = detections.slice((detectionsPage - 1) * pageSize, detectionsPage * pageSize);

  async function loadReports() {
    const rows = await api.uploadReports();
    setReports(rows);
    setSelectedReportIds((prev) => prev.filter((id) => rows.some((r) => r.id === id)));
  }

  useEffect(() => {
    let cancelled = false;
    const run = async () => {
      try {
        const rows = await api.uploadReports();
        if (!cancelled) {
          setReports(rows);
          setSelectedReportIds((prev) => prev.filter((id) => rows.some((r) => r.id === id)));
        }
      } catch (e: unknown) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : "Failed to load reports");
        }
      }
    };

    void run();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    api.score(selectedReportIds)
      .then(setData)
      .catch((e: Error) => setError(e.message));
    api.metricsOverview(selectedReportIds)
      .then((rows) => {
        setMetrics(rows);
      })
      .catch((e: Error) => setError(e.message));
    api.metricsTrend(selectedReportIds, 14)
      .then(setTrend)
      .catch((e: Error) => setError(e.message));
  }, [selectedReportIds]);

  async function deleteReport(reportId: string, filename: string) {
    const ok = window.confirm(`Delete report ${filename}? This removes associated findings for this upload.`);
    if (!ok) return;
    setError(null);
    setDeletingId(reportId);
    try {
      await api.deleteUploadReport(reportId);
      await loadReports();
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
      await loadReports();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Purge failed");
    } finally {
      setPurging(false);
    }
  }

  function toggleReport(id: string) {
    setDetectionsPage(1);
    setTrendPage(1);
    setSelectedReportIds((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]
    );
  }

  function selectAllReports() {
    setDetectionsPage(1);
    setTrendPage(1);
    setSelectedReportIds(reports.map((r) => r.id));
  }

  function clearReportSelection() {
    setDetectionsPage(1);
    setTrendPage(1);
    setSelectedReportIds([]);
  }

  function openChat() {
    const qs = new URLSearchParams();
    if (selectedReportIds.length) {
      qs.set("report_ids", selectedReportIds.join(","));
    }
    router.push(`/chat?${qs.toString()}`);
  }

  async function exportCompliancePdf() {
    setError(null);
    setExporting(true);
    try {
      const report = await api.generateComplianceReport(framework, selectedReportIds);
      const suffix = selectedReportIds.length ? "selected-files" : "all-files";
      const filename = `ragscan_${framework}_${suffix}.pdf`;
      await api.downloadComplianceReport(report.id, filename);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Export failed");
    } finally {
      setExporting(false);
    }
  }

  async function exportDeepEvalPdf() {
    setError(null);
    setExportingDeepEval(true);
    try {
      await api.downloadDeepEvalPdf();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "DeepEval export failed");
    } finally {
      setExportingDeepEval(false);
    }
  }

  return (
    <AuthGuard>
      <Nav />
      <main className="max-w-7xl mx-auto px-6 py-8 w-full">
        <div className="flex items-center justify-between gap-3 mb-6">
          <h2 className="text-xl font-semibold text-white">Dashboard</h2>
          <div className="flex items-center gap-2">
            <LlmProviderStatus />
            <Link
              href="/guide"
              className="border border-[#cb156d] text-[#cb156d] hover:bg-[#cb156d]/10 text-sm font-medium px-4 py-2 rounded-lg transition-colors"
            >
              Score Guide
            </Link>
            <Link
              href="/reports"
              className="bg-[#cb156d] hover:bg-[#aa125c] text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors"
            >
              Open Reports Workspace
            </Link>
          </div>
        </div>

        {error && (
          <div className="bg-red-50 border border-red-200 text-red-700 rounded-lg px-4 py-3 mb-6 text-sm">
            {error}
          </div>
        )}

        <div className="bg-white rounded-xl border border-gray-200 overflow-hidden mb-6">
          <div className="px-5 py-3 border-b border-gray-100 flex items-center justify-between">
            <h3 className="font-medium text-gray-700">Uploaded Files</h3>
            <div className="flex gap-2">
              <button
                onClick={selectAllReports}
                className="px-3 py-1.5 rounded border border-gray-300 text-gray-700 text-xs"
              >
                Select All
              </button>
              <button
                onClick={clearReportSelection}
                className="px-3 py-1.5 rounded border border-gray-300 text-gray-700 text-xs"
              >
                All Files
              </button>
              <button
                onClick={() => loadReports().catch((e: Error) => setError(e.message))}
                className="px-3 py-1.5 rounded border border-gray-300 text-gray-700 text-xs"
              >
                Refresh
              </button>
              <button
                onClick={purgeAllReports}
                disabled={purging}
                className="px-3 py-1.5 rounded border border-red-300 text-red-700 text-xs disabled:opacity-50"
              >
                {purging ? "Purging..." : "Purge All"}
              </button>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-gray-50 text-gray-600 text-xs uppercase tracking-wide">
                <tr>
                  <th className="px-4 py-3 text-left">Use</th>
                  <th className="px-4 py-3 text-left">File</th>
                  <th className="px-4 py-3 text-left">Date</th>
                  <th className="px-4 py-3 text-left">Tool</th>
                  <th className="px-4 py-3 text-right">Findings</th>
                  <th className="px-4 py-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {pagedReports.map((r) => (
                  <tr
                    key={r.id}
                    onClick={() => toggleReport(r.id)}
                    role="button"
                    tabIndex={0}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        toggleReport(r.id);
                      }
                    }}
                    className={`cursor-pointer hover:bg-gray-50 ${selectedReportIds.includes(r.id) ? "bg-gray-50" : ""}`}
                  >
                    <td className="px-4 py-3">
                      <input
                        type="checkbox"
                        checked={selectedReportIds.includes(r.id)}
                        onChange={() => toggleReport(r.id)}
                        onClick={(e) => e.stopPropagation()}
                      />
                    </td>
                    <td className="px-4 py-3 text-gray-700">{r.filename}</td>
                    <td className="px-4 py-3 text-gray-600 text-xs">{new Date(r.uploaded_at).toLocaleString()}</td>
                    <td className="px-4 py-3 text-gray-700 uppercase text-xs">{r.source}</td>
                    <td className="px-4 py-3 text-right text-gray-700">{r.finding_count}</td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={() => deleteReport(r.id, r.filename)}
                        onMouseDown={(e) => e.stopPropagation()}
                        onKeyDown={(e) => e.stopPropagation()}
                        disabled={deletingId === r.id}
                        className="text-xs px-2 py-1 rounded border border-red-300 text-red-700 disabled:opacity-50"
                      >
                        {deletingId === r.id ? "Deleting..." : "Delete"}
                      </button>
                    </td>
                  </tr>
                ))}
                {reports.length === 0 && (
                  <tr>
                    <td colSpan={6} className="px-4 py-6 text-center text-gray-500">
                      No uploads yet. Upload files from Import page.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          {reports.length > 0 && (
            <div className="px-4 py-3 border-t border-gray-100 flex items-center justify-between">
              <p className="text-gray-500 text-xs">Page {uploadsPage} of {uploadTotalPages}</p>
              <div className="flex gap-2">
                <button
                  onClick={() => setUploadsPage((p) => Math.max(1, p - 1))}
                  disabled={uploadsPage <= 1}
                  className="px-3 py-1 text-xs rounded border border-gray-300 text-gray-700 disabled:opacity-50"
                >
                  Previous
                </button>
                <button
                  onClick={() => setUploadsPage((p) => Math.min(uploadTotalPages, p + 1))}
                  disabled={uploadsPage >= uploadTotalPages}
                  className="px-3 py-1 text-xs rounded border border-gray-300 text-gray-700 disabled:opacity-50"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </div>

        {data && (
          <>
            <div className="mb-4 flex items-center justify-between">
              <p className="text-white text-sm">
                Scope: {selectedReportIds.length > 0 ? `${selectedReportIds.length} selected file(s)` : "All uploaded files"}
              </p>
              <button
                onClick={openChat}
                className="bg-[#cb156d] hover:bg-[#aa125c] text-white text-sm font-medium px-4 py-2 rounded-lg"
              >
                Open Chat With Selection
              </button>
            </div>
            <p className="mb-4 text-xs text-white/60">
              The summary cards, detections table, chat handoff, and compliance export all follow the current file scope. Clear the selection to use all uploaded files.
            </p>

            <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-4 mb-8">
              <StatCard label="Total" value={data.total} />
              <StatCard label="Critical" value={data.critical} />
              <StatCard label="High" value={data.high} />
              <StatCard label="Medium" value={data.medium} />
              <StatCard label="Low" value={data.low} />
              <StatCard label="KEV" value={data.kev_count} sub="CISA known-exploited" />
              <StatCard label="Avg Risk" value={data.avg_risk_score.toFixed(1)} sub="out of 100" />
            </div>

            <div className="bg-white rounded-xl border border-gray-200 p-5 mb-6">
              <div className="flex items-center justify-between gap-3 mb-3">
                <div>
                  <h3 className="font-medium text-gray-800">Grounding Metrics</h3>
                  <p className="text-xs text-gray-500 mt-1">
                    Live query metrics for the current file scope. Clear selection to view all uploaded files.
                  </p>
                </div>
                {metrics && (
                  <span className="text-xs text-gray-500">
                    {metrics.total_queries} query{metrics.total_queries === 1 ? "" : "ies"}
                  </span>
                )}
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <StatCard
                  label="Evidence Precision@10"
                  value={metrics ? metrics.avg_retrieval_precision_at_10.toFixed(3) : "0.000"}
                  sub="Retrieved sources used in answers"
                />
                <StatCard
                  label="Citation Accuracy"
                  value={metrics ? metrics.avg_citation_accuracy.toFixed(3) : "0.000"}
                  sub="Cited finding IDs matching sources"
                />
                <StatCard
                  label="Hallucination Rate"
                  value={metrics ? metrics.avg_hallucination_rate.toFixed(3) : "0.000"}
                  sub="Unsupported sentences / total sentences"
                />
              </div>
            </div>

            <div className="bg-white rounded-xl border border-gray-200 p-5 mb-6">
              <div className="flex items-center justify-between gap-3 mb-3">
                <div>
                  <h3 className="font-medium text-gray-800">Summary Over Time</h3>
                  <p className="text-xs text-gray-500 mt-1">Daily averages for the last 14 days in the current scope.</p>
                </div>
                <span className="text-xs text-gray-500">
                  {trend ? `${trend.total_queries} total query${trend.total_queries === 1 ? "" : "ies"}` : "0 total queries"}
                </span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="bg-gray-50 text-gray-600 text-xs uppercase tracking-wide">
                    <tr>
                      <th className="px-4 py-3 text-left">Day</th>
                      <th className="px-4 py-3 text-right">Queries</th>
                      <th className="px-4 py-3 text-right">P@10</th>
                      <th className="px-4 py-3 text-right">Citation</th>
                      <th className="px-4 py-3 text-right">Hallucination</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {pagedTrend.map((point) => (
                      <tr key={point.day} className="hover:bg-gray-50">
                        <td className="px-4 py-3 text-gray-700">{point.day}</td>
                        <td className="px-4 py-3 text-right text-gray-700">{point.queries}</td>
                        <td className="px-4 py-3 text-right text-gray-700">{point.avg_retrieval_precision_at_10.toFixed(3)}</td>
                        <td className="px-4 py-3 text-right text-gray-700">{point.avg_citation_accuracy.toFixed(3)}</td>
                        <td className="px-4 py-3 text-right text-gray-700">{point.avg_hallucination_rate.toFixed(3)}</td>
                      </tr>
                    ))}
                    {(trend?.points.length ?? 0) === 0 && (
                      <tr>
                        <td colSpan={5} className="px-4 py-6 text-center text-gray-500">
                          No query metrics yet for this scope.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
              {trendPoints.length > 0 && (
                <div className="px-4 py-3 border-t border-gray-100 flex items-center justify-between">
                  <p className="text-gray-500 text-xs">Page {trendPage} of {trendTotalPages}</p>
                  <div className="flex gap-2">
                    <button
                      onClick={() => setTrendPage((p) => Math.max(1, p - 1))}
                      disabled={trendPage <= 1}
                      className="px-3 py-1 text-xs rounded border border-gray-300 text-gray-700 disabled:opacity-50"
                    >
                      Previous
                    </button>
                    <button
                      onClick={() => setTrendPage((p) => Math.min(trendTotalPages, p + 1))}
                      disabled={trendPage >= trendTotalPages}
                      className="px-3 py-1 text-xs rounded border border-gray-300 text-gray-700 disabled:opacity-50"
                    >
                      Next
                    </button>
                  </div>
                </div>
              )}
            </div>

            <div className="bg-white rounded-xl border border-gray-200 p-5 mb-6">
              <div className="flex flex-col md:flex-row md:items-end gap-3 md:justify-between">
                <div>
                  <h3 className="font-medium text-gray-800">Compliance PDF Export</h3>
                  <p className="text-xs text-gray-500 mt-1">
                    Export a framework-aligned compliance report for one or more selected files.
                  </p>
                </div>
                <div className="flex flex-col sm:flex-row gap-2 sm:items-center">
                  <select
                    value={framework}
                    onChange={(e) => setFramework(e.target.value as "nist_csf" | "iso27001" | "executive")}
                    className="bg-white border border-gray-300 rounded-lg px-3 py-2 text-sm text-gray-700"
                  >
                    <option value="nist_csf">NIST CSF</option>
                    <option value="iso27001">ISO 27001</option>
                    <option value="executive">Executive</option>
                  </select>
                  <button
                    onClick={exportCompliancePdf}
                    disabled={exporting}
                    className="bg-[#580d60] hover:bg-[#4a0a51] text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors disabled:opacity-50"
                  >
                    {exporting ? "Generating..." : "Export PDF"}
                  </button>
                  <button
                    onClick={exportDeepEvalPdf}
                    disabled={exportingDeepEval}
                    className="border border-[#580d60] text-[#580d60] hover:bg-[#580d60]/10 text-sm font-medium px-4 py-2 rounded-lg transition-colors disabled:opacity-50"
                  >
                    {exportingDeepEval ? "Generating DeepEval..." : "Download DeepEval PDF"}
                  </button>
                </div>
              </div>
            </div>

            <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
              <div className="px-5 py-3 border-b border-gray-100">
                <h3 className="font-medium text-gray-700">Detections Summary</h3>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="bg-gray-50 text-gray-600 text-xs uppercase tracking-wide">
                    <tr>
                      <th className="px-4 py-3 text-left">CVE</th>
                      <th className="px-4 py-3 text-left">Title</th>
                      <th className="px-4 py-3 text-left">Severity</th>
                      <th className="px-4 py-3 text-right">Risk</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {pagedDetections.map((f) => (
                      <tr key={f.id} className="hover:bg-gray-50">
                        <td className="px-4 py-3 font-mono text-xs text-indigo-700">{f.cve_id ?? "NO-CVE"}</td>
                        <td className="px-4 py-3 text-gray-700 max-w-130 truncate" title={f.title}>{f.title}</td>
                        <td className="px-4 py-3 text-gray-700 uppercase text-xs">{f.severity_label}</td>
                        <td className="px-4 py-3 text-right text-gray-900 font-semibold">
                          {f.risk_score != null ? f.risk_score.toFixed(1) : "-"}
                        </td>
                      </tr>
                    ))}
                    {data.findings.length === 0 && (
                      <tr>
                        <td colSpan={4} className="px-4 py-8 text-center text-gray-500">
                          No detections for current selection.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
              {detections.length > 0 && (
                <div className="px-4 py-3 border-t border-gray-100 flex items-center justify-between">
                  <p className="text-gray-500 text-xs">Page {detectionsPage} of {detectionsTotalPages}</p>
                  <div className="flex gap-2">
                    <button
                      onClick={() => setDetectionsPage((p) => Math.max(1, p - 1))}
                      disabled={detectionsPage <= 1}
                      className="px-3 py-1 text-xs rounded border border-gray-300 text-gray-700 disabled:opacity-50"
                    >
                      Previous
                    </button>
                    <button
                      onClick={() => setDetectionsPage((p) => Math.min(detectionsTotalPages, p + 1))}
                      disabled={detectionsPage >= detectionsTotalPages}
                      className="px-3 py-1 text-xs rounded border border-gray-300 text-gray-700 disabled:opacity-50"
                    >
                      Next
                    </button>
                  </div>
                </div>
              )}
            </div>
          </>
        )}
      </main>
    </AuthGuard>
  );
}
