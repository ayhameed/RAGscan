"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import Nav from "@/components/Nav";
import AuthGuard from "@/components/AuthGuard";
import { api, ScoreSummary, UploadReport } from "@/lib/api";

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
  const [reports, setReports] = useState<UploadReport[]>([]);
  const [selectedReportIds, setSelectedReportIds] = useState<string[]>([]);
  const [deletingId, setDeletingId] = useState<string>("");
  const [purging, setPurging] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [framework, setFramework] = useState<"nist_csf" | "iso27001" | "executive">("nist_csf");
  const [exporting, setExporting] = useState(false);

  async function loadReports() {
    const rows = await api.uploadReports();
    setReports(rows);
    setSelectedReportIds((prev) => prev.filter((id) => rows.some((r) => r.id === id)));
  }

  useEffect(() => {
    loadReports().catch((e: Error) => setError(e.message));
  }, []);

  useEffect(() => {
    api.score(selectedReportIds)
      .then(setData)
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
    setSelectedReportIds((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]
    );
  }

  function selectAllReports() {
    setSelectedReportIds(reports.map((r) => r.id));
  }

  function clearReportSelection() {
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

  return (
    <AuthGuard>
      <Nav />
      <main className="max-w-7xl mx-auto px-6 py-8 w-full">
        <div className="flex items-center justify-between gap-3 mb-6">
          <h2 className="text-xl font-semibold text-white">Dashboard</h2>
          <div className="flex items-center gap-2">
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
                Use All (Clear)
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
                {reports.map((r) => (
                  <tr key={r.id} className="hover:bg-gray-50">
                    <td className="px-4 py-3">
                      <input
                        type="checkbox"
                        checked={selectedReportIds.includes(r.id)}
                        onChange={() => toggleReport(r.id)}
                      />
                    </td>
                    <td className="px-4 py-3 text-gray-700">{r.filename}</td>
                    <td className="px-4 py-3 text-gray-600 text-xs">{new Date(r.uploaded_at).toLocaleString()}</td>
                    <td className="px-4 py-3 text-gray-700 uppercase text-xs">{r.source}</td>
                    <td className="px-4 py-3 text-right text-gray-700">{r.finding_count}</td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={() => deleteReport(r.id, r.filename)}
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
                    {data.findings.map((f) => (
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
            </div>
          </>
        )}
      </main>
    </AuthGuard>
  );
}
