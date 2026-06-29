"use client";

import { useEffect, useState } from "react";
import Nav from "@/components/Nav";
import AuthGuard from "@/components/AuthGuard";
import { api, AuditLogEntry } from "@/lib/api";

export default function LogsPage() {
  const [rows, setRows] = useState<AuditLogEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.auditLogs(page, pageSize)
      .then((res) => {
        setRows(res.items);
        setTotal(res.total);
      })
      .catch((e: Error) => setError(e.message));
  }, [page, pageSize]);

  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return (
    <AuthGuard>
      <Nav />
      <main className="max-w-7xl mx-auto w-full px-6 py-8">
        <h1 className="text-2xl font-semibold text-white mb-1">Activity Logs</h1>
        <p className="text-white/70 text-sm mb-6">
          Shows operation, actor, and timestamp for platform activities.
        </p>

        {error && (
          <div className="mb-4 rounded-lg border border-red-400/40 bg-red-500/20 text-white px-4 py-3 text-sm">
            {error}
          </div>
        )}

        <section className="rounded-xl border border-white/15 bg-[rgba(34,17,38,0.82)] overflow-hidden">
          <div className="px-4 py-3 border-b border-white/10 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
            <p className="text-white/80 text-xs">Total events: {total}</p>
            <div className="flex items-center gap-2 text-xs">
              <label className="text-white/70">Rows</label>
              <select
                value={pageSize}
                onChange={(e) => {
                  setPage(1);
                  setPageSize(Number(e.target.value));
                }}
                className="bg-white/10 border border-white/30 text-white rounded px-2 py-1"
              >
                <option value={10}>10</option>
                <option value={25}>25</option>
                <option value={50}>50</option>
              </select>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-white/5 text-white/75 text-xs uppercase tracking-wide">
                <tr>
                  <th className="px-4 py-3 text-left">Action</th>
                  <th className="px-4 py-3 text-left">Entity</th>
                  <th className="px-4 py-3 text-left">Performed By</th>
                  <th className="px-4 py-3 text-left">Time</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/10">
                {rows.map((r) => (
                  <tr key={r.id} className="hover:bg-white/5">
                    <td className="px-4 py-3 text-white font-medium">{r.action}</td>
                    <td className="px-4 py-3 text-white/90">{r.entity}</td>
                    <td className="px-4 py-3 text-white/85">{r.user_email ?? "system"}</td>
                    <td className="px-4 py-3 text-white/70 text-xs">{new Date(r.ts).toLocaleString()}</td>
                  </tr>
                ))}
                {rows.length === 0 && !error && (
                  <tr>
                    <td colSpan={4} className="px-4 py-8 text-center text-white/60">
                      No log entries yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          <div className="px-4 py-3 border-t border-white/10 flex items-center justify-between">
            <p className="text-white/70 text-xs">Page {page} of {totalPages}</p>
            <div className="flex gap-2">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1}
                className="px-3 py-1 text-xs rounded border border-white/30 text-white disabled:opacity-50"
              >
                Previous
              </button>
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
                className="px-3 py-1 text-xs rounded border border-white/30 text-white disabled:opacity-50"
              >
                Next
              </button>
            </div>
          </div>
        </section>
      </main>
    </AuthGuard>
  );
}
