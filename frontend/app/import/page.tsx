"use client";
import { useEffect, useState, useRef, DragEvent, ChangeEvent } from "react";
import Nav from "@/components/Nav";
import AuthGuard from "@/components/AuthGuard";
import { api, DemoIngestItem, IngestResponse, UploadReport } from "@/lib/api";

export default function ImportPage() {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<IngestResponse | null>(null);
  const [demoResults, setDemoResults] = useState<DemoIngestItem[]>([]);
  const [demoLoading, setDemoLoading] = useState(false);
  const [uploads, setUploads] = useState<UploadReport[]>([]);
  const [page, setPage] = useState(1);
  const [error, setError] = useState<string | null>(null);

  const pageSize = 10;
  const totalPages = Math.max(1, Math.ceil(uploads.length / pageSize));
  const pagedUploads = uploads.slice((page - 1) * pageSize, page * pageSize);

  useEffect(() => {
    api.uploadReports().then(setUploads).catch(() => {});
  }, []);

  function pickFile(f: File) {
    setFile(f);
    setResult(null);
    setError(null);
  }

  function onDrop(e: DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setDragging(false);
    const f = e.dataTransfer.files[0];
    if (f) pickFile(f);
  }

  function onFileChange(e: ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0];
    if (f) pickFile(f);
  }

  async function upload() {
    if (!file) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await api.ingest(file);
      setResult(res);
      const reports = await api.uploadReports();
      setUploads(reports);
      setPage(1);
      setDemoResults([]);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Upload failed");
    } finally {
      setLoading(false);
    }
  }

  async function loadDemoData() {
    setDemoLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await api.ingestDemoData();
      setDemoResults(res.items);
      const reports = await api.uploadReports();
      setUploads(reports);
      setPage(1);
      const successful = res.items.find((item) => item.status === "ingested");
      if (successful) {
        setFile(null);
        if (inputRef.current) inputRef.current.value = "";
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Demo load failed");
    } finally {
      setDemoLoading(false);
    }
  }

  function reset() {
    setFile(null);
    setResult(null);
    setError(null);
    if (inputRef.current) inputRef.current.value = "";
  }

  return (
    <AuthGuard>
      <Nav />
      <main className="max-w-2xl mx-auto px-6 py-10 w-full">
        <h2 className="text-xl font-semibold text-gray-800 mb-2">Import Scan</h2>
        <p className="text-sm text-gray-500 mb-8">
          Upload an OpenSCAP XCCDF XML or Nessus <code>.nessus</code> file. Findings are parsed,
          enriched via NVD / EPSS / CISA KEV, scored, and indexed for RAG queries.
        </p>

        <div
          onDrop={onDrop}
          onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onClick={() => !file && inputRef.current?.click()}
          className={`border-2 border-dashed rounded-xl p-10 text-center transition-colors cursor-pointer ${
            dragging
              ? "border-indigo-400 bg-indigo-50"
              : file
              ? "border-green-400 bg-green-50 cursor-default"
              : "border-gray-300 hover:border-indigo-300 bg-white"
          }`}
        >
          <input
            ref={inputRef}
            type="file"
            accept=".xml,.nessus"
            className="hidden"
            onChange={onFileChange}
          />

          {file ? (
            <div className="flex flex-col items-center gap-2">
              <div className="text-green-600 text-4xl">&#10003;</div>
              <p className="font-medium text-gray-800">{file.name}</p>
              <p className="text-xs text-gray-500">{(file.size / 1024).toFixed(1)} KB</p>
              <button
                onClick={(e) => { e.stopPropagation(); reset(); }}
                className="mt-2 text-xs text-gray-400 hover:text-red-500 underline"
              >
                Remove
              </button>
            </div>
          ) : (
            <div className="flex flex-col items-center gap-2 text-gray-500">
              <svg className="w-10 h-10 text-gray-300" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
                  d="M12 16v-8m0 0-3 3m3-3 3 3M20 16.5A4.5 4.5 0 0 0 15.5 12H14a6 6 0 1 0-6 6h7.5a3 3 0 0 0 3-3z" />
              </svg>
              <p className="font-medium">Drop file here or click to browse</p>
              <p className="text-xs">Accepts <code>.xml</code> (OpenSCAP XCCDF) or <code>.nessus</code></p>
            </div>
          )}
        </div>

        <button
          onClick={upload}
          disabled={!file || loading}
          className="mt-5 w-full bg-indigo-600 hover:bg-indigo-700 text-white font-medium py-3 rounded-xl text-sm transition-colors disabled:opacity-40"
        >
          {loading ? "Uploading and processing..." : "Upload and ingest"}
        </button>

        <button
          onClick={loadDemoData}
          disabled={demoLoading || loading}
          className="mt-3 w-full border border-indigo-300 text-indigo-700 hover:bg-indigo-50 font-medium py-3 rounded-xl text-sm transition-colors disabled:opacity-40"
        >
          {demoLoading ? "Loading demo data..." : "Load Demo Data"}
        </button>

        {error && (
          <div className="mt-4 bg-red-50 border border-red-200 text-red-700 rounded-lg px-4 py-3 text-sm">
            {error}
          </div>
        )}

        {result && (
          <div className="mt-6 bg-white border border-gray-200 rounded-xl p-6">
            <h3 className="font-semibold text-gray-800 mb-4">Ingest complete</h3>
            <div className="mb-4 rounded-lg border border-indigo-100 bg-indigo-50 px-3 py-2 text-xs text-indigo-800">
              <p><span className="font-semibold">File:</span> {result.filename}</p>
              <p><span className="font-semibold">Uploaded:</span> {new Date(result.uploaded_at).toLocaleString()}</p>
              <p><span className="font-semibold">Report ID:</span> <span className="font-mono">{result.upload_id}</span></p>
            </div>
            <div className="grid grid-cols-3 gap-4 text-center">
              <div>
                <p className="text-3xl font-bold text-indigo-600">{result.ingested}</p>
                <p className="text-xs text-gray-500 mt-1">Findings ingested</p>
              </div>
              <div>
                <p className="text-3xl font-bold text-green-600">{result.enriched}</p>
                <p className="text-xs text-gray-500 mt-1">CVEs enriched</p>
              </div>
              <div>
                <p className="text-3xl font-bold text-gray-400">{result.skipped}</p>
                <p className="text-xs text-gray-500 mt-1">Skipped</p>
              </div>
            </div>
            <p className="text-xs text-gray-400 mt-4 text-center">
              Go to the{" "}
              <a href="/dashboard" className="text-indigo-600 underline">
                Dashboard
              </a>{" "}
              to view risk scores, or{" "}
              <a href="/chat" className="text-indigo-600 underline">
                Chat
              </a>{" "}
              to query findings.
            </p>
          </div>
        )}

        {demoResults.length > 0 && (
          <div className="mt-6 bg-white border border-gray-200 rounded-xl p-6">
            <h3 className="font-semibold text-gray-800 mb-4">Demo data load result</h3>
            <div className="space-y-3">
              {demoResults.map((item) => (
                <div key={`${item.filename}-${item.status}`} className="rounded-lg border border-indigo-100 bg-indigo-50 px-3 py-2 text-xs text-indigo-900">
                  <p><span className="font-semibold">File:</span> {item.filename}</p>
                  <p><span className="font-semibold">Status:</span> {item.status}</p>
                  {item.upload_id && <p><span className="font-semibold">Report ID:</span> <span className="font-mono">{item.upload_id}</span></p>}
                  {item.status === "ingested" && (
                    <p>
                      <span className="font-semibold">Counts:</span> ingested {item.ingested}, enriched {item.enriched}, skipped {item.skipped}
                    </p>
                  )}
                  {item.detail && <p><span className="font-semibold">Detail:</span> {item.detail}</p>}
                </div>
              ))}
            </div>
            <p className="text-xs text-gray-500 mt-4">Demo files are now available in the upload log below. You can proceed to Dashboard or Chat.</p>
          </div>
        )}

        <div className="mt-8 bg-white border border-gray-200 rounded-xl overflow-hidden">
          <div className="px-5 py-3 border-b border-gray-100 flex items-center justify-between">
            <h3 className="font-medium text-gray-700">Upload Log</h3>
            <span className="text-xs text-gray-400">{uploads.length} reports</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-gray-50 text-gray-500 text-xs uppercase tracking-wide">
                <tr>
                  <th className="px-4 py-3 text-left">File</th>
                  <th className="px-4 py-3 text-left">User</th>
                  <th className="px-4 py-3 text-left">Source</th>
                  <th className="px-4 py-3 text-left">Uploaded</th>
                  <th className="px-4 py-3 text-right">Findings</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {pagedUploads.map((u) => (
                  <tr key={u.id} className="hover:bg-gray-50">
                    <td className="px-4 py-3 text-gray-700">{u.filename}</td>
                    <td className="px-4 py-3 text-gray-500 text-xs">{u.user_email}</td>
                    <td className="px-4 py-3 text-gray-500 uppercase text-xs">{u.source}</td>
                    <td className="px-4 py-3 text-gray-500 text-xs">{new Date(u.uploaded_at).toLocaleString()}</td>
                    <td className="px-4 py-3 text-right text-gray-700 font-medium">{u.finding_count}</td>
                  </tr>
                ))}
                {uploads.length === 0 && (
                  <tr>
                    <td colSpan={5} className="px-4 py-6 text-center text-gray-400 text-sm">
                      No uploads yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          {uploads.length > 0 && (
            <div className="px-4 py-3 border-t border-gray-100 flex items-center justify-between">
              <p className="text-gray-500 text-xs">Page {page} of {totalPages}</p>
              <div className="flex gap-2">
                <button
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page <= 1}
                  className="px-3 py-1 text-xs rounded border border-gray-300 text-gray-700 disabled:opacity-50"
                >
                  Previous
                </button>
                <button
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  disabled={page >= totalPages}
                  className="px-3 py-1 text-xs rounded border border-gray-300 text-gray-700 disabled:opacity-50"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </div>
      </main>
    </AuthGuard>
  );
}
