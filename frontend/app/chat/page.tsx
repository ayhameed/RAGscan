"use client";
import { useState, useRef, useEffect, FormEvent } from "react";
import Nav from "@/components/Nav";
import AuthGuard from "@/components/AuthGuard";
import LlmProviderStatus from "@/components/LlmProviderStatus";
import { api, QueryResponse, UploadReport, Finding, QueryMetrics } from "@/lib/api";

interface Message {
  role: "user" | "assistant";
  text: string;
  sources?: string[];
  intent?: string;
  metrics?: QueryMetrics;
  secondaryContext?: string;
}

const MAX_PREVIEW_CHARS = 480;

const STARTERS = [
  "Which findings are in the CISA Known Exploited Vulnerabilities catalog?",
  "What are the top 5 highest-risk vulnerabilities?",
  "Summarize NIST CSF compliance gaps.",
  "Which CVEs have EPSS above 50%?",
];

function ChatBubble({ msg }: { msg: Message }) {
  const isUser = msg.role === "user";
  const [expanded, setExpanded] = useState(false);
  const shouldCollapse = !isUser && msg.text.length > MAX_PREVIEW_CHARS;
  const visibleText = shouldCollapse && !expanded ? `${msg.text.slice(0, MAX_PREVIEW_CHARS)}...` : msg.text;
  return (
    <div className={`flex ${isUser ? "justify-end" : "justify-start"}`}>
      <div
        className={`max-w-[80%] rounded-2xl px-4 py-3 text-sm leading-relaxed ${
          isUser
            ? "bg-indigo-600 text-white rounded-br-sm"
            : "bg-white border border-gray-200 text-gray-800 rounded-bl-sm"
        }`}
      >
        <p className="whitespace-pre-wrap">{visibleText}</p>
        {shouldCollapse && (
          <button
            type="button"
            onClick={() => setExpanded((v) => !v)}
            className="mt-2 text-xs font-medium text-indigo-300 hover:text-indigo-200"
          >
            {expanded ? "Read less" : "Read more"}
          </button>
        )}
        {msg.sources && msg.sources.length > 0 && (
          <div className="mt-2 border-t border-gray-100 pt-2">
            <p className="text-xs text-gray-400 mb-1">Sources</p>
            <ul className="space-y-0.5">
              {msg.sources.map((s, i) => (
                <li key={i} className="text-xs text-indigo-600 font-mono break-all">
                  {s}
                </li>
              ))}
            </ul>
          </div>
        )}
        {msg.intent && (
          <p className="mt-1.5 text-xs text-gray-400">
            Intent: <span className="font-medium">{msg.intent}</span>
          </p>
        )}
        {msg.metrics && (
          <div className="mt-2 grid grid-cols-2 gap-2 text-xs text-gray-500">
            <div className="rounded border border-gray-200 px-2 py-1">
              P@10: {msg.metrics.retrieval_precision_at_10.toFixed(3)}
            </div>
            <div className="rounded border border-gray-200 px-2 py-1">
              Citation: {msg.metrics.citation_accuracy.toFixed(3)}
            </div>
            <div className="rounded border border-gray-200 px-2 py-1">
              Hallucination: {msg.metrics.hallucination_rate.toFixed(3)}
            </div>
            <div className="rounded border border-gray-200 px-2 py-1">
              Sources/Citations: {msg.metrics.source_count}/{msg.metrics.citation_count}
            </div>
          </div>
        )}
        {msg.secondaryContext && (
          <div className="mt-2 rounded border border-emerald-200 bg-emerald-50 px-2 py-2 text-xs text-emerald-900 whitespace-pre-wrap">
            {msg.secondaryContext}
          </div>
        )}
      </div>
    </div>
  );
}

export default function ChatPage() {
  const [handoffReportIds] = useState<string[]>(() => {
    if (typeof window === "undefined") return [];
    const params = new URLSearchParams(window.location.search);
    const single = params.get("report_id");
    const multi = params.get("report_ids");
    return multi
      ? multi.split(",").map((x) => x.trim()).filter(Boolean)
      : (single ? [single] : []);
  });
  const [handoffPrompt] = useState<string>(() => {
    if (typeof window === "undefined") return "";
    return new URLSearchParams(window.location.search).get("prompt") ?? "";
  });
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [sessionId, setSessionId] = useState<string>(() => {
    if (typeof window === "undefined") return "";
    return window.localStorage.getItem("ragscan_chat_session_id") ?? "";
  });
  const [exporting, setExporting] = useState(false);
  const [showInternetContext, setShowInternetContext] = useState(true);
  const [reports, setReports] = useState<UploadReport[]>([]);
  const [selectedReportIds, setSelectedReportIds] = useState<string[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedFindingIds, setSelectedFindingIds] = useState<string[]>([]);
  const [findingsPage, setFindingsPage] = useState(1);
  const bottomRef = useRef<HTMLDivElement>(null);
  const autoPromptSentRef = useRef(false);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  useEffect(() => {
    if (!sessionId) return;
    api.chatSessionHistory(sessionId)
      .then((res) => {
        setMessages(
          res.history.map((item) => ({
            role: item.role === "user" ? "user" : "assistant",
            text: item.text,
          }))
        );
      })
      .catch(() => {
        window.localStorage.removeItem("ragscan_chat_session_id");
        setSessionId("");
      });
  }, [sessionId]);

  useEffect(() => {
    api.uploadReports()
      .then((rows) => {
        setReports(rows);
        const valid = handoffReportIds.filter((id) => rows.some((r) => r.id === id));
        setSelectedReportIds(valid);
      })
      .catch(() => {});
  }, [handoffReportIds]);

  useEffect(() => {
    api.score(selectedReportIds)
      .then((s) => {
        setFindings(s.findings);
        setSelectedFindingIds([]);
        setFindingsPage(1);
      })
      .catch(() => {
        setFindings([]);
      });
  }, [selectedReportIds]);

  const findingsPageSize = 10;
  const findingsTotalPages = Math.max(1, Math.ceil(findings.length / findingsPageSize));
  const pagedFindings = findings.slice((findingsPage - 1) * findingsPageSize, findingsPage * findingsPageSize);

  useEffect(() => {
    const prompt = handoffPrompt;
    if (!prompt || autoPromptSentRef.current || loading) return;
    autoPromptSentRef.current = true;
    send(prompt);
  }, [handoffPrompt, loading, selectedReportIds]);

  async function send(question: string) {
    if (!question.trim() || loading) return;
    const userMsg: Message = { role: "user", text: question.trim() };
    setMessages((prev) => [...prev, userMsg]);
    setInput("");
    setLoading(true);
    try {
      const res: QueryResponse = await api.query(
        question.trim(),
        selectedReportIds,
        selectedFindingIds,
        sessionId || undefined,
        showInternetContext,
      );
      if (res.session_id && res.session_id !== sessionId) {
        setSessionId(res.session_id);
        window.localStorage.setItem("ragscan_chat_session_id", res.session_id);
      }
      const assistantMsg: Message = {
        role: "assistant",
        text: res.answer,
        sources: res.sources,
        intent: res.intent,
        metrics: res.metrics ?? undefined,
        secondaryContext: res.secondary_context ?? undefined,
      };
      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err: unknown) {
      const text = err instanceof Error ? err.message : "Request failed";
      setMessages((prev) => [...prev, { role: "assistant", text: `Error: ${text}` }]);
    } finally {
      setLoading(false);
    }
  }

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    send(input);
  }

  function toggleFinding(id: string) {
    setSelectedFindingIds((prev) =>
      prev.includes(id) ? prev.filter((v) => v !== id) : [...prev, id]
    );
  }

  function toggleReport(id: string) {
    setSelectedReportIds((prev) =>
      prev.includes(id) ? prev.filter((v) => v !== id) : [...prev, id]
    );
  }

  async function exportConversationPdf() {
    if (!sessionId) {
      setMessages((prev) => [
        ...prev,
        { role: "assistant", text: "No saved session yet. Send a message first, then export the conversation." },
      ]);
      return;
    }
    setExporting(true);
    try {
      await api.downloadChatSession(sessionId);
    } catch (err: unknown) {
      const text = err instanceof Error ? err.message : "Export failed";
      setMessages((prev) => [...prev, { role: "assistant", text: `Error: ${text}` }]);
    } finally {
      setExporting(false);
    }
  }

  async function clearSession() {
    const current = sessionId;
    setMessages([]);
    setSessionId("");
    window.localStorage.removeItem("ragscan_chat_session_id");
    if (!current) return;
    try {
      await api.clearChatSession(current);
    } catch {
      // Session is already cleared locally; backend cleanup can fail silently.
    }
  }

  return (
    <AuthGuard>
      <Nav />
      <div className="flex flex-col flex-1 max-w-3xl mx-auto w-full px-4 pb-4">
        <div className="mt-4 mb-3 bg-[rgba(34,17,38,0.82)] border border-white/15 rounded-xl p-3">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
            <div>
              <label className="text-xs text-white/70 mr-2">Report scope</label>
              <p className="text-xs text-white/60 mt-1">Choose one or more uploaded files:</p>
              <div className="mt-1 max-h-20 overflow-auto rounded border border-white/10 bg-white/5 p-2">
                {reports.map((r) => (
                  <label key={r.id} className="flex items-center gap-2 text-xs text-white/90 py-0.5">
                    <input
                      type="checkbox"
                      checked={selectedReportIds.includes(r.id)}
                      onChange={() => toggleReport(r.id)}
                    />
                    <span className="truncate">{r.filename}</span>
                  </label>
                ))}
                {reports.length === 0 && <p className="text-white/60 text-xs">No uploaded files.</p>}
              </div>
            </div>
            <div className="text-xs text-white/70 flex flex-col items-end gap-2">
              <LlmProviderStatus />
              <span>
                {selectedFindingIds.length > 0
                  ? `${selectedFindingIds.length} individual findings selected`
                  : selectedReportIds.length > 0
                  ? `Semantic retrieval over ${selectedReportIds.length} selected file(s)`
                  : "No file selected: querying across all uploaded findings"}
              </span>
              <label className="flex items-center gap-2 text-xs text-white/80">
                <input
                  type="checkbox"
                  checked={showInternetContext}
                  onChange={(e) => setShowInternetContext(e.target.checked)}
                />
                Show internet context
              </label>
              <button
                type="button"
                onClick={exportConversationPdf}
                disabled={exporting || messages.length === 0}
                className="px-3 py-1.5 rounded-lg border border-white/25 text-white hover:bg-white/10 disabled:opacity-40"
              >
                {exporting ? "Exporting PDF..." : "Export Conversation PDF"}
              </button>
              <button
                type="button"
                onClick={clearSession}
                disabled={messages.length === 0 && !sessionId}
                className="px-3 py-1.5 rounded-lg border border-white/25 text-white hover:bg-white/10 disabled:opacity-40"
              >
                Clear Session
              </button>
            </div>
          </div>
          <p className="mt-2 text-xs text-white/60">
            Tip: choose one or more uploaded files above, then optionally choose specific findings below.
          </p>
          <div className="mt-3 max-h-36 overflow-auto border border-white/10 rounded-lg bg-white/5">
            {pagedFindings.map((f) => (
              <label key={f.id} className="flex items-start gap-2 px-3 py-2 text-xs border-b border-white/10">
                <input
                  type="checkbox"
                  checked={selectedFindingIds.includes(f.id)}
                  onChange={() => toggleFinding(f.id)}
                  className="mt-0.5"
                />
                <span className="text-white">
                  <span className="font-mono text-[#ff8ccd] mr-1">{f.cve_id ?? "NO-CVE"}</span>
                  {f.title}
                </span>
              </label>
            ))}
            {findings.length === 0 && (
              <div className="px-3 py-2 text-xs text-white/60">No findings available for selection.</div>
            )}
          </div>
          {findings.length > 0 && (
            <div className="mt-2 flex items-center justify-between text-xs text-white/70">
              <span>Page {findingsPage} of {findingsTotalPages}</span>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => setFindingsPage((p) => Math.max(1, p - 1))}
                  disabled={findingsPage <= 1}
                  className="px-2 py-1 rounded border border-white/30 disabled:opacity-40"
                >
                  Previous
                </button>
                <button
                  type="button"
                  onClick={() => setFindingsPage((p) => Math.min(findingsTotalPages, p + 1))}
                  disabled={findingsPage >= findingsTotalPages}
                  className="px-2 py-1 rounded border border-white/30 disabled:opacity-40"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </div>

        <div className="flex-1 overflow-y-auto py-6 flex flex-col gap-4 min-h-0">
          {messages.length === 0 && (
            <div className="flex flex-col items-center justify-center flex-1 gap-6 py-12">
              <div className="text-center">
                <h2 className="text-xl font-semibold text-white mb-1">Ask about your findings</h2>
                <p className="text-sm text-white/70">
                  Answers are grounded in ingested scan data with citations.
                </p>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 w-full max-w-lg">
                {STARTERS.map((q) => (
                  <button
                    key={q}
                    onClick={() => send(q)}
                    className="text-left bg-white/10 border border-white/20 rounded-xl px-4 py-3 text-sm text-white hover:border-[#cb156d] hover:bg-[#cb156d]/20 transition-colors"
                  >
                    {q}
                  </button>
                ))}
              </div>
            </div>
          )}

          {messages.map((msg, i) => (
            <ChatBubble key={i} msg={msg} />
          ))}

          {loading && (
            <div className="flex justify-start">
              <div className="rounded-2xl rounded-bl-sm px-4 py-3 border border-white/20 bg-[rgba(34,17,38,0.9)] min-w-55">
                <div className="flex items-center gap-2 mb-2">
                  <span className="w-2 h-2 rounded-full bg-[#cb156d] animate-pulse" />
                  <span className="text-xs text-white/80">Analyzing evidence...</span>
                </div>
                <div className="space-y-1.5">
                  <div className="h-1.5 rounded bg-white/20 animate-pulse" />
                  <div className="h-1.5 rounded bg-white/15 animate-pulse" style={{ animationDelay: "120ms" }} />
                  <div className="h-1.5 w-2/3 rounded bg-white/10 animate-pulse" style={{ animationDelay: "220ms" }} />
                </div>
              </div>
            </div>
          )}

          <div ref={bottomRef} />
        </div>

        <form
          onSubmit={onSubmit}
          className="flex gap-2 bg-[rgba(34,17,38,0.86)] border border-white/20 rounded-2xl px-4 py-2.5 shadow-sm"
        >
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask a question about your vulnerabilities..."
            disabled={loading}
            className="flex-1 text-sm outline-none text-white placeholder-white/50 bg-transparent"
          />
          <button
            type="submit"
            disabled={loading || !input.trim()}
            className="bg-[#cb156d] hover:bg-[#aa125c] text-white text-sm font-medium px-4 py-1.5 rounded-xl transition-colors disabled:opacity-40"
          >
            Send
          </button>
        </form>
      </div>
    </AuthGuard>
  );
}
