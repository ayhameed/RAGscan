"use client";
import { useState, useRef, useEffect, FormEvent } from "react";
import Nav from "@/components/Nav";
import AuthGuard from "@/components/AuthGuard";
import { api, QueryResponse, UploadReport, Finding } from "@/lib/api";

interface Message {
  role: "user" | "assistant";
  text: string;
  sources?: string[];
  intent?: string;
}

const STARTERS = [
  "Which findings are in the CISA Known Exploited Vulnerabilities catalog?",
  "What are the top 5 highest-risk vulnerabilities?",
  "Summarize NIST CSF compliance gaps.",
  "Which CVEs have EPSS above 50%?",
];

function ChatBubble({ msg }: { msg: Message }) {
  const isUser = msg.role === "user";
  return (
    <div className={`flex ${isUser ? "justify-end" : "justify-start"}`}>
      <div
        className={`max-w-[80%] rounded-2xl px-4 py-3 text-sm leading-relaxed ${
          isUser
            ? "bg-indigo-600 text-white rounded-br-sm"
            : "bg-white border border-gray-200 text-gray-800 rounded-bl-sm"
        }`}
      >
        <p className="whitespace-pre-wrap">{msg.text}</p>
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
      </div>
    </div>
  );
}

export default function ChatPage() {
  const [handoffReportIds, setHandoffReportIds] = useState<string[]>([]);
  const [handoffPrompt, setHandoffPrompt] = useState("");
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [reports, setReports] = useState<UploadReport[]>([]);
  const [selectedReportIds, setSelectedReportIds] = useState<string[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedFindingIds, setSelectedFindingIds] = useState<string[]>([]);
  const bottomRef = useRef<HTMLDivElement>(null);
  const autoPromptSentRef = useRef(false);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const single = params.get("report_id");
    const multi = params.get("report_ids");
    const parsed = multi
      ? multi.split(",").map((x) => x.trim()).filter(Boolean)
      : (single ? [single] : []);
    setHandoffReportIds(parsed);
    setHandoffPrompt(params.get("prompt") ?? "");
  }, []);

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
      })
      .catch(() => {
        setFindings([]);
      });
  }, [selectedReportIds]);

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
      );
      const assistantMsg: Message = {
        role: "assistant",
        text: res.answer,
        sources: res.sources,
        intent: res.intent,
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
            <span className="text-xs text-white/70">
              {selectedFindingIds.length > 0
                ? `${selectedFindingIds.length} individual findings selected`
                : selectedReportIds.length > 0
                ? `Semantic retrieval over ${selectedReportIds.length} selected file(s)`
                : "No file selected: querying across all uploaded findings"}
            </span>
          </div>
          <p className="mt-2 text-xs text-white/60">
            Tip: choose one or more uploaded files above, then optionally choose specific findings below.
          </p>
          <div className="mt-3 max-h-36 overflow-auto border border-white/10 rounded-lg bg-white/5">
            {findings.map((f) => (
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
              <div className="bg-white border border-gray-200 rounded-2xl rounded-bl-sm px-4 py-3">
                <span className="flex gap-1">
                  {[0, 1, 2].map((i) => (
                    <span
                      key={i}
                      className="w-2 h-2 bg-white/60 rounded-full animate-bounce"
                      style={{ animationDelay: `${i * 0.15}s` }}
                    />
                  ))}
                </span>
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
