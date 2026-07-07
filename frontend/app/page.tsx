"use client";
import { useState, FormEvent } from "react";
import { useRouter } from "next/navigation";
import { api, setToken } from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setLoading(true);
    try {
      if (mode === "login") {
        const { access_token } = await api.login(email, password);
        setToken(access_token);
        await api.me();
        router.push("/reports");
      } else {
        const res = await api.register(email, password);
        setNotice(res.message);
        setMode("login");
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Request failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex flex-1 items-center justify-center min-h-screen">
      <div className="w-full max-w-sm bg-[rgba(34,17,38,0.86)] border border-white/10 rounded-xl shadow-lg p-8">
        <h1 className="text-white text-2xl font-bold mb-1">RAGScan</h1>
        <p className="text-white/70 text-sm mb-6">Vulnerability intelligence platform</p>

        <div className="flex gap-2 mb-6">
          {(["login", "register"] as const).map((m) => (
            <button
              key={m}
              onClick={() => setMode(m)}
              className={`flex-1 py-2 rounded-lg text-sm font-medium transition-colors ${
                mode === m
                  ? "bg-[#cb156d] text-white"
                  : "bg-white/10 text-white/70 hover:text-white"
              }`}
            >
              {m === "login" ? "Sign in" : "Register"}
            </button>
          ))}
        </div>

        <form onSubmit={submit} className="flex flex-col gap-4">
          <input
            type="email"
            placeholder="Email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            className="bg-white/10 text-white placeholder-white/45 rounded-lg px-4 py-2.5 text-sm outline-none focus:ring-2 focus:ring-[#cb156d]"
          />
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            className="bg-white/10 text-white placeholder-white/45 rounded-lg px-4 py-2.5 text-sm outline-none focus:ring-2 focus:ring-[#cb156d]"
          />
          {error && <p className="text-red-400 text-sm">{error}</p>}
          {notice && <p className="text-emerald-300 text-sm">{notice}</p>}
          <button
            type="submit"
            disabled={loading}
            className="bg-[#cb156d] hover:bg-[#aa125c] text-white font-medium py-2.5 rounded-lg text-sm transition-colors disabled:opacity-50"
          >
            {loading ? "Please wait..." : mode === "login" ? "Sign in" : "Create account"}
          </button>
        </form>
      </div>
    </div>
  );
}
