"use client";

import Link from "next/link";
import Nav from "@/components/Nav";
import AuthGuard from "@/components/AuthGuard";

export default function GuidePage() {
  return (
    <AuthGuard>
      <Nav />
      <main className="max-w-4xl mx-auto w-full px-6 py-8">
        <div className="rounded-xl border border-white/15 bg-[rgba(34,17,38,0.82)] p-6 text-white">
          <h1 className="text-2xl font-semibold">How to Read Risk Score</h1>
          <p className="text-white/75 text-sm mt-2">
            RAGScan combines CVSS, EPSS, and KEV to rank remediation priority.
          </p>

          <div className="mt-6 grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="rounded-lg bg-white/10 border border-white/10 p-4">
              <p className="text-xs text-white/70">CVSS (40%)</p>
              <p className="text-sm mt-1">Normalized from 0-10 into 0-1 then weighted.</p>
            </div>
            <div className="rounded-lg bg-white/10 border border-white/10 p-4">
              <p className="text-xs text-white/70">EPSS (40%)</p>
              <p className="text-sm mt-1">Exploit probability from FIRST weighted directly.</p>
            </div>
            <div className="rounded-lg bg-white/10 border border-white/10 p-4">
              <p className="text-xs text-white/70">KEV (20%)</p>
              <p className="text-sm mt-1">CISA Known Exploited Vulnerability bonus.</p>
            </div>
          </div>

          <div className="mt-6 rounded-lg bg-black/20 border border-white/10 p-4 font-mono text-sm overflow-auto">
            risk_score = ((cvss3 / 10.0) * 0.4 + epss * 0.4 + kev * 0.2) * 100
          </div>

          <div className="mt-6">
            <h2 className="font-medium">Score Bands</h2>
            <div className="mt-3 grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
              <div className="rounded-lg border border-red-300/40 bg-red-500/20 p-3">80-100: Critical priority</div>
              <div className="rounded-lg border border-orange-300/40 bg-orange-500/20 p-3">60-79.9: High priority</div>
              <div className="rounded-lg border border-yellow-300/40 bg-yellow-500/20 p-3">40-59.9: Medium priority</div>
              <div className="rounded-lg border border-green-300/40 bg-green-500/20 p-3">0-39.9: Lower priority</div>
            </div>
          </div>

          <div className="mt-6 rounded-lg bg-white/10 border border-white/10 p-4 text-sm">
            <p className="font-medium">How to use this in workflow</p>
            <ol className="list-decimal pl-5 mt-2 space-y-1 text-white/90">
              <li>Select a report in Reports.</li>
              <li>Review top risk findings first.</li>
              <li>Use Chat prompt: "What are the top 5 highest-risk vulnerabilities?"</li>
              <li>Export framework PDF from Dashboard for stakeholder review.</li>
            </ol>
          </div>

          <div className="mt-6 flex gap-3">
            <Link
              href="/dashboard"
              className="bg-[#cb156d] hover:bg-[#aa125c] text-white text-sm font-medium px-4 py-2 rounded-lg"
            >
              Back to Dashboard
            </Link>
            <Link
              href="/reports"
              className="border border-white/30 hover:bg-white/10 text-white text-sm font-medium px-4 py-2 rounded-lg"
            >
              Open Reports
            </Link>
          </div>
        </div>
      </main>
    </AuthGuard>
  );
}
