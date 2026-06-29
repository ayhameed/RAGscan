"use client";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { clearToken } from "@/lib/api";

const links = [
  { href: "/reports",   label: "Reports" },
  { href: "/dashboard", label: "Dashboard" },
  { href: "/guide",     label: "Guide" },
  { href: "/logs",      label: "Logs" },
  { href: "/import",    label: "Import" },
  { href: "/chat",      label: "Chat" },
];

export default function Nav() {
  const path = usePathname();
  const router = useRouter();

  function logout() {
    clearToken();
    router.push("/");
  }

  return (
    <nav className="bg-[rgba(34,17,38,0.82)] backdrop-blur border-b border-white/10 text-white flex items-center gap-6 px-6 py-3 text-sm font-medium">
      <span className="text-white font-bold text-base mr-4 tracking-wide">RAGScan</span>
      {links.map(({ href, label }) => (
        <Link
          key={href}
          href={href}
          className={`hover:text-white text-white/80 transition-colors ${path.startsWith(href) ? "text-white border-b border-[#cb156d] pb-0.5" : ""}`}
        >
          {label}
        </Link>
      ))}
      <button
        onClick={logout}
        className="ml-auto text-white/70 hover:text-white transition-colors"
      >
        Sign out
      </button>
    </nav>
  );
}
