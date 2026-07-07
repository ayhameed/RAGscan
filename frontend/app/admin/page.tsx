"use client";

import { useEffect, useState } from "react";
import AuthGuard from "@/components/AuthGuard";
import Nav from "@/components/Nav";
import { AdminUserUpdate, api, UserProfile } from "@/lib/api";

export default function AdminPage() {
  const [users, setUsers] = useState<UserProfile[]>([]);
  const [loading, setLoading] = useState(true);
  const [savingId, setSavingId] = useState<string>("");
  const [page, setPage] = useState(1);
  const [error, setError] = useState<string | null>(null);

  const pageSize = 10;
  const totalPages = Math.max(1, Math.ceil(users.length / pageSize));
  const pagedUsers = users.slice((page - 1) * pageSize, page * pageSize);

  useEffect(() => {
    let cancelled = false;
    const run = async () => {
      try {
        const res = await api.adminUsers();
        if (!cancelled) {
          setUsers(res.items);
        }
      } catch (e: unknown) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : "Failed to load users");
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };

    void run();
    return () => {
      cancelled = true;
    };
  }, []);

  async function applyPatch(userId: string, patch: AdminUserUpdate) {
    setSavingId(userId);
    setError(null);
    try {
      const updated = await api.updateAdminUser(userId, patch);
      setUsers((prev) => prev.map((u) => (u.id === updated.id ? updated : u)));
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Update failed");
    } finally {
      setSavingId("");
    }
  }

  return (
    <AuthGuard requireAdmin>
      <Nav />
      <main className="max-w-7xl mx-auto w-full px-6 py-8">
        <h1 className="text-2xl font-semibold text-white mb-1">Admin Console</h1>
        <p className="text-white/70 text-sm mb-6">Approve users, grant admin access, and block or unblock accounts.</p>

        {error && (
          <div className="mb-4 rounded-lg border border-red-400/40 bg-red-500/20 text-white px-4 py-3 text-sm">
            {error}
          </div>
        )}

        <section className="rounded-xl border border-white/15 bg-[rgba(34,17,38,0.82)] overflow-hidden">
          <div className="px-4 py-3 border-b border-white/10 text-white/80 text-sm">
            {loading ? "Loading users..." : `Users: ${users.length}`}
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-white/5 text-white/75 text-xs uppercase tracking-wide">
                <tr>
                  <th className="px-4 py-3 text-left">Email</th>
                  <th className="px-4 py-3 text-left">Role</th>
                  <th className="px-4 py-3 text-left">Approved</th>
                  <th className="px-4 py-3 text-left">Admin</th>
                  <th className="px-4 py-3 text-left">Blocked</th>
                  <th className="px-4 py-3 text-left">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/10">
                {pagedUsers.map((u) => (
                  <tr key={u.id} className="hover:bg-white/5">
                    <td className="px-4 py-3 text-white">{u.email}</td>
                    <td className="px-4 py-3 text-white/80">{u.role}</td>
                    <td className="px-4 py-3 text-white/80">{u.is_approved ? "Yes" : "No"}</td>
                    <td className="px-4 py-3 text-white/80">{u.is_admin ? "Yes" : "No"}</td>
                    <td className="px-4 py-3 text-white/80">{u.is_blocked ? "Yes" : "No"}</td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-2">
                        <button
                          onClick={() => applyPatch(u.id, { is_approved: !u.is_approved })}
                          disabled={savingId === u.id}
                          className="px-2 py-1 text-xs rounded border border-white/30 text-white disabled:opacity-50"
                        >
                          {u.is_approved ? "Revoke" : "Approve"}
                        </button>
                        <button
                          onClick={() => applyPatch(u.id, { is_admin: !u.is_admin })}
                          disabled={savingId === u.id}
                          className="px-2 py-1 text-xs rounded border border-white/30 text-white disabled:opacity-50"
                        >
                          {u.is_admin ? "Remove Admin" : "Make Admin"}
                        </button>
                        <button
                          onClick={() => applyPatch(u.id, { is_blocked: !u.is_blocked })}
                          disabled={savingId === u.id}
                          className="px-2 py-1 text-xs rounded border border-red-300/60 text-white disabled:opacity-50"
                        >
                          {u.is_blocked ? "Unblock" : "Block"}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
                {!loading && users.length === 0 && (
                  <tr>
                    <td colSpan={6} className="px-4 py-8 text-center text-white/60">
                      No users found.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          {users.length > 0 && (
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
          )}
        </section>
      </main>
    </AuthGuard>
  );
}
