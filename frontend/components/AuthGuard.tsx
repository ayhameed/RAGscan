"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { api, getCurrentUser } from "@/lib/api";

export default function AuthGuard({
  children,
  requireAdmin = false,
}: {
  children: React.ReactNode;
  requireAdmin?: boolean;
}) {
  const router = useRouter();
  const [ready, setReady] = useState<boolean>(() => {
    if (typeof window === "undefined") return false;
    const token = localStorage.getItem("ragscan_token");
    if (!token) return false;
    const cached = getCurrentUser();
    return !!cached && (!requireAdmin || cached.is_admin);
  });

  useEffect(() => {
    const token = localStorage.getItem("ragscan_token");
    if (!token) {
      router.replace("/");
      return;
    }

    if (ready) {
      return;
    }

    api
      .me()
      .then((me) => {
        if (requireAdmin && !me.is_admin) {
          router.replace("/reports");
          return;
        }
        setReady(true);
      })
      .catch(() => {
        router.replace("/");
      });
  }, [ready, requireAdmin, router]);

  if (!ready) return null;
  return <>{children}</>;
}
