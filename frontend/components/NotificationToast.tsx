"use client";

import { useEffect, useState } from "react";

type NoticeType = "info" | "warning" | "error";

type Notice = {
  id: number;
  message: string;
  type: NoticeType;
};

export default function NotificationToast() {
  const [items, setItems] = useState<Notice[]>([]);

  useEffect(() => {
    const handler = (event: Event) => {
      const detail = (event as CustomEvent).detail as { message?: string; type?: NoticeType };
      const message = (detail?.message || "").trim();
      if (!message) return;
      const next: Notice = {
        id: Date.now() + Math.floor(Math.random() * 1000),
        message,
        type: detail?.type || "info",
      };
      setItems((prev) => [...prev, next]);
      setTimeout(() => {
        setItems((prev) => prev.filter((item) => item.id !== next.id));
      }, 5000);
    };

    window.addEventListener("ragscan-notify", handler as EventListener);
    return () => window.removeEventListener("ragscan-notify", handler as EventListener);
  }, []);

  if (items.length === 0) return null;

  return (
    <div className="fixed right-4 top-4 z-50 flex max-w-sm flex-col gap-2">
      {items.map((item) => {
        const cls =
          item.type === "error"
            ? "border-red-300 bg-red-50 text-red-800"
            : item.type === "warning"
            ? "border-amber-300 bg-amber-50 text-amber-800"
            : "border-blue-300 bg-blue-50 text-blue-800";
        return (
          <div key={item.id} className={`rounded-lg border px-3 py-2 text-sm shadow ${cls}`}>
            {item.message}
          </div>
        );
      })}
    </div>
  );
}
