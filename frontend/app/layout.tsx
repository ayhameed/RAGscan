import type { Metadata } from "next";
import { Poppins } from "next/font/google";
import "./globals.css";

const poppins = Poppins({
  variable: "--font-poppins",
  weight: ["400", "500", "600", "700"],
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "RAGScan",
  description: "Retrieval-augmented vulnerability intelligence",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${poppins.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col">
        <div className="flex-1">{children}</div>
        <footer className="border-t border-white/10 bg-[rgba(34,17,38,0.82)] text-white/70 text-xs px-6 py-3 text-center">
          All rights reserved. See Repo: https://github.com/ayhameed/RAGscan
        </footer>
      </body>
    </html>
  );
}
