import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "AuditGPT — Cryptographic Proof for Every Autonomous Tool Call",
  description:
    "Deterministic fail-closed PreToolUse runtime hooks, Ed25519 execution receipts, and pre-merge CI blast-radius gating for autonomous AI agents.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={`${inter.variable} antialiased bg-[#ebeff5] text-[#242426]`}>
        {children}
      </body>
    </html>
  );
}

