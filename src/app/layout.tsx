import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
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
    <html lang="en" className="dark">
      <body className={`${geistSans.variable} ${geistMono.variable} antialiased bg-[#0B0D11] text-[#F3F4F6]`}>
        {children}
      </body>
    </html>
  );
}

