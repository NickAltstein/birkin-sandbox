import type { Metadata } from "next";
import { Inter, Fragment_Mono } from "next/font/google";
import "./globals.css";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
});

const fragmentMono = Fragment_Mono({
  variable: "--font-fragment-mono",
  subsets: ["latin"],
  weight: "400",
});

export const metadata: Metadata = {
  title: "AuditGPT Sandbox — Browser-Side Policy Simulation for Hooked Tool Calls",
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
      <body className={`${inter.variable} ${fragmentMono.variable} antialiased bg-[#ebeff5] text-[#242426]`}>
        {children}
      </body>
    </html>
  );
}

