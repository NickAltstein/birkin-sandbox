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
  title: "Birkin Blast-Radius Simulator | Zero-Trust Agent Interceptor",
  description:
    "Interactive adversarial MCP attack vector simulator, RFC-8785 deterministic canonicalization, WebCrypto Ed25519 execution receipts, and SHA-256 Merkle audit ledgers.",
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

