import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Birkin Sandbox — MCP Blast-Radius Simulator",
  description:
    "Interactive WebCrypto MCP blast-radius simulator with Ed25519 receipts and Merkle tamper verification.",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
