import type { Metadata } from "next";
import { BlastRadiusSimulator } from "@/features/blast-radius-simulator";

export const metadata: Metadata = {
  title: "AuditGPT — Cryptographic Proof for Every Autonomous Tool Call",
  description:
    "Interactive adversarial MCP attack vector simulator, canonical JSON (sorted keys) serialization, WebCrypto Ed25519 execution receipts, and SHA-256 Merkle audit ledgers.",
};

export default function RootPage() {
  return (
    <main className="min-h-screen bg-[#ebeff5] text-[#242426] selection:bg-[#9EFFA9] selection:text-[#111827]">
      <BlastRadiusSimulator />
    </main>
  );
}

