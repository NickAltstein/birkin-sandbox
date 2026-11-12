# Receiptd Blast-Radius Simulator & Deterministic Interceptor

[![Live Demo](https://img.shields.io/badge/live--demo-sandbox-38BDF8?style=flat-square)](https://sandbox.auditgpt.ai)
[![Protocol](https://img.shields.io/badge/MCP-JSON--RPC%202.0-38BDF8?style=flat-square)](https://modelcontextprotocol.io)
[![Cryptography](https://img.shields.io/badge/crypto-Ed25519%20%2B%20Canonical%20JSON-0B0D11?style=flat-square)](#cryptographic-features)
[![License: MIT](https://img.shields.io/badge/license-MIT-64748B?style=flat-square)](./LICENSE)

Interactive, zero-trust execution sandbox demonstrating real-time deterministic policy enforcement, blast-radius scoring, WebCrypto Ed25519 execution receipts, and SHA-256 Merkle audit trees against adversarial MCP agent attacks.

---

## Key Features

1. **Deterministic Canonical JSON Serialization**:
   Normalizes and lexicographically sorts object keys before computing SHA-256 digests, guaranteeing byte-level hash reproducibility across disparate runtimes.

2. **Resilient WebCrypto Signer with Graceful Fallback**:
   Uses native WebCrypto `Ed25519` key generation and digital signatures in modern runtimes, with deterministic automatic fallback to `HMAC-SHA256` in legacy browser environments.

3. **1-Click "Corrupt Ledger (1-Byte Flip)" Tamper Demonstration**:
   Mutates a single byte in the committed execution parameters without re-signing. Instantly trips fail-closed verification: `✗ TAMPER DETECTED — MERKLE ROOT & SIGNATURE MISMATCH` in `#F43F5E` rose-red.

4. **Exploit Deep-Linking via URLSearchParams**:
   Full simulation state (`scenario`, `step`, `tamper`, `disabledPolicies`) is mirrored to URL query parameters via `window.history.replaceState`. A dedicated header button copies exact exploit frames to clipboard for incident handoffs.

5. **Aesthetic & Design Constraint**:
   Dark canvas (`#0B0D11`), elevated surface (`#11141C`), 1px hairline structural grid (`#222733`), telemetry cyan (`#38BDF8`), and fail-closed rose-red (`#F43F5E`). Zero bloated glassmorphism.

---

## Adversarial Scenarios

- **`MCP-EXFIL-01`**: Indirect Prompt Injection via Poisoned Pull Request (exfiltration of environment secrets via curl).
- **`MCP-MUTATE-02`**: Hallucinated Schema Migration on Production Database (`DROP TABLE customer_settlements CASCADE;`).
- **`MCP-LOOP-03`**: Recursive Subagent Fork & Runaway Spend Loop.

---

## Quickstart

```bash
# 1. Install dependencies
bun install

# 2. Run unit tests (9 assertions: canonicalization, WebCrypto, tamper detection, Merkle trees)
bun test

# 3. Start local development server
bun dev
```

Visit `http://localhost:3000` to interact with the simulator.

---

## License

MIT © [Nick Altstein](https://github.com/NickAltstein)

