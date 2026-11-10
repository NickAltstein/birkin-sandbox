# Birkin Sandbox

Interactive WebCrypto MCP blast-radius simulator. Ed25519 receipts and a Merkle tamper check, running entirely in the browser.

An agent proposes a tool call. The page canonicalizes the call, hashes it, and signs the digest. A policy gate fail-closes on destructive SQL (`POL-02`) and destructive shell (`POL-01`). The signed denial is a receipt. Changing one byte of the execution parameters after signing, without producing a new signature, makes verification fail.

No tool call leaves the page. SQL and shell text are fixtures. Disabling a policy only changes the simulated decision.

## Run

```bash
npm install
npm test
npm run dev
```

Open the dev server and use the query string:

```text
?scenario=sql-blast&step=1&tamper=0&disabledPolicies=
```

`step` is a zero-based index. `tamper=1` flips one byte of the current step's parameters and does not re-sign. `disabledPolicies` is a comma-separated list (`POL-01`, `POL-02`). **Copy Exploit Deep-Link** copies that URL. **Inject 1-Byte Tamper** sets `tamper=1`.

`npm run build` prerenders the page as a static export in `out/`.

## What is signed

Object keys are sorted by UTF-16 code unit and the payload is compact JSON. That is the RFC 8785 key-order rule. Strings, arrays, booleans, and null use JSON serialization. Finite numbers use JSON number serialization, and `-0` is written as `0`.

The leaf hash is SHA-256 of those bytes. The active signer signs the raw 32-byte digest. WebCrypto Ed25519 is tried first. If the platform cannot generate or sign with Ed25519, the header badge switches to `HMAC-SHA256`. HMAC verifies inside the same page session; it is not a public-key receipt you can hand to someone who does not hold the key.

The Merkle root hashes raw child digests. An odd node is promoted unchanged. The checkpoint signature is over the root of the untampered leaves. Verification recomputes the root from the bytes on screen, so a one-byte parameter flip fails both the step signature and the checkpoint.

## Tests

```bash
npm test
```

The suite covers canonical key order, array and primitive encoding, Ed25519 signing, the HMAC fallback, intact verification, payload tamper, signature tamper, the Merkle root, the `POL-02` SQL deny, and an allowed audited read.
