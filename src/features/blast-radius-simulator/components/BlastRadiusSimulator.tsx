"use client";

import React, { useState, useEffect, useCallback, useMemo } from "react";
import {
  MCPToolCall,
  PolicyRule,
  ExecutionReceipt,
  DEFAULT_POLICIES,
  CryptoSignerContext,
  canonicalizeJson,
  initSignerContext,
  evaluateAndSignMCPCall,
  verifyReceiptIntegrity,
  sha256Hex,
  formatLatency,
} from "../lib/birkin-engine";
import { EXPLOIT_SCENARIOS, ExploitScenario } from "../lib/scenarios";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Terminal,
  Key,
  Copy,
  Check,
  RotateCcw,
  GitBranch,
  Sliders,
  Bug,
  FileCode,
  X,
} from "lucide-react";

export function BlastRadiusSimulator() {
  const [signerCtx, setSignerCtx] = useState<CryptoSignerContext | null>(null);
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>("poisoned-pr");
  const [policies, setPolicies] = useState<PolicyRule[]>(DEFAULT_POLICIES);
  const [receipts, setReceipts] = useState<ExecutionReceipt[]>([]);
  const [activeStepIdx, setActiveStepIdx] = useState<number>(0);
  const [editableArgs, setEditableArgs] = useState<string>("");
  const [isTampered, setIsTampered] = useState<boolean>(false);
  const [verificationRequest, setVerificationRequest] = useState<ExecutionReceipt | null>(null);
  const [verification, setVerification] = useState<{
    receipt: ExecutionReceipt;
    tampered: boolean;
    valid: boolean;
    reason: string;
  } | null>(null);
  const [cryptoUnavailable, setCryptoUnavailable] = useState(false);
  const [copiedLink, setCopiedLink] = useState<boolean>(false);
  const [forkedSteps, setForkedSteps] = useState<MCPToolCall[] | null>(null);

  // New Elis AI Pitch Capabilities: Custom Frame, BYOK Context, CI Gate Exporter
  const [isCustomMode, setIsCustomMode] = useState<boolean>(false);
  const [customToolName, setCustomToolName] = useState<string>("elis_node.execute_tx");
  const [customToolArgs, setCustomToolArgs] = useState<string>(
    '{\n  "query": "DROP TABLE elis_vault_keys CASCADE;",\n  "env": ".env"\n}'
  );
  const [envMode, setEnvMode] = useState<"DECENTRALIZED_NODE" | "BYOK_CLOUD" | "LOCAL_VPC">(
    "DECENTRALIZED_NODE"
  );
  const [showYamlModal, setShowYamlModal] = useState<boolean>(false);
  const [copiedYaml, setCopiedYaml] = useState<boolean>(false);

  const customStep: MCPToolCall = useMemo(() => {
    let parsedArgs: Record<string, unknown> = {};
    try {
      parsedArgs = JSON.parse(customToolArgs);
    } catch {
      parsedArgs = { raw_payload: customToolArgs };
    }
    return {
      jsonrpc: "2.0",
      id: "req-custom-01",
      method: "tools/call",
      params: {
        name: customToolName,
        arguments: parsedArgs,
      },
    };
  }, [customToolName, customToolArgs]);

  const selectedScenario = useMemo(() => {
    return (
      EXPLOIT_SCENARIOS.find((s) => s.id === selectedScenarioId) ??
      EXPLOIT_SCENARIOS[0]
    );
  }, [selectedScenarioId]);

  // 1. Initialize WebCrypto Signer (Ed25519 with HMAC-SHA256 fallback)
  useEffect(() => {
    let mounted = true;
    async function initKeys() {
      try {
        const ctx = await initSignerContext();
        if (mounted) setSignerCtx(ctx);
      } catch (err) {
        if (mounted) setCryptoUnavailable(true);
        console.error("Crypto init error:", err);
      }
    }
    initKeys();
    return () => {
      mounted = false;
    };
  }, []);

  // 2. Read Deep-Link URL State on mount
  useEffect(() => {
    if (typeof window === "undefined") return;
    const params = new URLSearchParams(window.location.search);
    const scenParam = params.get("scenario");
    const stepParam = params.get("step");
    const tamperParam = params.get("tamper");
    const disabledParam = params.get("disabledPolicies");

    if (scenParam && EXPLOIT_SCENARIOS.some((s) => s.id === scenParam)) {
      setSelectedScenarioId(scenParam);
    }
    if (tamperParam === "1") {
      setIsTampered(true);
    }
    if (disabledParam) {
      const disabledList = disabledParam.split(",");
      setPolicies((prev) =>
        prev.map((p) => ({
          ...p,
          enabled: !disabledList.includes(p.id),
        }))
      );
    }
    if (stepParam) {
      const parsedStep = parseInt(stepParam, 10);
      if (!isNaN(parsedStep)) {
        setActiveStepIdx(parsedStep);
      }
    }
  }, []);

  // 3. Sync Deep-Link State using replaceState (avoids Next.js router re-renders)
  const syncUrlParams = useCallback(
    (scenId: string, stepIdx: number, tampered: boolean, activePolicies: PolicyRule[]) => {
      if (typeof window === "undefined") return;
      const params = new URLSearchParams();
      params.set("scenario", scenId);
      params.set("step", String(stepIdx));
      if (tampered) params.set("tamper", "1");
      const disabled = activePolicies
        .filter((p) => !p.enabled)
        .map((p) => p.id)
        .join(",");
      if (disabled) params.set("disabledPolicies", disabled);

      const newUrl = `${window.location.pathname}?${params.toString()}`;
      window.history.replaceState(null, "", newUrl);
    },
    []
  );

  // 4. Run deterministic trace across scenario steps
  const runTrace = useCallback(
    async (
      steps: MCPToolCall[],
      activePolicies: PolicyRule[],
      tamperActive: boolean,
      stepToSelect?: number
    ) => {
      if (!signerCtx) return;
      const generated: ExecutionReceipt[] = [];
      const leafHashes: string[] = [];
      let prevHash = "0".repeat(64);

      for (let i = 0; i < steps.length; i++) {
        const rec = await evaluateAndSignMCPCall(
          steps[i],
          activePolicies,
          i,
          prevHash,
          leafHashes,
          signerCtx
        );
        generated.push(rec);
        leafHashes.push(rec.payloadSha256);
        prevHash = rec.payloadSha256;
      }

      setReceipts(generated);
      const targetIdx =
        stepToSelect !== undefined
          ? Math.max(0, Math.min(stepToSelect, generated.length - 1))
          : generated.length - 1;
      setActiveStepIdx(targetIdx);

      if (generated[targetIdx]) {
        setEditableArgs(
          JSON.stringify(generated[targetIdx].mcpRequest.params.arguments, null, 2)
        );
      }

      syncUrlParams(selectedScenarioId, targetIdx, tamperActive, activePolicies);
    },
    [signerCtx, selectedScenarioId, syncUrlParams]
  );

  // Re-run trace on scenario, policies, custom mode, or signer context change
  useEffect(() => {
    if (!signerCtx) return;
    if (isCustomMode) {
      runTrace([customStep], policies, isTampered, 0);
    } else {
      const stepsToRun = forkedSteps ?? selectedScenario.steps;
      runTrace(stepsToRun, policies, isTampered, activeStepIdx);
    }
  }, [signerCtx, isCustomMode, customStep, selectedScenario, policies, forkedSteps, runTrace]);

  // 5. Scenario Switcher
  const handleSelectScenario = (scen: ExploitScenario) => {
    setIsCustomMode(false);
    setSelectedScenarioId(scen.id);
    setForkedSteps(null);
    setIsTampered(false);
    setVerificationRequest(null);
    const steps = scen.steps;
    const lastStep = steps.length - 1;
    setActiveStepIdx(lastStep);
    syncUrlParams(scen.id, lastStep, false, policies);
  };

  const handleSelectCustomMode = () => {
    setIsCustomMode(true);
    setForkedSteps(null);
    setIsTampered(false);
    setActiveStepIdx(0);
    setVerificationRequest(null);
  };

  // 6. Policy Toggle Handler
  const handleTogglePolicy = (policyId: string) => {
    setPolicies((prev) => {
      const updated = prev.map((p) =>
        p.id === policyId ? { ...p, enabled: !p.enabled } : p
      );
      syncUrlParams(selectedScenarioId, activeStepIdx, isTampered, updated);
      return updated;
    });
  };

  // 7. INFINI Time-Travel Replay & State Fork
  const handleForkAndReplay = () => {
    try {
      const parsedArgs = JSON.parse(editableArgs) as Record<string, unknown>;
      const baseSteps = forkedSteps ?? selectedScenario.steps;
      const updated = baseSteps.slice(0, activeStepIdx + 1).map((s, idx) =>
        idx === activeStepIdx
          ? {
              ...s,
              params: { ...s.params, arguments: parsedArgs },
            }
          : s
      );
      setForkedSteps(updated);
      setIsTampered(false);
      runTrace(updated, policies, false, activeStepIdx);
    } catch {
      alert("Invalid JSON payload in tool arguments editor.");
    }
  };

  const handleResetFork = () => {
    setForkedSteps(null);
    setIsTampered(false);
    runTrace(selectedScenario.steps, policies, false, selectedScenario.steps.length - 1);
  };

  const handleToggleTamper = () => {
    const nextTamper = !isTampered;
    setIsTampered(nextTamper);
    setVerificationRequest(null);
    syncUrlParams(selectedScenarioId, activeStepIdx, nextTamper, policies);
  };

  // 10. Copy Exploit Deep-Link to Clipboard
  const handleCopyLink = () => {
    if (typeof window === "undefined") return;
    navigator.clipboard.writeText(window.location.href);
    setCopiedLink(true);
    setTimeout(() => setCopiedLink(false), 2000);
  };

  const activeReceipt = receipts[activeStepIdx];

  const canonicalPayload = activeReceipt?.canonicalPayload;
  // Canonical receipt JSON begins with an ASCII opening brace. Change that
  // byte while preserving the original digest and signature.
  const payloadToVerify = canonicalPayload && isTampered
    ? `[${canonicalPayload.slice(1)}`
    : canonicalPayload;
  const verificationRequested = isTampered || Boolean(activeReceipt && verificationRequest === activeReceipt);

  useEffect(() => {
    if (!activeReceipt || !signerCtx || !payloadToVerify || !verificationRequested) return;
    let current = true;

    const verify = async () => {
      try {
        const result = await verifyReceiptIntegrity(
          signerCtx,
          payloadToVerify,
          activeReceipt.payloadSha256,
          activeReceipt.ed25519SignatureHex
        );
        if (current) setVerification({ receipt: activeReceipt, tampered: isTampered, ...result });
      } catch {
        if (current) {
          setVerification({
            receipt: activeReceipt,
            tampered: isTampered,
            valid: false,
            reason: "Browser verification could not complete.",
          });
        }
      }
    };

    void verify();
    return () => { current = false; };
  }, [activeReceipt, isTampered, payloadToVerify, signerCtx, verificationRequested]);

  const currentVerification = verificationRequested &&
    verification && verification.receipt === activeReceipt && verification.tampered === isTampered
    ? verification
    : null;
  const verifyReason = currentVerification?.reason ?? "";
  const verifyStatus = currentVerification
    ? currentVerification.valid ? "VALID" : "REJECTED"
    : "IDLE";
  const verifyActiveReceipt = () => {
    if (activeReceipt) setVerificationRequest(activeReceipt);
  };
  const displayPayload = activeReceipt
    ? JSON.stringify(activeReceipt.mcpRequest, null, 2)
    : "Initializing…";

  // Highlight hazardous AST substrings inside JSON-RPC viewer
  const renderHighlightedPayload = useCallback((rawJson: string) => {
    const hazardousTokens = [
      "DROP TABLE",
      "CASCADE",
      "TRUNCATE",
      "DELETE FROM",
      ".env",
      "curl",
      "UNBOUNDED",
      "rm -rf",
      "admin_override",
      "cat .env",
    ];

    const regex = new RegExp(
      `(${hazardousTokens.map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})`,
      "gi"
    );
    const parts = rawJson.split(regex);

    return (
      <code>
        {parts.map((part, idx) => {
          const isHazardous = hazardousTokens.some(
            (t) => t.toLowerCase() === part.toLowerCase()
          );
          if (isHazardous) {
            return (
              <mark
                key={idx}
                className="bg-rose-500/20 text-[#e05243] font-bold px-1 py-0.5 rounded border border-rose-300 font-mono inline-block animate-pulse"
              >
                {part}
              </mark>
            );
          }
          return <span key={idx}>{part}</span>;
        })}
      </code>
    );
  }, []);

  const generatedYaml = useMemo(() => {
    const pol01 = policies.find((p) => p.id === "POL-01")?.enabled ?? true;
    const pol02 = policies.find((p) => p.id === "POL-02")?.enabled ?? true;
    const pol03 = policies.find((p) => p.id === "POL-03")?.enabled ?? true;

    return `version: "1.2"
environment: "${envMode}"
crypto_receipts:
  signing: "ed25519"
  merkle_ledger: true
  byok_zero_egress: true

bounds:
  max_cost_per_task_usd: 0.15
  max_subagent_depth: 3

policies:
  POL-01_NO_ENV_EXFILTRATION: ${pol01}
  POL-02_NO_DESTRUCTIVE_DDL: ${pol02}
  POL-03_NO_RECURSIVE_SPAWN: ${pol03}`;
  }, [envMode, policies]);

  const handleCopyYaml = () => {
    if (typeof window === "undefined") return;
    navigator.clipboard.writeText(generatedYaml);
    setCopiedYaml(true);
    setTimeout(() => setCopiedYaml(false), 2000);
  };

  return (
    <div className="min-h-screen bg-[#ebeff5] text-[#242426] font-sans selection:bg-[#9EFFA9] selection:text-[#111827]">
      {/* Top Floating Header Bar Aligned with AuditGPT Design System */}
      <header className="sticky top-3 z-40 mx-auto max-w-7xl px-4 py-2">
        <nav className="flex items-center justify-between gap-4 rounded-full border border-slate-200/80 bg-white/95 px-3 py-2.5 shadow-xs sm:px-5 backdrop-blur-md">
          <div className="flex items-center gap-3.5 whitespace-nowrap shrink-0">
            <a
              href="https://auditgpt.ai"
              className="flex items-center gap-3 group whitespace-nowrap shrink-0"
              title="Return to AuditGPT.ai"
            >
              <div className="relative flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-slate-100 border border-slate-200/80 shadow-2xs transition-transform group-hover:scale-105">
                <img
                  src="/logo-shield.png"
                  alt="AuditGPT Shield Logo"
                  width={24}
                  height={24}
                  className="h-6 w-6 rounded-full object-contain"
                />
              </div>
              <div className="flex flex-col leading-none">
                <div className="font-sans text-base font-extrabold tracking-[-0.025em] text-[#111827]">
                  AuditGPT<span className="text-slate-400 font-normal">.ai</span>
                </div>
                <div className="font-mono text-[9px] uppercase tracking-wider text-[#58718a] mt-0.5">
                  Blast-Radius Simulator
                </div>
              </div>
            </a>
            <span className="hidden xl:inline-flex items-center rounded-full bg-slate-100 border border-slate-200/80 px-2.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-[#475467] whitespace-nowrap shrink-0">
              Receiptd policy simulation
            </span>
          </div>

          {/* Right Links & Exploit Deep-Link */}
          <div className="flex items-center gap-2.5 sm:gap-3 font-mono text-xs text-[#667085] whitespace-nowrap shrink-0">
            <div className="hidden md:flex items-center gap-1.5 px-3 py-1 rounded-full bg-slate-50 border border-slate-200/80 whitespace-nowrap shrink-0">
              <span className="text-[10px] text-[#667085] uppercase">Browser receipt creation:</span>
              <span className="text-[#111827] font-semibold">
                {formatLatency(activeReceipt?.latencyMs)}
              </span>
            </div>
            <button
              onClick={() => setShowYamlModal(true)}
              className="hidden lg:inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-slate-100 hover:bg-[#9EFFA9] text-[#111827] text-xs font-mono font-semibold border border-slate-200/80 transition-colors cursor-pointer whitespace-nowrap shrink-0"
            >
              <FileCode className="w-3.5 h-3.5 text-[#58718a]" />
              <span>Export CI Gate YAML &rarr;</span>
            </button>
            <a
              href="https://auditgpt.ai"
              className="hidden lg:inline-block px-3 py-1.5 rounded-full text-[#475467] hover:text-[#111827] hover:bg-slate-100 border border-slate-200/80 transition-colors text-xs font-mono whitespace-nowrap shrink-0"
            >
              &larr; auditgpt.ai
            </a>
            <button
              onClick={handleCopyLink}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-full bg-[#111827] text-white text-xs font-mono hover:bg-[#242426] transition-colors cursor-pointer whitespace-nowrap shrink-0"
              title="Copy shareable exploit deep-link"
            >
              {copiedLink ? (
                <>
                  <Check className="w-3.5 h-3.5 text-[#9EFFA9]" />
                  <span className="text-[#9EFFA9] font-semibold">Copied!</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5 text-slate-300" />
                  <span>Copy Deep-Link</span>
                </>
              )}
            </button>
          </div>
        </nav>
      </header>

      <section aria-labelledby="demo-title" className="mx-auto max-w-7xl px-4 py-5 sm:py-8">
        <div className="grid gap-6 rounded-3xl border border-slate-200 bg-white p-5 shadow-sm sm:p-8 lg:grid-cols-[1fr_0.9fr] lg:gap-10">
          <div className="min-w-0">
            <p className="font-mono text-xs font-semibold uppercase tracking-widest text-slate-600">
              Interactive browser simulation
            </p>
            <h1 id="demo-title" className="mt-3 text-3xl font-bold tracking-tight text-slate-950 sm:text-5xl">
              Inspect an agent tool decision
            </h1>
            <p className="mt-3 max-w-lg text-sm leading-relaxed text-slate-600 sm:text-base">
              See the policy decision, verify the signed receipt, then change one byte to see what the verifier catches. Sample tool calls stay in the browser.
            </p>
            <a href="#simulator" className="mt-5 inline-flex items-center gap-2 text-sm font-semibold text-slate-800 underline underline-offset-4">
              Explore scenario controls and trace <span aria-hidden="true">↓</span>
            </a>
          </div>
          <div className="min-w-0 rounded-2xl border border-slate-200 bg-slate-50 p-4 sm:p-5">
            <div role="status" aria-live="polite">
              <p className="font-mono text-xs font-semibold uppercase tracking-wider text-slate-700">
                {cryptoUnavailable ? "Browser cryptography unavailable" : activeReceipt
                  ? activeReceipt.decision === "BLOCKED_FAIL_CLOSED" ? "Blocked by policy" : "Allowed by policy"
                  : "Preparing demo…"}
              </p>
              {activeReceipt && (
                <>
                  <p className="mt-2 break-all font-mono text-sm font-semibold text-slate-950">
                    {activeReceipt.mcpRequest.params.name}
                  </p>
                  <p className="mt-1 break-words text-sm text-slate-600">
                    {activeReceipt.matchedRules.length
                      ? `Matched rules: ${activeReceipt.matchedRules.join(", ")}`
                      : "No matching rules."}
                  </p>
                  <p className="mt-3 text-sm font-medium text-slate-800">
                    {verifyStatus === "VALID" ? `Receipt verified · ${activeReceipt.signingScheme}`
                      : verifyStatus === "REJECTED" ? (verifyReason.startsWith("PAYLOAD_HASH_MISMATCH")
                        ? "Tamper detected · payload hash differs from the signed receipt"
                        : "Receipt verification failed")
                      : verificationRequested ? "Verifying receipt…"
                      : `Receipt ready · ${activeReceipt.signingScheme}`}
                  </p>
                </>
              )}
            </div>
            <div className="mt-4 flex flex-wrap gap-2">
              <button type="button" onClick={verifyActiveReceipt} disabled={!activeReceipt || isTampered}
                className="min-h-11 rounded-lg bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-700 disabled:opacity-50">
                Verify receipt
              </button>
              <button type="button" onClick={handleToggleTamper} disabled={!activeReceipt}
                className="min-h-11 rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-semibold text-slate-900 hover:bg-slate-100 disabled:opacity-50">
                {isTampered ? "Restore original" : "Change one byte"}
              </button>
            </div>
            {isTampered && activeReceipt && (
              <p className="mt-3 text-sm text-slate-600">The payload’s first byte changed from <code>{'{'}</code> to <code>[</code>. The stored hash and signature are unchanged.</p>
            )}
          </div>
        </div>
      </section>

      {/* Sub-Header Context Bar: Target Environment Selector & BYOK Telemetry */}
      <div className="mx-auto max-w-7xl px-4 pt-1 pb-1">
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-slate-200/80 bg-white/80 backdrop-blur-xs px-4 py-2 font-mono text-xs shadow-2xs">
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <span className="text-[10px] uppercase tracking-wider text-[#667085] font-semibold whitespace-nowrap shrink-0">
              Target Environment:
            </span>
            <div className="flex flex-wrap items-center gap-1 p-0.5 rounded-xl border border-slate-200/80 bg-slate-50 text-[11px]">
              {(
                [
                  { id: "DECENTRALIZED_NODE", label: "Decentralized Node" },
                  { id: "BYOK_CLOUD", label: "BYOK (Zero-Egress)" },
                  { id: "LOCAL_VPC", label: "Local / CI Runner" },
                ] as const
              ).map((env) => (
                <button
                  key={env.id}
                  onClick={() => setEnvMode(env.id)}
                  className={`px-3 py-1 rounded-full transition-all cursor-pointer whitespace-nowrap shrink-0 ${
                    envMode === env.id
                      ? "bg-[#111827] text-white font-semibold shadow-2xs"
                      : "text-[#58718a] hover:text-[#111827]"
                  }`}
                >
                  {env.label}
                </button>
              ))}
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2 text-[11px]">
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-slate-50 border border-slate-200/80 text-[#475467] whitespace-nowrap shrink-0">
              BYOK KEYS: <span className="text-[#16a34a] font-semibold">LOCAL-HASHED</span>
            </span>
            <span className="hidden md:inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-slate-50 border border-slate-200/80 text-[#475467] whitespace-nowrap shrink-0">
              RUNTIME: <span className="text-[#16a34a] font-semibold">Browser simulation</span>
            </span>
            <span className="hidden sm:inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-slate-50 border border-slate-200/80 text-[#475467] whitespace-nowrap shrink-0">
              TRACE: <span className="text-[#58718a] font-semibold">INFINI traces</span>
            </span>
          </div>
        </div>
      </div>

      {/* Main 3-Pane Split Grid */}
      <main id="simulator" className="max-w-7xl mx-auto scroll-mt-24 p-4 sm:p-5 grid grid-cols-12 gap-5 items-start">
        {/* PANE 1: ATTACK VECTOR & SCENARIO SELECTOR (3 Cols) */}
        <section className="col-span-12 lg:col-span-3 p-5 rounded-[1.25rem] border border-[rgba(36,36,38,0.08)] bg-white shadow-xs space-y-6 flex flex-col justify-between">
          <div className="space-y-6">
            <div>
              <div className="text-[10px] font-mono uppercase tracking-wider text-[#667085] mb-2.5 flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-[#58718a]" />
                <span>01 / Select Adversarial Vector</span>
              </div>
              <div className="space-y-2">
                {EXPLOIT_SCENARIOS.map((scen) => {
                  const isSelected = !isCustomMode && scen.id === selectedScenario.id;
                  return (
                    <button
                      key={scen.id}
                      onClick={() => handleSelectScenario(scen)}
                      className={`w-full text-left p-3.5 rounded-xl border transition-all cursor-pointer ${
                        isSelected
                          ? "border-[#58718a] bg-slate-50 ring-1 ring-[#58718a]/30"
                          : "border-slate-200/80 bg-white hover:border-slate-300 hover:bg-slate-50/50"
                      }`}
                    >
                      <div className="flex items-center justify-between font-mono text-[10px] mb-1">
                        <span className="text-[#58718a] font-semibold">{scen.cveStyleTag}</span>
                        <span className="text-[#e05243] font-medium">{scen.estimatedDamage}</span>
                      </div>
                      <div className="font-sans font-bold text-xs text-[#111827] mb-1 tracking-tight">
                        {scen.title}
                      </div>
                      <p className="text-[11px] text-[#475467] leading-relaxed line-clamp-2">
                        {scen.description}
                      </p>
                    </button>
                  );
                })}

                {/* Custom BYOK / MCP Payload Option */}
                <button
                  type="button"
                  onClick={handleSelectCustomMode}
                  className={`w-full text-left p-3.5 rounded-xl border transition-all cursor-pointer ${
                    isCustomMode
                      ? "border-[#58718a] bg-slate-50 ring-1 ring-[#58718a]/30"
                      : "border-slate-200/80 bg-white hover:border-slate-300 hover:bg-slate-50/50"
                  }`}
                >
                  <div className="flex items-center justify-between font-mono text-[10px] mb-1">
                    <span className="text-[#58718a] font-semibold">CUSTOM-RPC</span>
                    <span className="text-sky-600 font-medium font-mono">Bring Your Own Tool Call</span>
                  </div>
                  <div className="font-sans font-bold text-xs text-[#111827] mb-1 tracking-tight">
                    Custom MCP JSON-RPC Frame
                  </div>
                  <p className="text-[11px] text-[#475467] leading-relaxed line-clamp-2">
                    Paste custom MCP tool schemas or SQL/Shell payloads to test live AST scoring and real WebCrypto signing.
                  </p>
                </button>
              </div>
            </div>

            {/* Active Policy-as-Code Toggles */}
            <div>
              <div className="text-[10px] font-mono uppercase tracking-wider text-[#667085] mb-2.5 flex items-center justify-between">
                <div className="flex items-center gap-1.5">
                  <Sliders className="w-3.5 h-3.5 text-[#58718a]" />
                  <span>02 / Policy Gates (Toggle Bypass)</span>
                </div>
                <span className="text-[10px] text-[#667085] font-mono">AST Fail-Closed</span>
              </div>
              <div className="space-y-2">
                {policies.map((pol) => (
                  <label
                    key={pol.id}
                    className="flex items-center justify-between p-2.5 rounded-xl border border-slate-200/80 bg-[#f8fafc] cursor-pointer hover:border-slate-300 transition-colors"
                  >
                    <div className="space-y-0.5">
                      <div className="font-mono text-xs text-[#111827] font-semibold">
                        {pol.id}: {pol.name}
                      </div>
                      <div className="font-mono text-[10px] text-[#667085]">
                        Weight: +{pol.weight} Blast Score Contribution
                      </div>
                    </div>
                    <input
                      type="checkbox"
                      checked={pol.enabled}
                      onChange={() => handleTogglePolicy(pol.id)}
                      className="h-4 w-4 accent-[#111827] rounded cursor-pointer"
                    />
                  </label>
                ))}
              </div>
            </div>
          </div>

          <div className="p-3.5 rounded-xl border border-slate-200/80 bg-[#f8fafc] font-mono text-[11px] text-[#475467] leading-relaxed">
            <span className="text-[#111827] font-semibold">Live Experiment:</span> Uncheck a policy gate above to watch the agent bypass the firewall and transition into green <span className="text-[#16a34a] font-semibold">ALLOWED_VERIFIED</span> state.
          </div>
        </section>

        {/* PANE 2: RECEIPTD INTERCEPTOR & CRYPTOGRAPHIC RECEIPT (5 Cols) */}
        <section className="col-span-12 lg:col-span-5 p-5 sm:p-6 rounded-[1.25rem] border border-[rgba(36,36,38,0.08)] bg-white shadow-xs space-y-6">
          <div className="flex items-center justify-between border-b border-slate-200/80 pb-4">
            <div>
              <div className="text-[10px] font-mono uppercase tracking-wider text-[#667085]">
                03 / Receiptd AST &amp; JSON-RPC Interceptor
              </div>
              <h2 className="font-sans text-xl sm:text-2xl font-extrabold text-[#111827] mt-0.5 tracking-[-0.025em]">
                Step T+{activeStepIdx}: {activeReceipt?.mcpRequest.params.name ?? "..."}
              </h2>
            </div>

            {activeReceipt && (
              <span
                className={`font-mono text-xs px-3 py-1 rounded-full border font-bold tracking-wider uppercase ${
                  activeReceipt.decision === "BLOCKED_FAIL_CLOSED"
                    ? "border-[#fca5a5] bg-[#fef2f2] text-[#e05243]"
                    : "border-[#bbf7d0] bg-[#f0fdf4] text-[#16a34a]"
                }`}
              >
                {activeReceipt.decision}
              </span>
            )}
          </div>

          {/* Blast Radius Quantitative Meter */}
          {activeReceipt && (
            <div className="p-4 rounded-xl border border-slate-200/80 bg-[#f8fafc] space-y-2.5">
              <div className="flex justify-between font-mono text-xs">
                <span className="text-[#667085] uppercase tracking-wider text-[10px]">
                  DETERMINISTIC BLAST-RADIUS SCORE
                </span>
                <span
                  className={`font-semibold ${
                    activeReceipt.blastRadiusScore >= 75
                      ? "text-[#e05243]"
                      : activeReceipt.blastRadiusScore >= 40
                      ? "text-amber-600"
                      : "text-[#16a34a]"
                  }`}
                >
                  {activeReceipt.blastRadiusScore} / 100
                </span>
              </div>
              <div className="w-full h-2 bg-slate-200 rounded-full overflow-hidden">
                <div
                  className={`h-full transition-all duration-300 rounded-full ${
                    activeReceipt.blastRadiusScore >= 75
                      ? "bg-[#e05243]"
                      : activeReceipt.blastRadiusScore >= 40
                      ? "bg-amber-500"
                      : "bg-[#16a34a]"
                  }`}
                  style={{ width: `${activeReceipt.blastRadiusScore}%` }}
                />
              </div>
              <div className="font-mono text-[10px] text-[#667085] flex items-center justify-between">
                <span>
                  Triggered Gates:{" "}
                  <strong className="text-[#111827]">
                    {activeReceipt.matchedRules.length > 0
                      ? activeReceipt.matchedRules.join(", ")
                      : "NONE (SAFE_EXECUTION)"}
                  </strong>
                </span>
                <span>Threshold: &ge;50 Block</span>
              </div>
            </div>
          )}

          {/* Custom Tool Call Injector (Active when CUSTOM-RPC is selected) */}
          {isCustomMode && (
            <div className="p-4 rounded-xl border border-sky-300 bg-sky-50/50 space-y-2.5 font-mono text-xs">
              <div className="flex items-center justify-between text-[#111827] font-semibold text-[11px]">
                <span className="flex items-center gap-1.5 text-sky-800">
                  <Terminal className="w-3.5 h-3.5 text-sky-600" />
                  Live AST Payload Injector (Bring Your Own Tool Call):
                </span>
                <span className="text-[10px] text-sky-700 font-medium">Real-Time WebCrypto Eval</span>
              </div>
              <input
                type="text"
                value={customToolName}
                onChange={(e) => setCustomToolName(e.target.value)}
                placeholder="Tool name (e.g. elis_node.execute_tx)"
                className="w-full bg-white border border-slate-300 rounded-lg px-3 py-1.5 text-xs font-mono text-[#111827] focus:outline-none focus:ring-1 focus:ring-sky-500"
              />
              <textarea
                rows={3}
                value={customToolArgs}
                onChange={(e) => setCustomToolArgs(e.target.value)}
                placeholder='JSON arguments (e.g. {"query": "DROP TABLE keys;"})'
                className="w-full bg-white border border-slate-300 rounded-lg p-2.5 text-xs font-mono text-[#111827] focus:outline-none focus:ring-1 focus:ring-sky-500 leading-relaxed"
                spellCheck={false}
              />
            </div>
          )}

          {/* Raw MCP JSON-RPC Payload Inspector */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <div className="text-[10px] font-mono uppercase tracking-wider text-[#667085] flex items-center gap-1.5">
                <Key className="w-3 h-3 text-[#58718a]" />
                <span>Intercepted MCP JSON-RPC 2.0 Frame</span>
              </div>
              <span className="font-mono text-[10px] text-[#667085]">Canonical JSON &bull; AST Token Highlight</span>
            </div>
            <pre className="p-3.5 rounded-xl border border-slate-200/80 bg-[#f8fafc] font-mono text-xs text-[#242426] overflow-x-auto max-h-56 leading-relaxed">
              {renderHighlightedPayload(displayPayload)}
            </pre>
          </div>

          {/* Ed25519 Receipt & Merkle Ledger */}
          {activeReceipt && (
            <div className="p-4 rounded-xl border border-slate-200/80 bg-[#f8fafc] space-y-3 font-mono text-xs">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-[#667085] uppercase text-[10px] tracking-wider">
                  Cryptographic Execution Receipt
                </span>
                <div className="flex flex-wrap items-center gap-2">
                  <button
                    onClick={() => setShowYamlModal(true)}
                    className="px-2.5 py-1 rounded-full border border-slate-300 text-[10px] font-mono text-[#111827] bg-white hover:bg-slate-50 transition-colors flex items-center gap-1 cursor-pointer"
                  >
                    <FileCode className="w-3 h-3 text-[#58718a]" />
                    <span>Export CI YAML</span>
                  </button>
                  <button
                    onClick={handleToggleTamper}
                    className={`px-2.5 py-1 rounded-full border text-[10px] font-mono transition-colors flex items-center gap-1 cursor-pointer ${
                      isTampered
                        ? "border-[#fca5a5] bg-[#fef2f2] text-[#e05243]"
                        : "border-slate-300 text-[#475467] bg-white hover:border-[#e05243] hover:text-[#e05243]"
                    }`}
                    title="Intentionally mutate a byte in the payload to test tamper detection"
                  >
                    <Bug className="w-3 h-3" />
                    <span>{isTampered ? "Revert Tamper" : "Inject 1-Byte Tamper"}</span>
                  </button>
                  <button
                    onClick={verifyActiveReceipt}
                    className={`px-3 py-1 rounded-full border text-[10px] font-mono font-semibold transition-colors cursor-pointer ${
                      verifyStatus === "VALID"
                        ? "border-[#bbf7d0] bg-[#f0fdf4] text-[#16a34a]"
                        : verifyStatus === "REJECTED"
                        ? "border-[#fca5a5] bg-[#fef2f2] text-[#e05243]"
                        : "border-slate-300 bg-white text-[#111827] hover:bg-slate-50"
                    }`}
                  >
                    {verifyStatus === "VALID"
                      ? "✓ SIGNATURE VALIDATED"
                      : verifyStatus === "REJECTED"
                      ? "✗ VERIFICATION FAILED"
                      : "Verify receipt"}
                  </button>
                </div>
              </div>

              {verifyStatus !== "IDLE" && (
                <div
                  className={`p-2.5 rounded-xl border text-[11px] font-mono flex items-center justify-between ${
                    verifyStatus === "VALID"
                      ? "border-[#bbf7d0] bg-[#f0fdf4] text-[#16a34a]"
                      : "border-[#fca5a5] bg-[#fef2f2] text-[#e05243]"
                  }`}
                >
                  <div className="flex items-center gap-1.5">
                    {verifyStatus === "VALID" ? (
                      <ShieldCheck className="w-4 h-4 shrink-0" />
                    ) : (
                      <ShieldAlert className="w-4 h-4 shrink-0" />
                    )}
                    <span>
                      {verifyStatus === "VALID"
                        ? `✓ ${verifyReason}`
                        : `✗ ${verifyReason}`}
                    </span>
                  </div>
                </div>
              )}

              <div className="grid grid-cols-3 gap-2 pt-2 border-t border-slate-200/80 text-[10px]">
                <span className="text-[#667085]">Payload SHA-256:</span>
                <span className="col-span-2 truncate text-[#242426] select-all font-mono">
                  {activeReceipt.payloadSha256}
                </span>

                <span className="text-[#667085]">Prev Hash Link:</span>
                <span className="col-span-2 truncate text-[#667085] select-all font-mono">
                  {activeReceipt.prevReceiptHash}
                </span>

                <span className="text-[#667085]">Merkle Root:</span>
                <span className="col-span-2 truncate text-[#58718a] font-semibold select-all font-mono">
                  {activeReceipt.merkleRoot}
                </span>

                <span className="text-[#667085]">Signature:</span>
                <span className="col-span-2 truncate text-[#16a34a] font-semibold select-all font-mono">
                  {activeReceipt.ed25519SignatureHex}
                </span>

                <span className="text-[#667085]">Verification key:</span>
                <span className="col-span-2 truncate text-[#475467] select-all font-mono">
                  {activeReceipt.publicKeyHex}
                </span>
              </div>
            </div>
          )}
        </section>

        {/* PANE 3: INFINI TIME-TRAVEL DEBUGGER & STATE FORK (4 Cols) */}
        <section className="col-span-12 lg:col-span-4 p-5 sm:p-6 rounded-[1.25rem] border border-[rgba(36,36,38,0.08)] bg-white shadow-xs flex flex-col justify-between space-y-6">
          <div className="space-y-6">
            <div className="flex items-center justify-between border-b border-slate-200/80 pb-3">
              <div>
                <div className="text-[10px] font-mono uppercase tracking-wider text-[#667085] flex items-center gap-1.5">
                  <GitBranch className="w-3.5 h-3.5 text-[#58718a]" />
                  <span>04 / INFINI Deterministic Time-Travel Replay</span>
                </div>
                <p className="text-[11px] text-[#475467] mt-1">
                  Scrub state timeline, mutate frame arguments, and fork execution deterministically.
                </p>
              </div>
              {forkedSteps && (
                <button
                  onClick={handleResetFork}
                  className="px-2.5 py-1 rounded-full border border-slate-300 text-[10px] font-mono text-[#475467] hover:text-[#111827] hover:bg-slate-50 flex items-center gap-1 cursor-pointer"
                >
                  <RotateCcw className="w-3 h-3" />
                  <span>Reset Fork</span>
                </button>
              )}
            </div>

            {/* Trace Timeline Scrubber */}
            <div className="space-y-2">
              {receipts.map((rec, idx) => {
                const isCurrent = idx === activeStepIdx;
                return (
                  <button
                    key={`${rec.payloadSha256}-${idx}`}
                    onClick={() => {
                      setActiveStepIdx(idx);
                      setEditableArgs(
                        JSON.stringify(rec.mcpRequest.params.arguments, null, 2)
                      );
                      setIsTampered(false);
                      setVerificationRequest(null);
                      syncUrlParams(selectedScenarioId, idx, false, policies);
                    }}
                    className={`w-full text-left p-3 rounded-xl border font-mono text-xs flex items-center justify-between transition-all cursor-pointer ${
                      isCurrent
                        ? "border-[#58718a] bg-slate-50 ring-1 ring-[#58718a]/30"
                        : "border-slate-200/80 bg-white hover:border-slate-300 hover:bg-slate-50/50"
                    }`}
                  >
                    <div className="truncate pr-2">
                      <span className="text-[#667085] mr-2 font-semibold">T+{idx}</span>
                      <span className="text-[#111827] font-semibold">
                        {rec.mcpRequest.params.name}
                      </span>
                    </div>
                    <span
                      className={`text-[9px] font-bold px-2 py-0.5 rounded-full border uppercase tracking-wider shrink-0 ${
                        rec.decision === "BLOCKED_FAIL_CLOSED"
                          ? "border-[#fca5a5] text-[#e05243] bg-[#fef2f2]"
                          : "border-[#bbf7d0] text-[#16a34a] bg-[#f0fdf4]"
                      }`}
                    >
                      {rec.decision === "BLOCKED_FAIL_CLOSED" ? "BLOCKED" : "ALLOWED"}
                    </span>
                  </button>
                );
              })}
            </div>

            {/* Live Payload Mutation & Fork Box */}
            <div className="space-y-2">
              <div className="flex items-center justify-between font-mono text-[10px]">
                <span className="text-[#667085] uppercase tracking-wider">
                  Mutate Frame T+{activeStepIdx} Arguments
                </span>
                <span className="text-[#16a34a] font-semibold">0 LLM Tokens Burned</span>
              </div>
              <textarea
                rows={5}
                value={editableArgs}
                onChange={(e) => setEditableArgs(e.target.value)}
                className="w-full p-3 bg-[#f8fafc] border border-slate-200/80 rounded-xl font-mono text-xs text-[#242426] focus:outline-none focus:ring-1 focus:ring-[#58718a] focus:border-[#58718a] transition-all leading-relaxed"
                spellCheck={false}
              />
              <button
                onClick={handleForkAndReplay}
                className="w-full py-2.5 rounded-full bg-[#111827] text-white font-mono text-xs font-bold uppercase tracking-wider hover:bg-[#242426] transition-colors cursor-pointer"
              >
                Fork Trace &amp; Replay from T+{activeStepIdx}
              </button>
            </div>
          </div>

          {/* Local CLI Quickstart Card */}
          <div className="p-3.5 rounded-xl border border-slate-200/80 bg-[#f8fafc] font-mono text-xs space-y-1.5">
            <div className="text-[10px] text-[#667085] uppercase tracking-wider">
              Wrap Any Agent In 1 Command
            </div>
            <div className="text-[#242426] text-[11px] select-all bg-white p-2 rounded-lg border border-slate-200/80">
              $ pip install git+https://github.com/NickAltstein/receiptd &amp;&amp; receiptd init --claude-code
            </div>
            <div className="text-[10px] text-[#16a34a] font-mono flex items-center gap-1 pt-0.5 font-medium">
              <span>✓ 100% Local Execution • Zero Data Egress • Open Source (MIT)</span>
            </div>
          </div>
        </section>
      </main>

      {/* Clean Minimal Footer */}
      <footer className="border-t border-slate-200/80 bg-white/60 px-6 py-4 mt-8">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4 font-mono text-xs text-[#667085]">
          <div className="flex items-center gap-2">
            <span>&copy; 2026 AuditGPT.ai</span>
            <span>&bull;</span>
            <span>Runtime Evidence: <a href="https://github.com/NickAltstein/receiptd" target="_blank" rel="noopener noreferrer" className="text-[#16a34a] font-semibold hover:underline">Receiptd</a></span>
            <span>&bull;</span>
            <span>Trace Replay: <a href="https://github.com/NickAltstein/infini" target="_blank" rel="noopener noreferrer" className="text-[#58718a] font-semibold hover:underline">INFINI</a></span>
          </div>
          <div className="flex items-center gap-6">
            <a href="https://auditgpt.ai" className="hover:text-[#111827] transition-colors">
              &larr; Return to AuditGPT.ai
            </a>
            <a href="/terms" className="hover:text-[#111827] transition-colors">
              Terms of Service
            </a>
            <a href="/privacy" className="hover:text-[#111827] transition-colors">
              Privacy Policy
            </a>
            <span className="text-[#16a34a]">Local-First · Zero Data Egress</span>
          </div>
        </div>
      </footer>

      {/* 1-Click Export CI Gate YAML Modal */}
      {showYamlModal && (
        <div
          role="dialog"
          aria-modal="true"
          className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4"
          onClick={() => setShowYamlModal(false)}
        >
          <div
            className="bg-white border border-slate-300 rounded-2xl max-w-xl w-full p-6 shadow-2xl space-y-4"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between pb-3 border-b border-slate-200">
              <div className="flex items-center gap-2 font-mono text-sm font-bold text-[#111827]">
                <FileCode className="w-4 h-4 text-[#58718a]" />
                <span>auditgpt.config.yaml &bull; Live Merge Gate</span>
              </div>
              <button
                type="button"
                onClick={() => setShowYamlModal(false)}
                className="text-slate-400 hover:text-[#111827] text-sm font-mono cursor-pointer p-1"
                aria-label="Close modal"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-xs text-[#475467] leading-relaxed">
              This configuration enforces the exact policy gates tested in the simulator (AST Fail-Closed) across your GitHub Actions PR pipeline and local developer hooks.
            </p>

            <pre className="bg-[#f8fafc] p-4 rounded-xl border border-slate-200 text-xs font-mono text-[#242426] overflow-x-auto leading-relaxed">
              {generatedYaml}
            </pre>

            <div className="flex items-center justify-between pt-2">
              <span className="text-[11px] font-mono text-[#16a34a] font-medium">
                ✓ Generated from active Section 02 toggles
              </span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={handleCopyYaml}
                  className="px-4 py-2 rounded-full font-mono text-xs font-bold bg-[#111827] text-white hover:bg-slate-800 transition-colors cursor-pointer flex items-center gap-1.5"
                >
                  {copiedYaml ? <Check className="w-3.5 h-3.5 text-[#9EFFA9]" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedYaml ? "Copied!" : "Copy YAML Config"}</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default BlastRadiusSimulator;
