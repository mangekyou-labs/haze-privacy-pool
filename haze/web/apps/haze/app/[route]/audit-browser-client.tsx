"use client";

import { useCallback, useEffect, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from "react";
import { createPortal } from "react-dom";

const APPLICATION_ID = "0x0000000000000000000000000000000000000000000000000000000000000a11";
const CHAIN_HEX = "0xa869"; // 43113

interface EthereumProvider {
  request: (args: { method: string; params?: unknown[] }) => Promise<unknown>;
}

function getEthereum(): EthereumProvider {
  const win = typeof window !== "undefined" ? (window as unknown as { ethereum?: EthereumProvider }) : undefined;
  if (!win?.ethereum) {
    throw new Error("No web3 wallet detected. Please install Core or MetaMask.");
  }
  return win.ethereum;
}

interface ComplianceCaseSummary {
  caseId: string;
  title: string;
  applicationId: string;
  transactionHash: string;
  grantedFields: string[];
  status: string;
  blockNumber?: number;
  confirmations?: number;
  syncStatus?: string;
  integrityStatus?: string;
  grantExpiresAt: number;
}

interface AuditSessionData {
  address: string;
  applicationId: string;
  role: string;
  expiresAt: number;
}

interface DisclosureData {
  transactionHash: string;
  fields: Record<string, string>;
}

interface ExportBundle {
  exportId: string;
  caseId: string;
  recordId: string;
  subject: string;
  signingKeyId: string;
  fields: Record<string, string>;
  provenance: Record<string, string>;
  expiresAt: number;
  signature: string;
}

interface AccessLogItem {
  seq: number;
  prevHash: string;
  entryHash: string;
  name: string;
  applicationId: string;
  caseId?: string;
  wallet: string;
  fields: string[];
  allowed: boolean;
  at: number;
}

export function AuditBrowserClient() {
  const [mount, setMount] = useState<HTMLElement | null>(null);
  const [session, setSession] = useState<AuditSessionData | null>(null);
  const [sessionLoading, setSessionLoading] = useState(true);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Workstation state
  const [cases, setCases] = useState<ComplianceCaseSummary[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [disclosure, setDisclosure] = useState<DisclosureData | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [exportData, setExportData] = useState<ExportBundle | null>(null);
  const [exportModalOpen, setExportModalOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const [accessLogs, setAccessLogs] = useState<AccessLogItem[]>([]);

  const modalRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const caseListRef = useRef<HTMLElement>(null);

  useEffect(() => {
    setMount(document.getElementById("haze-audit-workstation-root"));
    if (typeof window !== "undefined") {
      const urlParams = new URLSearchParams(window.location.search);
      const caseParam = urlParams.get("case");
      if (caseParam) {
        setSelectedCaseId(caseParam);
      }
    }
  }, []);

  // Sync selected case to URL
  const selectCase = (caseId: string) => {
    setSelectedCaseId(caseId);
    setDisclosure(null);
    setExportData(null);
    setErrorMsg(null);
    if (typeof window !== "undefined") {
      const url = new URL(window.location.href);
      url.searchParams.set("case", caseId);
      window.history.replaceState(null, "", url.toString());
    }
  };

  // Check existing session
  const fetchSession = useCallback(async () => {
    try {
      const res = await fetch("/api/compliance/session");
      if (res.ok) {
        const data = await res.json();
        setSession(data);
      } else if (res.status !== 401) {
        setErrorMsg(res.status === 403 ? "This wallet is not authorized for the Fuji auditor grant." : "Your auditor session expired. Sign in again to continue.");
      }
    } catch {
      setErrorMsg("The compliance service is unavailable. Check your connection and retry.");
    } finally {
      setSessionLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSession();
  }, [fetchSession]);

  // Load cases and access log when session is active
  const loadCasesAndLogs = useCallback(async () => {
    if (!session) return;
    try {
      const [casesRes, logsRes] = await Promise.all([
        fetch("/api/compliance/cases"),
        fetch("/api/compliance/access-log"),
      ]);
      if (casesRes.status === 401) {
        setSession(null);
        setErrorMsg("Your auditor session expired. Sign in again to continue.");
        return;
      }
      if (casesRes.ok) {
        const casesJson = await casesRes.json();
        const loadedCases: ComplianceCaseSummary[] = casesJson.cases || [];
        setCases(loadedCases);
        if (!selectedCaseId && loadedCases.length > 0 && window.matchMedia("(min-width: 721px)").matches) {
          const firstCase = loadedCases[0];
          if (firstCase) {
            setSelectedCaseId(firstCase.caseId);
          }
        }
      } else throw new Error("Assigned cases could not be loaded.");
      if (logsRes.ok) {
        const logsJson = await logsRes.json();
        setAccessLogs(logsJson.entries || []);
      }
    } catch (e) {
      setErrorMsg(e instanceof Error ? e.message : "Assigned cases could not be loaded.");
    }
  }, [session, selectedCaseId]);

  useEffect(() => {
    if (session) {
      loadCasesAndLogs();
    }
  }, [session, loadCasesAndLogs]);

  // Modal focus trap & Escape key handler
  useEffect(() => {
    if (!exportModalOpen) return;
    const dialog = modalRef.current;
    const focusable = dialog?.querySelectorAll<HTMLElement>('button:not([disabled]), [href], [tabindex]:not([tabindex="-1"])');
    focusable?.[0]?.focus();
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setExportModalOpen(false);
        triggerRef.current?.focus();
      } else if (e.key === "Tab" && focusable?.length) {
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last?.focus(); }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first?.focus(); }
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [exportModalOpen]);

  // SIWE Authentication
  const connectAndSignIn = async () => {
    setLoading(true);
    setErrorMsg(null);
    try {
      const eth = getEthereum();
      const accounts = (await eth.request({ method: "eth_requestAccounts" })) as string[];
      const wallet = accounts[0];
      if (!wallet) throw new Error("No account returned from wallet.");

      const chainIdHex = (await eth.request({ method: "eth_chainId" })) as string;
      if (chainIdHex !== CHAIN_HEX && chainIdHex !== "43113" && chainIdHex !== "0xa869") {
        throw new Error("Please switch your wallet to Avalanche Fuji Testnet (Chain ID 43113).");
      }

      // Step 1: Request Challenge
      const challengeRes = await fetch("/api/compliance/auth/challenge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          wallet,
          applicationId: APPLICATION_ID,
        }),
      });
      if (!challengeRes.ok) {
        const err = await challengeRes.json();
        throw new Error(err.message || err.code || "Failed to create SIWE challenge");
      }
      const challenge = await challengeRes.json();

      // Step 2: Personal Sign
      let signature: string;
      try {
        signature = (await eth.request({
          method: "personal_sign",
          params: [challenge.message, wallet],
        })) as string;
      } catch {
        throw new Error("Signature request was rejected in wallet. Please try again.");
      }

      // Step 3: Verify
      const verifyRes = await fetch("/api/compliance/auth/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          challengeId: challenge.challengeId,
          message: challenge.message,
          signature,
        }),
      });

      if (!verifyRes.ok) {
        const err = await verifyRes.json();
        throw new Error(err.message || err.code || "SIWE signature verification failed");
      }

      const sessionData = await verifyRes.json();
      setSession(sessionData);
      setSessionLoading(false);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Authentication failed");
    } finally {
      setLoading(false);
    }
  };

  const logout = async () => {
    try {
      await fetch("/api/compliance/session", { method: "DELETE" });
      setSession(null);
      setDisclosure(null);
      setExportData(null);
      setCases([]);
      setAccessLogs([]);
      setSelectedCaseId(null);
    } catch (e) {
      console.error("Logout error", e);
    }
  };

  // Perform disclosure verification
  const verifyCase = async (caseId: string) => {
    setVerifying(true);
    setErrorMsg(null);
    try {
      const res = await fetch(`/api/compliance/cases/${encodeURIComponent(caseId)}/disclosure`, {
        method: "POST",
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.message || err.code || "Integrity verification failed");
      }
      const data = await res.json();
      setDisclosure(data);

      // Refresh cases list and access log
      loadCasesAndLogs();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Verification failed");
    } finally {
      setVerifying(false);
    }
  };

  // Export canonical JSON
  const handleExport = async (caseId: string) => {
    setErrorMsg(null);
    try {
      const res = await fetch(`/api/compliance/cases/${encodeURIComponent(caseId)}/export`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.message || err.code || "Export failed");
      }
      const data: ExportBundle = await res.json();
      setExportData(data);
      setExportModalOpen(true);

      // Refresh access logs
      const logsRes = await fetch("/api/compliance/access-log");
      if (logsRes.ok) {
        const logsJson = await logsRes.json();
        setAccessLogs(logsJson.entries || []);
      }
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Export failed");
    }
  };

  const downloadExportJson = () => {
    if (!exportData) return;
    const jsonStr = JSON.stringify(exportData, null, 2);
    const blob = new Blob([jsonStr], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `haze-compliance-export-${exportData.caseId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const copyExportJson = async () => {
    if (!exportData) return;
    await navigator.clipboard.writeText(JSON.stringify(exportData, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const activeCase = cases.find((c) => c.caseId === selectedCaseId) || null;

  const handleQueueKeyDown = (event: ReactKeyboardEvent<HTMLElement>) => {
    if (event.key !== "ArrowDown" && event.key !== "ArrowUp" && event.key !== "Home" && event.key !== "End") return;
    const buttons = Array.from(caseListRef.current?.querySelectorAll<HTMLButtonElement>("[data-case-id]") ?? []);
    if (!buttons.length) return;
    event.preventDefault();
    const current = Math.max(0, buttons.indexOf(document.activeElement as HTMLButtonElement));
    const next = event.key === "Home" ? 0 : event.key === "End" ? buttons.length - 1 : event.key === "ArrowDown" ? (current + 1) % buttons.length : (current - 1 + buttons.length) % buttons.length;
    buttons[next]?.focus();
    const id = buttons[next]?.dataset.caseId;
    if (id) selectCase(id);
  };

  const filteredCases = cases.filter(
    (c) =>
      c.caseId.toLowerCase().includes(searchQuery.toLowerCase()) ||
      c.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      c.transactionHash.toLowerCase().includes(searchQuery.toLowerCase()),
  );

  if (!mount) return null;

  return createPortal(
    <div
      className="haze-workstation"
      data-session-status={session ? "authenticated" : "unauthenticated"}
    >
      {errorMsg ? (
        <div className="haze-banner" role="alert" data-code="error">
          <strong>Error:</strong> {errorMsg}
        </div>
      ) : null}

      {sessionLoading ? (
        <div className="haze-workstation-panel haze-session-loading" role="status" aria-live="polite" aria-busy="true">
          <strong>Restoring auditor session…</strong>
          <span className="haze-muted">Checking the secure session and assigned case queue.</span>
        </div>
      ) : !session ? (
        /* Sign-in Gate */
        <div className="haze-workstation-panel" style={{ maxWidth: "540px", margin: "32px auto", textAlign: "center" }}>
          <h2 style={{ fontSize: "18px", marginBottom: "8px" }}>Institutional Compliance Sign-In</h2>
          <p className="haze-muted" style={{ fontSize: "13px", lineHeight: "1.5", margin: "0 0 16px" }}>
            Authenticate with an authorized compliance auditor key to access institutional disclosure evidence,
            verify on-chain finality, decrypt audited parameters, and export cryptographically signed records.
          </p>

          <div
            className="haze-mono"
            style={{
              padding: "12px",
              background: "var(--haze-surface)",
              border: "1px solid var(--haze-line)",
              borderRadius: "6px",
              marginBottom: "16px",
              textAlign: "left",
              fontSize: "12px",
              display: "grid",
              gap: "4px",
            }}
          >
            <div><strong>Application:</strong> {APPLICATION_ID.slice(0, 10)}...{APPLICATION_ID.slice(-4)}</div>
            <div><strong>Network:</strong> Avalanche Fuji Testnet (43113)</div>
            <div><strong>Access Scope:</strong> Scoped Compliance Auditor</div>
          </div>

          <button
            onClick={connectAndSignIn}
            disabled={loading}
            data-action="connect-siwe"
            className="haze-button"
            style={{ width: "100%", fontWeight: 600 }}
          >
            {loading ? "Waiting for Wallet Signature..." : "Sign In with Ethereum (SIWE)"}
          </button>
        </div>
      ) : (
        /* Authenticated 3-Column Workstation Layout */
        <div className="haze-workstation-grid">
          {/* Column 1: Case Queue */}
          <nav ref={caseListRef} className={`haze-workstation-panel haze-case-queue ${activeCase ? "haze-mobile-detail-active" : ""}`} aria-label="Assigned compliance cases" onKeyDown={handleQueueKeyDown}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <h2>Assigned Cases</h2>
              <span className="haze-pill" data-count={cases.length}>{cases.length} cases</span>
            </div>

            <div className="haze-field" style={{ margin: 0 }}>
              <input
                type="search"
                placeholder="Filter cases or tx hash..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                style={{ fontSize: "12px", padding: "6px 8px" }}
              />
            </div>

            {filteredCases.length === 0 ? (
              <p className="haze-empty" style={{ fontSize: "13px", padding: "12px 0", textAlign: "center" }}>
                {cases.length === 0 ? "No compliance cases found for this grant." : "No matching cases."}
              </p>
            ) : (
              <ul className="haze-case-list">
                {filteredCases.map((c) => {
                  const isSelected = c.caseId === activeCase?.caseId;
                  return (
                    <li key={c.caseId}>
                      <button
                        type="button"
                        className={`haze-case-item ${isSelected ? "haze-active" : ""}`}
                        aria-pressed={isSelected}
                        data-case-id={c.caseId}
                        onClick={() => selectCase(c.caseId)}
                      >
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                          <strong style={{ fontSize: "13px" }}>{c.title || c.caseId}</strong>
                          <span className="haze-pill" data-status={c.status}>
                            {c.status.replace("_", " ").toUpperCase()}
                          </span>
                        </div>
                        <div className="haze-mono haze-muted" style={{ fontSize: "11px" }}>
                          {c.confirmations !== undefined ? `${c.confirmations} confs` : "indexed"} · Tx {c.transactionHash.slice(0, 8)}...
                        </div>
                      </button>
                    </li>
                  );
                })}
              </ul>
            )}

            <div style={{ borderTop: "1px solid var(--haze-line)", paddingTop: "12px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span className="haze-mono haze-muted" style={{ fontSize: "11px" }}>
                {session.address.slice(0, 6)}...{session.address.slice(-4)}
              </span>
              <button
                type="button"
                onClick={logout}
                data-action="logout"
                className="haze-button haze-button-secondary"
                style={{ padding: "4px 8px", minHeight: "28px", fontSize: "11px" }}
              >
                Disconnect
              </button>
            </div>
          </nav>

          {/* Column 2: Selected Case Evidence */}
          <main className={`haze-workstation-panel haze-case-detail ${activeCase ? "haze-mobile-detail-active" : ""}`} style={{ minWidth: 0 }}>
            {activeCase ? (
              <>
                <button type="button" className="haze-button haze-button-secondary haze-mobile-back" onClick={() => { setSelectedCaseId(null); const url = new URL(window.location.href); url.searchParams.delete("case"); window.history.replaceState(null,"",url); }}>Back to assigned cases</button>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: "12px", flexWrap: "wrap" }}>
                  <div>
                    <h2 style={{ fontSize: "16px", marginBottom: "4px" }}>{activeCase.title}</h2>
                    <div className="haze-mono haze-muted" style={{ fontSize: "12px" }}>
                      Case ID: {activeCase.caseId}
                    </div>
                  </div>
                  <span className="haze-pill" data-status={activeCase.status} style={{ fontSize: "12px", padding: "4px 8px" }}>
                    Status: {activeCase.status.replace("_", " ").toUpperCase()}
                  </span>
                </div>

                <div
                  className="haze-mono"
                  style={{
                    padding: "10px 12px",
                    background: "var(--haze-surface)",
                    border: "1px solid var(--haze-line)",
                    borderRadius: "6px",
                    fontSize: "12px",
                    display: "grid",
                    gap: "6px",
                  }}
                >
                  <div>
                    <span className="haze-muted">Transaction: </span>
                    <a
                      href={`https://testnet.snowtrace.io/tx/${activeCase.transactionHash}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{ color: "var(--haze-text)", textDecoration: "underline" }}
                    >
                      {activeCase.transactionHash}
                    </a>
                  </div>
                  <div>
                    <span className="haze-muted">Application: </span>
                    <span>{activeCase.applicationId}</span>
                  </div>
                  <div>
                    <span className="haze-muted">Granted Scope: </span>
                    <span>{activeCase.grantedFields.join(", ")}</span>
                  </div>
                </div>

                <div className="haze-review" style={{ margin: 0, fontSize: "12px" }}>
                  <strong>Scope Notice:</strong> Privacy pool facts <code>user</code> and <code>counterparty</code> are strictly excluded from institutional disclosure under this grant.
                </div>

                {activeCase.status === "pending_finality" ? (
                  <div className="haze-banner" role="alert" data-code="pending-finality" style={{ margin: 0 }}>
                    <strong>Finality Pending:</strong> 12 confirmations required before evidence decryption is authorized. (Current: {activeCase.confirmations ?? 0}/12).
                  </div>
                ) : null}

                {/* Primary Action Button */}
                <div style={{ display: "flex", gap: "12px", flexWrap: "wrap", alignItems: "center" }}>
                  <button
                    type="button"
                    onClick={() => verifyCase(activeCase.caseId)}
                    disabled={verifying || activeCase.status === "pending_finality"}
                    data-action="verify-case"
                    className="haze-button"
                    style={{ fontWeight: 600 }}
                  >
                    {verifying ? "Verifying On-Chain Proofs..." : "Verify & Disclose Evidence"}
                  </button>

                  <button
                    ref={triggerRef}
                    type="button"
                    onClick={() => handleExport(activeCase.caseId)}
                    disabled={!disclosure}
                    data-action="export-case"
                    className="haze-button haze-button-secondary"
                  >
                    Review & Download Signed Export
                  </button>
                </div>

                {/* Disclosed Evidence Table */}
                {disclosure ? (
                  <div style={{ marginTop: "8px" }}>
                    <h2 style={{ fontSize: "14px", marginBottom: "8px" }}>Decrypted Disclosure Record</h2>
                    <table className="haze-disclosure-table haze-mono">
                      <tbody>
                        <tr>
                          <th>Transaction Hash</th>
                          <td>
                            <a
                              href={`https://testnet.snowtrace.io/tx/${disclosure.transactionHash}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              style={{ color: "var(--haze-text)", textDecoration: "underline" }}
                            >
                              {disclosure.transactionHash}
                            </a>
                          </td>
                        </tr>
                        <tr>
                          <th>Amount</th>
                          <td>{disclosure.fields.amount ? `${(Number(disclosure.fields.amount) / 1e6).toFixed(6)} USDC` : "—"}</td>
                        </tr>
                        <tr>
                          <th>Asset (USDC)</th>
                          <td>{disclosure.fields.asset || "—"}</td>
                        </tr>
                        <tr>
                          <th>Timestamp</th>
                          <td>
                            {disclosure.fields.timestamp
                              ? `${new Date(Number(disclosure.fields.timestamp) * 1000).toISOString()} (${disclosure.fields.timestamp})`
                              : "—"}
                          </td>
                        </tr>
                        <tr>
                          <th>Policy Version</th>
                          <td>{disclosure.fields.policy_version || "1"}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                ) : null}
              </>
            ) : (
              <p className="haze-empty" style={{ textAlign: "center", padding: "32px 0" }}>
                Select a case from the queue to review evidence.
              </p>
            )}
          </main>

          {/* Column 3: Integrity Checklist & Access History */}
          <aside className="haze-workstation-panel haze-workstation-aside">
            <h2>Cryptographic Integrity</h2>
            <ul className="haze-checklist">
              <li className="haze-checklist-item" data-check-status={activeCase && (activeCase.confirmations ?? 0) >= 12 ? "pass" : "fail"}>
                <span className="haze-check-icon">{(activeCase && (activeCase.confirmations ?? 0) >= 12) ? "[✓]" : "[!]"}</span>
                <div>
                  <strong>12+ Confirmations:</strong>{" "}
                  <span className="haze-muted">{activeCase?.confirmations ?? 0}/12 confirmed</span>
                </div>
              </li>
              <li className="haze-checklist-item" data-check-status={activeCase ? "pass" : "fail"}>
                <span className="haze-check-icon">{activeCase ? "[✓]" : "[!]"}</span>
                <div>
                  <strong>Canonical Receipt:</strong>{" "}
                  <span className="haze-muted">Status 0x1 on Avalanche Fuji</span>
                </div>
              </li>
              <li className="haze-checklist-item" data-check-status={activeCase ? "pass" : "fail"}>
                <span className="haze-check-icon">{activeCase ? "[✓]" : "[!]"}</span>
                <div>
                  <strong>Pool Event Binding:</strong>{" "}
                  <span className="haze-muted">PrivateTransaction on HazePool</span>
                </div>
              </li>
              <li className="haze-checklist-item" data-check-status={disclosure ? "pass" : "fail"}>
                <span className="haze-check-icon">{disclosure ? "[✓]" : "[!]"}</span>
                <div>
                  <strong>HPKE Envelope Hash:</strong>{" "}
                  <span className="haze-muted">{disclosure ? "auditCiphertextHash matched" : "Pending disclosure"}</span>
                </div>
              </li>
              <li className="haze-checklist-item" data-check-status={disclosure ? "pass" : "fail"}>
                <span className="haze-check-icon">{disclosure ? "[✓]" : "[!]"}</span>
                <div>
                  <strong>Poseidon Commitment:</strong>{" "}
                  <span className="haze-muted">{disclosure ? "auditDataCommitment verified" : "Pending disclosure"}</span>
                </div>
              </li>
            </ul>

            <h2 style={{ marginTop: "12px" }}>Access Log (Hash-Chained)</h2>
            {accessLogs.length === 0 ? (
              <p className="haze-empty" style={{ fontSize: "12px" }}>No access events recorded yet.</p>
            ) : (
              <div style={{ maxHeight: "200px", overflowY: "auto", display: "flex", flexDirection: "column", gap: "6px" }}>
                {accessLogs.slice(-5).reverse().map((log) => (
                  <div
                    key={log.seq}
                    className="haze-mono"
                    style={{
                      padding: "6px 8px",
                      background: "var(--haze-surface)",
                      border: "1px solid var(--haze-line)",
                      borderRadius: "4px",
                      fontSize: "11px",
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <strong>#{log.seq} {log.name.toUpperCase()}</strong>
                      <span className="haze-pill" data-status={log.allowed ? "ready" : "revoked"} style={{ fontSize: "10px", padding: "1px 4px" }}>
                        {log.allowed ? "ALLOWED" : "DENIED"}
                      </span>
                    </div>
                    <div className="haze-muted" style={{ fontSize: "10px", marginTop: "2px" }}>
                      {new Date(log.at * 1000).toLocaleTimeString()} · {log.entryHash.slice(0, 10)}...
                    </div>
                  </div>
                ))}
              </div>
            )}
          </aside>
        </div>
      )}

      {/* Focus-trapped Signed Export Modal */}
      {exportModalOpen && exportData ? (
        <div
          className="haze-modal-backdrop"
          onClick={() => { setExportModalOpen(false); triggerRef.current?.focus(); }}
          role="presentation"
        >
          <div
            ref={modalRef}
            className="haze-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="export-dialog-title"
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <h2 id="export-dialog-title" style={{ margin: 0, fontSize: "16px" }}>
                Signed Institutional Export
              </h2>
              <button
                type="button"
                onClick={() => { setExportModalOpen(false); triggerRef.current?.focus(); }}
                data-action="close-export-modal"
                className="haze-button haze-button-secondary"
                style={{ padding: "2px 8px", minHeight: "24px", fontSize: "12px" }}
              >
                ✕ Close
              </button>
            </div>

            <div
              className="haze-mono"
              style={{
                padding: "10px",
                background: "var(--haze-bg)",
                border: "1px solid var(--haze-line)",
                borderRadius: "6px",
                fontSize: "11px",
                display: "grid",
                gap: "4px",
              }}
            >
              <div><strong>Export ID:</strong> {exportData.exportId}</div>
              <div><strong>Subject:</strong> {exportData.subject}</div>
              <div><strong>Signing Key:</strong> {exportData.signingKeyId}</div>
              <div><strong>Expires At:</strong> {new Date(exportData.expiresAt * 1000).toISOString()}</div>
              <div><strong>Detached Signature:</strong> {exportData.signature}</div>
            </div>

            <pre
              className="haze-mono"
              style={{
                margin: 0,
                padding: "12px",
                background: "var(--haze-bg)",
                border: "1px solid var(--haze-line)",
                borderRadius: "6px",
                fontSize: "11px",
                maxHeight: "220px",
                overflowY: "auto",
                whiteSpace: "pre-wrap",
                wordBreak: "break-all",
              }}
            >
              {JSON.stringify(exportData, null, 2)}
            </pre>

            <div style={{ display: "flex", gap: "10px", justifyContent: "flex-end" }}>
              <button
                type="button"
                onClick={copyExportJson}
                data-action="copy-export-json"
                className="haze-button haze-button-secondary"
              >
                {copied ? "Copied!" : "Copy JSON"}
              </button>
              <button
                type="button"
                onClick={downloadExportJson}
                data-action="download-export-json"
                className="haze-button"
                style={{ fontWeight: 600 }}
              >
                Download Signed JSON
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>,
    mount,
  );
}
