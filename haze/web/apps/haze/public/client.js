(() => {
  async function post(path, body) {
    const response = await fetch(path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body ?? {}),
    });
    return response.json();
  }

  async function connectWallet() {
    if (!window.ethereum) {
      throw new Error("NO_INJECTED_WALLET");
    }
    const accounts = await window.ethereum.request({ method: "eth_requestAccounts" });
    const chainIdHex = await window.ethereum.request({ method: "eth_chainId" });
    return post("/api/connect", {
      address: accounts[0],
      chainId: Number.parseInt(chainIdHex, 16),
    });
  }

  async function handleSiwe() {
    if (!window.ethereum) {
      throw new Error("NO_INJECTED_WALLET");
    }
    const accounts = await window.ethereum.request({ method: "eth_requestAccounts" });
    const address = accounts[0];
    const challenge = await post("/api/compliance/auth/challenge", { address });
    if (!challenge.nonce) {
      throw new Error("CHALLENGE_FAILED");
    }
    // The server is the message authority: a server-issued `message` is the only
    // accepted preimage. Fall back to the legacy local construction only when a
    // pre-message server is talking (kept so INFRA curls do not regress).
    const message = challenge.message ??
      `${challenge.statement}\n\nURI: https://${challenge.domain}/audit\nVersion: 1\nChain ID: ${challenge.chainId}\nNonce: ${challenge.nonce}\nIssued At: ${new Date().toISOString()}`;
    const signature = await window.ethereum.request({
      method: "personal_sign",
      params: [message, address],
    });
    const verified = await post("/api/compliance/auth/verify", {
      address,
      nonce: challenge.nonce,
      signature,
    });
    if (!verified.ok) {
      throw new Error(verified.reason || "SIWE_VERIFY_FAILED");
    }
  }

  document.addEventListener("click", async (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) {
      return;
    }
    const control = target.closest("[data-action]");
    if (!(control instanceof HTMLElement)) {
      return;
    }
    const action = control.getAttribute("data-action");
    if (!action) {
      return;
    }
    if (control.tagName === "A" && !control.getAttribute("data-action")) {
      return;
    }
    event.preventDefault();
    try {
      if (action === "nav-toggle") {
        document.getElementById("haze-nav")?.classList.toggle("is-open");
        return;
      }
      if (action === "connect") {
        await connectWallet();
      } else if (action === "disconnect") {
        await fetch("/api/compliance/session", { method: "DELETE" }).catch(() => undefined);
        await post("/api/disconnect", {});
      } else if (action === "switch-network") {
        const live = document.querySelector("form[data-live='true']");
        await window.ethereum?.request({
          method: "wallet_switchEthereumChain",
          params: [{ chainId: live ? "0xa869" : "0x7a69" }],
        });
        await connectWallet();
      } else if (action === "preview") {
        await post("/api/preview", { kind: control.getAttribute("data-kind") });
      } else if (action === "run") {
        const form = control.closest("form");
        if (form?.getAttribute("data-live") === "true") {
          form.requestSubmit();
          return;
        }
        const data = form ? Object.fromEntries(new FormData(form).entries()) : {};
        await post("/api/run", {
          kind: control.getAttribute("data-kind"),
          ...data,
        });
      } else if (action === "wipe") {
        await post("/api/wipe", {});
      } else if (action === "recover") {
        await post("/api/recover", {});
      } else if (action === "manifest") {
        await post("/api/portal/manifest", {});
      } else if (action === "delegate") {
        await post("/api/portal/delegate", {});
      } else if (action === "revoke") {
        await post("/api/portal/revoke", {});
      } else if (action === "case") {
        await post("/api/portal/case", {});
      } else if (action === "siwe") {
        await handleSiwe();
      } else if (action === "select-case") {
        const caseId = control.getAttribute("data-case-id");
        if (caseId) {
          const url = new URL(window.location.href);
          url.searchParams.set("caseId", caseId);
          window.history.pushState({}, "", url);
        }
      } else if (action === "verify-disclose") {
        const caseId = control.getAttribute("data-case-id");
        if (caseId) {
          await post(`/api/compliance/cases/${encodeURIComponent(caseId)}/disclosure`, {});
        }
      } else if (action === "export-review") {
        const caseId = control.getAttribute("data-case-id");
        if (caseId) {
          const res = await post(`/api/compliance/cases/${encodeURIComponent(caseId)}/export`, {});
          if (res.export) {
            let modal = document.querySelector(".haze-modal-backdrop");
            if (!modal) {
              modal = document.createElement("div");
              modal.className = "haze-modal-backdrop";
              document.body.appendChild(modal);
            }
            modal.innerHTML = `<div class="haze-modal-dialog">
              <h2 class="haze-title">Signed Export Review</h2>
              <p class="haze-muted">Case ID: <span class="haze-mono">${escapeHtml(caseId)}</span></p>
              <pre class="haze-mono" style="background:var(--haze-bg); padding:12px; border-radius:8px; overflow-x:auto; font-size:12px;" data-export-preview>${escapeHtml(JSON.stringify(res.export, null, 2))}</pre>
              <div style="display:flex; justify-content:flex-end; gap:8px; margin-top:16px;">
                <button class="haze-button haze-button-secondary" type="button" data-action="close-modal">Close</button>
                <button class="haze-button" type="button" data-action="download-export" data-case-id="${escapeHtml(caseId)}">Download signed JSON</button>
              </div>
            </div>`;
            return;
          }
        }
      } else if (action === "download-export") {
        const caseId = control.getAttribute("data-case-id");
        const res = await post(`/api/compliance/cases/${encodeURIComponent(caseId)}/export`, {});
        const jsonStr = JSON.stringify(res.export ?? res, null, 2);
        const blob = new Blob([jsonStr], { type: "application/json" });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `compliance-case-${caseId}.json`;
        a.click();
        return;
      } else if (action === "close-modal") {
        document.querySelector(".haze-modal-backdrop")?.remove();
        return;
      } else if (action === "export") {
        await post("/api/portal/export", { fields: [control.getAttribute("data-field") || "commitment"] });
      } else if (action === "gov-preview") {
        await post("/api/governance/preview", {});
      } else if (action === "gov-execute") {
        await post("/api/governance/execute", {});
      }
      window.location.reload();
    } catch (error) {
      const status = document.querySelector("[data-error]");
      if (status) {
        status.textContent = error instanceof Error ? error.message : "UNAVAILABLE";
      }
    }
  });

  function escapeHtml(val) {
    return String(val ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] ?? c);
  }
})();
