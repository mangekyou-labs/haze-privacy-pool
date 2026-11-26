(() => {
  async function post(path, body) {
    const response = await fetch(path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body ?? {}),
    });
    return response.json();
  }

  function setBalanceFigure(selector, value) {
    const el = document.querySelector(selector);
    if (el && value != null) {
      el.textContent = `${value} USDC`;
    }
  }

  async function hydrateBalances() {
    if (!document.querySelector("[data-pool-usdc]")) {
      return;
    }
    try {
      const data = await fetch("/api/live-balances").then((response) => response.json());
      setBalanceFigure('[data-balance="public"] .haze-figure', data.publicUsdc);
      setBalanceFigure('[data-balance="private"] .haze-figure', data.privateUsdc);
      setBalanceFigure("[data-pool-usdc] .haze-figure", data.poolUsdc);
    } catch {
      /* keep last rendered figures */
    }
  }

  globalThis.hazeRefreshBalances = hydrateBalances;
  void hydrateBalances();

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
    if (control.tagName === "A") {
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
        const started = await post("/api/portal/siwe/start", {});
        await post("/api/portal/siwe/complete", { nonce: started.nonce });
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
})();
