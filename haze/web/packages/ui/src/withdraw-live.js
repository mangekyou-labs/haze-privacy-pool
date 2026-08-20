(() => {
  const form = document.querySelector('form[data-live="true"]');
  if (!form) {
    return;
  }
  const status = form.querySelector("[data-live-status]");
  const phase = form.querySelector("[data-prove-phase]");
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const provider = globalThis.ethereum;
    if (!provider?.request) {
      status.textContent = "WALLET_MISSING";
      return;
    }
    const fields = new FormData(form);
    const amountUsdc = Number(fields.get("amount") || "1");
    const amount = Math.round(amountUsdc * 1_000_000);
    const recipient = String(fields.get("recipient") || "").trim();
    try {
      const accounts = await provider.request({ method: "eth_requestAccounts" });
      const user = accounts[0];
      await provider
        .request({
          method: "wallet_switchEthereumChain",
          params: [{ chainId: "0xa869" }],
        })
        .catch(() => undefined);
      if (phase) {
        phase.textContent = "Planning the operator withdraw…";
      }
      const planned = await fetch("/api/live-withdraw/plan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ user, amount, recipient: recipient || user }),
      });
      const plan = await planned.json();
      if (!plan.allowed) {
        status.textContent = plan.reason || "KEYS_MISSING";
        return;
      }
      if (phase) {
        phase.textContent = "Proving Groth16 spend — this can take several minutes.";
      }
      const proved = await fetch("/api/live-withdraw/prove", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ user, amount, recipient: recipient || user }),
      });
      const proof = await proved.json();
      if (!proof.allowed || !proof.proofBytes) {
        status.textContent = proof.reason || "KEYS_MISSING";
        return;
      }
      plan.proof = proof.proofBytes;
      if (phase) {
        phase.textContent = "Confirm the authorization in your wallet.";
      }
      const signature = await provider.request({
        method: "eth_signTypedData_v4",
        params: [user, JSON.stringify(plan.typedData)],
      });
      const encoded = await fetch("/api/live-withdraw/encode", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ plan, signature }),
      });
      const transact = await encoded.json();
      if (phase) {
        phase.textContent = "Submitting the withdraw…";
      }
      const hash = await provider.request({
        method: "eth_sendTransaction",
        params: [{ from: user, to: transact.to, data: transact.data }],
      });
      if (phase) {
        phase.textContent = "Withdraw submitted.";
      }
      status.textContent = hash;
    } catch (error) {
      status.textContent = error?.message || "LIVE_WITHDRAW_FAILED";
    }
  });
})();
