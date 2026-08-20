(() => {
  const form = document.querySelector('form[data-live="true"]');
  if (!form) {
    return;
  }
  const status = form.querySelector("[data-live-status]");
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const provider = globalThis.ethereum;
    if (!provider?.request) {
      status.textContent = "WALLET_MISSING";
      return;
    }
    const amountUsdc = Number(new FormData(form).get("amount") || "1");
    const amount = Math.round(amountUsdc * 1_000_000);
    try {
      const accounts = await provider.request({ method: "eth_requestAccounts" });
      const user = accounts[0];
      await provider.request({
        method: "wallet_switchEthereumChain",
        params: [{ chainId: "0xa869" }],
      }).catch(() => undefined);
      const planned = await fetch("/api/live-deposit/plan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ user, amount }),
      });
      const plan = await planned.json();
      if (!plan.allowed) {
        status.textContent = plan.reason || "LIVE_DEPOSIT_DENIED";
        return;
      }
      if (plan.operatorHatch) {
        status.textContent = "Proving Groth16 deposit — this can take several minutes.";
        const proved = await fetch("/api/live-deposit/prove", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            user,
            amount,
            leafIndex: plan.circuitPlan?.note?.leafIndex,
          }),
        });
        const proof = await proved.json();
        if (!proof.allowed || !proof.proofBytes) {
          status.textContent = proof.reason || "KEYS_MISSING";
          return;
        }
        plan.proof = proof.proofBytes;
      }
      await provider.request({
        method: "eth_sendTransaction",
        params: [{ from: user, to: plan.approve.to, data: plan.approve.data }],
      });
      const signature = await provider.request({
        method: "eth_signTypedData_v4",
        params: [user, JSON.stringify(plan.typedData)],
      });
      const encoded = await fetch("/api/live-deposit/encode", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ plan, signature }),
      });
      const deposit = await encoded.json();
      const hash = await provider.request({
        method: "eth_sendTransaction",
        params: [{ from: user, to: deposit.to, data: deposit.data }],
      });
      let receipt = null;
      const minedDeadline = Date.now() + 180_000;
      while (Date.now() < minedDeadline) {
        receipt = await provider.request({
          method: "eth_getTransactionReceipt",
          params: [hash],
        });
        if (receipt) {
          break;
        }
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
      if (!receipt || receipt.status !== "0x1") {
        status.textContent = "RECEIPT_REVERTED";
        return;
      }
      if (plan.operatorHatch && plan.circuitPlan) {
        await fetch("/api/live-deposit/persist", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ plan: plan.circuitPlan }),
        });
      }
      status.textContent = hash;
    } catch (error) {
      status.textContent = error?.message || "LIVE_DEPOSIT_FAILED";
    }
  });
})();
