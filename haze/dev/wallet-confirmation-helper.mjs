/** Helper to dismiss MetaMask alert modals, scroll signatures, and confirm wallet actions. */

export async function confirmVisibleWalletAction({ context, origin, maxRetries = 3 }) {
  for (const popup of context.pages()) {
    let url = "";
    try {
      url = popup.url();
    } catch {
      // ignore
    }
    if (url && url.startsWith(origin)) {
      continue;
    }

    // Check for visible alert modal
    const alert = popup.getByTestId("alert-modal");
    if (await alert.isVisible().catch(() => false)) {
      const dismiss = alert.getByRole("button").last();
      if ((await dismiss.isVisible().catch(() => false)) && (await dismiss.isEnabled().catch(() => false))) {
        await popup.bringToFront().catch(() => {});
        await dismiss.click({ force: true }).catch(() => {});
        console.log(`[WALLET HELPER] Dismissed alert modal on ${url}`);
        return true;
      }
    }

    // Scroll down for signature requests if scroll button is present
    const scrollBtn = popup.locator("[data-testid='signature-request-scroll-button']").first();
    if (await scrollBtn.isVisible().catch(() => false)) {
      await scrollBtn.click().catch(() => {});
      console.log(`[WALLET HELPER] Clicked signature scroll button on ${url}`);
      await new Promise((resolve) => setTimeout(resolve, 250));
    }

    // Check for confirmation button
    const button = popup
      .getByTestId("confirm-footer-button")
      .or(popup.getByTestId("confirm-btn"))
      .or(popup.getByTestId("page-container-footer-next"))
      .or(popup.getByRole("button", { name: /^(Confirm|Approve|Next|Sign|Connect)$/i }))
      .first();

    if ((await button.isVisible().catch(() => false)) && (await button.isEnabled().catch(() => false))) {
      const btnText = await button.textContent().catch(() => "unknown");
      await popup.bringToFront().catch(() => {});
      for (let attempt = 0; attempt < maxRetries; attempt += 1) {
        try {
          await button.click({ timeout: 2_000, force: true });
          console.log(`[WALLET HELPER] Clicked button "${btnText.trim()}" on ${url}`);
          return true;
        } catch (error) {
          if (await alert.isVisible().catch(() => false)) {
            const dismiss = alert.getByRole("button").last();
            if ((await dismiss.isVisible().catch(() => false)) && (await dismiss.isEnabled().catch(() => false))) {
              await popup.bringToFront().catch(() => {});
              await dismiss.click({ force: true }).catch(() => {});
              continue;
            }
          }
          const msg = String(error?.message || error);
          if (
            msg.includes("Target page, context or browser has been closed") ||
            msg.includes("Execution context was destroyed") ||
            msg.includes("Target closed")
          ) {
            return true;
          }
          throw error;
        }
      }
    }
  }
  return false;
}
