/** Helper to dismiss MetaMask alert modals and confirm wallet actions with bounded retries and error propagation. */

export async function confirmVisibleWalletAction({ context, origin, maxRetries = 3 }) {
  for (const popup of context.pages()) {
    if (popup === pageRef(popup, origin)) continue;

    // Check for visible alert modal
    const alert = popup.getByTestId("alert-modal");
    if (await alert.isVisible().catch(() => false)) {
      const dismiss = alert.getByRole("button").last();
      if (await dismiss.isVisible().catch(() => false) && await dismiss.isEnabled().catch(() => false)) {
        await popup.bringToFront().catch(() => {});
        await dismiss.click({ force: true }).catch(() => {});
        return true;
      }
    }

    // Check for confirmation button
    const button = popup
      .getByTestId("confirm-footer-button")
      .or(popup.getByTestId("confirm-btn"))
      .or(popup.getByTestId("page-container-footer-next"))
      .or(popup.getByRole("button", { name: /^(Confirm|Approve|Next|Sign)$/ }))
      .first();

    if (await button.isVisible().catch(() => false) && await button.isEnabled().catch(() => false)) {
      await popup.bringToFront().catch(() => {});
      for (let attempt = 0; attempt < maxRetries; attempt += 1) {
        try {
          await button.click({ timeout: 2_000, force: true });
          return true;
        } catch (error) {
          // If click failed, check if an alert modal appeared/raced the click
          if (await alert.isVisible().catch(() => false)) {
            const dismiss = alert.getByRole("button").last();
            if (await dismiss.isVisible().catch(() => false) && await dismiss.isEnabled().catch(() => false)) {
              await popup.bringToFront().catch(() => {});
              await dismiss.click({ force: true }).catch(() => {});
              // Continue to next attempt after alert dismissal
              continue;
            }
          }
          // If popup was closed or destroyed because MetaMask processed the action, treat as handled
          const msg = String(error?.message || error);
          if (msg.includes("Target page, context or browser has been closed") || msg.includes("Execution context was destroyed") || msg.includes("Target closed")) {
            return true;
          }
          // Unrelated click error: propagate error immediately
          throw error;
        }
      }
    }
  }
  return false;
}

function pageRef(popup, origin) {
  try {
    const url = popup.url();
    if (!url || url.startsWith(origin)) return popup;
  } catch {
    // Ignore URL read error
  }
  return null;
}
