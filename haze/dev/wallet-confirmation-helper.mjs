/** Helper to dismiss MetaMask alert modals and confirm wallet actions with bounded retries and error propagation. */

export function isWalletNotificationPage(url) {
  return /(?:notification|confirmation)\.html/i.test(String(url || ""));
}

export function hasWalletNotification(context) {
  return (context?.pages?.() || []).some((popup) => {
    try {
      return isWalletNotificationPage(popup.url());
    } catch {
      return false;
    }
  });
}

export async function confirmVisibleWalletAction({ context, origin, maxRetries = 3 }) {
  for (const popup of context.pages()) {
    if (popup === pageRef(popup, origin)) continue;
    let popupUrl = "";
    try {
      popupUrl = popup.url();
    } catch {
      continue;
    }
    if (!isWalletNotificationPage(popupUrl)) continue;

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

    // Check for custom spending cap "Use default" or "Max" buttons
    const useDefault = popup.getByRole("button", { name: /^(Use default|Max|Max amount)$/i }).or(popup.getByTestId("custom-spending-cap-max")).first();
    if (await useDefault.isVisible().catch(() => false) && await useDefault.isEnabled().catch(() => false)) {
      await popup.bringToFront().catch(() => {});
      await useDefault.click({ force: true }).catch(() => {});
    }

    // EIP-712 / SIWE: MetaMask keeps Confirm disabled until the payload is scrolled.
    // Evaluate without bringToFront so probing does not pin MetaMask over other Playwright windows.
    if (typeof popup.evaluate === "function") {
      try {
        await popup.evaluate(() => {
          const byTestId = document.querySelector(
            '[data-testid="confirm-scroll-to-bottom-button"], [data-testid="signature-request-scroll-button"]',
          );
          if (byTestId && !byTestId.disabled) byTestId.click();
          const named = [...document.querySelectorAll("button")].find((button) =>
            /scroll (down|to bottom)/i.test(button.textContent || ""),
          );
          if (named && !named.disabled) named.click();
        });
      } catch (error) {
        const msg = String(error?.message || error);
        if (msg.includes("Target page, context or browser has been closed") || msg.includes("Execution context was destroyed") || msg.includes("Target closed")) {
          return true;
        }
        // MetaMask LavaMoat scuttles page.evaluate; fall through to locator Confirm.
        if (!(msg.includes("LavaMoat") || msg.includes("scuttling mode"))) {
          throw error;
        }
      }
    }

    // Check for confirmation button
    const button = popup
      .getByTestId("confirm-footer-button")
      .or(popup.getByTestId("confirm-btn"))
      .or(popup.getByTestId("page-container-footer-next"))
      .or(popup.getByTestId("confirmation-submit-button"))
      .or(popup.getByTestId("page-container-footer-cancel").locator("..").getByRole("button", { name: /^(Confirm|Approve|Next|Sign|Submit|Got it)$/i }))
      .or(popup.getByRole("button", { name: /^(Confirm|Approve|Next|Sign|Submit|Got it|I understand)$/i }))
      .first();
    if (await button.isVisible().catch(() => false)) {
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
