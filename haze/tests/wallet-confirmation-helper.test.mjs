import assert from "node:assert/strict";
import test from "node:test";
import { confirmVisibleWalletAction } from "../dev/wallet-confirmation-helper.mjs";

function createMockPopup({ alertVisible = false, confirmVisible = true, clickError = null, alertOnFail = false } = {}) {
  let alertIsVisible = alertVisible;
  let alertDismissed = false;
  let confirmClicked = false;

  const mockAlertButton = {
    isVisible: async () => alertIsVisible && !alertDismissed,
    isEnabled: async () => true,
    click: async () => { alertDismissed = true; alertIsVisible = false; },
  };

  const mockAlert = {
    isVisible: async () => alertIsVisible && !alertDismissed,
    getByRole: (role) => {
      if (role === "button") {
        return { last: () => mockAlertButton };
      }
      return mockAlertButton;
    },
  };

  const mockConfirmButton = {
    isVisible: async () => confirmVisible,
    isEnabled: async () => true,
    click: async () => {
      if (clickError) {
        if (alertOnFail) {
          alertIsVisible = true;
        }
        throw clickError;
      }
      confirmClicked = true;
    },
  };

  const mockPopup = {
    url: () => "chrome-extension://nkbihfbeogaeaoehlefnkodbefgpgknn/notification.html",
    bringToFront: async () => {},
    getByTestId: (testId) => {
      if (testId === "alert-modal") return mockAlert;
      const locator = {
        or: () => locator,
        first: () => mockConfirmButton,
        isVisible: mockConfirmButton.isVisible,
        isEnabled: mockConfirmButton.isEnabled,
        click: mockConfirmButton.click,
      };
      return locator;
    },
    getByRole: () => {
      const locator = {
        or: () => locator,
        first: () => mockConfirmButton,
        isVisible: mockConfirmButton.isVisible,
        isEnabled: mockConfirmButton.isEnabled,
        click: mockConfirmButton.click,
      };
      return locator;
    },
    get state() {
      return { alertIsVisible, alertDismissed, confirmClicked };
    },
  };

  return mockPopup;
}

test("confirmVisibleWalletAction dismisses an already visible alert modal", async () => {
  const popup = createMockPopup({ alertVisible: true, confirmVisible: false });
  const context = { pages: () => [popup] };
  const origin = "https://haze-mu-flax.vercel.app";

  const handled = await confirmVisibleWalletAction({ context, origin });
  assert.equal(handled, true);
  assert.equal(popup.state.alertDismissed, true);
});

test("confirmVisibleWalletAction retries when alert races confirmation click", async () => {
  let attempts = 0;
  const mockAlertButton = {
    isVisible: async () => true,
    isEnabled: async () => true,
    click: async () => {},
  };
  const mockAlert = {
    isVisible: async () => attempts > 0,
    getByRole: () => ({ last: () => mockAlertButton }),
  };
  const mockConfirmButton = {
    isVisible: async () => true,
    isEnabled: async () => true,
    click: async () => {
      attempts += 1;
      if (attempts === 1) {
        throw new Error("Element obscured");
      }
    },
  };

  const mockLocator = {
    or() { return mockLocator; },
    first() { return mockConfirmButton; },
    isVisible: async () => true,
    isEnabled: async () => true,
    click: mockConfirmButton.click,
  };

  const popup = {
    url: () => "chrome-extension://metamask/notification.html",
    bringToFront: async () => {},
    getByTestId: (id) => id === "alert-modal" ? mockAlert : mockLocator,
    getByRole: () => mockLocator,
  };

  const context = { pages: () => [popup] };
  const origin = "https://haze-mu-flax.vercel.app";

  const handled = await confirmVisibleWalletAction({ context, origin });
  assert.equal(handled, true);
  assert.equal(attempts, 2);
});

test("confirmVisibleWalletAction propagates unrelated click errors when no alert appears", async () => {
  const popup = createMockPopup({ clickError: new Error("Target detached"), alertOnFail: false });
  const context = { pages: () => [popup] };
  const origin = "https://haze-mu-flax.vercel.app";

  await assert.rejects(
    async () => { await confirmVisibleWalletAction({ context, origin }); },
    /Target detached/
  );
});
