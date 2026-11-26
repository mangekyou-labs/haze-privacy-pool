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
        locator: () => locator,
        getByRole: () => locator,
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
        locator: () => locator,
        getByRole: () => locator,
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
    locator() { return mockLocator; },
    getByRole() { return mockLocator; },
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

test("confirmVisibleWalletAction treats popup closing on confirmation click as handled", async () => {
  const popup = createMockPopup({ clickError: new Error("locator.click: Target page, context or browser has been closed"), alertOnFail: false });
  const context = { pages: () => [popup] };
  const origin = "https://haze-mu-flax.vercel.app";

  const handled = await confirmVisibleWalletAction({ context, origin });
  assert.equal(handled, true);
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

test("confirmVisibleWalletAction force-clicks a visible Confirm that MetaMask left disabled", async () => {
  let confirmClicked = false;
  const mockConfirmButton = {
    isVisible: async () => true,
    isEnabled: async () => false,
    click: async () => {
      confirmClicked = true;
    },
  };
  const mockAlert = {
    isVisible: async () => false,
    getByRole: () => ({ last: () => ({ isVisible: async () => false, isEnabled: async () => false, click: async () => {} }) }),
  };
  const confirmLocator = {
    or() { return confirmLocator; },
    locator() { return confirmLocator; },
    getByRole() { return confirmLocator; },
    first() { return mockConfirmButton; },
    isVisible: mockConfirmButton.isVisible,
    isEnabled: mockConfirmButton.isEnabled,
    click: mockConfirmButton.click,
  };
  const popup = {
    url: () => "chrome-extension://nkbihfbeogaeaoehlefnkodbefgpgknn/notification.html",
    bringToFront: async () => {},
    getByTestId: (id) => (id === "alert-modal" ? mockAlert : confirmLocator),
    getByRole: () => confirmLocator,
  };
  const handled = await confirmVisibleWalletAction({
    context: { pages: () => [popup] },
    origin: "https://haze-mu-flax.vercel.app",
  });
  assert.equal(handled, true);
  assert.equal(confirmClicked, true);
});

function createHiddenWalletChrome({ url, evaluate } = {}) {
  let fronts = 0;
  let evaluated = 0;
  const hidden = {
    isVisible: async () => false,
    isEnabled: async () => false,
    click: async () => {
      throw new Error("hidden wallet chrome must not be clicked");
    },
  };
  const locator = {
    or() { return locator; },
    locator() { return locator; },
    getByRole() { return locator; },
    first() { return hidden; },
    last() { return hidden; },
    isVisible: hidden.isVisible,
    isEnabled: hidden.isEnabled,
    click: hidden.click,
  };
  return {
    url: () => url,
    bringToFront: async () => { fronts += 1; },
    evaluate: async (...args) => {
      evaluated += 1;
      if (typeof evaluate === "function") return evaluate(...args);
    },
    getByTestId: () => locator,
    getByRole: () => locator,
    get fronts() { return fronts; },
    get evaluated() { return evaluated; },
  };
}

test("confirmVisibleWalletAction does not pin MetaMask home when no notification dialog is open", async () => {
  const home = createHiddenWalletChrome({
    url: "chrome-extension://nkbihfbeogaeaoehlefnkodbefgpgknn/home.html",
  });
  const handled = await confirmVisibleWalletAction({
    context: { pages: () => [home] },
    origin: "https://haze-mu-flax.vercel.app",
  });
  assert.equal(handled, false);
  assert.equal(home.fronts, 0);
  assert.equal(home.evaluated, 0);
});

test("confirmVisibleWalletAction does not bringToFront a notification just to probe EIP-712 scroll", async () => {
  const notification = createHiddenWalletChrome({
    url: "chrome-extension://nkbihfbeogaeaoehlefnkodbefgpgknn/notification.html",
  });
  const handled = await confirmVisibleWalletAction({
    context: { pages: () => [notification] },
    origin: "https://haze-mu-flax.vercel.app",
  });
  assert.equal(handled, false);
  assert.equal(notification.fronts, 0);
});

test("confirmVisibleWalletAction scrolls EIP-712 content then confirms a disabled footer", async () => {
  let scrolled = false;
  let confirmClicked = false;
  let confirmEnabled = false;

  const scrollButton = {
    isVisible: async () => !scrolled,
    isEnabled: async () => !scrolled,
    click: async () => {
      scrolled = true;
      confirmEnabled = true;
    },
  };

  const mockConfirmButton = {
    isVisible: async () => true,
    isEnabled: async () => confirmEnabled,
    click: async () => {
      if (!confirmEnabled) throw new Error("Element is not enabled");
      confirmClicked = true;
    },
  };

  const mockAlert = {
    isVisible: async () => false,
    getByRole: () => ({ last: () => ({ isVisible: async () => false, isEnabled: async () => false, click: async () => {} }) }),
  };

  const confirmLocator = {
    or() { return confirmLocator; },
    locator() { return confirmLocator; },
    getByRole() { return confirmLocator; },
    first() { return mockConfirmButton; },
    isVisible: mockConfirmButton.isVisible,
    isEnabled: mockConfirmButton.isEnabled,
    click: mockConfirmButton.click,
  };

  const popup = {
    url: () => "chrome-extension://nkbihfbeogaeaoehlefnkodbefgpgknn/notification.html",
    bringToFront: async () => {},
    evaluate: async () => {
      await scrollButton.click();
    },
    getByTestId: (id) => (id === "alert-modal" ? mockAlert : confirmLocator),
    getByRole: () => confirmLocator,
  };

  const handled = await confirmVisibleWalletAction({
    context: { pages: () => [popup] },
    origin: "https://haze-mu-flax.vercel.app",
  });
  assert.equal(handled, true);
  assert.equal(scrolled, true);
  assert.equal(confirmClicked, true);
});

test("confirmVisibleWalletAction still confirms when MetaMask evaluate is LavaMoat-scuttled", async () => {
  let confirmClicked = false;
  const mockConfirmButton = {
    isVisible: async () => true,
    isEnabled: async () => true,
    click: async () => {
      confirmClicked = true;
    },
  };
  const mockAlert = {
    isVisible: async () => false,
    getByRole: () => ({ last: () => ({ isVisible: async () => false, isEnabled: async () => false, click: async () => {} }) }),
  };
  const confirmLocator = {
    or() { return confirmLocator; },
    locator() { return confirmLocator; },
    getByRole() { return confirmLocator; },
    first() { return mockConfirmButton; },
    isVisible: mockConfirmButton.isVisible,
    isEnabled: mockConfirmButton.isEnabled,
    click: mockConfirmButton.click,
  };
  const popup = {
    url: () => "chrome-extension://nkbihfbeogaeaoehlefnkodbefgpgknn/notification.html",
    bringToFront: async () => {},
    evaluate: async () => {
      throw new Error(
        'LavaMoat - property "setInterval" of globalThis is inaccessible under scuttling mode. To learn more visit https://github.com/LavaMoat/LavaMoat/pull/360.',
      );
    },
    getByTestId: (id) => (id === "alert-modal" ? mockAlert : confirmLocator),
    getByRole: () => confirmLocator,
  };
  const handled = await confirmVisibleWalletAction({
    context: { pages: () => [popup] },
    origin: "https://haze-mu-flax.vercel.app",
  });
  assert.equal(handled, true);
  assert.equal(confirmClicked, true);
});
