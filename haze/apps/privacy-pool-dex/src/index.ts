/** Independent deployment boundary for the end-user product. */
export { designSystem, lintPrivacyCopy, primitive, threatModel } from "../../_shared/ux.ts";
export type { Decision, Session } from "../../_shared/ux.ts";

import {
  authorizeApi as authorizeFor,
  authorizeRoute as authorizeRouteFor,
  copyFor as factCopy,
  layoutFor as layoutAt,
  navFor as navItems,
} from "../../_shared/ux.ts";
import type { Session } from "../../_shared/ux.ts";

export const HAZE_APP_KIND = "privacy-pool-dex" as const;

export function authorizeRoute(session: Session, path: string, resource?: { applicationId?: string }) {
  return authorizeRouteFor(HAZE_APP_KIND, session, path, resource);
}

export function authorizeApi(
  session: Session,
  method: string,
  path: string,
  resource?: { applicationId?: string },
) {
  return authorizeFor(HAZE_APP_KIND, session, method, path, resource);
}

export function navFor(session: Session) {
  return navItems(HAZE_APP_KIND, session);
}

export function copyFor(fact: string) {
  return factCopy(fact);
}

export function layoutFor(width: number) {
  return layoutAt(width);
}

export { createDexApp, renderDexHtml } from "./app.ts";
export type { DexAppConfig, DexScreen, WalletStatus } from "./app.ts";
