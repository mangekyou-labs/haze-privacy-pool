import type { ReactNode } from "react";
import "../../../packages/ui/src/theme.css";
import "../../../packages/ui/fonts/plex.css";
import { WalletSessionProvider } from "./wallet-session-provider";

export const metadata = { title: "Haze" };

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <WalletSessionProvider>{children}</WalletSessionProvider>
      </body>
    </html>
  );
}
