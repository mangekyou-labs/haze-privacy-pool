import type { ReactNode } from "react";
import "../../../packages/ui/src/theme.css";

export const metadata = { title: "Haze" };

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
