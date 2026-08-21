import type { NextConfig } from "next";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const nextConfig: NextConfig = {
  transpilePackages: ["@haze-avalanche/ui"],
  poweredByHeader: false,
  webpack(config) {
    config.resolve.alias["web-worker"] = resolve(dirname(fileURLToPath(import.meta.url)), "../../../node_modules/web-worker/cjs/browser.js");
    return config;
  },
  async headers() {
    const disclosureOrigin = process.env.NEXT_PUBLIC_HAZE_DISCLOSURE_ORIGIN || "https://haze-fuji-disclosure.onrender.com";
    const disclosureConnect = disclosureOrigin.startsWith("https://") ? ` ${disclosureOrigin}` : "";
    return [
      {
        source: "/:path*",
        headers: [
          {
            key: "Content-Security-Policy",
            value:
              `default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval' 'unsafe-eval' blob:; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://api.avax-test.network https://*.public.blob.vercel-storage.com https://*.vercel-storage.com${disclosureConnect}; worker-src 'self' blob:; font-src 'self'`,
          },
        ],
      },
    ];
  },
};

export default nextConfig;
