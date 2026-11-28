import type { NextConfig } from "next";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const nextConfig: NextConfig = {
  transpilePackages: ["@haze-avalanche/ui"],
  webpack(config, { isServer, webpack }) {
    config.resolve.alias["web-worker"] = resolve(dirname(fileURLToPath(import.meta.url)), "../../../node_modules/web-worker/cjs/browser.js");
    if (!isServer) {
      // The SDK statically imports node:crypto for server-side sealing; the browser path never calls it
      // (it seals with browser-crypto.ts), so resolve it to an empty module in client bundles.
      config.plugins.push(new webpack.NormalModuleReplacementPlugin(/^node:crypto$/, (resource: { request: string }) => { resource.request = "crypto"; }));
      config.resolve.fallback = { ...config.resolve.fallback, crypto: false };
    }
    return config;
  },
  async headers() {
    const disclosureOrigin = process.env.NEXT_PUBLIC_HAZE_DISCLOSURE_ORIGIN || "https://haze-fuji-disclosure-uegs.onrender.com";
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
