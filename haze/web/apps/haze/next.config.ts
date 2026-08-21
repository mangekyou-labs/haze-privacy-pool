import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  transpilePackages: ["@haze-avalanche/ui"],
  poweredByHeader: false,
  async headers() {
    const disclosureOrigin = process.env.NEXT_PUBLIC_HAZE_DISCLOSURE_ORIGIN;
    const disclosureConnect = disclosureOrigin?.startsWith("https://") ? ` ${disclosureOrigin}` : "";
    return [
      {
        source: "/:path*",
        headers: [
          {
            key: "Content-Security-Policy",
            value:
              `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://api.avax-test.network${disclosureConnect}; font-src 'self'`,
          },
        ],
      },
    ];
  },
};

export default nextConfig;
