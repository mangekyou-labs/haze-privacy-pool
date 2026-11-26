// Live Fuji v2 deployment (deployments/fuji-v2.live.json). Every value here is public.
// Apps read NEXT_PUBLIC_HAZE_* env overrides first and fall back to these.
export const FUJI_V2 = {
  chainId: 43113,
  pool: "0x2A75Ed378cf23Dd724A4077cF122E87491172e71",
  router: "0xd4a102FaCcf541b28a1dD7baa19989b88e531D26",
  applicationRegistry: "0xF7BFcAF26a2A20A4CE3322D2Bd986a0F43336b38",
  policyRegistry: "0xD3039e93AdA153f6e331998415608e34609f5fff",
  usdc: "0x5425890298aed601595a70AB815c96711a31Bc65",
  // First block to scan for pool events; earlier blocks cannot hold any.
  deploymentBlock: 61513413,
  // v2 was deployed with approvedExit = address(0) and has no predecessor to migrate from.
  emergencyExit: "",
  migrationPool: "",
  disclosureOrigin: "https://haze-fuji-disclosure-uegs.onrender.com",
  // Public half of the HAZE_FUJI_AUDIT_IKM held by the Render disclosure service.
  auditPublicKey: "0x1b9b5de7274e874632960720219be873afa5fd0249347e3900763d8a774c2546",
} as const;
