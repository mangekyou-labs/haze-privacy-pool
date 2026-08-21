export type ProverErrorCode =
  | "CANCELLED"
  | "KEYS_MISSING"
  | "UNSUPPORTED_RECOVERY"
  | "ARTIFACT_INVALID"
  | "WITNESS_INVALID"
  | "PROOF_INVALID";

export class ProverError extends Error {
  readonly code: ProverErrorCode;
  constructor(code: ProverErrorCode) {
    super(code);
    this.code = code;
    this.name = "ProverError";
  }
}

export type DevelopmentProof = {
  profile: "development";
  notForProduction: true;
  publicValue: number;
  verified: boolean;
};

export type WorkerOutbound =
  | { type: "cancelled" }
  | { type: "cleared" }
  | { type: "proof"; proof: DevelopmentProof; stages: string[] }
  | { type: "error"; code: string };
