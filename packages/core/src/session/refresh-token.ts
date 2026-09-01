import { createHash } from "node:crypto";
import { randomToken } from "../crypto/random.js";
import type { RefreshTokenPair } from "./types.js";

export function createRefreshToken(familyId: string): RefreshTokenPair {
  const token = randomToken(48);
  return {
    token,
    tokenHash: hashRefreshToken(token),
    familyId,
  };
}

export function hashRefreshToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}
