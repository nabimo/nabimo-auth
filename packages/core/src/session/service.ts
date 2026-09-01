import { randomUUID } from "node:crypto";
import { createRefreshToken } from "./refresh-token.js";

export interface SessionPolicy {
  accessTokenTtlSeconds: number;
  refreshTokenTtlSeconds: number;
}

export const DEFAULT_SESSION_POLICY: SessionPolicy = {
  accessTokenTtlSeconds: 15 * 60,
  refreshTokenTtlSeconds: 30 * 24 * 60 * 60,
};

export interface NewSession {
  sessionId: string;
  familyId: string;
  refreshToken: string;
  refreshTokenHash: string;
  expiresAt: Date;
}

export function createSession(now = Date.now(), policy: SessionPolicy = DEFAULT_SESSION_POLICY): NewSession {
  validatePolicy(policy);
  const sessionId = randomUUID();
  const familyId = randomUUID();
  const refresh = createRefreshToken(familyId);

  return {
    sessionId,
    familyId,
    refreshToken: refresh.token,
    refreshTokenHash: refresh.tokenHash,
    expiresAt: new Date(now + policy.refreshTokenTtlSeconds * 1000),
  };
}

function validatePolicy(policy: SessionPolicy): void {
  if (!Number.isInteger(policy.accessTokenTtlSeconds) || policy.accessTokenTtlSeconds < 60 || policy.accessTokenTtlSeconds > 3600) {
    throw new RangeError("Access token TTL must be between 60 and 3600 seconds");
  }
  if (!Number.isInteger(policy.refreshTokenTtlSeconds) || policy.refreshTokenTtlSeconds < 300) {
    throw new RangeError("Refresh token TTL must be at least 300 seconds");
  }
}
