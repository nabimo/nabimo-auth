import { randomToken } from "../crypto/random.js";
import type { AuthChallenge, AuthMethod } from "./types.js";

export function createAuthChallenge(
  userId: string,
  method: AuthMethod,
  requiresTwoFactor: boolean,
  ttlSeconds = 300,
): AuthChallenge {
  if (!Number.isInteger(ttlSeconds) || ttlSeconds <= 0 || ttlSeconds > 900) {
    throw new RangeError("Challenge TTL must be between 1 and 900 seconds");
  }

  return {
    challengeId: randomToken(32),
    userId,
    method,
    requiresTwoFactor,
    expiresAt: new Date(Date.now() + ttlSeconds * 1000),
  };
}

export function isChallengeExpired(challenge: AuthChallenge, now = Date.now()): boolean {
  return challenge.expiresAt.getTime() <= now;
}
