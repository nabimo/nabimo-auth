export interface AccessTokenPolicy {
  issuer: string;
  audience: string;
  ttlSeconds: number;
}

export const DEFAULT_ACCESS_TOKEN_POLICY: AccessTokenPolicy = {
  issuer: "nabimo-auth",
  audience: "nabimo-auth-client",
  ttlSeconds: 15 * 60,
};

export function createAccessTokenClaims(
  userId: string,
  sessionId: string,
  tokenId: string,
  now = Math.floor(Date.now() / 1000),
  policy: AccessTokenPolicy = DEFAULT_ACCESS_TOKEN_POLICY,
) {
  if (!Number.isSafeInteger(now)) throw new RangeError("Invalid token timestamp");
  if (!Number.isInteger(policy.ttlSeconds) || policy.ttlSeconds < 60 || policy.ttlSeconds > 3600) {
    throw new RangeError("Access token TTL must be between 60 and 3600 seconds");
  }

  return {
    sub: userId,
    sid: sessionId,
    jti: tokenId,
    iat: now,
    exp: now + policy.ttlSeconds,
    iss: policy.issuer,
    aud: policy.audience,
  } as const;
}
