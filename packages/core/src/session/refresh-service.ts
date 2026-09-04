import { randomUUID } from "node:crypto";
import { authErrors } from "../auth/errors.js";
import { createAccessTokenClaims, DEFAULT_ACCESS_TOKEN_POLICY } from "../auth/token-policy.js";
import { signAccessToken } from "../crypto/jwt.js";
import { createRefreshToken, hashRefreshToken } from "./refresh-token.js";
import { DEFAULT_SESSION_POLICY } from "./service.js";

export interface RefreshTokenStore {
  getRefreshToken(tokenHash: string): Promise<{
    userId: string;
    email: string | null;
    sessionId: string;
    familyId: string;
    sessionExpiresAt: Date;
    sessionRevokedAt: Date | null;
    expiresAt: Date;
    usedAt: Date | null;
    revokedAt: Date | null;
  } | null>;

  rotateRefreshToken(input: {
    tokenHash: string;
    now: Date;
    familyId: string;
    newTokenId: string;
    newTokenHash: string;
    newTokenExpiresAt: Date;
  }): Promise<boolean>;
}

export interface RefreshServiceConfig {
  refreshTokens: RefreshTokenStore;
  jwtPrivateKeyPem: string;
  jwtKeyId: string;
  issuer?: string;
  audience?: string;
}

export class RefreshService {
  constructor(private readonly config: RefreshServiceConfig) {}

  async refresh(refreshToken: string, now = new Date()) {
    if (typeof refreshToken !== "string" || refreshToken.length < 32) {
      throw authErrors.invalidCredentials();
    }

    const tokenHash = hashRefreshToken(refreshToken);
    const stored = await this.config.refreshTokens.getRefreshToken(tokenHash);
    if (!stored) throw authErrors.invalidCredentials();

    // Do not reject used tokens here. The persistence layer must receive them
    // so it can atomically detect reuse and revoke the entire token family.
    // This is security-critical: rejecting here would bypass reuse detection.
    if (stored.revokedAt || stored.sessionRevokedAt || stored.expiresAt <= now || stored.sessionExpiresAt <= now) {
      throw authErrors.invalidCredentials();
    }

    const replacement = createRefreshToken(stored.familyId);
    const replacementId = randomUUID();
    const rotated = await this.config.refreshTokens.rotateRefreshToken({
      tokenHash,
      now,
      familyId: stored.familyId,
      newTokenId: replacementId,
      newTokenHash: replacement.tokenHash,
      newTokenExpiresAt: stored.sessionExpiresAt,
    });

    if (!rotated) throw authErrors.invalidCredentials();

    const claims = createAccessTokenClaims(
      stored.userId,
      stored.sessionId,
      randomUUID(),
      Math.floor(now.getTime() / 1000),
      {
        issuer: this.config.issuer ?? DEFAULT_ACCESS_TOKEN_POLICY.issuer,
        audience: this.config.audience ?? DEFAULT_ACCESS_TOKEN_POLICY.audience,
        ttlSeconds: DEFAULT_SESSION_POLICY.accessTokenTtlSeconds,
      },
    );

    return {
      user: { id: stored.userId, email: stored.email },
      sessionId: stored.sessionId,
      accessToken: signAccessToken(claims, this.config.jwtPrivateKeyPem, this.config.jwtKeyId),
      refreshToken: replacement.token,
    };
  }
}
