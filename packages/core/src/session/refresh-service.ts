import { randomUUID } from "node:crypto";
import { authErrors } from "../auth/errors.js";
import { createAccessTokenClaims, DEFAULT_ACCESS_TOKEN_POLICY } from "../auth/token-policy.js";
import { signAccessToken } from "../crypto/jwt.js";
import { createRefreshToken, hashRefreshToken } from "./refresh-token.js";
import { DEFAULT_SESSION_POLICY } from "./service.js";

export interface RefreshTokenStore {
  rotateRefreshToken(input: {
    tokenHash: string;
    now: Date;
    newTokenHash: string;
    newTokenFamilyId: string;
    newTokenExpiresAt: Date;
    replacedBy: string;
  }): Promise<{
    userId: string;
    email: string | null;
    sessionId: string;
    familyId: string;
    sessionExpiresAt: Date;
  } | null>;
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
    const tokenId = randomUUID();
    const familyId = randomUUID();
    const replacement = createRefreshToken(familyId);
    const result = await this.config.refreshTokens.rotateRefreshToken({
      tokenHash,
      now,
      newTokenHash: replacement.tokenHash,
      newTokenFamilyId: replacement.familyId,
      newTokenExpiresAt: new Date(now.getTime() + DEFAULT_SESSION_POLICY.refreshTokenTtlSeconds * 1000),
      replacedBy: tokenId,
    });

    if (!result) throw authErrors.invalidCredentials();

    const claims = createAccessTokenClaims(
      result.userId,
      result.sessionId,
      randomUUID(),
      Math.floor(now.getTime() / 1000),
      {
        issuer: this.config.issuer ?? DEFAULT_ACCESS_TOKEN_POLICY.issuer,
        audience: this.config.audience ?? DEFAULT_ACCESS_TOKEN_POLICY.audience,
        ttlSeconds: DEFAULT_SESSION_POLICY.accessTokenTtlSeconds,
      },
    );

    return {
      user: { id: result.userId, email: result.email },
      sessionId: result.sessionId,
      accessToken: signAccessToken(claims, this.config.jwtPrivateKeyPem, this.config.jwtKeyId),
      refreshToken: replacement.token,
    };
  }
}
