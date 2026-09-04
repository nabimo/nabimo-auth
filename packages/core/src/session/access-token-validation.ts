import { authErrors } from "../auth/errors.js";
import { verifyAccessToken, type AccessTokenClaims } from "../crypto/jwt.js";
import { DEFAULT_ACCESS_TOKEN_POLICY } from "../auth/token-policy.js";
import { isActive, type ManagedSessionRecord } from "./management.js";

export interface AccessTokenSessionStore {
  getSession(sessionId: string): Promise<ManagedSessionRecord | null>;
}

export interface AccessTokenValidationConfig {
  publicKeyPem: string;
  sessions: AccessTokenSessionStore;
  issuer?: string;
  audience?: string;
}

export interface ValidatedAccessToken {
  claims: AccessTokenClaims;
  session: ManagedSessionRecord;
}

export class AccessTokenValidationService {
  constructor(private readonly config: AccessTokenValidationConfig) {}

  async validate(token: string, now = new Date()): Promise<ValidatedAccessToken> {
    const nowSeconds = Math.floor(now.getTime() / 1000);
    if (!Number.isSafeInteger(nowSeconds)) throw authErrors.invalidCredentials();

    const claims = verifyAccessToken(token, this.config.publicKeyPem, nowSeconds);
    if (!claims) throw authErrors.invalidCredentials();

    const issuer = this.config.issuer ?? DEFAULT_ACCESS_TOKEN_POLICY.issuer;
    const audience = this.config.audience ?? DEFAULT_ACCESS_TOKEN_POLICY.audience;
    if (claims.iss !== issuer || claims.aud !== audience) {
      throw authErrors.invalidCredentials();
    }

    const session = await this.config.sessions.getSession(claims.sid);
    if (!session || session.userId !== claims.sub || !isActive(session, now)) {
      throw authErrors.invalidCredentials();
    }

    return { claims, session };
  }
}
