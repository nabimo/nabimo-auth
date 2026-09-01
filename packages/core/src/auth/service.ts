import { randomUUID } from "node:crypto";
import { authErrors } from "./errors.js";
import { createAccessTokenClaims, DEFAULT_ACCESS_TOKEN_POLICY } from "./token-policy.js";
import { createPasswordHash, verifyUserPassword } from "./password.js";
import { normalizeEmail } from "./credentials.js";
import { createSession, DEFAULT_SESSION_POLICY } from "../session/service.js";
import { signAccessToken } from "../crypto/jwt.js";

export interface RegistrationTransactionStore {
  registerUser(input: {
    email: string;
    passwordHash: string;
    sessionId: string;
    familyId: string;
    refreshTokenHash: string;
    sessionExpiresAt: Date;
  }): Promise<{ id: string; email: string | null }>;
}

export interface AuthUserStore {
  findByEmail(email: string): Promise<{
    id: string;
    email: string | null;
    passwordCredential: { passwordHash: string } | null;
  } | null>;
}

export interface SessionStore {
  create(input: {
    id: string;
    userId: string;
    familyId: string;
    expiresAt: Date;
    refreshTokenHash: string;
  }): Promise<void>;
}

export interface AuthServiceConfig {
  users: AuthUserStore;
  sessions: SessionStore;
  registration: RegistrationTransactionStore;
  jwtPrivateKeyPem: string;
  jwtKeyId: string;
  issuer?: string;
  audience?: string;
}

export class AuthService {
  constructor(private readonly config: AuthServiceConfig) {}

  async registerWithPassword(emailInput: string, password: string) {
    const email = normalizeEmail(emailInput);
    const existing = await this.config.users.findByEmail(email);
    if (existing) throw authErrors.accountAlreadyExists();

    const passwordHash = await createPasswordHash(password);
    const session = createSession();
    const user = await this.config.registration.registerUser({
      email,
      passwordHash,
      sessionId: session.sessionId,
      familyId: session.familyId,
      refreshTokenHash: session.refreshTokenHash,
      sessionExpiresAt: session.expiresAt,
    });

    return this.createAuthenticationResult(user.id, user.email ?? email, session);
  }

  async loginWithPassword(emailInput: string, password: string) {
    const email = normalizeEmail(emailInput);
    const user = await this.config.users.findByEmail(email);
    const passwordHash = user?.passwordCredential?.passwordHash;
    if (!passwordHash) throw authErrors.invalidCredentials();

    await verifyUserPassword(password, passwordHash);
    const session = createSession();
    await this.config.sessions.create({
      id: session.sessionId,
      userId: user.id,
      familyId: session.familyId,
      expiresAt: session.expiresAt,
      refreshTokenHash: session.refreshTokenHash,
    });

    return this.createAuthenticationResult(user.id, user.email ?? email, session);
  }

  private createAuthenticationResult(userId: string, email: string, session: ReturnType<typeof createSession>) {
    const claims = createAccessTokenClaims(
      userId,
      session.sessionId,
      randomUUID(),
      Math.floor(Date.now() / 1000),
      {
        issuer: this.config.issuer ?? DEFAULT_ACCESS_TOKEN_POLICY.issuer,
        audience: this.config.audience ?? DEFAULT_ACCESS_TOKEN_POLICY.audience,
        ttlSeconds: DEFAULT_SESSION_POLICY.accessTokenTtlSeconds,
      },
    );

    return {
      user: { id: userId, email },
      sessionId: session.sessionId,
      accessToken: signAccessToken(claims, this.config.jwtPrivateKeyPem, this.config.jwtKeyId),
      refreshToken: session.refreshToken,
    };
  }
}
