import { randomUUID } from "node:crypto";
import { authErrors } from "./errors.js";
import { createAccessTokenClaims, DEFAULT_ACCESS_TOKEN_POLICY } from "./token-policy.js";
import { createPasswordHash, verifyUserPassword } from "./password.js";
import { normalizeEmail } from "./credentials.js";
import { createSession, DEFAULT_SESSION_POLICY, type SessionPolicy } from "../session/service.js";
import { signAccessToken } from "../crypto/jwt.js";
import type { TwoFactorLoginService } from "./two-factor-login.js";
import { DEFAULT_PASSWORD_LOGIN_RATE_LIMIT_POLICY, RateLimiter, type RateLimitPolicy } from "./rate-limit.js";

export interface RegistrationTransactionStore {
  registerUser(input: { email: string; passwordHash: string; sessionId: string; familyId: string; refreshTokenHash: string; sessionExpiresAt: Date }): Promise<{ id: string; email: string | null }>;
}

export interface AuthUserStore {
  findByEmail(email: string): Promise<{ id: string; email: string | null; passwordCredential: { passwordHash: string } | null } | null>;
  findById(id: string): Promise<{ id: string; email: string | null } | null>;
}

export interface SessionStore {
  create(input: { id: string; userId: string; familyId: string; expiresAt: Date; refreshTokenHash: string }): Promise<void>;
}

export interface AuthServiceConfig {
  users: AuthUserStore;
  sessions: SessionStore;
  registration: RegistrationTransactionStore;
  jwtPrivateKeyPem: string;
  jwtKeyId: string;
  issuer?: string;
  audience?: string;
  sessionPolicy?: SessionPolicy;
  twoFactorLogin?: TwoFactorLoginService;
  loginRateLimiter?: RateLimiter;
  loginRateLimitPolicy?: RateLimitPolicy;
}

export interface TwoFactorRequiredAuthentication {
  twoFactorRequired: true;
  user: { id: string; email: string };
  challengeToken: string;
  challengeExpiresAt: Date;
}

export class AuthService {
  constructor(private readonly config: AuthServiceConfig) {}

  async registerWithPassword(emailInput: string, password: string) {
    const email = normalizeEmail(emailInput);
    const existing = await this.config.users.findByEmail(email);
    if (existing) throw authErrors.accountAlreadyExists();
    const passwordHash = await createPasswordHash(password);
    const session = createSession(Date.now(), this.config.sessionPolicy ?? DEFAULT_SESSION_POLICY);
    const user = await this.config.registration.registerUser({ email, passwordHash, sessionId: session.sessionId, familyId: session.familyId, refreshTokenHash: session.refreshTokenHash, sessionExpiresAt: session.expiresAt });
    return this.createAuthenticationResult(user.id, user.email ?? email, session);
  }

  async loginWithPassword(emailInput: string, password: string): Promise<ReturnType<AuthService["createAuthenticationResult"]> | TwoFactorRequiredAuthentication> {
    const email = normalizeEmail(emailInput);
    const user = await this.config.users.findByEmail(email);
    const passwordHash = user?.passwordCredential?.passwordHash;
    if (!passwordHash) {
      await this.recordFailedLogin(email);
      throw authErrors.invalidCredentials();
    }

    try {
      await verifyUserPassword(password, passwordHash);
    } catch {
      await this.recordFailedLogin(email);
      throw authErrors.invalidCredentials();
    }

    if (this.config.twoFactorLogin && await this.config.twoFactorLogin.configuredForUser(user.id)) {
      const challenge = await this.config.twoFactorLogin.createChallenge(user.id);
      return { twoFactorRequired: true, user: { id: user.id, email: user.email ?? email }, challengeToken: challenge.challengeToken, challengeExpiresAt: challenge.expiresAt };
    }

    return this.createSessionResult(user.id, user.email ?? email);
  }

  async completeTwoFactorLogin(challengeToken: string, code: string) {
    if (!this.config.twoFactorLogin) throw authErrors.invalidTwoFactorCode();
    const userId = await this.config.twoFactorLogin.verifyChallenge(challengeToken, code);
    const user = await this.config.users.findById(userId);
    if (!user) throw authErrors.invalidCredentials();
    return this.createSessionResult(user.id, user.email ?? "");
  }

  private async recordFailedLogin(email: string): Promise<void> {
    if (!this.config.loginRateLimiter) return;
    await this.config.loginRateLimiter.check(
      `password-login:${email}`,
      this.config.loginRateLimitPolicy ?? DEFAULT_PASSWORD_LOGIN_RATE_LIMIT_POLICY,
    );
  }

  private async createSessionResult(userId: string, email: string) {
    const session = createSession(Date.now(), this.config.sessionPolicy ?? DEFAULT_SESSION_POLICY);
    await this.config.sessions.create({ id: session.sessionId, userId, familyId: session.familyId, expiresAt: session.expiresAt, refreshTokenHash: session.refreshTokenHash });
    return this.createAuthenticationResult(userId, email, session);
  }

  private createAuthenticationResult(userId: string, email: string, session: ReturnType<typeof createSession>) {
    const sessionPolicy = this.config.sessionPolicy ?? DEFAULT_SESSION_POLICY;
    const claims = createAccessTokenClaims(userId, session.sessionId, randomUUID(), Math.floor(Date.now() / 1000), {
      issuer: this.config.issuer ?? DEFAULT_ACCESS_TOKEN_POLICY.issuer,
      audience: this.config.audience ?? DEFAULT_ACCESS_TOKEN_POLICY.audience,
      ttlSeconds: sessionPolicy.accessTokenTtlSeconds,
    });
    return { user: { id: userId, email }, sessionId: session.sessionId, accessToken: signAccessToken(claims, this.config.jwtPrivateKeyPem, this.config.jwtKeyId), refreshToken: session.refreshToken };
  }
}
