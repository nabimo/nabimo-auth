import { randomUUID } from "node:crypto";
import { authErrors } from "./errors.js";
import { generateToken } from "../crypto/token.js";
import { sha256 } from "../crypto/hash.js";
import type { TwoFactorService } from "./two-factor.js";

export interface TwoFactorLoginChallenge { challengeToken: string; userId: string; expiresAt: Date; }
export interface TwoFactorLoginStore {
  create(input: { id: string; userId: string; tokenHash: string; expiresAt: Date }): Promise<void>;
  find(input: { tokenHash: string; now: Date; maxAttempts: number }): Promise<{ userId: string } | null>;
  incrementAttempts(input: { tokenHash: string; now: Date; maxAttempts: number }): Promise<boolean>;
  consume(input: { tokenHash: string; now: Date }): Promise<boolean>;
}
export interface TwoFactorLoginServiceConfig {
  store: TwoFactorLoginStore;
  twoFactor: Pick<TwoFactorService, "verify" | "verifyRecoveryCode" | "isEnabled">;
  ttlSeconds?: number;
  maxAttempts?: number;
}

export class TwoFactorLoginService {
  private readonly ttlSeconds: number;
  private readonly maxAttempts: number;

  constructor(private readonly config: TwoFactorLoginServiceConfig) {
    this.ttlSeconds = config.ttlSeconds ?? 5 * 60;
    this.maxAttempts = config.maxAttempts ?? 5;
  }

  async configuredForUser(userId: string): Promise<boolean> { return this.config.twoFactor.isEnabled(userId); }

  async createChallenge(userId: string): Promise<TwoFactorLoginChallenge> {
    if (!await this.config.twoFactor.isEnabled(userId)) throw authErrors.invalidTwoFactorCode();
    const { token, hash } = generateToken(32);
    const expiresAt = new Date(Date.now() + this.ttlSeconds * 1000);
    await this.config.store.create({ id: randomUUID(), userId, tokenHash: hash, expiresAt });
    return { challengeToken: token, userId, expiresAt };
  }

  async verifyChallenge(challengeToken: string, code: string): Promise<string> {
    if (typeof challengeToken !== "string" || challengeToken.length < 32 || typeof code !== "string" || code.length === 0) throw authErrors.invalidTwoFactorCode();
    const tokenHash = sha256(challengeToken);
    const now = new Date();
    const challenge = await this.config.store.find({ tokenHash, now, maxAttempts: this.maxAttempts });
    if (!challenge) throw authErrors.invalidTwoFactorCode();
    if (!await this.config.store.incrementAttempts({ tokenHash, now, maxAttempts: this.maxAttempts })) throw authErrors.invalidTwoFactorCode();

    try {
      await this.config.twoFactor.verify(challenge.userId, code);
    } catch {
      try {
        await this.config.twoFactor.verifyRecoveryCode(challenge.userId, code);
      } catch {
        throw authErrors.invalidTwoFactorCode();
      }
    }

    if (!await this.config.store.consume({ tokenHash, now: new Date() })) throw authErrors.invalidTwoFactorCode();
    return challenge.userId;
  }
}
