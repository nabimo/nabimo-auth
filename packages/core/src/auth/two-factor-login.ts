import { randomUUID } from "node:crypto";
import { authErrors } from "./errors.js";
import { generateToken } from "../crypto/token.js";
import { sha256 } from "../crypto/hash.js";
import type { TwoFactorService } from "./two-factor.js";

export interface TwoFactorLoginChallenge {
  challengeToken: string;
  userId: string;
  expiresAt: Date;
}

export interface TwoFactorLoginStore {
  create(input: { id: string; userId: string; tokenHash: string; expiresAt: Date }): Promise<void>;
  consume(input: { tokenHash: string; now: Date }): Promise<string | null>;
}

export interface TwoFactorLoginServiceConfig {
  store: TwoFactorLoginStore;
  twoFactor: Pick<TwoFactorService, "verify" | "isEnabled">;
  ttlSeconds?: number;
}

export class TwoFactorLoginService {
  private readonly ttlSeconds: number;

  constructor(private readonly config: TwoFactorLoginServiceConfig) {
    this.ttlSeconds = config.ttlSeconds ?? 5 * 60;
  }

  async createChallenge(userId: string): Promise<TwoFactorLoginChallenge> {
    if (!await this.config.twoFactor.isEnabled(userId)) {
      throw authErrors.invalidTwoFactorCode();
    }

    const { token, hash } = generateToken(32);
    const expiresAt = new Date(Date.now() + this.ttlSeconds * 1000);
    await this.config.store.create({ id: randomUUID(), userId, tokenHash: hash, expiresAt });
    return { challengeToken: token, userId, expiresAt };
  }

  async verifyChallenge(challengeToken: string, code: string): Promise<string> {
    if (typeof challengeToken !== "string" || challengeToken.length < 32 || !/^\d{6}$/.test(code)) {
      throw authErrors.invalidTwoFactorCode();
    }

    const userId = await this.config.store.consume({ tokenHash: sha256(challengeToken), now: new Date() });
    if (!userId) throw authErrors.invalidTwoFactorCode();

    try {
      await this.config.twoFactor.verify(userId, code);
    } catch (error) {
      throw error;
    }

    return userId;
  }
}
