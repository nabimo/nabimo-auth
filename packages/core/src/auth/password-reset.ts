import { randomUUID } from "node:crypto";
import { authErrors } from "./errors.js";
import { normalizeEmail } from "./credentials.js";
import { createPasswordHash } from "./password.js";
import { generateToken } from "../crypto/token.js";
import { sha256 } from "../crypto/hash.js";

export interface PasswordResetStore {
  create(input: {
    id: string;
    userId: string;
    target: string;
    tokenHash: string;
    expiresAt: Date;
    now: Date;
    cooldownSeconds: number;
    maxRequests: number;
    requestWindowSeconds: number;
    maxActiveChallenges: number;
  }): Promise<void>;
  consumeAndSetPassword(input: { tokenHash: string; passwordHash: string; now: Date }): Promise<boolean>;
}

export interface PasswordResetSender {
  send(input: { target: string; token: string; expiresAt: Date }): Promise<void>;
}

export interface PasswordResetServiceConfig {
  store: PasswordResetStore;
  sender: PasswordResetSender;
  findUserByEmail(email: string): Promise<{ id: string; email: string | null } | null>;
  ttlSeconds?: number;
  cooldownSeconds?: number;
  maxRequests?: number;
  requestWindowSeconds?: number;
  maxActiveChallenges?: number;
}

export class PasswordResetService {
  private readonly ttlSeconds: number;
  private readonly cooldownSeconds: number;
  private readonly maxRequests: number;
  private readonly requestWindowSeconds: number;
  private readonly maxActiveChallenges: number;

  constructor(private readonly config: PasswordResetServiceConfig) {
    this.ttlSeconds = config.ttlSeconds ?? 30 * 60;
    this.cooldownSeconds = config.cooldownSeconds ?? 60;
    this.maxRequests = config.maxRequests ?? 5;
    this.requestWindowSeconds = config.requestWindowSeconds ?? 60 * 60;
    this.maxActiveChallenges = config.maxActiveChallenges ?? 3;
  }

  async request(emailInput: string): Promise<void> {
    const email = normalizeEmail(emailInput);
    const user = await this.config.findUserByEmail(email);
    if (!user?.email) return;

    const now = new Date();
    const { token, hash } = generateToken(32);
    const expiresAt = new Date(now.getTime() + this.ttlSeconds * 1000);
    await this.config.store.create({
      id: randomUUID(),
      userId: user.id,
      target: email,
      tokenHash: hash,
      expiresAt,
      now,
      cooldownSeconds: this.cooldownSeconds,
      maxRequests: this.maxRequests,
      requestWindowSeconds: this.requestWindowSeconds,
      maxActiveChallenges: this.maxActiveChallenges,
    });
    await this.config.sender.send({ target: email, token, expiresAt });
  }

  async confirm(token: string, newPassword: string): Promise<void> {
    if (typeof token !== "string" || token.length < 32) throw authErrors.invalidPasswordResetToken();
    const passwordHash = await createPasswordHash(newPassword);
    const reset = await this.config.store.consumeAndSetPassword({
      tokenHash: sha256(token),
      passwordHash,
      now: new Date(),
    });
    if (!reset) throw authErrors.invalidPasswordResetToken();
  }
}
