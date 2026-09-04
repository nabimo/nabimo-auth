import { randomInt, randomUUID } from "node:crypto";
import { authErrors } from "./errors.js";
import { normalizeEmail, normalizePhone } from "./credentials.js";
import { sha256 } from "../crypto/hash.js";

export type OtpVerificationType = "email_otp" | "phone_otp";

export interface VerificationRecord {
  id: string;
  userId: string | null;
  type: OtpVerificationType;
  target: string;
  codeHash: string;
  expiresAt: Date;
  consumedAt: Date | null;
  attempts: number;
}

export interface OtpIssuancePolicy {
  cooldownSeconds: number;
  maxRequests: number;
  requestWindowSeconds: number;
  maxActiveChallenges: number;
}

export interface VerificationStore {
  create(input: {
    id: string;
    userId: string | null;
    type: OtpVerificationType;
    target: string;
    codeHash: string;
    expiresAt: Date;
  }): Promise<void>;
  createWithPolicy(input: {
    id: string;
    userId: string | null;
    type: OtpVerificationType;
    target: string;
    codeHash: string;
    expiresAt: Date;
    now: Date;
    policy: OtpIssuancePolicy;
  }): Promise<void>;
  findActive(id: string, now: Date): Promise<VerificationRecord | null>;
  incrementAttempts(id: string): Promise<void>;
  /** Atomically consumes an active challenge. */
  consume(id: string, now: Date): Promise<boolean>;
  markVerified(userId: string, type: OtpVerificationType): Promise<void>;
}

export interface VerificationCodeSender {
  send(input: { type: OtpVerificationType; target: string; code: string }): Promise<void>;
}

export interface OtpChallenge {
  challengeId: string;
  type: OtpVerificationType;
  target: string;
  expiresAt: Date;
}

export interface VerificationServiceConfig {
  store: VerificationStore;
  sender: VerificationCodeSender;
  ttlSeconds?: number;
  maxAttempts?: number;
  otpPolicy?: Partial<OtpIssuancePolicy>;
}

export class VerificationService {
  private readonly ttlSeconds: number;
  private readonly maxAttempts: number;
  private readonly otpPolicy: OtpIssuancePolicy;

  constructor(private readonly config: VerificationServiceConfig) {
    this.ttlSeconds = config.ttlSeconds ?? 10 * 60;
    this.maxAttempts = config.maxAttempts ?? 5;
    this.otpPolicy = {
      cooldownSeconds: config.otpPolicy?.cooldownSeconds ?? 60,
      maxRequests: config.otpPolicy?.maxRequests ?? 5,
      requestWindowSeconds: config.otpPolicy?.requestWindowSeconds ?? 60 * 60,
      maxActiveChallenges: config.otpPolicy?.maxActiveChallenges ?? 3,
    };
  }

  async requestEmailOtp(userId: string | null, emailInput: string): Promise<OtpChallenge> {
    return this.requestOtp(userId, "email_otp", normalizeEmail(emailInput));
  }

  async requestPhoneOtp(userId: string | null, phoneInput: string): Promise<OtpChallenge> {
    return this.requestOtp(userId, "phone_otp", normalizePhone(phoneInput));
  }

  async verifyOtp(challengeId: string, code: string): Promise<void> {
    const now = new Date();
    const challenge = await this.config.store.findActive(challengeId, now);
    if (!challenge || challenge.consumedAt || challenge.expiresAt <= now || challenge.attempts >= this.maxAttempts) {
      throw authErrors.invalidOtp();
    }

    if (sha256(code) !== challenge.codeHash) {
      await this.config.store.incrementAttempts(challengeId);
      throw authErrors.invalidOtp();
    }

    // Consume atomically so concurrent requests cannot both verify the same OTP.
    const consumed = await this.config.store.consume(challengeId, now);
    if (!consumed) throw authErrors.invalidOtp();

    if (challenge.userId) await this.config.store.markVerified(challenge.userId, challenge.type);
  }

  private async requestOtp(userId: string | null, type: OtpVerificationType, target: string): Promise<OtpChallenge> {
    const now = new Date();
    const code = randomInt(0, 1_000_000).toString().padStart(6, "0");
    const challengeId = randomUUID();
    const expiresAt = new Date(now.getTime() + this.ttlSeconds * 1000);

    await this.config.store.createWithPolicy({
      id: challengeId,
      userId,
      type,
      target,
      codeHash: sha256(code),
      expiresAt,
      now,
      policy: this.otpPolicy,
    });
    await this.config.sender.send({ type, target, code });

    return { challengeId, type, target, expiresAt };
  }
}
