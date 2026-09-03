import type { PrismaClient } from "./generated/client.js";
import type { OtpVerificationType, VerificationRecord, VerificationStore } from "@nabimo-auth/core";

function toPrismaType(type: OtpVerificationType) {
  return type === "email_otp" ? "EMAIL_OTP" as const : "PHONE_OTP" as const;
}

function toCoreType(type: "EMAIL_OTP" | "PHONE_OTP"): OtpVerificationType {
  return type === "EMAIL_OTP" ? "email_otp" : "phone_otp";
}

export class PrismaVerificationStore implements VerificationStore {
  constructor(private readonly db: PrismaClient) {}

  async create(input: Parameters<VerificationStore["create"]>[0]): Promise<void> {
    await this.db.verification.create({
      data: {
        id: input.id,
        userId: input.userId,
        type: toPrismaType(input.type),
        target: input.target,
        codeHash: input.codeHash,
        expiresAt: input.expiresAt,
      },
    });
  }

  async findActive(id: string, now: Date): Promise<VerificationRecord | null> {
    const record = await this.db.verification.findFirst({
      where: { id, expiresAt: { gt: now }, consumedAt: null },
    });
    if (!record || (record.type !== "EMAIL_OTP" && record.type !== "PHONE_OTP") || !record.codeHash) return null;
    return {
      id: record.id,
      userId: record.userId,
      type: toCoreType(record.type),
      target: record.target,
      codeHash: record.codeHash,
      expiresAt: record.expiresAt,
      consumedAt: record.consumedAt,
      attempts: record.attempts,
    };
  }

  async incrementAttempts(id: string): Promise<void> {
    await this.db.verification.update({ where: { id }, data: { attempts: { increment: 1 } } });
  }

  async consume(id: string, now: Date): Promise<void> {
    await this.db.verification.updateMany({
      where: { id, consumedAt: null, expiresAt: { gt: now } },
      data: { consumedAt: now },
    });
  }

  async markVerified(userId: string, type: OtpVerificationType): Promise<void> {
    await this.db.user.update({
      where: { id: userId },
      data: type === "email_otp" ? { emailVerified: true } : { phoneVerified: true },
    });
  }
}
