import { authErrors } from "@nabimo-auth/core";
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

  async createWithPolicy(input: Parameters<VerificationStore["createWithPolicy"]>[0]): Promise<void> {
    const lockKey = `${input.type}:${input.target}`;
    await this.db.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${lockKey}))`;

      const cooldownSince = new Date(input.now.getTime() - input.policy.cooldownSeconds * 1000);
      const windowSince = new Date(input.now.getTime() - input.policy.requestWindowSeconds * 1000);
      const prismaType = toPrismaType(input.type);

      const latest = await tx.verification.findFirst({
        where: { target: input.target, type: prismaType },
        orderBy: { createdAt: "desc" },
        select: { createdAt: true },
      });
      if (latest && latest.createdAt > cooldownSince) throw authErrors.otpCooldown();

      const recentRequests = await tx.verification.count({
        where: { target: input.target, type: prismaType, createdAt: { gt: windowSince } },
      });
      if (recentRequests >= input.policy.maxRequests) throw authErrors.otpRateLimited();

      const activeRequests = await tx.verification.count({
        where: { target: input.target, type: prismaType, consumedAt: null, expiresAt: { gt: input.now } },
      });
      if (activeRequests >= input.policy.maxActiveChallenges) throw authErrors.otpRateLimited();

      await tx.verification.create({
        data: {
          id: input.id,
          userId: input.userId,
          type: prismaType,
          target: input.target,
          codeHash: input.codeHash,
          expiresAt: input.expiresAt,
        },
      });
    });
  }

  async findActive(id: string, now: Date): Promise<VerificationRecord | null> {
    const record = await this.db.verification.findFirst({ where: { id, expiresAt: { gt: now }, consumedAt: null } });
    if (!record || (record.type !== "EMAIL_OTP" && record.type !== "PHONE_OTP") || !record.codeHash) return null;
    return { id: record.id, userId: record.userId, type: toCoreType(record.type), target: record.target, codeHash: record.codeHash, expiresAt: record.expiresAt, consumedAt: record.consumedAt, attempts: record.attempts };
  }

  async incrementAttempts(id: string): Promise<void> {
    await this.db.verification.updateMany({ where: { id, consumedAt: null }, data: { attempts: { increment: 1 } } });
  }

  async consume(id: string, now: Date): Promise<void> {
    await this.db.verification.updateMany({ where: { id, consumedAt: null, expiresAt: { gt: now } }, data: { consumedAt: now } });
  }

  async markVerified(userId: string, type: OtpVerificationType): Promise<void> {
    await this.db.user.update({ where: { id: userId }, data: type === "email_otp" ? { emailVerified: true } : { phoneVerified: true } });
  }
}
