import { authErrors } from "@nabimo-auth/core";
import type { PasswordResetStore } from "@nabimo-auth/core";
import type { PrismaClient } from "./generated/client.js";

export class PrismaPasswordResetStore implements PasswordResetStore {
  constructor(private readonly db: PrismaClient) {}

  async create(input: Parameters<PasswordResetStore["create"]>[0]): Promise<void> {
    await this.db.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`password_reset:${input.target}`}))`;
      const since = new Date(input.now.getTime() - input.cooldownSeconds * 1000);
      const windowSince = new Date(input.now.getTime() - input.requestWindowSeconds * 1000);

      const latest = await tx.verification.findFirst({
        where: { target: input.target, type: "PASSWORD_RESET" },
        orderBy: { createdAt: "desc" },
        select: { createdAt: true },
      });
      if (latest && latest.createdAt > since) throw authErrors.otpCooldown();

      const recent = await tx.verification.count({
        where: { target: input.target, type: "PASSWORD_RESET", createdAt: { gt: windowSince } },
      });
      if (recent >= input.maxRequests) throw authErrors.otpRateLimited();

      const active = await tx.verification.count({
        where: { target: input.target, type: "PASSWORD_RESET", consumedAt: null, expiresAt: { gt: input.now } },
      });
      if (active >= input.maxActiveChallenges) throw authErrors.otpRateLimited();

      await tx.verification.create({
        data: {
          id: input.id,
          userId: input.userId,
          type: "PASSWORD_RESET",
          target: input.target,
          tokenHash: input.tokenHash,
          expiresAt: input.expiresAt,
        },
      });
    });
  }

  async consumeAndSetPassword(input: Parameters<PasswordResetStore["consumeAndSetPassword"]>[0]): Promise<string | null> {
    return this.db.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`password_reset_token:${input.tokenHash}`}))`;
      const record = await tx.verification.findFirst({
        where: {
          tokenHash: input.tokenHash,
          type: "PASSWORD_RESET",
          consumedAt: null,
          expiresAt: { gt: input.now },
        },
        select: { id: true, userId: true },
      });
      if (!record?.userId) return null;

      const consumed = await tx.verification.updateMany({
        where: { id: record.id, consumedAt: null, expiresAt: { gt: input.now } },
        data: { consumedAt: input.now },
      });
      if (consumed.count !== 1) return null;

      await tx.passwordCredential.upsert({
        where: { userId: record.userId },
        create: { userId: record.userId, passwordHash: input.passwordHash },
        update: { passwordHash: input.passwordHash },
      });
      return record.userId;
    });
  }
}
