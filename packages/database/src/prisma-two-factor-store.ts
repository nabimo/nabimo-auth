import type { TwoFactorStore } from "@nabimo-auth/core";
import type { PrismaClient } from "./generated/client.js";

export class PrismaTwoFactorStore implements TwoFactorStore {
  constructor(private readonly db: PrismaClient) {}

  async get(userId: string) {
    const factor = await this.db.twoFactor.findUnique({ where: { userId } });
    if (!factor) return null;
    return {
      userId: factor.userId,
      secretCipher: factor.secretCipher,
      enabledAt: factor.enabledAt,
    };
  }

  async savePending(input: { id: string; userId: string; secretCipher: string; recoveryCodeHashes: string[] }): Promise<void> {
    await this.db.$transaction(async (tx) => {
      await tx.twoFactor.upsert({
        where: { userId: input.userId },
        create: { id: input.id, userId: input.userId, secretCipher: input.secretCipher },
        update: { secretCipher: input.secretCipher, enabledAt: null },
      });
      await tx.recoveryCode.deleteMany({ where: { userId: input.userId } });
      await tx.recoveryCode.createMany({
        data: input.recoveryCodeHashes.map((codeHash) => ({ userId: input.userId, codeHash })),
      });
    });
  }

  async enable(userId: string, enabledAt: Date): Promise<boolean> {
    const result = await this.db.twoFactor.updateMany({
      where: { userId, enabledAt: null },
      data: { enabledAt },
    });
    return result.count === 1;
  }

  async disable(userId: string): Promise<boolean> {
    return this.db.$transaction(async (tx) => {
      const result = await tx.twoFactor.deleteMany({ where: { userId } });
      await tx.recoveryCode.deleteMany({ where: { userId } });
      return result.count === 1;
    });
  }

  async consumeRecoveryCode(userId: string, codeHash: string, now: Date): Promise<boolean> {
    const result = await this.db.recoveryCode.updateMany({
      where: { userId, codeHash, usedAt: null },
      data: { usedAt: now },
    });
    return result.count === 1;
  }
}
