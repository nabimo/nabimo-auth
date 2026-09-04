import type { TwoFactorLoginStore } from "@nabimo-auth/core";
import type { PrismaClient } from "./generated/client.js";

export class PrismaTwoFactorLoginStore implements TwoFactorLoginStore {
  constructor(private readonly db: PrismaClient) {}

  async create(input: Parameters<TwoFactorLoginStore["create"]>[0]): Promise<void> {
    await this.db.verification.create({
      data: { id: input.id, userId: input.userId, type: "TWO_FACTOR_LOGIN", target: input.userId, tokenHash: input.tokenHash, expiresAt: input.expiresAt },
    });
  }

  async find(input: Parameters<TwoFactorLoginStore["find"]>[0]): Promise<{ userId: string } | null> {
    const record = await this.db.verification.findFirst({
      where: { tokenHash: input.tokenHash, type: "TWO_FACTOR_LOGIN", consumedAt: null, expiresAt: { gt: input.now }, attempts: { lt: 5 } },
      select: { userId: true },
    });
    return record?.userId ? { userId: record.userId } : null;
  }

  async incrementAttempts(input: Parameters<TwoFactorLoginStore["incrementAttempts"]>[0]): Promise<boolean> {
    const result = await this.db.verification.updateMany({
      where: { tokenHash: input.tokenHash, type: "TWO_FACTOR_LOGIN", consumedAt: null, expiresAt: { gt: input.now }, attempts: { lt: 5 } },
      data: { attempts: { increment: 1 } },
    });
    return result.count === 1;
  }

  async consume(input: Parameters<TwoFactorLoginStore["consume"]>[0]): Promise<boolean> {
    const result = await this.db.verification.updateMany({
      where: { tokenHash: input.tokenHash, type: "TWO_FACTOR_LOGIN", consumedAt: null, expiresAt: { gt: input.now } },
      data: { consumedAt: input.now },
    });
    return result.count === 1;
  }
}
