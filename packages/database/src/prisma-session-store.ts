import type { PrismaClient } from "../generated/client.js";
import type { SessionStore } from "@nabimo-auth/core";

export class PrismaSessionStore implements SessionStore {
  constructor(private readonly db: PrismaClient) {}

  async create(input: Parameters<SessionStore["create"]>[0]): Promise<void> {
    await this.db.$transaction(async (tx) => {
      await tx.session.create({
        data: {
          id: input.id,
          userId: input.userId,
          expiresAt: input.expiresAt,
        },
      });

      await tx.refreshToken.create({
        data: {
          userId: input.userId,
          sessionId: input.id,
          tokenHash: input.refreshTokenHash,
          familyId: input.familyId,
          expiresAt: input.expiresAt,
        },
      });
    });
  }
}
