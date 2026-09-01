import type { PrismaClient } from "./generated/client.js";
import type { RegistrationTransactionStore } from "@nabimo-auth/core";

export class PrismaRegistrationTransactionStore implements RegistrationTransactionStore {
  constructor(private readonly db: PrismaClient) {}

  async registerUser(input: Parameters<RegistrationTransactionStore["registerUser"]>[0]) {
    return this.db.$transaction(async (tx) => {
      const existing = await tx.user.findUnique({ where: { email: input.email } });
      if (existing) throw new Error("ACCOUNT_ALREADY_EXISTS");

      const user = await tx.user.create({
        data: { email: input.email, passwordHash: input.passwordHash },
      });

      await tx.session.create({
        data: {
          id: input.sessionId,
          userId: user.id,
          expiresAt: input.sessionExpiresAt,
        },
      });

      await tx.refreshToken.create({
        data: {
          userId: user.id,
          sessionId: input.sessionId,
          tokenHash: input.refreshTokenHash,
          familyId: input.familyId,
          expiresAt: input.sessionExpiresAt,
        },
      });

      return { id: user.id, email: user.email };
    });
  }
}
