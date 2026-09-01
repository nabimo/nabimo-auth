import type { PrismaClient } from "./generated/client.js";

export interface RegisterTransactionInput {
  email: string;
  passwordHash: string;
  sessionId: string;
  familyId: string;
  refreshTokenHash: string;
  sessionExpiresAt: Date;
}

export async function createUserWithSession(
  db: PrismaClient,
  input: RegisterTransactionInput,
) {
  return db.$transaction(async (tx) => {
    const existing = await tx.user.findUnique({ where: { email: input.email } });
    if (existing) throw new Error("ACCOUNT_ALREADY_EXISTS");

    const user = await tx.user.create({
      data: {
        email: input.email,
        passwordHash: input.passwordHash,
      },
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

    return user;
  });
}
