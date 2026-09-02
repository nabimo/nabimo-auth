import type { PrismaClient } from "./generated/client.js";
import type { RefreshTokenStore } from "@nabimo-auth/core";

export class PrismaRefreshTokenStore implements RefreshTokenStore {
  constructor(private readonly db: PrismaClient) {}

  async getRefreshToken(tokenHash: string) {
    const token = await this.db.refreshToken.findUnique({
      where: { tokenHash },
      include: {
        user: { select: { email: true } },
        session: { select: { expiresAt: true } },
      },
    });

    if (!token) return null;

    return {
      userId: token.userId,
      email: token.user.email,
      sessionId: token.sessionId,
      familyId: token.familyId,
      sessionExpiresAt: token.session.expiresAt,
      expiresAt: token.expiresAt,
      usedAt: token.usedAt,
      revokedAt: token.revokedAt,
    };
  }

  async rotateRefreshToken(input: Parameters<RefreshTokenStore["rotateRefreshToken"]>[0]): Promise<boolean> {
    return this.db.$transaction(async (tx) => {
      const token = await tx.refreshToken.findUnique({ where: { tokenHash: input.tokenHash } });
      if (!token) return false;

      if (token.usedAt || token.revokedAt || token.expiresAt <= input.now) {
        // Presenting an old token is a reuse signal. Revoke the whole family
        // and the associated session so an attacker cannot keep refreshing it.
        if (token.usedAt) {
          await tx.refreshToken.updateMany({
            where: { familyId: token.familyId, revokedAt: null },
            data: { revokedAt: input.now },
          });
          await tx.session.update({
            where: { id: token.sessionId },
            data: { revokedAt: input.now },
          });
        }
        return false;
      }

      const claimed = await tx.refreshToken.updateMany({
        where: {
          id: token.id,
          usedAt: null,
          revokedAt: null,
        },
        data: {
          usedAt: input.now,
          replacedBy: input.replacedBy,
        },
      });

      if (claimed.count !== 1) return false;

      await tx.refreshToken.create({
        data: {
          userId: token.userId,
          sessionId: token.sessionId,
          tokenHash: input.newTokenHash,
          familyId: input.familyId,
          expiresAt: input.newTokenExpiresAt,
        },
      });

      await tx.session.update({
        where: { id: token.sessionId },
        data: { lastUsedAt: input.now },
      });

      return true;
    });
  }
}
