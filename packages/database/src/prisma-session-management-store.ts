import type { SessionManagementStore } from "@nabimo-auth/core";
import type { PrismaClient } from "./generated/client.js";

export class PrismaSessionManagementStore implements SessionManagementStore {
  constructor(private readonly db: PrismaClient) {}

  async getSession(sessionId: string) {
    const session = await this.db.session.findUnique({ where: { id: sessionId } });
    if (!session) return null;

    return {
      id: session.id,
      userId: session.userId,
      expiresAt: session.expiresAt,
      revokedAt: session.revokedAt,
      createdAt: session.createdAt,
      lastUsedAt: session.lastUsedAt,
      userAgent: session.userAgent,
      ipAddress: session.ipAddress,
    };
  }

  async revokeSession(sessionId: string, now: Date): Promise<boolean> {
    return this.db.$transaction(async (tx) => {
      const result = await tx.session.updateMany({
        where: { id: sessionId, revokedAt: null },
        data: { revokedAt: now },
      });
      if (result.count !== 1) return false;

      await tx.refreshToken.updateMany({
        where: { sessionId, revokedAt: null },
        data: { revokedAt: now },
      });
      return true;
    });
  }

  async revokeAllSessions(userId: string, now: Date): Promise<number> {
    return this.db.$transaction(async (tx) => {
      const sessions = await tx.session.findMany({
        where: { userId, revokedAt: null },
        select: { id: true },
      });
      if (sessions.length === 0) return 0;

      await tx.session.updateMany({
        where: { userId, revokedAt: null },
        data: { revokedAt: now },
      });

      await tx.refreshToken.updateMany({
        where: { userId, revokedAt: null },
        data: { revokedAt: now },
      });

      return sessions.length;
    });
  }
}
