import type { PrismaClient } from "./generated/client.js";

export interface CreateSessionInput {
  userId: string;
  expiresAt: Date;
  userAgent?: string;
  ipAddress?: string;
}

export interface CreateRefreshTokenInput {
  userId: string;
  sessionId: string;
  tokenHash: string;
  familyId: string;
  expiresAt: Date;
}

export function createSessionRepository(db: PrismaClient) {
  return {
    createSession(input: CreateSessionInput) {
      return db.session.create({ data: input });
    },

    findActiveSession(id: string) {
      return db.session.findFirst({
        where: {
          id,
          revokedAt: null,
          expiresAt: { gt: new Date() },
        },
      });
    },

    revokeSession(id: string) {
      return db.session.updateMany({
        where: { id, revokedAt: null },
        data: { revokedAt: new Date() },
      });
    },

    revokeUserSessions(userId: string) {
      return db.session.updateMany({
        where: { userId, revokedAt: null },
        data: { revokedAt: new Date() },
      });
    },

    createRefreshToken(input: CreateRefreshTokenInput) {
      return db.refreshToken.create({ data: input });
    },

    findRefreshToken(tokenHash: string) {
      return db.refreshToken.findUnique({ where: { tokenHash } });
    },

    markRefreshTokenUsed(id: string, replacedBy: string) {
      return db.refreshToken.updateMany({
        where: { id, usedAt: null, revokedAt: null },
        data: { usedAt: new Date(), replacedBy },
      });
    },

    revokeRefreshTokenFamily(familyId: string) {
      return db.refreshToken.updateMany({
        where: { familyId, revokedAt: null },
        data: { revokedAt: new Date() },
      });
    },
  };
}
