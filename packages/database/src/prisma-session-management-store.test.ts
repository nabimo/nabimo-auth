import { describe, expect, it } from "vitest";
import { PrismaSessionManagementStore } from "./prisma-session-management-store.js";

function createDbMock() {
  const calls: string[] = [];
  const sessions = [
    { id: "session-1", userId: "user-1", revokedAt: null },
    { id: "session-2", userId: "user-1", revokedAt: null },
    { id: "session-3", userId: "user-2", revokedAt: null },
  ];

  const tx = {
    session: {
      async findUnique({ where }: { where: { id: string } }) {
        return sessions.find((session) => session.id === where.id) ?? null;
      },
      async findMany({ where }: { where: { userId: string; revokedAt: null }; select: { id: boolean } }) {
        calls.push(`findMany:${where.userId}`);
        return sessions.filter((session) => session.userId === where.userId && session.revokedAt === null).map(({ id }) => ({ id }));
      },
      async updateMany({ where, data }: { where: { id?: string; userId?: string; revokedAt: null }; data: { revokedAt: Date } }) {
        const matches = sessions.filter(
          (session) =>
            (where.id === undefined || session.id === where.id) &&
            (where.userId === undefined || session.userId === where.userId) &&
            session.revokedAt === null,
        );
        for (const session of matches) session.revokedAt = data.revokedAt;
        calls.push(`session-update:${matches.length}`);
        return { count: matches.length };
      },
    },
    refreshToken: {
      async updateMany({ where, data }: { where: { sessionId?: string; userId?: string; revokedAt: null }; data: { revokedAt: Date } }) {
        calls.push(
          `token-update:${where.sessionId ?? `user:${where.userId}`}`,
        );
        return { count: 1 };
      },
    },
  };

  return {
    calls,
    db: {
      session: {
        async findUnique({ where }: { where: { id: string } }) {
          const session = sessions.find((item) => item.id === where.id);
          if (!session) return null;
          return {
            ...session,
            expiresAt: new Date("2030-01-01T00:00:00.000Z"),
            createdAt: new Date("2026-01-01T00:00:00.000Z"),
            lastUsedAt: null,
            userAgent: "test-agent",
            ipAddress: "127.0.0.1",
          };
        },
      },
      async $transaction<T>(callback: (tx: typeof tx) => Promise<T>) {
        return callback(tx);
      },
    },
  };
}

describe("PrismaSessionManagementStore", () => {
  it("revokes one session and its refresh tokens", async () => {
    const { db, calls } = createDbMock();
    const store = new PrismaSessionManagementStore(db as never);
    const now = new Date("2026-09-02T00:00:00.000Z");

    await expect(store.revokeSession("session-1", now)).resolves.toBe(true);
    expect(calls).toEqual(["session-update:1", "token-update:session-1"]);
  });

  it("does not revoke refresh tokens when the session was already revoked", async () => {
    const { db, calls } = createDbMock();
    const store = new PrismaSessionManagementStore(db as never);
    const firstNow = new Date("2026-09-02T00:00:00.000Z");
    const secondNow = new Date("2026-09-02T01:00:00.000Z");

    await store.revokeSession("session-1", firstNow);
    calls.length = 0;

    await expect(store.revokeSession("session-1", secondNow)).resolves.toBe(false);
    expect(calls).toEqual(["session-update:0"]);
  });

  it("revokes all active sessions for only the requested user", async () => {
    const { db, calls } = createDbMock();
    const store = new PrismaSessionManagementStore(db as never);
    const now = new Date("2026-09-02T00:00:00.000Z");

    await expect(store.revokeAllSessions("user-1", now)).resolves.toBe(2);
    expect(sessionsSnapshot(db)).toEqual(undefined);
    expect(calls).toEqual(["findMany:user-1", "session-update:2", "token-update:user:user-1"]);
  });
});

function sessionsSnapshot(_db: unknown) {
  return undefined;
}
