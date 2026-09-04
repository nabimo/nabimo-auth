import { describe, expect, it } from "vitest";
import { PrismaSessionManagementStore } from "./prisma-session-management-store.js";

type MockSession = { id: string; userId: string; revokedAt: Date | null };
type MockTx = {
  session: {
    findUnique(args: { where: { id: string } }): Promise<MockSession | null>;
    updateMany(args: { where: { id?: string; userId?: string; revokedAt: null }; data: { revokedAt: Date } }): Promise<{ count: number }>;
  };
  refreshToken: {
    updateMany(args: { where: { sessionId?: string; userId?: string; revokedAt: null }; data: { revokedAt: Date } }): Promise<{ count: number }>;
  };
};

function createDbMock() {
  const calls: string[] = [];
  const sessions: MockSession[] = [
    { id: "session-1", userId: "user-1", revokedAt: null },
    { id: "session-2", userId: "user-1", revokedAt: null },
    { id: "session-3", userId: "user-2", revokedAt: null },
  ];
  const tx: MockTx = {
    session: {
      async findUnique({ where }) { return sessions.find((s) => s.id === where.id) ?? null; },
      async updateMany({ where, data }) {
        const matches = sessions.filter((s) => (where.id === undefined || s.id === where.id) && (where.userId === undefined || s.userId === where.userId) && s.revokedAt === null);
        for (const session of matches) session.revokedAt = data.revokedAt;
        calls.push(`session-update:${matches.length}`); return { count: matches.length };
      },
    },
    refreshToken: {
      async updateMany({ where }) {
        calls.push(`token-update:${where.sessionId ?? `user:${where.userId}`}`);
        return { count: 1 };
      },
    },
  };
  const db = { session: { async findUnique({ where }: { where: { id: string } }) { const s = sessions.find((x) => x.id === where.id); return s ? { ...s, expiresAt: new Date("2030-01-01T00:00:00.000Z"), createdAt: new Date("2026-01-01T00:00:00.000Z"), lastUsedAt: null, userAgent: "test-agent", ipAddress: "127.0.0.1" } : null; } }, async $transaction<T>(callback: (tx: MockTx) => Promise<T>) { return callback(tx); } };
  return { db, calls, sessions };
}

describe("PrismaSessionManagementStore", () => {
  it("revokes one session and its refresh tokens", async () => {
    const { db, calls, sessions } = createDbMock();
    const store = new PrismaSessionManagementStore(db as never);
    const now = new Date("2026-09-02T00:00:00.000Z");
    await expect(store.revokeSession("session-1", now)).resolves.toBe(true);
    expect(sessions.find((s) => s.id === "session-1")?.revokedAt).toEqual(now);
    expect(calls).toEqual(["session-update:1", "token-update:session-1"]);
  });

  it("does not revoke refresh tokens when the session was already revoked", async () => {
    const { db, calls } = createDbMock();
    const store = new PrismaSessionManagementStore(db as never);
    await store.revokeSession("session-1", new Date("2026-09-02T00:00:00.000Z"));
    calls.length = 0;
    await expect(store.revokeSession("session-1", new Date("2026-09-02T01:00:00.000Z"))).resolves.toBe(false);
    expect(calls).toEqual(["session-update:0"]);
  });

  it("revokes all active sessions and every active refresh token for the user", async () => {
    const { db, calls, sessions } = createDbMock();
    const store = new PrismaSessionManagementStore(db as never);
    const now = new Date("2026-09-02T00:00:00.000Z");
    await expect(store.revokeAllSessions("user-1", now)).resolves.toBe(2);
    expect(sessions.filter((s) => s.revokedAt === now).map((s) => s.id)).toEqual(["session-1", "session-2"]);
    expect(sessions.find((s) => s.id === "session-3")?.revokedAt).toBeNull();
    expect(calls).toEqual(["session-update:2", "token-update:user:user-1"]);
  });
});
