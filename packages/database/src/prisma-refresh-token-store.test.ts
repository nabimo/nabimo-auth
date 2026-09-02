import { describe, expect, it } from "vitest";
import { PrismaRefreshTokenStore } from "./prisma-refresh-token-store.js";

function createDbMock() {
  const calls: string[] = [];
  const token = {
    id: "token-1",
    userId: "user-1",
    sessionId: "session-1",
    tokenHash: "hash-1",
    familyId: "family-1",
    expiresAt: new Date("2030-01-01T00:00:00.000Z"),
    usedAt: null as Date | null,
    revokedAt: null as Date | null,
    session: {
      expiresAt: new Date("2030-01-01T00:00:00.000Z"),
      revokedAt: null as Date | null,
    },
  };

  const tx = {
    refreshToken: {
      async findUnique() {
        return token;
      },
      async updateMany(args: { where: { id?: string; familyId?: string; usedAt?: null; revokedAt?: null }; data: { usedAt?: Date; replacedBy?: string; revokedAt?: Date } }) {
        if (args.where.id === token.id) {
          calls.push("claim");
          return { count: 0 };
        }
        calls.push("revoke-family");
        return { count: 1 };
      },
      async create() {
        calls.push("create");
      },
    },
    session: {
      async updateMany() {
        calls.push("revoke-session");
        return { count: 1 };
      },
      async update() {
        calls.push("update-session");
      },
    },
  };

  return {
    calls,
    db: {
      async $transaction<T>(callback: (tx: typeof tx) => Promise<T>) {
        return callback(tx);
      },
    };
  };
}

describe("PrismaRefreshTokenStore", () => {
  it("revokes the refresh-token family when an atomic claim loses a race", async () => {
    const { db, calls } = createDbMock();
    const store = new PrismaRefreshTokenStore(db as never);

    const rotated = await store.rotateRefreshToken({
      tokenHash: "hash-1",
      now: new Date("2026-09-02T00:00:00.000Z"),
      familyId: "family-1",
      newTokenId: "token-2",
      newTokenHash: "hash-2",
      newTokenExpiresAt: new Date("2030-01-01T00:00:00.000Z"),
    });

    expect(rotated).toBe(false);
    expect(calls).toEqual(["claim", "revoke-family", "revoke-session"]);
    expect(calls).not.toContain("create");
  });
});
