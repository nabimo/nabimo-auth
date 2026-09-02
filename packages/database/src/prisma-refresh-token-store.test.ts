import { describe, expect, it } from "vitest";
import { PrismaRefreshTokenStore } from "./prisma-refresh-token-store.js";

interface MockTransaction {
  refreshToken: {
    findUnique(): Promise<MockToken>;
    updateMany(args: {
      where: { id?: string; familyId?: string; usedAt?: null; revokedAt?: null };
      data: { usedAt?: Date; replacedBy?: string; revokedAt?: Date };
    }): Promise<{ count: number }>;
    create(args: { data: Record<string, unknown> }): Promise<void>;
  };
  session: {
    updateMany(): Promise<{ count: number }>;
    update(): Promise<void>;
  };
}

interface MockToken {
  id: string;
  userId: string;
  sessionId: string;
  tokenHash: string;
  familyId: string;
  expiresAt: Date;
  usedAt: Date | null;
  revokedAt: Date | null;
  session: {
    expiresAt: Date;
    revokedAt: Date | null;
  };
}

function createDbMock(options: { claimCount?: number; usedAt?: Date | null } = {}) {
  const calls: string[] = [];
  let claimData: { usedAt?: Date; replacedBy?: string } | undefined;
  let createdData: Record<string, unknown> | undefined;
  const token: MockToken = {
    id: "token-1",
    userId: "user-1",
    sessionId: "session-1",
    tokenHash: "hash-1",
    familyId: "family-1",
    expiresAt: new Date("2030-01-01T00:00:00.000Z"),
    usedAt: options.usedAt ?? null,
    revokedAt: null,
    session: {
      expiresAt: new Date("2030-01-01T00:00:00.000Z"),
      revokedAt: null,
    },
  };

  const tx: MockTransaction = {
    refreshToken: {
      async findUnique() {
        return token;
      },
      async updateMany(args) {
        if (args.where.id === token.id) {
          calls.push("claim");
          claimData = args.data;
          return { count: options.claimCount ?? 0 };
        }
        calls.push("revoke-family");
        return { count: 1 };
      },
      async create(args) {
        calls.push("create");
        createdData = args.data;
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
    get claimData() {
      return claimData;
    },
    get createdData() {
      return createdData;
    },
    db: {
      async $transaction<T>(callback: (transaction: MockTransaction) => Promise<T>) {
        return callback(tx);
      },
    },
  };
}

describe("PrismaRefreshTokenStore", () => {
  it("rotates the token atomically and creates its replacement", async () => {
    const { db, calls, claimData, createdData } = createDbMock({ claimCount: 1 });
    const store = new PrismaRefreshTokenStore(db as never);
    const now = new Date("2026-09-02T00:00:00.000Z");

    const rotated = await store.rotateRefreshToken({
      tokenHash: "hash-1",
      now,
      familyId: "family-1",
      newTokenId: "token-2",
      newTokenHash: "hash-2",
      newTokenExpiresAt: new Date("2030-01-01T00:00:00.000Z"),
    });

    expect(rotated).toBe(true);
    expect(claimData).toEqual({ usedAt: now, replacedBy: "token-2" });
    expect(createdData).toMatchObject({
      id: "token-2",
      userId: "user-1",
      sessionId: "session-1",
      tokenHash: "hash-2",
      familyId: "family-1",
    });
    expect(calls).toEqual(["claim", "create", "update-session"]);
  });

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

  it("revokes the family when a previously-used token is presented again", async () => {
    const { db, calls } = createDbMock({ usedAt: new Date("2026-09-01T00:00:00.000Z") });
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
    expect(calls).toEqual(["revoke-family", "revoke-session"]);
  });
});
