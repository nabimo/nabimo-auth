import { describe, expect, it } from "vitest";
import { PrismaRateLimitStore } from "./prisma-rate-limit-store.js";

interface Bucket {
  id: string;
  key: string;
  windowStartedAt: Date;
  count: number;
}

interface DbMock {
  $transaction<T>(callback: (tx: DbMock) => Promise<T>): Promise<T>;
  $executeRaw(): Promise<number>;
  rateLimitBucket: {
    deleteMany(args: { where: { key: string; windowStartedAt: { lt: Date } } }): Promise<{ count: number }>;
    upsert(args: {
      where: { key_windowStartedAt: { key: string; windowStartedAt: Date } };
      create: { id: string; key: string; windowStartedAt: Date; count: number };
      update: Record<string, never>;
    }): Promise<Bucket>;
    update(args: { where: { id: string }; data: { count: { increment: number } } }): Promise<Bucket>;
  };
}

function createDbMock(): DbMock {
  const buckets = new Map<string, Bucket>();
  let nextId = 0;

  const db: DbMock = {
    async $transaction<T>(callback) {
      return callback(db);
    },
    async $executeRaw() {
      return 1;
    },
    rateLimitBucket: {
      async deleteMany(args) {
        for (const [id, bucket] of buckets) {
          if (bucket.key === args.where.key && bucket.windowStartedAt < args.where.windowStartedAt.lt) {
            buckets.delete(id);
          }
        }
        return { count: 0 };
      },
      async upsert(args) {
        const { key, windowStartedAt } = args.where.key_windowStartedAt;
        const bucketKey = `${key}:${windowStartedAt.toISOString()}`;
        const existing = buckets.get(bucketKey);
        if (existing) return existing;
        const bucket = { ...args.create, id: `bucket-${++nextId}` };
        buckets.set(bucketKey, bucket);
        return bucket;
      },
      async update(args) {
        const bucket = [...buckets.values()].find((value) => value.id === args.where.id);
        if (!bucket) throw new Error("Bucket not found");
        bucket.count += args.data.count.increment;
        return bucket;
      },
    },
  };

  return db;
}

describe("PrismaRateLimitStore", () => {
  it("allows up to the configured limit and then rejects", async () => {
    const store = new PrismaRateLimitStore(createDbMock() as never);
    const now = new Date("2026-09-04T12:00:05.000Z");

    expect(await store.consume({ key: "login:user-1", limit: 3, windowSeconds: 60, now })).toEqual({
      allowed: true,
      remaining: 2,
      retryAfterSeconds: 0,
    });
    expect(await store.consume({ key: "login:user-1", limit: 3, windowSeconds: 60, now })).toMatchObject({ allowed: true, remaining: 1 });
    expect(await store.consume({ key: "login:user-1", limit: 3, windowSeconds: 60, now })).toMatchObject({ allowed: true, remaining: 0 });

    const rejected = await store.consume({ key: "login:user-1", limit: 3, windowSeconds: 60, now });
    expect(rejected.allowed).toBe(false);
    expect(rejected.remaining).toBe(0);
    expect(rejected.retryAfterSeconds).toBe(55);
  });

  it("starts a new bucket at the next fixed window", async () => {
    const store = new PrismaRateLimitStore(createDbMock() as never);
    const before = new Date("2026-09-04T12:00:59.999Z");
    const after = new Date("2026-09-04T12:01:00.000Z");

    await store.consume({ key: "login:user-1", limit: 1, windowSeconds: 60, now: before });
    expect((await store.consume({ key: "login:user-1", limit: 1, windowSeconds: 60, now: before })).allowed).toBe(false);
    expect((await store.consume({ key: "login:user-1", limit: 1, windowSeconds: 60, now: after })).allowed).toBe(true);
  });

  it("rejects invalid policies", async () => {
    const store = new PrismaRateLimitStore(createDbMock() as never);
    const now = new Date("2026-09-04T12:00:00.000Z");

    await expect(store.consume({ key: "x", limit: 0, windowSeconds: 60, now })).rejects.toThrow();
    await expect(store.consume({ key: "x", limit: 1, windowSeconds: 0, now })).rejects.toThrow();
  });
});
