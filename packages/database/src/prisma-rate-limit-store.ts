import { randomUUID } from "node:crypto";
import type { RateLimitResult, RateLimitStore } from "@nabimo-auth/core";
import type { PrismaClient } from "./generated/client.js";

function getWindowStart(now: Date, windowSeconds: number): Date {
  const windowMs = windowSeconds * 1000;
  return new Date(Math.floor(now.getTime() / windowMs) * windowMs);
}

export class PrismaRateLimitStore implements RateLimitStore {
  constructor(private readonly db: PrismaClient) {}

  async consume(input: Parameters<RateLimitStore["consume"]>[0]): Promise<RateLimitResult> {
    if (!Number.isInteger(input.limit) || input.limit < 1) {
      throw new Error("Rate limit must be a positive integer");
    }
    if (!Number.isInteger(input.windowSeconds) || input.windowSeconds < 1) {
      throw new Error("Rate-limit window must be a positive integer");
    }

    const windowStartedAt = getWindowStart(input.now, input.windowSeconds);
    const windowEndsAt = new Date(windowStartedAt.getTime() + input.windowSeconds * 1000);
    const retryAfterSeconds = Math.max(1, Math.ceil((windowEndsAt.getTime() - input.now.getTime()) / 1000));

    return this.db.$transaction(async (tx) => {
      // Serialize counters for the same key so concurrent requests cannot
      // both observe the same count and exceed the configured limit.
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`rate_limit:${input.key}`}))`;

      // Keep the bucket table bounded for keys that continue to be used.
      await tx.rateLimitBucket.deleteMany({
        where: { key: input.key, windowStartedAt: { lt: windowStartedAt } },
      });

      const bucket = await tx.rateLimitBucket.upsert({
        where: {
          key_windowStartedAt: {
            key: input.key,
            windowStartedAt,
          },
        },
        create: {
          id: randomUUID(),
          key: input.key,
          windowStartedAt,
          count: 0,
        },
        update: {},
      });

      if (bucket.count >= input.limit) {
        return {
          allowed: false,
          remaining: 0,
          retryAfterSeconds,
        };
      }

      const updated = await tx.rateLimitBucket.update({
        where: { id: bucket.id },
        data: { count: { increment: 1 } },
      });

      return {
        allowed: true,
        remaining: Math.max(0, input.limit - updated.count),
        retryAfterSeconds: 0,
      };
    });
  }
}
