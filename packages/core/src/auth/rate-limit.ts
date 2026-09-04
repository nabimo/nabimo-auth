export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  retryAfterSeconds: number;
}

export interface RateLimitStore {
  consume(input: {
    key: string;
    limit: number;
    windowSeconds: number;
    now: Date;
  }): Promise<RateLimitResult>;
}

export interface RateLimitPolicy {
  limit: number;
  windowSeconds: number;
}

export class RateLimiter {
  constructor(private readonly store: RateLimitStore) {}

  async check(key: string, policy: RateLimitPolicy, now = new Date()): Promise<void> {
    const result = await this.store.consume({ key, ...policy, now });
    if (!result.allowed) throw new Error(`Rate limit exceeded; retry after ${result.retryAfterSeconds}s`);
  }
}
