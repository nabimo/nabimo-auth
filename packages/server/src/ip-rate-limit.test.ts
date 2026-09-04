import { describe, expect, it, vi } from "vitest";
import { authErrors } from "@nabimo-auth/core";
import { createIpRateLimitMiddleware, resolveClientIp } from "./ip-rate-limit.js";

function event(peer: string, forwarded?: string, url = "/auth/login/password") {
  return {
    node: {
      req: {
        socket: { remoteAddress: peer },
        headers: forwarded === undefined ? {} : { "x-forwarded-for": forwarded },
        method: "POST",
        url,
      },
      res: { setHeader: vi.fn() },
    },
    path: url,
  } as any;
}

describe("resolveClientIp", () => {
  it("uses the socket peer by default", () => {
    expect(resolveClientIp(event("203.0.113.10", "198.51.100.20"))).toBe("203.0.113.10");
  });

  it("ignores spoofed forwarded headers from an untrusted peer", () => {
    expect(resolveClientIp(event("203.0.113.10", "198.51.100.20, 198.51.100.30"), ["127.0.0.1"])).toBe("203.0.113.10");
  });

  it("uses the forwarded client address behind one trusted proxy", () => {
    expect(resolveClientIp(event("127.0.0.1", "198.51.100.20"), ["127.0.0.1"])).toBe("198.51.100.20");
  });

  it("skips trusted proxy entries from the right", () => {
    expect(resolveClientIp(event("127.0.0.1", "198.51.100.20, 127.0.0.2"), ["127.0.0.1", "127.0.0.2"])).toBe("198.51.100.20");
  });

  it("falls back to the peer when no forwarded address is valid", () => {
    expect(resolveClientIp(event("127.0.0.1", "not-an-ip"), ["127.0.0.1"])).toBe("127.0.0.1");
  });
});

describe("createIpRateLimitMiddleware", () => {
  it("uses the pathname so query parameters cannot bypass route limits", async () => {
    const check = vi.fn().mockResolvedValue({ allowed: true, remaining: 9, retryAfterSeconds: 0 });
    const middleware = createIpRateLimitMiddleware({
      limiter: { check } as any,
      trustedProxyIps: [],
      policies: { "login-password": { limit: 10, windowSeconds: 60 } },
    });

    await middleware(event("203.0.113.10", undefined, "/auth/login/password?next=/register"));

    expect(check).toHaveBeenCalledWith("ip:203.0.113.10:login-password", { limit: 10, windowSeconds: 60 });
  });

  it("does not rate-limit GET requests or unlisted POST routes", async () => {
    const check = vi.fn().mockResolvedValue({ allowed: true, remaining: 9, retryAfterSeconds: 0 });
    const middleware = createIpRateLimitMiddleware({
      limiter: { check } as any,
      policies: { "login-password": { limit: 10, windowSeconds: 60 } },
    });

    const getEvent = event("203.0.113.10");
    getEvent.node.req.method = "GET";
    await middleware(getEvent);
    await middleware(event("203.0.113.10", undefined, "/auth/logout"));

    expect(check).not.toHaveBeenCalled();
  });

  it("returns a 429 error and Retry-After when the limiter rejects", async () => {
    const check = vi.fn().mockRejectedValue(authErrors.rateLimited(7));
    const request = event("203.0.113.10");
    const middleware = createIpRateLimitMiddleware({
      limiter: { check } as any,
      policies: { "login-password": { limit: 10, windowSeconds: 60 } },
    });

    await expect(middleware(request)).rejects.toMatchObject({
      statusCode: 429,
      data: { code: "RATE_LIMITED", retryAfterSeconds: 7 },
    });
    expect(request.node.res.setHeader).toHaveBeenCalledWith("Retry-After", "7");
  });
});
