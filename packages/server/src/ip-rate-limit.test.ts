import { describe, expect, it } from "vitest";
import { resolveClientIp } from "./ip-rate-limit.js";

function event(peer: string, forwarded?: string) {
  return {
    node: {
      req: {
        socket: { remoteAddress: peer },
        headers: forwarded === undefined ? {} : { "x-forwarded-for": forwarded },
        method: "POST",
      },
    },
    path: "/auth/login/password",
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
