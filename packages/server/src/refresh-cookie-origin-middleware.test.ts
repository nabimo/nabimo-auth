import { createApp, toWebHandler } from "h3";
import { describe, expect, it } from "vitest";
import { createRefreshCookieOriginMiddleware } from "./refresh-cookie-origin-middleware.js";

function createTestHandler(options: Parameters<typeof createRefreshCookieOriginMiddleware>[0]) {
  const app = createApp();
  app.use("/auth", createRefreshCookieOriginMiddleware(options));
  app.post("/auth/refresh", () => ({ ok: true }));
  return toWebHandler(app);
}

async function request(handler: ReturnType<typeof toWebHandler>, init: RequestInit = {}) {
  return handler(new Request("https://auth.example.com/auth/refresh", { method: "POST", ...init }));
}

describe("refresh cookie origin middleware", () => {
  it("allows a configured origin with SameSite=None", async () => {
    const handler = createTestHandler({ enabled: true, sameSite: "None", allowedOrigins: ["https://app.example.com"] });
    const response = await request(handler, {
      headers: { cookie: "nabimo_refresh=refresh-token", origin: "https://app.example.com" },
    });
    expect(response.status).toBe(200);
  });

  it("rejects a disallowed origin", async () => {
    const handler = createTestHandler({ enabled: true, sameSite: "None", allowedOrigins: ["https://app.example.com"] });
    const response = await request(handler, {
      headers: { cookie: "nabimo_refresh=refresh-token", origin: "https://evil.example.com" },
    });
    expect(response.status).toBe(403);
    expect((await response.json()).data.code).toBe("CSRF_ORIGIN_NOT_ALLOWED");
  });

  it("rejects a missing Origin header when a cross-site cookie is enabled", async () => {
    const handler = createTestHandler({ enabled: true, sameSite: "None", allowedOrigins: ["https://app.example.com"] });
    const response = await request(handler, { headers: { cookie: "nabimo_refresh=refresh-token" } });
    expect(response.status).toBe(403);
  });

  it("does not apply the origin check to bearer refresh requests", async () => {
    const handler = createTestHandler({ enabled: true, sameSite: "None", allowedOrigins: ["https://app.example.com"] });
    const response = await request(handler, { headers: { authorization: "Bearer refresh-token" } });
    expect(response.status).toBe(200);
  });

  it("does not apply the origin check when SameSite is Lax", async () => {
    const handler = createTestHandler({ enabled: true, sameSite: "Lax", allowedOrigins: [] });
    const response = await request(handler, { headers: { cookie: "nabimo_refresh=refresh-token" } });
    expect(response.status).toBe(200);
  });

  it("normalizes configured origins and rejects origins with a path", async () => {
    const handler = createTestHandler({ enabled: true, sameSite: "None", allowedOrigins: ["https://app.example.com/"] });
    const response = await request(handler, {
      headers: { cookie: "nabimo_refresh=refresh-token", origin: "https://app.example.com/path" },
    });
    expect(response.status).toBe(403);
  });

  it("requires an allowlist for SameSite=None", () => {
    expect(() => createTestHandler({ enabled: true, sameSite: "None" })).toThrow(/requires at least one allowed origin/);
  });
});
