import { createApp, toWebHandler } from "h3";
import { describe, expect, it } from "vitest";
import { createRefreshCookieOriginMiddleware } from "./refresh-cookie-origin.js";

function createTestApp(options: Parameters<typeof createRefreshCookieOriginMiddleware>[0]) {
  const app = createApp();
  app.use("/auth", createRefreshCookieOriginMiddleware(options));
  app.use("/auth/refresh", () => ({ ok: true }));
  return toWebHandler(app);
}

async function request(handler: ReturnType<typeof toWebHandler>, headers: HeadersInit = {}) {
  return handler(new Request("https://auth.example.com/auth/refresh", { method: "POST", headers }));
}

describe("refresh cookie origin policy", () => {
  it("allows a configured origin with SameSite=None", async () => {
    const app = createTestApp({ enabled: true, cookieName: "nabimo_refresh", sameSite: "None", allowedOrigins: ["https://app.example.com"] });
    const response = await request(app, { cookie: "nabimo_refresh=token", origin: "https://app.example.com" });
    expect(response.status).toBe(200);
  });

  it("rejects a disallowed origin with SameSite=None", async () => {
    const app = createTestApp({ enabled: true, cookieName: "nabimo_refresh", sameSite: "None", allowedOrigins: ["https://app.example.com"] });
    const response = await request(app, { cookie: "nabimo_refresh=token", origin: "https://evil.example.com" });
    expect(response.status).toBe(403);
    expect((await response.json()).data.code).toBe("CSRF_ORIGIN_NOT_ALLOWED");
  });

  it("rejects a missing Origin with SameSite=None", async () => {
    const app = createTestApp({ enabled: true, cookieName: "nabimo_refresh", sameSite: "None", allowedOrigins: ["https://app.example.com"] });
    const response = await request(app, { cookie: "nabimo_refresh=token" });
    expect(response.status).toBe(403);
  });

  it("requires an allowlist when SameSite=None is enabled", () => {
    expect(() => createTestApp({ enabled: true, cookieName: "nabimo_refresh", sameSite: "None", allowedOrigins: [] })).toThrow("requires at least one allowed origin");
  });

  it("does not apply the origin policy to bearer refresh requests", async () => {
    const app = createTestApp({ enabled: true, cookieName: "nabimo_refresh", sameSite: "None", allowedOrigins: ["https://app.example.com"] });
    const response = await request(app, { origin: "https://evil.example.com" });
    expect(response.status).toBe(200);
  });

  it("rejects malformed allowed origins", () => {
    expect(() => createTestApp({ enabled: true, cookieName: "nabimo_refresh", sameSite: "Lax", allowedOrigins: ["https://app.example.com/path"] })).toThrow("Invalid allowed origin");
  });
});
