import { createApp, toWebHandler } from "h3";
import { describe, expect, it, vi } from "vitest";
import { AuthError } from "@nabimo-auth/core";
import { createAuthRouter } from "./auth.js";

function createTestApp(overrides: Record<string, unknown> = {}) {
  const dependencies = {
    auth: {
      registerWithPassword: vi.fn().mockResolvedValue({ ok: true }),
      loginWithPassword: vi.fn().mockResolvedValue({ ok: true }),
    },
    accessTokens: { validate: vi.fn().mockResolvedValue({ claims: { sub: "user-1", sid: "session-1" } }) },
    refresh: { refresh: vi.fn().mockResolvedValue({ ok: true }) },
    sessionManagement: {
      logout: vi.fn().mockResolvedValue(undefined),
      logoutAll: vi.fn().mockResolvedValue(1),
    },
    ...overrides,
  };
  const app = createApp();
  app.use("/auth", createAuthRouter(dependencies as never).handler);
  return { app: toWebHandler(app), dependencies };
}

async function request(handler: ReturnType<typeof toWebHandler>, path: string, init?: RequestInit) {
  return handler(new Request(`http://localhost${path}`, init));
}

describe("auth server contract", () => {
  it("returns the authentication response for registration", async () => {
    const result = {
      user: { id: "user-1", email: "user@example.com" },
      sessionId: "session-1",
      accessToken: "access-token",
      refreshToken: "refresh-token",
    };
    const { app } = createTestApp({
      auth: { registerWithPassword: vi.fn().mockResolvedValue(result), loginWithPassword: vi.fn() },
    });
    const response = await request(app, "/auth/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "user@example.com", password: "password" }),
    });
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual(result);
  });

  it("returns 400 for malformed requests", async () => {
    const { app } = createTestApp();
    const response = await request(app, "/auth/refresh", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(response.status).toBe(400);
    const body = await response.json();
    expect(body.data?.code).toBe("INVALID_REQUEST");
  });

  it("maps domain auth errors to stable HTTP errors", async () => {
    const { app } = createTestApp({
      auth: {
        registerWithPassword: vi.fn().mockRejectedValue(new AuthError("An account already exists", "ACCOUNT_ALREADY_EXISTS")),
        loginWithPassword: vi.fn(),
      },
    });
    const response = await request(app, "/auth/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "user@example.com", password: "password" }),
    });
    expect(response.status).toBe(409);
    expect((await response.json()).data?.code).toBe("ACCOUNT_ALREADY_EXISTS");
  });

  it("requires bearer authentication for logout", async () => {
    const { app } = createTestApp();
    const response = await request(app, "/auth/logout", { method: "POST" });
    expect(response.status).toBe(401);
    expect((await response.json()).data?.code).toBe("INVALID_CREDENTIALS");
  });

  it("requires bearer authentication for email verification requests", async () => {
    const verification = { requestEmailOtp: vi.fn(), verifyOtp: vi.fn() };
    const users = { findById: vi.fn() };
    const { app } = createTestApp({ verification, users });
    const response = await request(app, "/auth/verify/email/request", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "user@example.com" }),
    });
    expect(response.status).toBe(401);
    expect((await response.json()).data?.code).toBe("INVALID_CREDENTIALS");
    expect(verification.requestEmailOtp).not.toHaveBeenCalled();
  });

  it("requires bearer authentication for phone verification requests", async () => {
    const verification = { requestPhoneOtp: vi.fn(), verifyOtp: vi.fn() };
    const users = { findById: vi.fn() };
    const { app } = createTestApp({ verification, users });
    const response = await request(app, "/auth/verify/phone/request", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ phone: "+12025550123" }),
    });
    expect(response.status).toBe(401);
    expect((await response.json()).data?.code).toBe("INVALID_CREDENTIALS");
    expect(verification.requestPhoneOtp).not.toHaveBeenCalled();
  });

  it("requests a normalized phone verification OTP for the authenticated user's phone", async () => {
    const challenge = {
      challengeId: "challenge-1",
      type: "phone_otp" as const,
      target: "+12025550123",
      expiresAt: new Date(Date.now() + 60_000),
    };
    const verification = { requestPhoneOtp: vi.fn().mockResolvedValue(challenge), verifyOtp: vi.fn() };
    const users = { findById: vi.fn().mockResolvedValue({ id: "user-1", email: null, phone: "+12025550123" }) };
    const { app } = createTestApp({ verification, users });
    const response = await request(app, "/auth/verify/phone/request", {
      method: "POST",
      headers: { authorization: "Bearer access-token", "content-type": "application/json" },
      body: JSON.stringify({ phone: "+1 (202) 555-0123" }),
    });
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      challengeId: "challenge-1",
      type: "phone_otp",
      target: "+12025550123",
      expiresAt: challenge.expiresAt.toISOString(),
    });
    expect(verification.requestPhoneOtp).toHaveBeenCalledWith("user-1", "+12025550123");
  });

  it("rejects an invalid phone number", async () => {
    const verification = { requestPhoneOtp: vi.fn(), verifyOtp: vi.fn() };
    const users = { findById: vi.fn() };
    const { app } = createTestApp({ verification, users });
    const response = await request(app, "/auth/verify/phone/request", {
      method: "POST",
      headers: { authorization: "Bearer access-token", "content-type": "application/json" },
      body: JSON.stringify({ phone: "not-a-phone" }),
    });
    expect(response.status).toBe(400);
    expect((await response.json()).data?.code).toBe("INVALID_REQUEST");
    expect(verification.requestPhoneOtp).not.toHaveBeenCalled();
  });

  it("verifies a valid OTP through the verification service", async () => {
    const verification = { requestEmailOtp: vi.fn(), verifyOtp: vi.fn().mockResolvedValue(undefined) };
    const { app } = createTestApp({ verification });
    const response = await request(app, "/auth/verify/otp", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ challengeId: "challenge-1", code: "123456" }),
    });
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ success: true });
    expect(verification.verifyOtp).toHaveBeenCalledWith("challenge-1", "123456");
  });

  it("sets an HttpOnly refresh cookie and omits the refresh token from registration JSON", async () => {
    const result = {
      user: { id: "user-1", email: "user@example.com" },
      sessionId: "session-1",
      accessToken: "access-token",
      refreshToken: "refresh-token",
    };
    const { app } = createTestApp({
      auth: { registerWithPassword: vi.fn().mockResolvedValue(result), loginWithPassword: vi.fn() },
      refreshCookie: { enabled: true, secure: true, sameSite: "Strict" },
    });
    const response = await request(app, "/auth/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "user@example.com", password: "password" }),
    });
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ user: result.user, sessionId: result.sessionId, accessToken: result.accessToken });
    const cookie = response.headers.get("set-cookie");
    expect(cookie).toContain("nabimo_refresh=refresh-token");
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("Secure");
    expect(cookie).toContain("SameSite=Strict");
    expect(cookie).toContain("Path=/auth/refresh");
    expect(cookie).toContain("Max-Age=2592000");
  });

  it("refreshes using the HttpOnly cookie and rotates it", async () => {
    const refresh = { refresh: vi.fn().mockResolvedValue({
      user: { id: "user-1", email: "user@example.com" },
      sessionId: "session-1",
      accessToken: "access-token-2",
      refreshToken: "refresh-token-2",
    }) };
    const { app } = createTestApp({ refresh, refreshCookie: { enabled: true, secure: true, sameSite: "Lax" } });
    const response = await request(app, "/auth/refresh", {
      method: "POST",
      headers: { cookie: "nabimo_refresh=refresh-token-1" },
    });
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ user: { id: "user-1", email: "user@example.com" }, sessionId: "session-1", accessToken: "access-token-2" });
    expect(refresh.refresh).toHaveBeenCalledWith("refresh-token-1");
    expect(response.headers.get("set-cookie")).toContain("nabimo_refresh=refresh-token-2");
  });

  it("clears the refresh cookie on logout", async () => {
    const { app } = createTestApp({ refreshCookie: { enabled: true, secure: true, sameSite: "Strict" } });
    const response = await request(app, "/auth/logout", {
      method: "POST",
      headers: { authorization: "Bearer access-token" },
    });
    expect(response.status).toBe(200);
    const cookie = response.headers.get("set-cookie");
    expect(cookie).toContain("nabimo_refresh=");
    expect(cookie).toContain("Max-Age=0");
    expect(cookie).toContain("Expires=Thu, 01 Jan 1970 00:00:00 GMT");
  });

  it("keeps bearer refresh backward compatible when cookie mode is disabled", async () => {
    const refresh = { refresh: vi.fn().mockResolvedValue({ ok: true, refreshToken: "refresh-token-2" }) };
    const { app } = createTestApp({ refresh });
    const response = await request(app, "/auth/refresh", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ refreshToken: "refresh-token-1" }),
    });
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ ok: true, refreshToken: "refresh-token-2" });
    expect(response.headers.get("set-cookie")).toBeNull();
    expect(refresh.refresh).toHaveBeenCalledWith("refresh-token-1");
  });
});
