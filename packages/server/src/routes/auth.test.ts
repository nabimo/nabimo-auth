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
    accessTokens: { validate: vi.fn() },
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
});
