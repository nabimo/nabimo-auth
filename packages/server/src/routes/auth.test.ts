import { createApp } from "h3";
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
  return { app, dependencies };
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
    const response = await app.request("/auth/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "user@example.com", password: "password" }),
    });
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual(result);
  });

  it("returns 400 for malformed requests", async () => {
    const { app } = createTestApp();
    const response = await app.request("/auth/refresh", {
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
    const response = await app.request("/auth/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "user@example.com", password: "password" }),
    });
    expect(response.status).toBe(409);
    expect((await response.json()).data?.code).toBe("ACCOUNT_ALREADY_EXISTS");
  });

  it("requires bearer authentication for logout", async () => {
    const { app } = createTestApp();
    const response = await app.request("/auth/logout", { method: "POST" });
    expect(response.status).toBe(401);
    expect((await response.json()).data?.code).toBe("INVALID_CREDENTIALS");
  });
});
