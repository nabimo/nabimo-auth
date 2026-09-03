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
    accessTokens: {
      validate: vi.fn(),
    },
    refresh: {
      refresh: vi.fn().mockResolvedValue({ ok: true }),
    },
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

describe("auth HTTP contract", () => {
  it("returns 400 for malformed registration requests", async () => {
    const { app } = createTestApp();

    const response = await request(app, "/auth/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "user@example.com" }),
    });

    expect(response.status).toBe(400);
    const body = await response.json();
    expect(body.statusCode ?? body.status).toBe(400);
    expect(body.data?.code).toBe("INVALID_REQUEST");
  });

  it("maps known auth errors to their HTTP status and code", async () => {
    const auth = {
      registerWithPassword: vi.fn().mockRejectedValue(new AuthError("An account already exists", "ACCOUNT_ALREADY_EXISTS")),
      loginWithPassword: vi.fn(),
    };
    const { app } = createTestApp({ auth });

    const response = await request(app, "/auth/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "user@example.com", password: "password" }),
    });

    expect(response.status).toBe(409);
    const body = await response.json();
    expect(body.data?.code).toBe("ACCOUNT_ALREADY_EXISTS");
  });

  it("returns 401 for logout without a bearer token", async () => {
    const { app } = createTestApp();

    const response = await request(app, "/auth/logout", { method: "POST" });

    expect(response.status).toBe(401);
    const body = await response.json();
    expect(body.data?.code).toBe("INVALID_CREDENTIALS");
  });
});
