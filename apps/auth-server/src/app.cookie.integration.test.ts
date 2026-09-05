import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { createServer, type Server } from "node:http";
import { toNodeListener } from "h3";

let server: Server;
let baseUrl: string;
let db: { $disconnect: () => Promise<void> };

function generatePrivateKeyPem(): string {
  const { privateKey } = generateKeyPairSync("ed25519");
  return privateKey.export({ type: "pkcs8", format: "pem" }).toString();
}

async function startServer() {
  process.env.NODE_ENV = "test";
  process.env.DATABASE_URL ??= "postgresql://nabimo:nabimo_dev@localhost:5432/nabimo_auth?schema=public";
  process.env.NABIMO_JWT_PRIVATE_KEY ??= generatePrivateKeyPem().replace(/\n/g, "\\n");
  process.env.NABIMO_JWT_KEY_ID ??= "cookie-integration-test";
  process.env.NABIMO_JWT_ISSUER ??= "nabimo-auth-cookie-test";
  process.env.NABIMO_JWT_AUDIENCE ??= "nabimo-auth-cookie-test-client";
  process.env.NABIMO_2FA_ENCRYPTION_KEY ??= randomBytes(32).toString("base64");
  process.env.NABIMO_REFRESH_COOKIE_ENABLED = "true";
  process.env.NABIMO_REFRESH_COOKIE_NAME = "nabimo_test_refresh";
  process.env.NABIMO_REFRESH_COOKIE_PATH = "/auth/refresh";
  process.env.NABIMO_REFRESH_COOKIE_SAME_SITE = "Lax";
  process.env.NABIMO_REFRESH_COOKIE_SECURE = "true";

  const module = await import("./app.js");
  const created = module.createAuthApp();
  db = created.db as typeof db;

  server = createServer(toNodeListener(created.app));
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Failed to determine integration test server port");
  baseUrl = `http://127.0.0.1:${address.port}`;
}

async function request(path: string, init?: RequestInit) {
  return fetch(`${baseUrl}${path}`, init);
}

function cookiePair(setCookie: string): string {
  return setCookie.split(";", 1)[0];
}

describe("auth server cookie integration", () => {
  beforeAll(async () => {
    await startServer();
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
    await db.$disconnect();
  });

  it("uses an HttpOnly refresh cookie, rotates it, and clears it on logout", async () => {
    const email = `cookie-integration-${Date.now()}@example.com`;

    const register = await request("/auth/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password: "StrongPassword123!" }),
    });
    expect(register.status).toBe(200);
    const registration = await register.json() as { accessToken: string; refreshToken?: string; sessionId: string };
    expect(registration.refreshToken).toBeUndefined();

    const firstCookie = register.headers.get("set-cookie");
    expect(firstCookie).toEqual(expect.stringContaining("nabimo_test_refresh="));
    expect(firstCookie).toEqual(expect.stringContaining("HttpOnly"));
    expect(firstCookie).toEqual(expect.stringContaining("Secure"));
    expect(firstCookie).toEqual(expect.stringContaining("SameSite=Lax"));
    expect(firstCookie).toEqual(expect.stringContaining("Path=/auth/refresh"));

    const refresh = await request("/auth/refresh", {
      method: "POST",
      headers: { cookie: cookiePair(firstCookie!) },
    });
    expect(refresh.status).toBe(200);
    const refreshed = await refresh.json() as { accessToken: string; refreshToken?: string; sessionId: string };
    expect(refreshed.refreshToken).toBeUndefined();
    expect(refreshed.sessionId).toBe(registration.sessionId);

    const rotatedCookie = refresh.headers.get("set-cookie");
    expect(rotatedCookie).toEqual(expect.stringContaining("nabimo_test_refresh="));
    expect(cookiePair(rotatedCookie!)).not.toBe(cookiePair(firstCookie!));

    const replay = await request("/auth/refresh", {
      method: "POST",
      headers: { cookie: cookiePair(firstCookie!) },
    });
    expect(replay.status).toBe(401);

    const logout = await request("/auth/logout", {
      method: "POST",
      headers: { authorization: `Bearer ${refreshed.accessToken}` },
    });
    expect(logout.status).toBe(200);
    const clearedCookie = logout.headers.get("set-cookie");
    expect(clearedCookie).toEqual(expect.stringContaining("nabimo_test_refresh="));
    expect(clearedCookie).toEqual(expect.stringContaining("Max-Age=0"));
  });
});
