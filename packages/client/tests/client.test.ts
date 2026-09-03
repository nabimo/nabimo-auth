import { describe, expect, it, vi } from "vitest";
import { AuthClient, AuthClientError, MemoryTokenStorage } from "../src/index.js";

const authResponse = {
  user: { id: "user-1", email: "nabi@example.com" },
  sessionId: "session-1",
  accessToken: "access-token",
  refreshToken: "refresh-token",
};

function response(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("AuthClient", () => {
  it("registers and stores returned tokens", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(response(authResponse));
    const storage = new MemoryTokenStorage();
    const client = new AuthClient({ baseUrl: "https://auth.example.com/", fetch, storage });

    const result = await client.register("nabi@example.com", "password");

    expect(result).toEqual(authResponse);
    expect(fetch).toHaveBeenCalledWith(
      "https://auth.example.com/auth/register",
      expect.objectContaining({
        method: "POST",
        headers: expect.any(Headers),
        body: JSON.stringify({ email: "nabi@example.com", password: "password" }),
      }),
    );
    expect(await client.getTokens()).toEqual({ accessToken: "access-token", refreshToken: "refresh-token" });
  });

  it("adds the access token to authenticated requests", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(response({ ok: true }));
    const storage = new MemoryTokenStorage();
    storage.set({ accessToken: "access-token", refreshToken: "refresh-token" });
    const client = new AuthClient({ baseUrl: "https://auth.example.com", fetch, storage });

    await client.request("/protected", { method: "GET", auth: true });

    const request = fetch.mock.calls[0]?.[1];
    expect(new Headers(request?.headers).get("Authorization")).toBe("Bearer access-token");
  });

  it("rotates stored tokens on refresh", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
      response({ ...authResponse, accessToken: "new-access", refreshToken: "new-refresh" }),
    );
    const storage = new MemoryTokenStorage();
    storage.set({ accessToken: "old-access", refreshToken: "old-refresh" });
    const client = new AuthClient({ baseUrl: "https://auth.example.com", fetch, storage });

    await client.refresh();

    expect(JSON.parse(String(fetch.mock.calls[0]?.[1]?.body))).toEqual({ refreshToken: "old-refresh" });
    expect(await client.getTokens()).toEqual({ accessToken: "new-access", refreshToken: "new-refresh" });
  });

  it("clears tokens after a failed refresh with invalid credentials", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
      response({ statusMessage: "Invalid credentials", data: { code: "INVALID_CREDENTIALS" } }, 401),
    );
    const storage = new MemoryTokenStorage();
    storage.set({ accessToken: "old-access", refreshToken: "old-refresh" });
    const client = new AuthClient({ baseUrl: "https://auth.example.com", fetch, storage });

    await expect(client.refresh()).rejects.toMatchObject({
      status: 401,
      code: "INVALID_CREDENTIALS",
    });
    expect(await client.getTokens()).toBeNull();
  });

  it("clears tokens after logout", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(response({ success: true }));
    const storage = new MemoryTokenStorage();
    storage.set({ accessToken: "access-token", refreshToken: "refresh-token" });
    const client = new AuthClient({ baseUrl: "https://auth.example.com", fetch, storage });

    await client.logout();

    expect(await client.getTokens()).toBeNull();
  });

  it("exposes structured API errors", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
      response({ statusMessage: "Account already exists", data: { code: "ACCOUNT_ALREADY_EXISTS" } }, 409),
    );
    const client = new AuthClient({ baseUrl: "https://auth.example.com", fetch });

    const error = await client.register("nabi@example.com", "password").catch((value) => value);

    expect(error).toBeInstanceOf(AuthClientError);
    expect(error).toMatchObject({ status: 409, code: "ACCOUNT_ALREADY_EXISTS" });
  });
});
