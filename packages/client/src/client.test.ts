import { describe, expect, it, vi } from "vitest";
import { AuthClient } from "./client.js";
import { CookieRefreshTransport } from "./refresh-coordinator.js";

function response(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

describe("AuthClient", () => {
  it("sends the access token when requesting email verification", async () => {
    const fetch = vi.fn().mockResolvedValue(response({ challengeId: "challenge-1", type: "email_otp", target: "user@example.com", expiresAt: new Date(Date.now() + 60_000).toISOString() }));
    const storage = { get: vi.fn().mockResolvedValue({ accessToken: "access-token", refreshToken: "refresh-token" }), set: vi.fn(), clear: vi.fn() };
    const client = new AuthClient({ baseUrl: "https://auth.example.com", fetch, storage });
    await client.requestEmailVerification("user@example.com");
    expect(fetch.mock.calls[0][0]).toBe("https://auth.example.com/auth/verify/email/request");
    expect(fetch.mock.calls[0][1].headers.get("Authorization")).toBe("Bearer access-token");
  });

  it("sends the access token when requesting phone verification", async () => {
    const fetch = vi.fn().mockResolvedValue(response({ challengeId: "challenge-1", type: "phone_otp", target: "+12025550123", expiresAt: new Date(Date.now() + 60_000).toISOString() }));
    const storage = { get: vi.fn().mockResolvedValue({ accessToken: "access-token", refreshToken: "refresh-token" }), set: vi.fn(), clear: vi.fn() };
    const client = new AuthClient({ baseUrl: "https://auth.example.com", fetch, storage });
    await expect(client.requestPhoneVerification("+12025550123")).resolves.toMatchObject({ type: "phone_otp" });
    expect(fetch.mock.calls[0][0]).toBe("https://auth.example.com/auth/verify/phone/request");
    expect(fetch.mock.calls[0][1].headers.get("Authorization")).toBe("Bearer access-token");
  });

  it("verifies an OTP without requiring authentication", async () => {
    const fetch = vi.fn().mockResolvedValue(response({ success: true }));
    const client = new AuthClient({ baseUrl: "https://auth.example.com", fetch });
    await expect(client.verifyOtp("challenge-1", "123456")).resolves.toEqual({ success: true });
    expect(fetch.mock.calls[0][1].headers.get("Authorization")).toBe(null);
  });

  it("refreshes after a 401 and retries with the new access token", async () => {
    const calls: string[] = [];
    let tokens = { accessToken: "old", refreshToken: "refresh" };
    const storage = {
      get: vi.fn().mockImplementation(async () => tokens),
      set: vi.fn().mockImplementation(async (next) => { tokens = next; }),
      clear: vi.fn(),
    };
    const fetch = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      calls.push(url);
      if (url.endsWith("/auth/refresh")) return response({ accessToken: "new", refreshToken: "refresh-new", sessionId: "session-1" });
      if (calls.length === 1) return response({ statusCode: 401 }, 401);
      return response({ ok: true });
    });
    const client = new AuthClient({ baseUrl: "https://auth.test", storage, fetch });
    await expect(client.request("/protected", { auth: true })).resolves.toEqual({ ok: true });
    expect(calls.map((url) => new URL(url).pathname)).toEqual(["/protected", "/auth/refresh", "/protected"]);
    expect(fetch.mock.calls[0][1].headers.get("Authorization")).toBe("Bearer old");
    expect(fetch.mock.calls[2][1].headers.get("Authorization")).toBe("Bearer new");
    expect(storage.set).toHaveBeenCalledWith({ accessToken: "new", refreshToken: "refresh-new" });
  });

  it("deduplicates concurrent refresh requests", async () => {
    let tokens = { accessToken: "old", refreshToken: "refresh" };
    const storage = {
      get: vi.fn().mockImplementation(async () => tokens),
      set: vi.fn().mockImplementation(async (next) => { tokens = next; }),
      clear: vi.fn(),
    };
    let refreshCalls = 0;
    let protectedCalls = 0;
    let resolveRefresh!: (value: Response) => void;
    const refreshResponse = new Promise<Response>((resolve) => { resolveRefresh = resolve; });
    const fetch = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/auth/refresh")) { refreshCalls++; return refreshResponse; }
      if (url.endsWith("/protected")) { protectedCalls++; return protectedCalls <= 3 ? response({ statusCode: 401 }, 401) : response({ ok: true }); }
      throw new Error(`Unexpected request: ${url}`);
    });
    const client = new AuthClient({ baseUrl: "https://auth.test", storage, fetch });
    const requests = [client.request("/protected", { auth: true }), client.request("/protected", { auth: true }), client.request("/protected", { auth: true })];
    await vi.waitFor(() => expect(refreshCalls).toBe(1));
    resolveRefresh(response({ accessToken: "new", refreshToken: "refresh-new", sessionId: "session-1" }));
    await expect(Promise.all(requests)).resolves.toEqual([{ ok: true }, { ok: true }, { ok: true }]);
    expect(refreshCalls).toBe(1);
    expect(protectedCalls).toBe(6);
  });

  it("uses cookie credentials and persists only the access token", async () => {
    const storage = { get: vi.fn().mockResolvedValue({ accessToken: "old" }), set: vi.fn(), clear: vi.fn() };
    const fetch = vi.fn().mockResolvedValue(response({ user: { id: "user-1", email: "user@example.com" }, sessionId: "session-1", accessToken: "new" }));
    const client = new AuthClient({ baseUrl: "https://auth.test", storage, fetch, refreshTransport: new CookieRefreshTransport() });
    await expect(client.refresh()).resolves.toEqual({ user: { id: "user-1", email: "user@example.com" }, sessionId: "session-1", accessToken: "new" });
    expect(fetch.mock.calls[0][1]).toMatchObject({ method: "POST", credentials: "include" });
    expect(fetch.mock.calls[0][1].body).toBeUndefined();
    expect(storage.set).toHaveBeenCalledWith({ accessToken: "new" });
  });

  it("clears tokens when refresh is rejected", async () => {
    const storage = { get: vi.fn().mockResolvedValue({ accessToken: "old", refreshToken: "refresh" }), set: vi.fn(), clear: vi.fn() };
    const fetch = vi.fn().mockImplementation(async (input: RequestInfo | URL) => String(input).endsWith("/auth/refresh") ? response({ statusCode: 401, data: { code: "INVALID_CREDENTIALS" } }, 401) : response({ statusCode: 401 }, 401));
    const client = new AuthClient({ baseUrl: "https://auth.test", storage, fetch });
    await expect(client.request("/protected", { auth: true })).rejects.toMatchObject({ status: 401 });
    expect(storage.clear).toHaveBeenCalledOnce();
  });

  it("does not refresh unauthenticated requests", async () => {
    const fetch = vi.fn().mockResolvedValue(response({ statusCode: 401 }, 401));
    const client = new AuthClient({ baseUrl: "https://auth.test", fetch });
    await expect(client.request("/public")).rejects.toMatchObject({ status: 401 });
    expect(fetch).toHaveBeenCalledOnce();
  });

  it("does not retry more than once after refresh", async () => {
    const paths: string[] = [];
    const storage = { get: vi.fn().mockResolvedValue({ accessToken: "old", refreshToken: "refresh" }), set: vi.fn(), clear: vi.fn() };
    const fetch = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input); paths.push(new URL(url).pathname);
      if (url.endsWith("/auth/refresh")) return response({ accessToken: "new", refreshToken: "refresh-new", sessionId: "session-1" });
      return response({ statusCode: 401 }, 401);
    });
    const client = new AuthClient({ baseUrl: "https://auth.test", storage, fetch });
    await expect(client.request("/protected", { auth: true })).rejects.toMatchObject({ status: 401 });
    expect(paths).toEqual(["/protected", "/auth/refresh", "/protected"]);
  });

  it("rejects authenticated requests to a different origin", async () => {
    const fetch = vi.fn();
    const storage = { get: vi.fn().mockResolvedValue({ accessToken: "secret", refreshToken: "refresh" }), set: vi.fn(), clear: vi.fn() };
    const client = new AuthClient({ baseUrl: "https://auth.example.com", fetch, storage });

    await expect(client.request("https://attacker.example/collect", { auth: true })).rejects.toThrow("Authenticated requests cannot target a different origin");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("allows an explicit same-origin authenticated URL", async () => {
    const fetch = vi.fn().mockResolvedValue(response({ ok: true }));
    const storage = { get: vi.fn().mockResolvedValue({ accessToken: "access-token", refreshToken: "refresh-token" }), set: vi.fn(), clear: vi.fn() };
    const client = new AuthClient({ baseUrl: "https://auth.example.com", fetch, storage });

    await expect(client.request("https://auth.example.com/protected", { auth: true })).resolves.toEqual({ ok: true });
    expect(fetch.mock.calls[0][1].headers.get("Authorization")).toBe("Bearer access-token");
  });
});
