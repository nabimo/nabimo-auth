import { describe, expect, it, vi } from "vitest";
import { AuthClient } from "./client.js";

function response(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

describe("AuthClient", () => {
  it("sends the access token when requesting email verification", async () => {
    const fetch = vi.fn().mockResolvedValue(response({
      challengeId: "challenge-1",
      type: "email_otp",
      target: "user@example.com",
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    }));
    const storage = {
      get: vi.fn().mockResolvedValue({ accessToken: "access-token", refreshToken: "refresh-token" }),
      set: vi.fn(),
      clear: vi.fn(),
    };
    const client = new AuthClient({ baseUrl: "https://auth.example.com", fetch, storage });

    await client.requestEmailVerification("user@example.com");

    expect(fetch).toHaveBeenCalledWith(
      "https://auth.example.com/auth/verify/email/request",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ email: "user@example.com" }),
        headers: expect.any(Headers),
      }),
    );
    const request = fetch.mock.calls[0][1];
    expect(request.headers.get("Authorization")).toBe("Bearer access-token");
  });

  it("verifies an OTP without requiring authentication", async () => {
    const fetch = vi.fn().mockResolvedValue(response({ success: true }));
    const client = new AuthClient({ baseUrl: "https://auth.example.com", fetch });

    await expect(client.verifyOtp("challenge-1", "123456")).resolves.toEqual({ success: true });
    expect(fetch.mock.calls[0][0]).toBe("https://auth.example.com/auth/verify/otp");
    expect(fetch.mock.calls[0][1].headers.get("Authorization")).toBe(null);
  });
});
