import { describe, expect, it } from "vitest";
import { generateJwtKeyPair, signAccessToken } from "../crypto/jwt.js";
import { createAccessTokenClaims } from "../auth/token-policy.js";
import { AccessTokenValidationService, type AccessTokenSessionStore } from "./access-token-validation.js";

describe("AccessTokenValidationService", () => {
  const now = new Date("2026-09-02T05:00:00.000Z");

  function createSession(overrides: Record<string, unknown> = {}) {
    return {
      id: "session-1",
      userId: "user-1",
      expiresAt: new Date("2030-01-01T00:00:00.000Z"),
      revokedAt: null,
      createdAt: new Date("2026-01-01T00:00:00.000Z"),
      lastUsedAt: null,
      userAgent: null,
      ipAddress: null,
      ...overrides,
    };
  }

  function createService(session = createSession()) {
    const keys = generateJwtKeyPair();
    const store: AccessTokenSessionStore = {
      async getSession() {
        return session;
      },
    };
    return { keys, service: new AccessTokenValidationService({ publicKeyPem: keys.publicKeyPem, sessions: store }) };
  }

  function createToken(privateKeyPem: string, issuedAt = now, overrides: Partial<{ sub: string; sid: string; iss: string; aud: string }> = {}) {
    const claims = createAccessTokenClaims(
      overrides.sub ?? "user-1",
      overrides.sid ?? "session-1",
      "token-1",
      Math.floor(issuedAt.getTime() / 1000),
      {
        issuer: overrides.iss ?? "nabimo-auth",
        audience: overrides.aud ?? "nabimo-auth-client",
        ttlSeconds: 7200,
      },
    );
    return signAccessToken(claims, privateKeyPem, "test-key");
  }

  it("accepts a valid token only when its session is active", async () => {
    const { keys, service } = createService();
    const token = createToken(keys.privateKeyPem, now);

    const result = await service.validate(token, now);
    expect(result.claims.sub).toBe("user-1");
    expect(result.claims.sid).toBe("session-1");
    expect(result.session.id).toBe("session-1");
  });

  it("rejects a token after its session is revoked", async () => {
    const { keys, service } = createService(createSession({ revokedAt: new Date("2026-09-01T00:00:00.000Z") }));
    const token = createToken(keys.privateKeyPem, now);

    await expect(service.validate(token, now)).rejects.toThrow("Invalid credentials");
  });

  it("rejects a token when session ownership does not match the token subject", async () => {
    const { keys, service } = createService(createSession({ userId: "different-user" }));
    const token = createToken(keys.privateKeyPem, now);

    await expect(service.validate(token, now)).rejects.toThrow("Invalid credentials");
  });

  it("rejects a token with the wrong issuer or audience", async () => {
    const { keys, service } = createService();
    const wrongIssuer = createToken(keys.privateKeyPem, now, { iss: "wrong-issuer" });
    const wrongAudience = createToken(keys.privateKeyPem, now, { aud: "wrong-audience" });

    await expect(service.validate(wrongIssuer, now)).rejects.toThrow("Invalid credentials");
    await expect(service.validate(wrongAudience, now)).rejects.toThrow("Invalid credentials");
  });
});
