import { describe, expect, it } from "vitest";
import { generateJwtKeyPair, verifyAccessToken } from "../crypto/jwt.js";
import { createRefreshToken, hashRefreshToken } from "./refresh-token.js";
import { RefreshService, type RefreshTokenStore } from "./refresh-service.js";

describe("RefreshService", () => {
  it("rotates a refresh token while preserving its family", async () => {
    const keys = generateJwtKeyPair();
    const original = createRefreshToken("family-1");
    let stored = {
      userId: "user-1",
      email: "user@example.com",
      sessionId: "session-1",
      familyId: "family-1",
      sessionExpiresAt: new Date("2030-09-03T00:00:00.000Z"),
      sessionRevokedAt: null as Date | null,
      expiresAt: new Date("2030-09-03T00:00:00.000Z"),
      usedAt: null as Date | null,
      revokedAt: null as Date | null,
    };
    let rotationInput: Parameters<RefreshTokenStore["rotateRefreshToken"]>[0] | undefined;

    const store: RefreshTokenStore = {
      async getRefreshToken(tokenHash) {
        return tokenHash === original.tokenHash ? stored : null;
      },
      async rotateRefreshToken(input) {
        rotationInput = input;
        stored = { ...stored, usedAt: input.now };
        return true;
      },
    };

    const service = new RefreshService({
      refreshTokens: store,
      jwtPrivateKeyPem: keys.privateKeyPem,
      jwtKeyId: "test-key",
    });

    const now = new Date("2030-09-02T00:00:00.000Z");
    const result = await service.refresh(original.token, now);

    expect(rotationInput?.familyId).toBe("family-1");
    expect(rotationInput?.tokenHash).toBe(original.tokenHash);
    expect(rotationInput?.newTokenId).toEqual(expect.any(String));
    expect(result.user).toEqual({ id: "user-1", email: "user@example.com" });
    expect(result.sessionId).toBe("session-1");
    expect(result.refreshToken).not.toBe(original.token);
    expect(hashRefreshToken(result.refreshToken)).not.toBe(original.tokenHash);

    const claims = verifyAccessToken(result.accessToken, keys.publicKeyPem, Math.floor(now.getTime() / 1000));
    expect(claims?.sub).toBe("user-1");
    expect(claims?.sid).toBe("session-1");
  });

  it("passes an already-used refresh token to the store for reuse detection", async () => {
    const keys = generateJwtKeyPair();
    const token = createRefreshToken("family-1");
    let rotateCalled = false;
    const store: RefreshTokenStore = {
      async getRefreshToken() {
        return {
          userId: "user-1",
          email: null,
          sessionId: "session-1",
          familyId: "family-1",
          sessionExpiresAt: new Date("2030-01-01T00:00:00.000Z"),
          sessionRevokedAt: null,
          expiresAt: new Date("2030-01-01T00:00:00.000Z"),
          usedAt: new Date("2026-09-01T00:00:00.000Z"),
          revokedAt: null,
        };
      },
      async rotateRefreshToken() {
        rotateCalled = true;
        return false;
      },
    };

    const service = new RefreshService({
      refreshTokens: store,
      jwtPrivateKeyPem: keys.privateKeyPem,
      jwtKeyId: "test-key",
    });

    await expect(service.refresh(token.token, new Date("2026-09-02T00:00:00.000Z"))).rejects.toThrow("Invalid credentials");
    expect(rotateCalled).toBe(true);
  });

  it("rejects an expired refresh token", async () => {
    const keys = generateJwtKeyPair();
    const token = createRefreshToken("family-1");
    const store: RefreshTokenStore = {
      async getRefreshToken() {
        return {
          userId: "user-1",
          email: null,
          sessionId: "session-1",
          familyId: "family-1",
          sessionExpiresAt: new Date("2026-09-01T00:00:00.000Z"),
          sessionRevokedAt: null,
          expiresAt: new Date("2026-09-01T00:00:00.000Z"),
          usedAt: null,
          revokedAt: null,
        };
      },
      async rotateRefreshToken() {
        throw new Error("must not rotate expired token");
      },
    };

    const service = new RefreshService({
      refreshTokens: store,
      jwtPrivateKeyPem: keys.privateKeyPem,
      jwtKeyId: "test-key",
    });

    await expect(
      service.refresh(token.token, new Date("2026-09-02T00:00:00.000Z")),
    ).rejects.toThrow("Invalid credentials");
  });

  it("rejects a refresh token from a revoked session", async () => {
    const keys = generateJwtKeyPair();
    const token = createRefreshToken("family-1");
    let rotateCalled = false;
    const store: RefreshTokenStore = {
      async getRefreshToken() {
        return {
          userId: "user-1",
          email: null,
          sessionId: "session-1",
          familyId: "family-1",
          sessionExpiresAt: new Date("2030-01-01T00:00:00.000Z"),
          sessionRevokedAt: new Date("2026-09-02T00:00:00.000Z"),
          expiresAt: new Date("2030-01-01T00:00:00.000Z"),
          usedAt: null,
          revokedAt: null,
        };
      },
      async rotateRefreshToken() {
        rotateCalled = true;
        return true;
      },
    };

    const service = new RefreshService({
      refreshTokens: store,
      jwtPrivateKeyPem: keys.privateKeyPem,
      jwtKeyId: "test-key",
    });

    await expect(service.refresh(token.token)).rejects.toThrow("Invalid credentials");
    expect(rotateCalled).toBe(false);
  });
});
