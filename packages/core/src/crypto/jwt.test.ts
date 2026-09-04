import { describe, expect, it } from "vitest";
import { generateJwtKeyPair, signAccessToken, verifyAccessToken, type AccessTokenClaims } from "./jwt.js";

describe("JWT access token validation", () => {
  const now = 1_800_000_000;
  const keyPair = generateJwtKeyPair();

  function token(overrides: Partial<{ iat: number; exp: number }> = {}) {
    return signAccessToken(
      {
        sub: "user-1",
        sid: "session-1",
        jti: "token-1",
        iat: now,
        exp: now + 900,
        iss: "nabimo-auth",
        aud: "nabimo-auth-client",
        ...overrides,
      },
      keyPair.privateKeyPem,
      "test-key",
    );
  }

  it("accepts a valid token", () => {
    expect(verifyAccessToken(token(), keyPair.publicKeyPem, now)).not.toBeNull();
  });

  it("rejects an expired token", () => {
    expect(verifyAccessToken(token({ exp: now }), keyPair.publicKeyPem, now)).toBeNull();
  });

  it("rejects a token whose expiration is not after iat", () => {
    expect(verifyAccessToken(token({ exp: now }), keyPair.publicKeyPem, now - 1)).toBeNull();
  });

  it("rejects a token issued too far in the future", () => {
    expect(verifyAccessToken(token({ iat: now + 61 }), keyPair.publicKeyPem, now)).toBeNull();
  });

  it("allows normal clock skew", () => {
    expect(verifyAccessToken(token({ iat: now + 60 }), keyPair.publicKeyPem, now)).not.toBeNull();
  });

  it("rejects malformed timestamp values", () => {
    expect(verifyAccessToken(token({ iat: Number.MAX_SAFE_INTEGER + 1 }), keyPair.publicKeyPem, now)).toBeNull();
    expect(verifyAccessToken(token({ exp: Number.MAX_SAFE_INTEGER + 1 }), keyPair.publicKeyPem, now)).toBeNull();
  });

  it("rejects claims with invalid types", () => {
    const malformed = signAccessToken(
      {
        sub: 123,
        sid: "session-1",
        jti: "token-1",
        iat: now,
        exp: now + 900,
        iss: "nabimo-auth",
        aud: "nabimo-auth-client",
      } as unknown as AccessTokenClaims,
      keyPair.privateKeyPem,
      "test-key",
    );

    expect(verifyAccessToken(malformed, keyPair.publicKeyPem, now)).toBeNull();
  });
});
