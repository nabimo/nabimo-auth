import { describe, expect, it } from "vitest";
import { createJwtKeyResolver, generateJwtKeyPair, signAccessToken, verifyAccessToken, type AccessTokenClaims } from "./jwt.js";

describe("JWT access token validation", () => {
  const now = 1_800_000_000;
  const keyPair = generateJwtKeyPair();
  const resolver = createJwtKeyResolver({ "test-key": keyPair.publicKeyPem });

  function token(overrides: Partial<{ iat: number; exp: number }> = {}, keyId = "test-key") {
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
      keyId,
    );
  }

  it("accepts a valid token", () => {
    expect(verifyAccessToken(token(), resolver, now)).not.toBeNull();
  });

  it("rejects a token with an unknown key id", () => {
    expect(verifyAccessToken(token({}, "unknown-key"), resolver, now)).toBeNull();
  });

  it("supports multiple signing keys during rotation", () => {
    const oldKey = generateJwtKeyPair();
    const newKey = generateJwtKeyPair();
    const rotatingResolver = createJwtKeyResolver({
      old: oldKey.publicKeyPem,
      current: newKey.publicKeyPem,
    });

    const oldToken = signAccessToken(
      { sub: "user-1", sid: "session-1", jti: "old", iat: now, exp: now + 900, iss: "nabimo-auth", aud: "nabimo-auth-client" },
      oldKey.privateKeyPem,
      "old",
    );
    const currentToken = signAccessToken(
      { sub: "user-1", sid: "session-1", jti: "current", iat: now, exp: now + 900, iss: "nabimo-auth", aud: "nabimo-auth-client" },
      newKey.privateKeyPem,
      "current",
    );

    expect(verifyAccessToken(oldToken, rotatingResolver, now)).not.toBeNull();
    expect(verifyAccessToken(currentToken, rotatingResolver, now)).not.toBeNull();
  });

  it("rejects a token whose key id does not match its signing key", () => {
    const otherKey = generateJwtKeyPair();
    const mismatchedResolver = createJwtKeyResolver({ "test-key": otherKey.publicKeyPem });
    expect(verifyAccessToken(token(), mismatchedResolver, now)).toBeNull();
  });

  it("rejects an expired token", () => {
    expect(verifyAccessToken(token({ exp: now }), resolver, now)).toBeNull();
  });

  it("rejects a token whose expiration is not after iat", () => {
    expect(verifyAccessToken(token({ exp: now }), resolver, now - 1)).toBeNull();
  });

  it("rejects a token issued too far in the future", () => {
    expect(verifyAccessToken(token({ iat: now + 61 }), resolver, now)).toBeNull();
  });

  it("allows normal clock skew", () => {
    expect(verifyAccessToken(token({ iat: now + 60 }), resolver, now)).not.toBeNull();
  });

  it("rejects malformed timestamp values", () => {
    expect(verifyAccessToken(token({ iat: Number.MAX_SAFE_INTEGER + 1 }), resolver, now)).toBeNull();
    expect(verifyAccessToken(token({ exp: Number.MAX_SAFE_INTEGER + 1 }), resolver, now)).toBeNull();
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

    expect(verifyAccessToken(malformed, resolver, now)).toBeNull();
  });
});
