import { describe, expect, it } from "vitest";
import {
  generateOtp,
  generateToken,
  hashOtp,
  hashPassword,
  verifyOtp,
  verifyPassword,
  generateTotp,
  verifyTotp,
  buildTotpOtpAuthUri,
} from "../src/index.js";

describe("passwords", () => {
  it("hashes and verifies a password", async () => {
    const hash = await hashPassword("correct horse battery staple");
    expect(hash).toMatch(/^scrypt-v1\$/);
    expect(await verifyPassword("correct horse battery staple", hash)).toBe(true);
    expect(await verifyPassword("wrong password", hash)).toBe(false);
  });

  it("rejects passwords shorter than 8 characters", async () => {
    await expect(hashPassword("short")).rejects.toThrow();
  });
});

describe("OTP", () => {
  it("generates a six digit OTP", () => {
    const otp = generateOtp();
    expect(otp).toMatch(/^\d{6}$/);
  });

  it("verifies an OTP against its hash", () => {
    const otp = generateOtp();
    const hash = hashOtp(otp);
    expect(verifyOtp(otp, hash)).toBe(true);
    expect(verifyOtp("000000", hash)).toBe(false);
  });
});

describe("opaque tokens", () => {
  it("returns a token and its hash", () => {
    const generated = generateToken();
    expect(generated.token).toBeTruthy();
    expect(generated.hash).toHaveLength(64);
  });
});

describe("TOTP", () => {
  // RFC 6238 test secret: ASCII "12345678901234567890", base32 encoded.
  const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  const timestamp = 59_000;

  it("generates the RFC 6238 SHA-1 test vector", () => {
    expect(generateTotp(secret, timestamp)).toBe("287082");
  });

  it("verifies the current code and rejects an incorrect code", () => {
    const code = generateTotp(secret, timestamp);
    expect(verifyTotp(secret, code, timestamp, { window: 0 })).toBe(true);
    expect(verifyTotp(secret, "000000", timestamp, { window: 0 })).toBe(false);
  });

  it("supports a one-period clock-skew window", () => {
    const previousCode = generateTotp(secret, timestamp - 30_000);
    expect(verifyTotp(secret, previousCode, timestamp, { window: 1 })).toBe(true);
    expect(verifyTotp(secret, previousCode, timestamp, { window: 0 })).toBe(false);
  });

  it("builds an otpauth URI", () => {
    const uri = buildTotpOtpAuthUri(secret, "user@example.com", "Nabimo Auth");
    expect(uri).toContain("otpauth://totp/");
    expect(uri).toContain("secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    expect(uri).toContain("issuer=Nabimo+Auth");
  });
});
