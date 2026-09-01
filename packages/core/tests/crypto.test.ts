import { describe, expect, it } from "vitest";
import {
  generateOtp,
  generateToken,
  hashOtp,
  hashPassword,
  verifyOtp,
  verifyPassword,
} from "../src/index.js";

describe("passwords", () => {
  it("hashes and verifies a password", async () => {
    const hash = await hashPassword("correct horse battery staple");

    expect(hash).toMatch(/^scrypt-v1\\$/);
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
    expect(otp).toMatch(/^\\d{6}$/);
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
