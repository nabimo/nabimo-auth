import { describe, expect, it, vi } from "vitest";
import { VerificationService, type VerificationStore, type VerificationCodeSender } from "./verification.js";

function createStore(): VerificationStore {
  return {
    create: vi.fn(),
    findActive: vi.fn(),
    incrementAttempts: vi.fn(),
    consume: vi.fn(),
    markVerified: vi.fn(),
  };
}

function createSender(): VerificationCodeSender {
  return { send: vi.fn() };
}

describe("VerificationService", () => {
  it("creates and sends a six-digit email OTP without exposing the code", async () => {
    const store = createStore();
    const sender = createSender();
    const service = new VerificationService({ store, sender });

    const challenge = await service.requestEmailOtp("user-1", " User@Example.COM ");

    expect(challenge.type).toBe("email_otp");
    expect(challenge.target).toBe("user@example.com");
    expect(challenge.challengeId).toBeTruthy();
    expect(challenge.expiresAt.getTime()).toBeGreaterThan(Date.now());
    expect(store.create).toHaveBeenCalledTimes(1);
    expect(sender.send).toHaveBeenCalledTimes(1);
    const sent = vi.mocked(sender.send).mock.calls[0][0];
    expect(sent.code).toMatch(/^\d{6}$/);
    expect(sent.target).toBe("user@example.com");
    expect(sent.type).toBe("email_otp");
  });

  it("consumes a valid OTP and marks the email verified", async () => {
    const store = createStore();
    const sender = createSender();
    vi.mocked(store.findActive).mockResolvedValue({
      id: "challenge-1",
      userId: "user-1",
      type: "email_otp",
      target: "user@example.com",
      codeHash: "03ac674216f3e15c761ee1a5e255f067953623c8e5f9f8a5e4c3c8c3f0f0f0f0",
      expiresAt: new Date(Date.now() + 60_000),
      consumedAt: null,
      attempts: 0,
    });
    const service = new VerificationService({ store, sender });

    const { sha256 } = await import("../crypto/hash.js");
    vi.mocked(store.findActive).mockResolvedValue({
      id: "challenge-1",
      userId: "user-1",
      type: "email_otp",
      target: "user@example.com",
      codeHash: sha256("123456"),
      expiresAt: new Date(Date.now() + 60_000),
      consumedAt: null,
      attempts: 0,
    });

    await service.verifyOtp("challenge-1", "123456");

    expect(store.consume).toHaveBeenCalledTimes(1);
    expect(store.markVerified).toHaveBeenCalledWith("user-1", "email_otp");
    expect(store.incrementAttempts).not.toHaveBeenCalled();
  });

  it("increments attempts for an invalid OTP", async () => {
    const store = createStore();
    const sender = createSender();
    const { sha256 } = await import("../crypto/hash.js");
    vi.mocked(store.findActive).mockResolvedValue({
      id: "challenge-1",
      userId: "user-1",
      type: "email_otp",
      target: "user@example.com",
      codeHash: sha256("123456"),
      expiresAt: new Date(Date.now() + 60_000),
      consumedAt: null,
      attempts: 0,
    });
    const service = new VerificationService({ store, sender });

    await expect(service.verifyOtp("challenge-1", "654321")).rejects.toMatchObject({ code: "INVALID_OTP" });
    expect(store.incrementAttempts).toHaveBeenCalledWith("challenge-1");
    expect(store.consume).not.toHaveBeenCalled();
  });
});
