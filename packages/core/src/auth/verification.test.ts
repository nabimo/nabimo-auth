import { describe, expect, it, vi } from "vitest";
import { VerificationService, type VerificationStore, type VerificationCodeSender } from "./verification.js";
import { sha256 } from "../crypto/hash.js";

function createStore(): VerificationStore {
  return {
    create: vi.fn(),
    createWithPolicy: vi.fn(),
    findActive: vi.fn(),
    incrementAttempts: vi.fn().mockResolvedValue(true),
    consume: vi.fn().mockResolvedValue(true),
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
    expect(store.createWithPolicy).toHaveBeenCalledTimes(1);
    expect(sender.send).toHaveBeenCalledTimes(1);
    const sent = vi.mocked(sender.send).mock.calls[0][0];
    expect(sent.code).toMatch(/^\d{6}$/);
    expect(sent.target).toBe("user@example.com");
    expect(sent.type).toBe("email_otp");
    expect(vi.mocked(store.createWithPolicy).mock.calls[0][0].policy).toEqual({
      cooldownSeconds: 60,
      maxRequests: 5,
      requestWindowSeconds: 3600,
      maxActiveChallenges: 3,
    });
  });

  it("normalizes and sends a phone OTP", async () => {
    const store = createStore();
    const sender = createSender();
    const service = new VerificationService({ store, sender });

    const challenge = await service.requestPhoneOtp("user-1", " +1 (202) 555-0123 ");

    expect(challenge.type).toBe("phone_otp");
    expect(challenge.target).toBe("+12025550123");
    const sent = vi.mocked(sender.send).mock.calls[0][0];
    expect(sent).toMatchObject({ type: "phone_otp", target: "+12025550123" });
    expect(sent.code).toMatch(/^\d{6}$/);
    expect(vi.mocked(store.createWithPolicy).mock.calls[0][0].type).toBe("phone_otp");
    expect(vi.mocked(store.createWithPolicy).mock.calls[0][0].target).toBe("+12025550123");
  });

  it("consumes a valid OTP and marks the email verified", async () => {
    const store = createStore();
    const sender = createSender();
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

    await service.verifyOtp("challenge-1", "123456");

    expect(store.consume).toHaveBeenCalledTimes(1);
    expect(store.markVerified).toHaveBeenCalledWith("user-1", "email_otp");
    expect(store.incrementAttempts).not.toHaveBeenCalled();
  });

  it("consumes a valid OTP and marks the phone verified", async () => {
    const store = createStore();
    const sender = createSender();
    vi.mocked(store.findActive).mockResolvedValue({
      id: "challenge-1",
      userId: "user-1",
      type: "phone_otp",
      target: "+12025550123",
      codeHash: sha256("123456"),
      expiresAt: new Date(Date.now() + 60_000),
      consumedAt: null,
      attempts: 0,
    });
    const service = new VerificationService({ store, sender });

    await service.verifyOtp("challenge-1", "123456");

    expect(store.consume).toHaveBeenCalledTimes(1);
    expect(store.markVerified).toHaveBeenCalledWith("user-1", "phone_otp");
  });

  it("increments attempts for an invalid OTP using the configured limit", async () => {
    const store = createStore();
    const sender = createSender();
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
    const service = new VerificationService({ store, sender, maxAttempts: 3 });

    await expect(service.verifyOtp("challenge-1", "654321")).rejects.toMatchObject({ code: "INVALID_OTP" });
    expect(store.incrementAttempts).toHaveBeenCalledWith("challenge-1", 3);
    expect(store.consume).not.toHaveBeenCalled();
  });

  it("rejects an invalid OTP when the atomic attempt increment loses the limit race", async () => {
    const store = createStore();
    const sender = createSender();
    vi.mocked(store.findActive).mockResolvedValue({
      id: "challenge-1",
      userId: "user-1",
      type: "email_otp",
      target: "user@example.com",
      codeHash: sha256("123456"),
      expiresAt: new Date(Date.now() + 60_000),
      consumedAt: null,
      attempts: 2,
    });
    vi.mocked(store.incrementAttempts).mockResolvedValue(false);
    const service = new VerificationService({ store, sender, maxAttempts: 3 });

    await expect(service.verifyOtp("challenge-1", "654321")).rejects.toMatchObject({ code: "INVALID_OTP" });
    expect(store.consume).not.toHaveBeenCalled();
  });

  it("rejects a correct OTP when another request consumed the challenge first", async () => {
    const store = createStore();
    const sender = createSender();
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
    vi.mocked(store.consume).mockResolvedValue(false);
    const service = new VerificationService({ store, sender });

    await expect(service.verifyOtp("challenge-1", "123456")).rejects.toMatchObject({ code: "INVALID_OTP" });
    expect(store.markVerified).not.toHaveBeenCalled();
  });
});
