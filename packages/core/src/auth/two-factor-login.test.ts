import { describe, expect, it, vi } from "vitest";
import { TwoFactorLoginService, type TwoFactorLoginStore } from "./two-factor-login.js";

function createStore(): TwoFactorLoginStore {
  return {
    create: vi.fn(),
    find: vi.fn(),
    incrementAttempts: vi.fn().mockResolvedValue(true),
    consume: vi.fn().mockResolvedValue(true),
  };
}

describe("TwoFactorLoginService", () => {
  it("accepts a valid TOTP code", async () => {
    const store = createStore();
    vi.mocked(store.find).mockResolvedValue({ userId: "user-1" });
    const twoFactor = {
      isEnabled: vi.fn().mockResolvedValue(true),
      verify: vi.fn().mockResolvedValue(undefined),
      verifyRecoveryCode: vi.fn(),
    };
    const service = new TwoFactorLoginService({ store, twoFactor });

    await expect(service.verifyChallenge("a".repeat(32), "123456")).resolves.toBe("user-1");
    expect(store.incrementAttempts).toHaveBeenCalledWith(expect.objectContaining({ maxAttempts: 5 }));
    expect(twoFactor.verify).toHaveBeenCalledWith("user-1", "123456");
    expect(twoFactor.verifyRecoveryCode).not.toHaveBeenCalled();
    expect(store.consume).toHaveBeenCalledTimes(1);
  });

  it("falls back to a recovery code when TOTP verification fails", async () => {
    const store = createStore();
    vi.mocked(store.find).mockResolvedValue({ userId: "user-1" });
    const twoFactor = {
      isEnabled: vi.fn().mockResolvedValue(true),
      verify: vi.fn().mockRejectedValue(new Error("invalid totp")),
      verifyRecoveryCode: vi.fn().mockResolvedValue(undefined),
    };
    const service = new TwoFactorLoginService({ store, twoFactor });

    await expect(service.verifyChallenge("b".repeat(32), "ABCD-2345-EFGH-6789")).resolves.toBe("user-1");
    expect(twoFactor.verifyRecoveryCode).toHaveBeenCalledWith("user-1", "ABCD-2345-EFGH-6789");
    expect(store.consume).toHaveBeenCalledTimes(1);
  });

  it("rejects an invalid TOTP and recovery code", async () => {
    const store = createStore();
    vi.mocked(store.find).mockResolvedValue({ userId: "user-1" });
    const twoFactor = {
      isEnabled: vi.fn().mockResolvedValue(true),
      verify: vi.fn().mockRejectedValue(new Error("invalid totp")),
      verifyRecoveryCode: vi.fn().mockRejectedValue(new Error("invalid recovery")),
    };
    const service = new TwoFactorLoginService({ store, twoFactor });

    await expect(service.verifyChallenge("c".repeat(32), "BAD-CODE")).rejects.toMatchObject({ code: "INVALID_2FA_CODE" });
    expect(store.consume).not.toHaveBeenCalled();
  });

  it("passes a custom maximum attempt policy to the store", async () => {
    const store = createStore();
    vi.mocked(store.find).mockResolvedValue({ userId: "user-1" });
    vi.mocked(store.incrementAttempts).mockResolvedValue(false);
    const twoFactor = {
      isEnabled: vi.fn().mockResolvedValue(true),
      verify: vi.fn().mockResolvedValue(undefined),
      verifyRecoveryCode: vi.fn(),
    };
    const service = new TwoFactorLoginService({ store, twoFactor, maxAttempts: 3 });

    await expect(service.verifyChallenge("d".repeat(32), "123456")).rejects.toMatchObject({ code: "INVALID_2FA_CODE" });
    expect(store.incrementAttempts).toHaveBeenCalledWith(expect.objectContaining({ maxAttempts: 3 }));
    expect(twoFactor.verify).not.toHaveBeenCalled();
  });
});
