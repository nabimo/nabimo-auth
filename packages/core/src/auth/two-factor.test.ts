import { describe, expect, it, vi } from "vitest";
import { TwoFactorService, type TwoFactorSecretCipher, type TwoFactorStore } from "./two-factor.js";
import { generateTotp } from "../crypto/totp.js";

const cipher: TwoFactorSecretCipher = { encrypt: (value) => value, decrypt: (value) => value };

function store(): TwoFactorStore {
  return { get: vi.fn(), savePending: vi.fn(), enable: vi.fn().mockResolvedValue(true), disable: vi.fn().mockResolvedValue(true), consumeRecoveryCode: vi.fn().mockResolvedValue(true) };
}

describe("TwoFactorService", () => {
  it("creates a TOTP setup with recovery codes", async () => {
    const s = store();
    const service = new TwoFactorService({ store: s, cipher, issuer: "Nabimo" });
    const result = await service.setup("user-1", "user@example.com");
    expect(result.secret).toMatch(/^[A-Z2-7]+$/);
    expect(result.otpauthUri).toContain("otpauth://totp/");
    expect(result.recoveryCodes).toHaveLength(10);
    expect(s.savePending).toHaveBeenCalledTimes(1);
  });

  it("enables a pending factor with a valid TOTP", async () => {
    const s = store();
    vi.mocked(s.get).mockResolvedValue({ userId: "user-1", secretCipher: "JBSWY3DPEHPK3PXP", enabledAt: null });
    const service = new TwoFactorService({ store: s, cipher });
    await service.enable("user-1", generateTotp("JBSWY3DPEHPK3PXP"));
    expect(s.enable).toHaveBeenCalledTimes(1);
  });

  it("rejects an invalid TOTP", async () => {
    const s = store();
    vi.mocked(s.get).mockResolvedValue({ userId: "user-1", secretCipher: "JBSWY3DPEHPK3PXP", enabledAt: null });
    const service = new TwoFactorService({ store: s, cipher });
    await expect(service.enable("user-1", "000000")).rejects.toMatchObject({ code: "INVALID_2FA_CODE" });
  });

  it("consumes a recovery code", async () => {
    const s = store();
    const service = new TwoFactorService({ store: s, cipher });
    await service.verifyRecoveryCode("user-1", "ABCD-EFGH-IJKL-MNPQ");
    expect(s.consumeRecoveryCode).toHaveBeenCalledTimes(1);
  });
});
