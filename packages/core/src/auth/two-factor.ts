import { randomInt, randomUUID } from "node:crypto";
import { authErrors } from "./errors.js";
import { sha256 } from "../crypto/hash.js";
import { buildTotpOtpAuthUri, generateTotpSecret, verifyTotp } from "../crypto/totp.js";
import { randomToken } from "../crypto/random.js";

export interface TwoFactorRecord {
  userId: string;
  secretCipher: string;
  enabledAt: Date | null;
}

export interface TwoFactorStore {
  get(userId: string): Promise<TwoFactorRecord | null>;
  savePending(input: { id: string; userId: string; secretCipher: string; recoveryCodeHashes: string[] }): Promise<void>;
  enable(userId: string, enabledAt: Date): Promise<boolean>;
  disable(userId: string): Promise<boolean>;
  consumeRecoveryCode(userId: string, codeHash: string, now: Date): Promise<boolean>;
}

export interface TwoFactorSecretCipher {
  encrypt(secret: string): string;
  decrypt(ciphertext: string): string;
}

export interface TwoFactorServiceConfig {
  store: TwoFactorStore;
  cipher: TwoFactorSecretCipher;
  issuer?: string;
}

export interface TwoFactorSetupResult {
  secret: string;
  otpauthUri: string;
  recoveryCodes: string[];
}

const RECOVERY_CODE_COUNT = 10;

export class TwoFactorService {
  private readonly issuer: string;

  constructor(private readonly config: TwoFactorServiceConfig) {
    this.issuer = config.issuer ?? "Nabimo Auth";
  }

  async setup(userId: string, accountName: string): Promise<TwoFactorSetupResult> {
    const existing = await this.config.store.get(userId);
    if (existing?.enabledAt) throw new Error("Two-factor authentication is already enabled");

    const secret = generateTotpSecret();
    const recoveryCodes = Array.from({ length: RECOVERY_CODE_COUNT }, () => this.generateRecoveryCode());
    await this.config.store.savePending({
      id: randomUUID(),
      userId,
      secretCipher: this.config.cipher.encrypt(secret),
      recoveryCodeHashes: recoveryCodes.map((code) => sha256(code)),
    });

    return {
      secret,
      otpauthUri: buildTotpOtpAuthUri(secret, accountName, this.issuer),
      recoveryCodes,
    };
  }

  async enable(userId: string, code: string): Promise<void> {
    const record = await this.config.store.get(userId);
    if (!record) throw authErrors.invalidTwoFactorCode();
    const secret = this.config.cipher.decrypt(record.secretCipher);
    if (!verifyTotp(secret, code)) throw authErrors.invalidTwoFactorCode();
    if (record.enabledAt) return;
    const enabled = await this.config.store.enable(userId, new Date());
    if (!enabled) throw authErrors.invalidTwoFactorCode();
  }

  async verify(userId: string, code: string): Promise<void> {
    const record = await this.config.store.get(userId);
    if (!record?.enabledAt) throw authErrors.invalidTwoFactorCode();
    const secret = this.config.cipher.decrypt(record.secretCipher);
    if (!verifyTotp(secret, code)) throw authErrors.invalidTwoFactorCode();
  }

  async verifyRecoveryCode(userId: string, code: string): Promise<void> {
    const normalized = code.trim().toUpperCase();
    if (!/^[A-Z0-9-]{8,32}$/.test(normalized)) throw authErrors.invalidTwoFactorCode();
    const consumed = await this.config.store.consumeRecoveryCode(userId, sha256(normalized), new Date());
    if (!consumed) throw authErrors.invalidTwoFactorCode();
  }

  async disable(userId: string): Promise<void> {
    const disabled = await this.config.store.disable(userId);
    if (!disabled) throw authErrors.invalidTwoFactorCode();
  }

  private generateRecoveryCode(): string {
    const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    const groups = Array.from({ length: 4 }, () => {
      let group = "";
      for (let i = 0; i < 4; i += 1) group += alphabet[randomInt(alphabet.length)];
      return group;
    });
    return groups.join("-");
  }
}
