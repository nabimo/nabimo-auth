import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import type { TwoFactorSecretCipher } from "@nabimo-auth/core";

export class AesTwoFactorSecretCipher implements TwoFactorSecretCipher {
  private readonly key: Buffer;

  constructor(keyInput: string) {
    this.key = createHash("sha256").update(keyInput, "utf8").digest();
  }

  encrypt(secret: string): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.key, iv);
    const ciphertext = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();
    return [iv, tag, ciphertext].map((part) => part.toString("base64url")).join(".");
  }

  decrypt(ciphertext: string): string {
    const [ivEncoded, tagEncoded, dataEncoded] = ciphertext.split(".");
    if (!ivEncoded || !tagEncoded || !dataEncoded) throw new Error("Invalid encrypted two-factor secret");
    const decipher = createDecipheriv("aes-256-gcm", this.key, Buffer.from(ivEncoded, "base64url"));
    decipher.setAuthTag(Buffer.from(tagEncoded, "base64url"));
    return Buffer.concat([
      decipher.update(Buffer.from(dataEncoded, "base64url")),
      decipher.final(),
    ]).toString("utf8");
  }
}
