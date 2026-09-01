import { createHmac } from "node:crypto";
import { constantTimeEqual } from "./constant-time.js";
import { randomBytesBuffer } from "./random.js";

export type TotpAlgorithm = "SHA1" | "SHA256" | "SHA512";

export interface TotpOptions {
  digits?: 6 | 8;
  period?: number;
  algorithm?: TotpAlgorithm;
  window?: number;
}

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function generateTotpSecret(bytes = 20): string {
  return base32Encode(randomBytesBuffer(bytes));
}

export function generateTotp(secret: string, timestamp = Date.now(), options: TotpOptions = {}): string {
  const digits = options.digits ?? 6;
  const period = options.period ?? 30;
  const algorithm = options.algorithm ?? "SHA1";
  const counter = Math.floor(timestamp / 1000 / period);
  return generateTotpForCounter(secret, counter, digits, algorithm);
}

export function verifyTotp(secret: string, code: string, timestamp = Date.now(), options: TotpOptions = {}): boolean {
  const digits = options.digits ?? 6;
  const period = options.period ?? 30;
  const algorithm = options.algorithm ?? "SHA1";
  const window = options.window ?? 1;

  if (!/^\d+$/.test(code) || code.length !== digits || window < 0 || window > 10) {
    return false;
  }

  const counter = Math.floor(timestamp / 1000 / period);
  const supplied = Buffer.from(code, "ascii");

  for (let offset = -window; offset <= window; offset += 1) {
    const expected = Buffer.from(generateTotpForCounter(secret, counter + offset, digits, algorithm), "ascii");
    if (constantTimeEqual(supplied, expected)) {
      return true;
    }
  }

  return false;
}

export function buildTotpOtpAuthUri(
  secret: string,
  accountName: string,
  issuer: string,
  options: Pick<TotpOptions, "digits" | "period" | "algorithm"> = {},
): string {
  const digits = options.digits ?? 6;
  const period = options.period ?? 30;
  const algorithm = options.algorithm ?? "SHA1";
  const label = `${issuer}:${accountName}`;
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm,
    digits: String(digits),
    period: String(period),
  });

  return `otpauth://totp/${encodeURIComponent(label)}?${params.toString()}`;
}

function generateTotpForCounter(secret: string, counter: number, digits: number, algorithm: TotpAlgorithm): string {
  if (!Number.isSafeInteger(counter) || counter < 0) {
    throw new RangeError("TOTP counter must be a non-negative safe integer");
  }

  const key = base32Decode(secret);
  const message = Buffer.allocUnsafe(8);
  message.writeUInt32BE(Math.floor(counter / 2 ** 32), 0);
  message.writeUInt32BE(counter >>> 0, 4);

  const digest = createHmac(algorithm.toLowerCase().replace("sha", "sha"), key).update(message).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24)
    | ((digest[offset + 1] & 0xff) << 16)
    | ((digest[offset + 2] & 0xff) << 8)
    | (digest[offset + 3] & 0xff);

  return String(binary % 10 ** digits).padStart(digits, "0");
}

function base32Encode(input: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = "";

  for (const byte of input) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }

  return output;
}

function base32Decode(input: string): Buffer {
  const normalized = input.replace(/=+$/g, "").replace(/\s+/g, "").toUpperCase();
  let bits = 0;
  let value = 0;
  const output: number[] = [];

  for (const char of normalized) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index === -1) {
      throw new Error("Invalid base32 secret");
    }
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return Buffer.from(output);
}
