import { randomBytes } from "node:crypto";

export function randomBytesBuffer(size: number): Buffer {
  if (!Number.isInteger(size) || size <= 0) {
    throw new RangeError("size must be a positive integer");
  }

  return randomBytes(size);
}

export function randomToken(size = 32): string {
  return randomBytesBuffer(size).toString("base64url");
}

export function randomOtp(length = 6): string {
  if (!Number.isInteger(length) || length < 4 || length > 10) {
    throw new RangeError("OTP length must be between 4 and 10");
  }

  const max = 10 ** length;
  const value = randomBytesBuffer(4).readUInt32BE(0) % max;
  return value.toString().padStart(length, "0");
}
