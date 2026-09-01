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
  if (!Number.isInteger(length) || length < 4 || length > 9) {
    throw new RangeError("OTP length must be between 4 and 9");
  }

  const upperBound = 10 ** length;
  const maxUint32 = 0x1_0000_0000;
  const limit = maxUint32 - (maxUint32 % upperBound);

  while (true) {
    const value = randomBytesBuffer(4).readUInt32BE(0);
    if (value < limit) {
      return (value % upperBound).toString().padStart(length, "0");
    }
  }
}
