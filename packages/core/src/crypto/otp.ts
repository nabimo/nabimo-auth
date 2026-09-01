import { randomOtp } from "./random.js";
import { safeEqual, sha256 } from "./hash.js";

export function generateOtp(length = 6): string {
  return randomOtp(length);
}

export function hashOtp(otp: string): string {
  return sha256(otp);
}

export function verifyOtp(otp: string, expectedHash: string): boolean {
  return safeEqual(hashOtp(otp), expectedHash);
}
