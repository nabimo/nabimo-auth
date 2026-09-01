import { timingSafeEqual } from "node:crypto";

/** Compare two byte sequences without leaking equality through timing. */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }

  return timingSafeEqual(a, b);
}
