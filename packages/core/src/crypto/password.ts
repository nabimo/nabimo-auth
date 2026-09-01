import { randomBytes, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(scryptCallback);

const VERSION = "scrypt-v1";
const KEY_LENGTH = 64;
const SALT_LENGTH = 16;
const COST = 65_536;
const BLOCK_SIZE = 8;
const PARALLELIZATION = 1;

export async function hashPassword(password: string): Promise<string> {
  assertPassword(password);

  const salt = randomBytes(SALT_LENGTH);
  const derivedKey = (await scrypt(password, salt, KEY_LENGTH, {
    N: COST,
    r: BLOCK_SIZE,
    p: PARALLELIZATION,
    maxmem: 128 * COST * BLOCK_SIZE + 1024,
  })) as Buffer;

  return [
    VERSION,
    `n=${COST},r=${BLOCK_SIZE},p=${PARALLELIZATION}`,
    salt.toString("base64url"),
    derivedKey.toString("base64url"),
  ].join("$");
}

export async function verifyPassword(password: string, encoded: string): Promise<boolean> {
  if (!password || !encoded) {
    return false;
  }

  const parts = encoded.split("$");
  if (parts.length !== 4 || parts[0] !== VERSION) {
    return false;
  }

  const params = parseParams(parts[1]);
  if (!params) {
    return false;
  }

  let salt: Buffer;
  let expected: Buffer;
  try {
    salt = Buffer.from(parts[2], "base64url");
    expected = Buffer.from(parts[3], "base64url");
  } catch {
    return false;
  }

  if (salt.length !== SALT_LENGTH || expected.length !== KEY_LENGTH) {
    return false;
  }

  const derivedKey = (await scrypt(password, salt, KEY_LENGTH, {
    N: params.N,
    r: params.r,
    p: params.p,
    maxmem: 128 * params.N * params.r + 1024,
  })) as Buffer;

  return timingSafeEqual(expected, derivedKey);
}

function assertPassword(password: string): void {
  if (typeof password !== "string" || password.length < 8) {
    throw new Error("Password must contain at least 8 characters");
  }

  if (password.length > 1024) {
    throw new Error("Password is too long");
  }
}

function parseParams(value: string): { N: number; r: number; p: number } | null {
  const match = /^n=(\d+),r=(\d+),p=(\d+)$/.exec(value);
  if (!match) return null;

  const N = Number(match[1]);
  const r = Number(match[2]);
  const p = Number(match[3]);

  if (!Number.isSafeInteger(N) || !Number.isSafeInteger(r) || !Number.isSafeInteger(p)) {
    return null;
  }

  if (N < 16_384 || (N & (N - 1)) !== 0 || r < 1 || p < 1) {
    return null;
  }

  return { N, r, p };
}
