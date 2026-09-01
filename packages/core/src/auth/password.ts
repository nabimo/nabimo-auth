import { authErrors } from "./errors.js";
import { hashPassword, verifyPassword } from "../crypto/password.js";

export async function createPasswordHash(password: string): Promise<string> {
  validatePassword(password);
  return hashPassword(password);
}

export async function verifyUserPassword(password: string, passwordHash: string): Promise<void> {
  const valid = await verifyPassword(password, passwordHash);
  if (!valid) throw authErrors.invalidCredentials();
}

function validatePassword(password: string): void {
  if (typeof password !== "string" || password.length < 8 || password.length > 128) {
    throw new Error("Password must be between 8 and 128 characters");
  }
}
