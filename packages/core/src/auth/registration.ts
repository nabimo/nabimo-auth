import { normalizeEmail } from "./credentials.js";
import { createPasswordHash } from "./password.js";

export interface RegistrationInput {
  email: string;
  password: string;
}

export interface PreparedRegistration {
  email: string;
  passwordHash: string;
}

export async function preparePasswordRegistration(input: RegistrationInput): Promise<PreparedRegistration> {
  return {
    email: normalizeEmail(input.email),
    passwordHash: await createPasswordHash(input.password),
  };
}
