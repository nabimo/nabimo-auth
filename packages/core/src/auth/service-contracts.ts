import type { AuthResult } from "./types.js";

export interface RegisterWithPasswordInput {
  email: string;
  password: string;
}

export interface LoginWithPasswordInput {
  email: string;
  password: string;
}

export interface PasswordAuthService {
  registerWithPassword(input: RegisterWithPasswordInput): Promise<AuthResult>;
  loginWithPassword(input: LoginWithPasswordInput): Promise<AuthResult>;
}
