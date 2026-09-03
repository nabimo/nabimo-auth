import type {
  AuthErrorResponse,
  AuthUserResponse,
  AuthenticationResponse,
  LogoutAllResponse,
  LogoutResponse,
  VerificationChallengeResponse,
  VerificationSuccessResponse,
} from "@nabimo-auth/protocol";

export type AuthUser = AuthUserResponse;
export type AuthenticationResult = AuthenticationResponse;
export type LogoutResult = LogoutResponse;
export type LogoutAllResult = LogoutAllResponse;
export type VerificationChallengeResult = VerificationChallengeResponse;
export type VerificationResult = VerificationSuccessResponse;
export type { AuthErrorResponse };

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
}

export interface TokenStorage {
  get(): AuthTokens | null | Promise<AuthTokens | null>;
  set(tokens: AuthTokens): void | Promise<void>;
  clear(): void | Promise<void>;
}

export interface AuthClientOptions {
  baseUrl: string;
  fetch?: typeof globalThis.fetch;
  storage?: TokenStorage;
  headers?: HeadersInit;
}

export interface AuthRequestOptions extends Omit<RequestInit, "body" | "headers"> {
  body?: unknown;
  headers?: HeadersInit;
  auth?: boolean;
}

export class AuthClientError extends Error {
  readonly status: number;
  readonly code: string | null;
  readonly details: unknown;

  constructor(status: number, message: string, code: string | null, details: unknown) {
    super(message);
    this.name = "AuthClientError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}
