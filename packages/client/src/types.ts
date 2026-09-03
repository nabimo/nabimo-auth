export interface AuthUser {
  id: string;
  email: string;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
}

export interface AuthenticationResult {
  user: AuthUser;
  sessionId: string;
  accessToken: string;
  refreshToken: string;
}

export interface LogoutResult {
  success: true;
}

export interface LogoutAllResult {
  success: true;
  revokedSessions: number;
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

export interface AuthErrorPayload {
  code?: string;
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
