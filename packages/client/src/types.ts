import type { AuthErrorResponse, AuthUserResponse, AuthenticationResponse, LogoutAllResponse, LogoutResponse, PasswordLoginResponse, PasswordResetConfirmResponse, PasswordResetRequestResponse, TwoFactorSetupResponse, TwoFactorSuccessResponse, TwoFactorRequiredResponse, VerificationChallengeResponse, VerificationSuccessResponse } from "@nabimo-auth/protocol";
import type { RefreshCoordinator, RefreshTransport } from "./refresh-coordinator.js";

export type AuthUser = AuthUserResponse;
export type AuthenticationResult = AuthenticationResponse;
export type PasswordLoginResult = PasswordLoginResponse;
export type TwoFactorRequiredResult = TwoFactorRequiredResponse;
export type LogoutResult = LogoutResponse;
export type LogoutAllResult = LogoutAllResponse;
export type VerificationChallengeResult = VerificationChallengeResponse;
export type VerificationResult = VerificationSuccessResponse;
export type PasswordResetRequestResult = PasswordResetRequestResponse;
export type PasswordResetConfirmResult = PasswordResetConfirmResponse;
export type TwoFactorSetupResult = TwoFactorSetupResponse;
export type TwoFactorResult = TwoFactorSuccessResponse;
export type { AuthErrorResponse };

export interface AuthTokens { accessToken: string; refreshToken: string; }
export interface TokenStorage { get(): AuthTokens | null | Promise<AuthTokens | null>; set(tokens: AuthTokens): void | Promise<void>; clear(): void | Promise<void>; }
export interface AuthClientOptions { baseUrl: string; fetch?: typeof globalThis.fetch; storage?: TokenStorage; headers?: HeadersInit; refreshCoordinator?: RefreshCoordinator; refreshTransport?: RefreshTransport; }
export interface AuthRequestOptions extends Omit<RequestInit, "body" | "headers"> { body?: unknown; headers?: HeadersInit; auth?: boolean; }
export class AuthClientError extends Error {
  readonly status: number;
  readonly code: string | null;
  readonly details: unknown;
  constructor(status: number, message: string, code: string | null, details: unknown) { super(message); this.name = "AuthClientError"; this.status = status; this.code = code; this.details = details; }
}
