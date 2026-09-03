import { MemoryTokenStorage } from "./storage.js";
import {
  AuthClientError,
  type AuthClientOptions,
  type AuthRequestOptions,
  type AuthenticationResult,
  type AuthTokens,
  type LogoutAllResult,
  type LogoutResult,
  type PasswordResetConfirmResult,
  type PasswordResetRequestResult,
  type TokenStorage,
  type VerificationChallengeResult,
  type VerificationResult,
} from "./types.js";
import type { AuthErrorResponse, PasswordLoginRequest, PasswordResetConfirmRequest, PasswordResetRequest, RefreshRequest, RegisterRequest } from "@nabimo-auth/protocol";

const JSON_CONTENT_TYPE = "application/json";

export class AuthClient {
  readonly baseUrl: string;
  private readonly requestFetch: typeof globalThis.fetch;
  private readonly storage: TokenStorage;
  private readonly defaultHeaders: HeadersInit;

  constructor(options: AuthClientOptions) {
    if (!options.baseUrl || typeof options.baseUrl !== "string") throw new TypeError("baseUrl is required");
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.requestFetch = options.fetch ?? globalThis.fetch;
    if (typeof this.requestFetch !== "function") throw new TypeError("A fetch implementation is required");
    this.storage = options.storage ?? new MemoryTokenStorage();
    this.defaultHeaders = options.headers ?? {};
  }

  async register(email: string, password: string): Promise<AuthenticationResult> { return this.authenticate("/auth/register", { email, password } satisfies RegisterRequest); }
  async loginWithPassword(email: string, password: string): Promise<AuthenticationResult> { return this.authenticate("/auth/login/password", { email, password } satisfies PasswordLoginRequest); }

  async refresh(): Promise<AuthenticationResult> {
    const tokens = await this.storage.get();
    if (!tokens?.refreshToken) throw new AuthClientError(401, "No refresh token available", "INVALID_CREDENTIALS", null);
    try {
      const result = await this.post<AuthenticationResult>("/auth/refresh", { refreshToken: tokens.refreshToken } satisfies RefreshRequest);
      await this.storage.set({ accessToken: result.accessToken, refreshToken: result.refreshToken });
      return result;
    } catch (error) {
      if (error instanceof AuthClientError && error.status === 401) await this.storage.clear();
      throw error;
    }
  }

  async requestEmailVerification(email: string): Promise<VerificationChallengeResult> { return this.post<VerificationChallengeResult>("/auth/verify/email/request", { email }, true); }
  async verifyOtp(challengeId: string, code: string): Promise<VerificationResult> { return this.post<VerificationResult>("/auth/verify/otp", { challengeId, code }); }
  async requestPasswordReset(email: string): Promise<PasswordResetRequestResult> { return this.post<PasswordResetRequestResult>("/auth/password/reset/request", { email } satisfies PasswordResetRequest); }
  async confirmPasswordReset(token: string, newPassword: string): Promise<PasswordResetConfirmResult> { return this.post<PasswordResetConfirmResult>("/auth/password/reset/confirm", { token, newPassword } satisfies PasswordResetConfirmRequest); }

  async logout(): Promise<LogoutResult> {
    const result = await this.request<LogoutResult>("/auth/logout", { method: "POST", auth: true });
    await this.storage.clear();
    return result;
  }
  async logoutAll(): Promise<LogoutAllResult> {
    const result = await this.request<LogoutAllResult>("/auth/logout-all", { method: "POST", auth: true });
    await this.storage.clear();
    return result;
  }
  async getTokens(): Promise<AuthTokens | null> { return this.storage.get(); }
  async getAccessToken(): Promise<string | null> { return (await this.storage.get())?.accessToken ?? null; }
  async clearTokens(): Promise<void> { await this.storage.clear(); }

  async request<T>(path: string, options: AuthRequestOptions = {}): Promise<T> {
    const headers = new Headers(this.defaultHeaders);
    new Headers(options.headers).forEach((value, key) => headers.set(key, value));
    if (options.auth ?? false) {
      const accessToken = (await this.storage.get())?.accessToken;
      if (!accessToken) throw new AuthClientError(401, "No access token available", "INVALID_CREDENTIALS", null);
      headers.set("Authorization", `Bearer ${accessToken}`);
    }
    let body: BodyInit | undefined;
    if (options.body !== undefined) {
      if (typeof options.body === "string" || options.body instanceof FormData || options.body instanceof URLSearchParams || options.body instanceof Blob || options.body instanceof ArrayBuffer) body = options.body;
      else { body = JSON.stringify(options.body); if (!headers.has("Content-Type")) headers.set("Content-Type", JSON_CONTENT_TYPE); }
    }
    const response = await this.requestFetch(this.resolve(path), { ...options, body, headers });
    return this.parseResponse<T>(response);
  }

  private async authenticate(path: string, body: RegisterRequest | PasswordLoginRequest): Promise<AuthenticationResult> {
    const result = await this.post<AuthenticationResult>(path, body);
    await this.storage.set({ accessToken: result.accessToken, refreshToken: result.refreshToken });
    return result;
  }
  private async post<T>(path: string, body: unknown, auth = false): Promise<T> { return this.request<T>(path, { method: "POST", body, auth }); }
  private resolve(path: string): string { if (/^https?:\/\//i.test(path)) return path; return `${this.baseUrl}${path.startsWith("/") ? path : `/${path}`}`; }
  private async parseResponse<T>(response: Response): Promise<T> {
    const text = await response.text();
    let payload: unknown = null;
    if (text) { try { payload = JSON.parse(text); } catch { payload = text; } }
    if (!response.ok) {
      const code = this.extractErrorCode(payload);
      const message = (this.extractErrorMessage(payload) ?? response.statusText) || `HTTP ${response.status}`;
      throw new AuthClientError(response.status, message, code, payload);
    }
    return payload as T;
  }
  private extractErrorCode(payload: unknown): string | null {
    if (!payload || typeof payload !== "object") return null;
    const code = (payload as AuthErrorResponse).data?.code;
    return typeof code === "string" ? code : null;
  }
  private extractErrorMessage(payload: unknown): string | null {
    if (!payload || typeof payload !== "object") return null;
    const error = payload as AuthErrorResponse;
    const value = error.statusMessage ?? error.message;
    return typeof value === "string" ? value : null;
  }
}
export function createAuthClient(options: AuthClientOptions): AuthClient { return new AuthClient(options); }
