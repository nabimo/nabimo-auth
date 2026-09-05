import { InMemoryRefreshCoordinator } from "./refresh-coordinator.js";
import { MemoryTokenStorage } from "./storage.js";
import { AuthClientError, type AuthClientOptions, type AuthRequestOptions, type AuthenticationResult, type AuthTokens, type LogoutAllResult, type LogoutResult, type PasswordLoginResult, type PasswordResetConfirmResult, type PasswordResetRequestResult, type TokenStorage, type TwoFactorResult, type TwoFactorSetupResult, type VerificationChallengeResult, type VerificationResult } from "./types.js";
import type { AuthErrorResponse, PasswordLoginRequest, PasswordResetConfirmRequest, PasswordResetRequest, PhoneVerificationRequest, RegisterRequest, TwoFactorCodeRequest, TwoFactorLoginRequest } from "@nabimo-auth/protocol";
import type { RefreshCoordinator } from "./refresh-coordinator.js";

const JSON_CONTENT_TYPE = "application/json";

export class AuthClient {
  readonly baseUrl: string;
  private readonly requestFetch: typeof globalThis.fetch;
  private readonly storage: TokenStorage;
  private readonly defaultHeaders: HeadersInit;
  private readonly refreshCoordinator: RefreshCoordinator;

  constructor(options: AuthClientOptions) {
    if (!options.baseUrl || typeof options.baseUrl !== "string") throw new TypeError("baseUrl is required");
    this.baseUrl = options.baseUrl.replace(/\/$/, ""); this.requestFetch = options.fetch ?? globalThis.fetch;
    if (typeof this.requestFetch !== "function") throw new TypeError("A fetch implementation is required");
    this.storage = options.storage ?? new MemoryTokenStorage(); this.defaultHeaders = options.headers ?? {};
    this.refreshCoordinator = options.refreshCoordinator ?? new InMemoryRefreshCoordinator();
  }

  async register(email: string, password: string): Promise<AuthenticationResult> { return this.authenticate<AuthenticationResult>("/auth/register", { email, password } satisfies RegisterRequest); }
  async loginWithPassword(email: string, password: string): Promise<PasswordLoginResult> { return this.authenticate<PasswordLoginResult>("/auth/login/password", { email, password } satisfies PasswordLoginRequest); }
  async loginWithTwoFactor(challengeToken: string, code: string): Promise<AuthenticationResult> { return this.authenticate<AuthenticationResult>("/auth/2fa/login", { challengeToken, code } satisfies TwoFactorLoginRequest); }

  async refresh(): Promise<AuthenticationResult> { return this.refreshCoordinator.run(() => this.performRefresh()); }

  async requestEmailVerification(email: string): Promise<VerificationChallengeResult> { return this.post<VerificationChallengeResult>("/auth/verify/email/request", { email }, true); }
  async requestPhoneVerification(phone: string): Promise<VerificationChallengeResult> { return this.post<VerificationChallengeResult>("/auth/verify/phone/request", { phone } satisfies PhoneVerificationRequest, true); }
  async verifyOtp(challengeId: string, code: string): Promise<VerificationResult> { return this.post<VerificationResult>("/auth/verify/otp", { challengeId, code }); }
  async requestPasswordReset(email: string): Promise<PasswordResetRequestResult> { return this.post<PasswordResetRequestResult>("/auth/password/reset/request", { email } satisfies PasswordResetRequest); }
  async confirmPasswordReset(token: string, newPassword: string): Promise<PasswordResetConfirmResult> { return this.post<PasswordResetConfirmResult>("/auth/password/reset/confirm", { token, newPassword } satisfies PasswordResetConfirmRequest); }
  async setupTwoFactor(): Promise<TwoFactorSetupResult> { return this.post<TwoFactorSetupResult>("/auth/2fa/setup", {}, true); }
  async enableTwoFactor(code: string): Promise<TwoFactorResult> { return this.post<TwoFactorResult>("/auth/2fa/enable", { code } satisfies TwoFactorCodeRequest, true); }
  async disableTwoFactor(code: string): Promise<TwoFactorResult> { return this.post<TwoFactorResult>("/auth/2fa/disable", { code } satisfies TwoFactorCodeRequest, true); }
  async logout(): Promise<LogoutResult> { try { return await this.request<LogoutResult>("/auth/logout", { method: "POST", auth: true }); } finally { await this.storage.clear(); } }
  async logoutAll(): Promise<LogoutAllResult> { try { return await this.request<LogoutAllResult>("/auth/logout-all", { method: "POST", auth: true }); } finally { await this.storage.clear(); } }
  async getTokens(): Promise<AuthTokens | null> { return this.storage.get(); }
  async getAccessToken(): Promise<string | null> { return (await this.storage.get())?.accessToken ?? null; }
  async clearTokens(): Promise<void> { await this.storage.clear(); }

  async request<T>(path: string, options: AuthRequestOptions = {}): Promise<T> {
    const headers = new Headers(this.defaultHeaders); new Headers(options.headers).forEach((value, key) => headers.set(key, value));
    const authenticated = options.auth ?? false;
    if (authenticated) {
      const accessToken = (await this.storage.get())?.accessToken;
      if (!accessToken) throw new AuthClientError(401, "No access token available", "INVALID_CREDENTIALS", null);
      headers.set("Authorization", `Bearer ${accessToken}`);
    }
    let body: BodyInit | undefined;
    if (options.body !== undefined) { if (typeof options.body === "string" || options.body instanceof FormData || options.body instanceof URLSearchParams || options.body instanceof Blob || options.body instanceof ArrayBuffer) body = options.body; else { body = JSON.stringify(options.body); if (!headers.has("Content-Type")) headers.set("Content-Type", JSON_CONTENT_TYPE); } }
    const url = this.resolve(path, authenticated);
    const response = await this.requestFetch(url, { ...options, body, headers });
    if (authenticated && response.status === 401) {
      await this.refresh();
      const retryHeaders = new Headers(this.defaultHeaders); new Headers(options.headers).forEach((value, key) => retryHeaders.set(key, value));
      const accessToken = (await this.storage.get())?.accessToken;
      if (!accessToken) throw new AuthClientError(401, "No access token available", "INVALID_CREDENTIALS", null);
      retryHeaders.set("Authorization", `Bearer ${accessToken}`);
      const retryResponse = await this.requestFetch(url, { ...options, body, headers: retryHeaders });
      return this.parseResponse<T>(retryResponse);
    }
    return this.parseResponse<T>(response);
  }

  private async performRefresh(): Promise<AuthenticationResult> {
    const tokens = await this.storage.get();
    if (!tokens?.refreshToken) throw new AuthClientError(401, "No refresh token available", "INVALID_CREDENTIALS", null);
    try {
      const result = await this.post<AuthenticationResult>("/auth/refresh", { refreshToken: tokens.refreshToken });
      await this.storage.set({ accessToken: result.accessToken, refreshToken: result.refreshToken });
      return result;
    } catch (error) {
      if (error instanceof AuthClientError && error.status === 401) await this.storage.clear();
      throw error;
    }
  }

  private async authenticate<T extends AuthenticationResult | PasswordLoginResult>(path: string, body: RegisterRequest | PasswordLoginRequest | TwoFactorLoginRequest): Promise<T> { const result = await this.post<T>(path, body); if ("accessToken" in result) await this.storage.set({ accessToken: result.accessToken, refreshToken: result.refreshToken }); return result; }
  private async post<T>(path: string, body: unknown, auth = false): Promise<T> { return this.request<T>(path, { method: "POST", body, auth }); }
  private resolve(path: string, authenticated: boolean): string { if (!/^https?:\/\//i.test(path)) return `${this.baseUrl}${path.startsWith("/") ? path : `/${path}`}`; const url = new URL(path); if (authenticated && url.origin !== new URL(this.baseUrl).origin) throw new TypeError("Authenticated requests cannot target a different origin"); return url.toString(); }
  private async parseResponse<T>(response: Response): Promise<T> { const text = await response.text(); let payload: unknown = null; if (text) { try { payload = JSON.parse(text); } catch { payload = text; } } if (!response.ok) { const code = this.extractErrorCode(payload); const message = (this.extractErrorMessage(payload) ?? response.statusText) || `HTTP ${response.status}`; throw new AuthClientError(response.status, message, code, payload); } return payload as T; }
  private extractErrorCode(payload: unknown): string | null { if (!payload || typeof payload !== "object") return null; const code = (payload as AuthErrorResponse).data?.code; return typeof code === "string" ? code : null; }
  private extractErrorMessage(payload: unknown): string | null { if (!payload || typeof payload !== "object") return null; const error = payload as AuthErrorResponse; const value = error.statusMessage ?? error.message; return typeof value === "string" ? value : null; }
}
export function createAuthClient(options: AuthClientOptions): AuthClient { return new AuthClient(options); }
