export interface AuthUserResponse { id: string; email?: string | null; }

export interface AuthenticationResponse {
  user: AuthUserResponse;
  sessionId: string;
  accessToken: string;
  refreshToken: string;
}

export interface TwoFactorRequiredResponse {
  twoFactorRequired: true;
  user: AuthUserResponse;
  challengeToken: string;
  challengeExpiresAt: string;
}

export type PasswordLoginResponse = AuthenticationResponse | TwoFactorRequiredResponse;

export interface LogoutResponse { success: true; }
export interface LogoutAllResponse { success: true; revokedSessions: number; }
export interface VerificationChallengeResponse { challengeId: string; type: "email_otp" | "phone_otp"; target: string; expiresAt: string; }
export interface VerificationSuccessResponse { success: true; }
export interface PasswordResetRequest { email: string; }
export interface PasswordResetConfirmRequest { token: string; newPassword: string; }
export interface PasswordResetRequestResponse { success: true; }
export interface PasswordResetConfirmResponse { success: true; }
export interface TwoFactorSetupResponse { secret: string; otpauthUri: string; recoveryCodes: string[]; }
export interface TwoFactorCodeRequest { code: string; }
export interface TwoFactorLoginRequest { challengeToken: string; code: string; }
export interface TwoFactorSuccessResponse { success: true; }
export interface RegisterRequest { email: string; password: string; }
export interface PasswordLoginRequest { email: string; password: string; }
export interface RefreshRequest { refreshToken: string; }
export interface EmailVerificationRequest { email: string; }
export interface PhoneVerificationRequest { phone: string; }
export interface VerifyOtpRequest { challengeId: string; code: string; }

export type AuthErrorCode =
  | "INVALID_REQUEST" | "INVALID_CREDENTIALS" | "ACCOUNT_ALREADY_EXISTS" | "INVALID_OTP"
  | "OTP_COOLDOWN" | "OTP_RATE_LIMITED" | "RATE_LIMITED" | "INVALID_PASSWORD_RESET_TOKEN"
  | "TWO_FACTOR_REQUIRED" | "INVALID_2FA_CODE" | "NOT_CONFIGURED";
export interface AuthErrorData { code?: AuthErrorCode; retryAfterSeconds?: number; }
export interface AuthErrorResponse { statusCode?: number; statusMessage?: string; message?: string; data?: AuthErrorData; }

export const AUTH_ENDPOINTS = {
  register: "POST /auth/register",
  passwordLogin: "POST /auth/login/password",
  twoFactorLogin: "POST /auth/2fa/login",
  refresh: "POST /auth/refresh",
  logout: "POST /auth/logout",
  logoutAll: "POST /auth/logout-all",
  requestEmailVerification: "POST /auth/verify/email/request",
  requestPhoneVerification: "POST /auth/verify/phone/request",
  verifyOtp: "POST /auth/verify/otp",
  requestPasswordReset: "POST /auth/password/reset/request",
  confirmPasswordReset: "POST /auth/password/reset/confirm",
  setupTwoFactor: "POST /auth/2fa/setup",
  enableTwoFactor: "POST /auth/2fa/enable",
  disableTwoFactor: "POST /auth/2fa/disable",
} as const;
