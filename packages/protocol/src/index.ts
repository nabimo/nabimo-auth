export interface AuthUserResponse {
  id: string;
  email: string;
}

export interface AuthenticationResponse {
  user: AuthUserResponse;
  sessionId: string;
  accessToken: string;
  refreshToken: string;
}

export interface LogoutResponse {
  success: true;
}

export interface LogoutAllResponse {
  success: true;
  revokedSessions: number;
}

export interface VerificationChallengeResponse {
  challengeId: string;
  type: "email_otp" | "phone_otp";
  target: string;
  expiresAt: string;
}

export interface VerificationSuccessResponse {
  success: true;
}

export interface RegisterRequest {
  email: string;
  password: string;
}

export interface PasswordLoginRequest {
  email: string;
  password: string;
}

export interface RefreshRequest {
  refreshToken: string;
}

export interface EmailVerificationRequest {
  email: string;
}

export interface VerifyOtpRequest {
  challengeId: string;
  code: string;
}

export interface AuthErrorData {
  code?: string;
}

export interface AuthErrorResponse {
  statusCode?: number;
  statusMessage?: string;
  message?: string;
  data?: AuthErrorData;
}

export const AUTH_ENDPOINTS = {
  register: "POST /auth/register",
  passwordLogin: "POST /auth/login/password",
  refresh: "POST /auth/refresh",
  logout: "POST /auth/logout",
  logoutAll: "POST /auth/logout-all",
  requestEmailVerification: "POST /auth/verify/email/request",
  verifyOtp: "POST /auth/verify/otp",
} as const;
