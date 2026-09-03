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
} as const;
