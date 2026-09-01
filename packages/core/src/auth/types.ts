export type AuthMethod = "password" | "email_otp" | "phone_otp";

export interface AuthenticatedUser {
  id: string;
  email?: string | null;
  phone?: string | null;
}

export interface AuthResult {
  user: AuthenticatedUser;
  sessionId: string;
  accessToken: string;
  refreshToken: string;
}

export interface AuthChallenge {
  challengeId: string;
  userId: string;
  method: AuthMethod;
  requiresTwoFactor: boolean;
  expiresAt: Date;
}
