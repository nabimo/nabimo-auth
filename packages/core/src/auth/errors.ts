export class AuthError extends Error {
  constructor(
    message: string,
    public readonly code: string,
  ) {
    super(message);
    this.name = "AuthError";
  }
}

export const authErrors = {
  invalidCredentials: () => new AuthError("Invalid credentials", "INVALID_CREDENTIALS"),
  accountAlreadyExists: () => new AuthError("An account already exists", "ACCOUNT_ALREADY_EXISTS"),
  invalidOtp: () => new AuthError("Invalid or expired OTP", "INVALID_OTP"),
  twoFactorRequired: () => new AuthError("Two-factor authentication is required", "TWO_FACTOR_REQUIRED"),
  invalidTwoFactorCode: () => new AuthError("Invalid two-factor authentication code", "INVALID_2FA_CODE"),
};
