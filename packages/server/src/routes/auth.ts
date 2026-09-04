import { createError, createRouter, eventHandler, getHeader, readBody, type H3Event } from "h3";
import { createHash } from "node:crypto";
import { AccessTokenValidationService, AuthError, AuthService, normalizePhone, PasswordResetService, RefreshService, SessionManagementService, TwoFactorService, TwoFactorLoginService, VerificationService } from "@nabimo-auth/core";
import type { AuthenticationResponse, LogoutAllResponse, LogoutResponse, PasswordLoginResponse, PasswordResetConfirmResponse, PasswordResetRequestResponse, TwoFactorCodeRequest, TwoFactorLoginRequest, TwoFactorSetupResponse, TwoFactorSuccessResponse, VerificationChallengeResponse, VerificationSuccessResponse } from "../api-contract.js";

export interface AuthRouteDependencies {
  auth: AuthService;
  accessTokens: AccessTokenValidationService;
  refresh: RefreshService;
  sessionManagement: SessionManagementService;
  verification?: VerificationService;
  passwordReset?: PasswordResetService;
  twoFactor?: TwoFactorService;
  twoFactorLogin?: TwoFactorLoginService;
  users?: { findById(id: string): Promise<{ id: string; email: string | null; phone: string | null } | null> };
}

export function createAuthRouter({ auth, accessTokens, refresh, sessionManagement, verification, passwordReset, twoFactor, twoFactorLogin, users }: AuthRouteDependencies) {
  const router = createRouter();
  router.post("/register", eventHandler(async (event) => withAuthErrors<AuthenticationResponse>(async () => {
    const body = await readBody<{ email?: unknown; password?: unknown }>(event);
    if (typeof body?.email !== "string" || typeof body?.password !== "string") throw httpError(400, "INVALID_REQUEST", "Email and password are required");
    return auth.registerWithPassword(body.email, body.password);
  })));
  router.post("/login/password", eventHandler(async (event) => withAuthErrors<PasswordLoginResponse>(async () => {
    const body = await readBody<{ email?: unknown; password?: unknown }>(event);
    if (typeof body?.email !== "string" || typeof body?.password !== "string") throw httpError(400, "INVALID_REQUEST", "Email and password are required");
    const result = await auth.loginWithPassword(body.email, body.password);
    if ("twoFactorRequired" in result) return { ...result, challengeExpiresAt: result.challengeExpiresAt.toISOString() };
    return result;
  })));
  router.post("/2fa/login", eventHandler(async (event) => withAuthErrors<AuthenticationResponse>(async () => {
    if (!twoFactorLogin) throw httpError(501, "NOT_CONFIGURED", "Two-factor authentication is not configured");
    const body = await readBody<TwoFactorLoginRequest>(event);
    if (typeof body?.challengeToken !== "string" || typeof body?.code !== "string" || body.code.length === 0) throw httpError(400, "INVALID_REQUEST", "Challenge token and verification code are required");
    return auth.completeTwoFactorLogin(body.challengeToken, body.code);
  })));
  router.post("/refresh", eventHandler(async (event) => withAuthErrors<AuthenticationResponse>(async () => {
    const body = await readBody<{ refreshToken?: unknown }>(event);
    if (typeof body?.refreshToken !== "string" || body.refreshToken.length === 0) throw httpError(400, "INVALID_REQUEST", "Refresh token is required");
    return refresh.refresh(body.refreshToken);
  })));
  router.post("/logout", eventHandler(async (event) => withAuthErrors<LogoutResponse>(async () => {
    const token = getBearerToken(event); if (!token) throw httpError(401, "INVALID_CREDENTIALS", "Invalid credentials");
    const { claims } = await accessTokens.validate(token); await sessionManagement.logout(claims.sid); return { success: true };
  })));
  router.post("/logout-all", eventHandler(async (event) => withAuthErrors<LogoutAllResponse>(async () => {
    const token = getBearerToken(event); if (!token) throw httpError(401, "INVALID_CREDENTIALS", "Invalid credentials");
    const { claims } = await accessTokens.validate(token); const revokedSessions = await sessionManagement.logoutAll(claims.sub); return { success: true, revokedSessions };
  })));
  router.post("/verify/email/request", eventHandler(async (event) => withAuthErrors<VerificationChallengeResponse>(async () => {
    if (!verification || !users) throw httpError(501, "NOT_CONFIGURED", "Email verification is not configured");
    const token = getBearerToken(event); if (!token) throw httpError(401, "INVALID_CREDENTIALS", "Invalid credentials");
    const { claims } = await accessTokens.validate(token); const body = await readBody<{ email?: unknown }>(event);
    if (typeof body?.email !== "string") throw httpError(400, "INVALID_REQUEST", "Email is required");
    const user = await users.findById(claims.sub);
    if (!user?.email || user.email.toLowerCase() !== body.email.trim().toLowerCase()) throw httpError(400, "INVALID_REQUEST", "Email does not belong to the authenticated user");
    const challenge = await verification.requestEmailOtp(user.id, user.email);
    return { challengeId: challenge.challengeId, type: challenge.type, target: challenge.target, expiresAt: challenge.expiresAt.toISOString() };
  })));
  router.post("/verify/phone/request", eventHandler(async (event) => withAuthErrors<VerificationChallengeResponse>(async () => {
    if (!verification || !users) throw httpError(501, "NOT_CONFIGURED", "Phone verification is not configured");
    const token = getBearerToken(event); if (!token) throw httpError(401, "INVALID_CREDENTIALS", "Invalid credentials");
    const { claims } = await accessTokens.validate(token); const body = await readBody<{ phone?: unknown }>(event);
    if (typeof body?.phone !== "string") throw httpError(400, "INVALID_REQUEST", "Phone is required");
    let phone: string; try { phone = normalizePhone(body.phone); } catch { throw httpError(400, "INVALID_REQUEST", "Invalid phone number"); }
    const user = await users.findById(claims.sub);
    if (!user?.phone || user.phone !== phone) throw httpError(400, "INVALID_REQUEST", "Phone does not belong to the authenticated user");
    const challenge = await verification.requestPhoneOtp(user.id, phone);
    return { challengeId: challenge.challengeId, type: challenge.type, target: challenge.target, expiresAt: challenge.expiresAt.toISOString() };
  })));
  router.post("/verify/otp", eventHandler(async (event) => withAuthErrors<VerificationSuccessResponse>(async () => {
    if (!verification) throw httpError(501, "NOT_CONFIGURED", "OTP verification is not configured");
    const body = await readBody<{ challengeId?: unknown; code?: unknown }>(event);
    if (typeof body?.challengeId !== "string" || typeof body?.code !== "string" || !/^\d{6}$/.test(body.code)) throw httpError(400, "INVALID_REQUEST", "Challenge ID and a 6-digit code are required");
    await verification.verifyOtp(body.challengeId, body.code); return { success: true };
  })));
  router.post("/password/reset/request", eventHandler(async (event) => withAuthErrors<PasswordResetRequestResponse>(async () => {
    if (!passwordReset) throw httpError(501, "NOT_CONFIGURED", "Password reset is not configured");
    const body = await readBody<{ email?: unknown }>(event); if (typeof body?.email !== "string") throw httpError(400, "INVALID_REQUEST", "Email is required");
    await passwordReset.request(body.email); return { success: true };
  })));
  router.post("/password/reset/confirm", eventHandler(async (event) => withAuthErrors<PasswordResetConfirmResponse>(async () => {
    if (!passwordReset) throw httpError(501, "NOT_CONFIGURED", "Password reset is not configured");
    const body = await readBody<{ token?: unknown; newPassword?: unknown }>(event);
    if (typeof body?.token !== "string" || typeof body?.newPassword !== "string") throw httpError(400, "INVALID_REQUEST", "Reset token and new password are required");
    await passwordReset.confirm(body.token, body.newPassword); return { success: true };
  })));
  router.post("/2fa/setup", eventHandler(async (event) => withAuthErrors<TwoFactorSetupResponse>(async () => {
    if (!twoFactor || !users) throw httpError(501, "NOT_CONFIGURED", "Two-factor authentication is not configured");
    const token = getBearerToken(event); if (!token) throw httpError(401, "INVALID_CREDENTIALS", "Invalid credentials");
    const { claims } = await accessTokens.validate(token); const user = await users.findById(claims.sub);
    if (!user) throw httpError(401, "INVALID_CREDENTIALS", "Invalid credentials");
    return twoFactor.setup(user.id, user.email ?? user.phone ?? user.id);
  })));
  router.post("/2fa/enable", eventHandler(async (event) => withAuthErrors<TwoFactorSuccessResponse>(async () => {
    if (!twoFactor) throw httpError(501, "NOT_CONFIGURED", "Two-factor authentication is not configured");
    const token = getBearerToken(event); if (!token) throw httpError(401, "INVALID_CREDENTIALS", "Invalid credentials");
    const { claims } = await accessTokens.validate(token); const body = await readBody<TwoFactorCodeRequest>(event);
    if (typeof body?.code !== "string" || !/^\d{6}$/.test(body.code)) throw httpError(400, "INVALID_REQUEST", "A 6-digit code is required");
    await twoFactor.enable(claims.sub, body.code); return { success: true };
  })));
  router.post("/2fa/disable", eventHandler(async (event) => withAuthErrors<TwoFactorSuccessResponse>(async () => {
    if (!twoFactor) throw httpError(501, "NOT_CONFIGURED", "Two-factor authentication is not configured");
    const token = getBearerToken(event); if (!token) throw httpError(401, "INVALID_CREDENTIALS", "Invalid credentials");
    const { claims } = await accessTokens.validate(token); const body = await readBody<TwoFactorCodeRequest>(event);
    if (typeof body?.code !== "string" || !/^\d{6}$/.test(body.code)) throw httpError(400, "INVALID_REQUEST", "A 6-digit code is required");
    await twoFactor.verify(claims.sub, body.code); await twoFactor.disable(claims.sub); return { success: true };
  })));
  return router;
}
async function withAuthErrors<T>(handler: () => Promise<T>): Promise<T> { try { return await handler(); } catch (error) { if (isHttpError(error)) throw error; if (error instanceof AuthError) throw httpError(authErrorStatus(error.code), error.code, error.message, error.retryAfterSeconds); throw error; } }
function httpError(statusCode: number, code: string, message: string, retryAfterSeconds?: number) { return createError({ statusCode, statusMessage: message, data: { code, ...(retryAfterSeconds === undefined ? {} : { retryAfterSeconds }) } }); }
function isHttpError(error: unknown): error is { statusCode: number } { return typeof error === "object" && error !== null && "statusCode" in error; }
function authErrorStatus(code: string): number { switch (code) { case "ACCOUNT_ALREADY_EXISTS": return 409; case "OTP_COOLDOWN": case "OTP_RATE_LIMITED": case "RATE_LIMITED": return 429; case "INVALID_CREDENTIALS": case "INVALID_OTP": case "INVALID_PASSWORD_RESET_TOKEN": case "INVALID_2FA_CODE": case "TWO_FACTOR_REQUIRED": return 401; default: return 400; } }
function getBearerToken(event: H3Event): string | null { const authorization = getHeader(event, "authorization"); if (!authorization) return null; return /^Bearer ([^\s]+)$/.exec(authorization)?.[1] ?? null; }
