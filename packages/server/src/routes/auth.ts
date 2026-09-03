import {
  createError,
  createRouter,
  eventHandler,
  getHeader,
  readBody,
  type H3Event,
} from "h3";
import {
  AccessTokenValidationService,
  AuthError,
  AuthService,
  RefreshService,
  SessionManagementService,
} from "@nabimo-auth/core";
import type { AuthenticationResponse, LogoutAllResponse, LogoutResponse } from "../api-contract.js";

export interface AuthRouteDependencies {
  auth: AuthService;
  accessTokens: AccessTokenValidationService;
  refresh: RefreshService;
  sessionManagement: SessionManagementService;
}

export function createAuthRouter({ auth, accessTokens, refresh, sessionManagement }: AuthRouteDependencies) {
  const router = createRouter();

  router.post("/register", eventHandler(async (event) => {
    return withAuthErrors<AuthenticationResponse>(async () => {
      const body = await readBody<{ email?: unknown; password?: unknown }>(event);
      if (typeof body?.email !== "string" || typeof body?.password !== "string") {
        throw httpError(400, "INVALID_REQUEST", "Email and password are required");
      }
      return auth.registerWithPassword(body.email, body.password);
    });
  }));

  router.post("/login/password", eventHandler(async (event) => {
    return withAuthErrors<AuthenticationResponse>(async () => {
      const body = await readBody<{ email?: unknown; password?: unknown }>(event);
      if (typeof body?.email !== "string" || typeof body?.password !== "string") {
        throw httpError(400, "INVALID_REQUEST", "Email and password are required");
      }
      return auth.loginWithPassword(body.email, body.password);
    });
  }));

  router.post("/refresh", eventHandler(async (event) => {
    return withAuthErrors<AuthenticationResponse>(async () => {
      const body = await readBody<{ refreshToken?: unknown }>(event);
      if (typeof body?.refreshToken !== "string" || body.refreshToken.length === 0) {
        throw httpError(400, "INVALID_REQUEST", "Refresh token is required");
      }
      return refresh.refresh(body.refreshToken);
    });
  }));

  router.post("/logout", eventHandler(async (event) => {
    return withAuthErrors<LogoutResponse>(async () => {
      const token = getBearerToken(event);
      if (!token) throw httpError(401, "INVALID_CREDENTIALS", "Invalid credentials");
      const { claims } = await accessTokens.validate(token);
      await sessionManagement.logout(claims.sid);
      return { success: true };
    });
  }));

  router.post("/logout-all", eventHandler(async (event) => {
    return withAuthErrors<LogoutAllResponse>(async () => {
      const token = getBearerToken(event);
      if (!token) throw httpError(401, "INVALID_CREDENTIALS", "Invalid credentials");
      const { claims } = await accessTokens.validate(token);
      const revokedSessions = await sessionManagement.logoutAll(claims.sub);
      return { success: true, revokedSessions };
    });
  }));

  return router;
}

async function withAuthErrors<T>(handler: () => Promise<T>): Promise<T> {
  try {
    return await handler();
  } catch (error) {
    if (isHttpError(error)) throw error;
    if (error instanceof AuthError) {
      throw httpError(authErrorStatus(error.code), error.code, error.message);
    }
    throw error;
  }
}

function httpError(statusCode: number, code: string, message: string) {
  return createError({ statusCode, statusMessage: message, data: { code } });
}

function isHttpError(error: unknown): error is { statusCode: number } {
  return typeof error === "object" && error !== null && "statusCode" in error;
}

function authErrorStatus(code: string): number {
  switch (code) {
    case "ACCOUNT_ALREADY_EXISTS": return 409;
    case "INVALID_CREDENTIALS":
    case "INVALID_OTP":
    case "INVALID_2FA_CODE":
    case "TWO_FACTOR_REQUIRED": return 401;
    default: return 400;
  }
}

function getBearerToken(event: H3Event): string | null {
  const authorization = getHeader(event, "authorization");
  if (!authorization) return null;
  const match = /^Bearer ([^\s]+)$/.exec(authorization);
  return match?.[1] ?? null;
}
