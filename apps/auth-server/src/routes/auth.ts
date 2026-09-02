import { createRouter, eventHandler, getHeader, readBody } from "h3";
import {
  AccessTokenValidationService,
  AuthService,
  RefreshService,
  SessionManagementService,
} from "@nabimo-auth/core";

export interface AuthRouteDependencies {
  auth: AuthService;
  accessTokens: AccessTokenValidationService;
  refresh: RefreshService;
  sessionManagement: SessionManagementService;
}

export function createAuthRouter({ auth, accessTokens, refresh, sessionManagement }: AuthRouteDependencies) {
  const router = createRouter();

  router.post("/register", eventHandler(async (event) => {
    const body = await readBody<{ email?: unknown; password?: unknown }>(event);
    if (typeof body?.email !== "string" || typeof body?.password !== "string") {
      return { error: "INVALID_REQUEST", message: "Email and password are required" };
    }
    return auth.registerWithPassword(body.email, body.password);
  }));

  router.post("/login/password", eventHandler(async (event) => {
    const body = await readBody<{ email?: unknown; password?: unknown }>(event);
    if (typeof body?.email !== "string" || typeof body?.password !== "string") {
      return { error: "INVALID_REQUEST", message: "Email and password are required" };
    }
    return auth.loginWithPassword(body.email, body.password);
  }));

  router.post("/refresh", eventHandler(async (event) => {
    const body = await readBody<{ refreshToken?: unknown }>(event);
    if (typeof body?.refreshToken !== "string") {
      return { error: "INVALID_REQUEST", message: "Refresh token is required" };
    }
    return refresh.refresh(body.refreshToken);
  }));

  router.post("/logout", eventHandler(async (event) => {
    const token = getBearerToken(event);
    if (!token) return { error: "INVALID_CREDENTIALS", message: "Invalid credentials" };

    const { claims } = await accessTokens.validate(token);
    await sessionManagement.logout(claims.sid);
    return { success: true };
  }));

  router.post("/logout-all", eventHandler(async (event) => {
    const token = getBearerToken(event);
    if (!token) return { error: "INVALID_CREDENTIALS", message: "Invalid credentials" };

    const { claims } = await accessTokens.validate(token);
    const revokedSessions = await sessionManagement.logoutAll(claims.sub);
    return { success: true, revokedSessions };
  }));

  return router;
}

function getBearerToken(event: Parameters<typeof eventHandler>[0] extends never ? never : any): string | null {
  const authorization = getHeader(event, "authorization");
  if (!authorization) return null;

  const match = /^Bearer ([^\s]+)$/.exec(authorization);
  return match?.[1] ?? null;
}
