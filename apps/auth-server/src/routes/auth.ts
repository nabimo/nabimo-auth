import { createRouter, eventHandler, readBody } from "h3";
import { AuthService } from "@nabimo-auth/core";

export interface AuthRouteDependencies {
  auth: AuthService;
}

export function createAuthRouter({ auth }: AuthRouteDependencies) {
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

  return router;
}
