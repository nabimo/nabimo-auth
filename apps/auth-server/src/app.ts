import { createApp, eventHandler, toNodeListener } from "h3";
import { createServer } from "node:http";
import { createPublicKey } from "node:crypto";
import { AuthService, AccessTokenValidationService, RefreshService, SessionManagementService } from "@nabimo-auth/core";
import {
  getDatabaseClient,
  UserRepository,
  PrismaSessionStore,
  PrismaRegistrationTransactionStore,
  PrismaSessionManagementStore,
  PrismaRefreshTokenStore,
} from "@nabimo-auth/database";
import { createAuthRouter } from "./routes/auth.js";
import { loadConfig } from "./config.js";

export function createAuthApp() {
  const config = loadConfig();
  const db = getDatabaseClient(config.databaseUrl);
  const users = new UserRepository(db);
  const sessions = new PrismaSessionStore(db);
  const registration = new PrismaRegistrationTransactionStore(db);
  const sessionManagementStore = new PrismaSessionManagementStore(db);
  const refreshTokenStore = new PrismaRefreshTokenStore(db);
  const publicKeyPem = createPublicKey(config.jwtPrivateKeyPem).export({ type: "spki", format: "pem" }).toString();

  const auth = new AuthService({
    users,
    sessions,
    registration,
    jwtPrivateKeyPem: config.jwtPrivateKeyPem,
    jwtKeyId: config.jwtKeyId,
    issuer: config.issuer,
    audience: config.audience,
  });

  const sessionManagement = new SessionManagementService(sessionManagementStore);
  const refresh = new RefreshService({
    refreshTokens: refreshTokenStore,
    jwtPrivateKeyPem: config.jwtPrivateKeyPem,
    jwtKeyId: config.jwtKeyId,
    issuer: config.issuer,
    audience: config.audience,
  });
  const accessTokens = new AccessTokenValidationService({
    publicKeyPem,
    sessions: sessionManagementStore,
    issuer: config.issuer,
    audience: config.audience,
  });

  const app = createApp();
  app.use("/health", eventHandler(() => ({ status: "ok" })));
  app.use("/auth", createAuthRouter({ auth, accessTokens, refresh, sessionManagement }).handler);

  return { app, db };
}

if (process.env.NODE_ENV !== "test") {
  const { app } = createAuthApp();
  createServer(toNodeListener(app)).listen(Number(process.env.PORT ?? 3000));
}
