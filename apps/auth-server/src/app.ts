import { createApp, eventHandler, toNodeListener } from "h3";
import { createServer } from "node:http";
import { AuthService } from "@nabimo-auth/core";
import { getDatabaseClient, UserRepository, PrismaSessionStore, PrismaRegistrationTransactionStore } from "@nabimo-auth/database";
import { createAuthRouter } from "./routes/auth.js";
import { loadConfig } from "./config.js";

export function createAuthApp() {
  const config = loadConfig();
  const db = getDatabaseClient(config.databaseUrl);
  const users = new UserRepository(db);
  const sessions = new PrismaSessionStore(db);
  const registration = new PrismaRegistrationTransactionStore(db);

  const auth = new AuthService({
    users,
    sessions,
    registration,
    jwtPrivateKeyPem: config.jwtPrivateKeyPem,
    jwtKeyId: config.jwtKeyId,
    issuer: config.issuer,
    audience: config.audience,
  });

  const app = createApp();
  app.use("/health", eventHandler(() => ({ status: "ok" })));
  app.use("/auth", createAuthRouter({ auth }).handler);

  return { app, db };
}

if (process.env.NODE_ENV !== "test") {
  const { app } = createAuthApp();
  createServer(toNodeListener(app)).listen(Number(process.env.PORT ?? 3000));
}
