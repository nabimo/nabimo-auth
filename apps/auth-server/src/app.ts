import { createApp, eventHandler, toNodeListener } from "h3";
import { createServer } from "node:http";
import { createPublicKey } from "node:crypto";
import { AuthService, AccessTokenValidationService, PasswordResetService, RateLimiter, RefreshService, SessionManagementService, TwoFactorService, TwoFactorLoginService, VerificationService } from "@nabimo-auth/core";
import { getDatabaseClient, UserRepository, PrismaSessionStore, PrismaRegistrationTransactionStore, PrismaSessionManagementStore, PrismaRefreshTokenStore, PrismaVerificationStore, PrismaPasswordResetStore, PrismaTwoFactorStore, PrismaTwoFactorLoginStore, PrismaRateLimitStore } from "@nabimo-auth/database";
import { createAuthRouter } from "@nabimo-auth/server";
import { loadConfig } from "./config.js";
import { ConsoleVerificationCodeSender } from "./verification-sender.js";
import { ConsolePasswordResetSender } from "./password-reset-sender.js";
import { AesTwoFactorSecretCipher } from "./two-factor-cipher.js";

export function createAuthApp() {
  const config = loadConfig();
  const db = getDatabaseClient(config.databaseUrl);
  const users = new UserRepository(db);
  const sessions = new PrismaSessionStore(db);
  const registration = new PrismaRegistrationTransactionStore(db);
  const sessionManagementStore = new PrismaSessionManagementStore(db);
  const refreshTokenStore = new PrismaRefreshTokenStore(db);
  const verificationStore = new PrismaVerificationStore(db);
  const verification = new VerificationService({ store: verificationStore, sender: new ConsoleVerificationCodeSender() });
  const passwordResetStore = new PrismaPasswordResetStore(db);
  const sessionManagement = new SessionManagementService(sessionManagementStore);
  const passwordReset = new PasswordResetService({ store: passwordResetStore, sender: new ConsolePasswordResetSender(), findUserByEmail: async (email) => users.findByEmail(email) });
  const twoFactor = new TwoFactorService({ store: new PrismaTwoFactorStore(db), cipher: new AesTwoFactorSecretCipher(config.twoFactorEncryptionKey), sessions: sessionManagement, issuer: config.issuer });
  const twoFactorLogin = new TwoFactorLoginService({ store: new PrismaTwoFactorLoginStore(db), twoFactor });
  const loginRateLimiter = new RateLimiter(new PrismaRateLimitStore(db));
  const publicKeyPem = createPublicKey(config.jwtPrivateKeyPem).export({ type: "spki", format: "pem" }).toString();

  const auth = new AuthService({ users, sessions, registration, jwtPrivateKeyPem: config.jwtPrivateKeyPem, jwtKeyId: config.jwtKeyId, issuer: config.issuer, audience: config.audience, twoFactorLogin, loginRateLimiter });
  const refresh = new RefreshService({ refreshTokens: refreshTokenStore, jwtPrivateKeyPem: config.jwtPrivateKeyPem, jwtKeyId: config.jwtKeyId, issuer: config.issuer, audience: config.audience });
  const accessTokens = new AccessTokenValidationService({ publicKeyPem, sessions: sessionManagementStore, issuer: config.issuer, audience: config.audience });

  const app = createApp();
  app.use("/health", eventHandler(() => ({ status: "ok" })));
  app.use("/auth", createAuthRouter({ auth, accessTokens, refresh, sessionManagement, verification, passwordReset, twoFactor, twoFactorLogin, users }).handler);
  return { app, db };
}

if (process.env.NODE_ENV !== "test") {
  const { app } = createAuthApp();
  createServer(toNodeListener(app)).listen(Number(process.env.PORT ?? 3000));
}
