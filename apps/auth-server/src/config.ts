function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

export interface AuthServerConfig {
  databaseUrl: string;
  jwtPrivateKeyPem: string;
  jwtKeyId: string;
  issuer: string;
  audience: string;
  twoFactorEncryptionKey: string;
  trustedProxyIps: string[];
  refreshCookieEnabled: boolean;
  refreshCookieName: string;
  refreshCookiePath: string;
  refreshCookieSameSite: "Strict" | "Lax" | "None";
  refreshCookieSecure: boolean;
  refreshCookieDomain?: string;
  refreshCookieMaxAgeSeconds: number;
}

function booleanEnv(name: string, fallback: boolean): boolean {
  const value = process.env[name];
  if (value === undefined) return fallback;
  if (value === "true") return true;
  if (value === "false") return false;
  throw new Error(`${name} must be true or false`);
}

function positiveIntegerEnv(name: string, fallback: number): number {
  const value = process.env[name];
  if (value === undefined) return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) throw new Error(`${name} must be a positive integer`);
  return parsed;
}

function sameSiteEnv(): "Strict" | "Lax" | "None" {
  const value = process.env.NABIMO_REFRESH_COOKIE_SAME_SITE ?? "Lax";
  if (value !== "Strict" && value !== "Lax" && value !== "None") throw new Error("NABIMO_REFRESH_COOKIE_SAME_SITE must be Strict, Lax, or None");
  return value;
}

export function loadConfig(): AuthServerConfig {
  const refreshCookieSameSite = sameSiteEnv();
  const refreshCookieSecure = booleanEnv("NABIMO_REFRESH_COOKIE_SECURE", true);
  if (refreshCookieSameSite === "None" && !refreshCookieSecure) throw new Error("NABIMO_REFRESH_COOKIE_SECURE must be true when SameSite=None");

  return {
    databaseUrl: required("DATABASE_URL"),
    jwtPrivateKeyPem: required("NABIMO_JWT_PRIVATE_KEY").replace(/\\n/g, "\n"),
    jwtKeyId: process.env.NABIMO_JWT_KEY_ID ?? "default",
    issuer: process.env.NABIMO_JWT_ISSUER ?? "nabimo-auth",
    audience: process.env.NABIMO_JWT_AUDIENCE ?? "nabimo-auth-client",
    twoFactorEncryptionKey: required("NABIMO_2FA_ENCRYPTION_KEY"),
    trustedProxyIps: (process.env.NABIMO_TRUSTED_PROXY_IPS ?? "")
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean),
    refreshCookieEnabled: booleanEnv("NABIMO_REFRESH_COOKIE_ENABLED", false),
    refreshCookieName: process.env.NABIMO_REFRESH_COOKIE_NAME ?? "nabimo_refresh",
    refreshCookiePath: process.env.NABIMO_REFRESH_COOKIE_PATH ?? "/auth/refresh",
    refreshCookieSameSite,
    refreshCookieSecure,
    refreshCookieDomain: process.env.NABIMO_REFRESH_COOKIE_DOMAIN || undefined,
    refreshCookieMaxAgeSeconds: positiveIntegerEnv("NABIMO_REFRESH_COOKIE_MAX_AGE_SECONDS", 30 * 24 * 60 * 60),
  };
}
