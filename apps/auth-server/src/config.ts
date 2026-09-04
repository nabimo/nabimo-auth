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
}

export function loadConfig(): AuthServerConfig {
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
  };
}
