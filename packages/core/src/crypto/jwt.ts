import { generateKeyPairSync, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";

export interface JwtKeyPair {
  privateKeyPem: string;
  publicKeyPem: string;
  algorithm: "EdDSA";
}

export interface AccessTokenClaims {
  sub: string;
  sid: string;
  iat: number;
  exp: number;
  iss: string;
  aud: string;
  jti: string;
}

const MAX_CLOCK_SKEW_SECONDS = 60;

export function generateJwtKeyPair(): JwtKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });

  return { privateKeyPem: privateKey, publicKeyPem: publicKey, algorithm: "EdDSA" };
}

export function signAccessToken(claims: AccessTokenClaims, privateKeyPem: string, keyId: string): string {
  const header = base64UrlJson({ alg: "EdDSA", typ: "JWT", kid: keyId });
  const payload = base64UrlJson(claims);
  const signingInput = `${header}.${payload}`;
  const signature = sign(null, Buffer.from(signingInput), createPrivateKey(privateKeyPem));
  return `${signingInput}.${base64Url(signature)}`;
}

export function verifyAccessToken(
  token: string,
  publicKeyPem: string,
  now = Math.floor(Date.now() / 1000),
): AccessTokenClaims | null {
  const parts = token.split(".");
  if (parts.length !== 3 || !Number.isSafeInteger(now)) return null;

  try {
    const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8")) as {
      alg?: unknown;
      typ?: unknown;
      kid?: unknown;
    };
    if (header.alg !== "EdDSA" || header.typ !== "JWT" || typeof header.kid !== "string" || !header.kid) return null;

    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")) as Partial<AccessTokenClaims>;
    const valid = verify(
      null,
      Buffer.from(`${parts[0]}.${parts[1]}`),
      createPublicKey(publicKeyPem),
      Buffer.from(parts[2], "base64url"),
    );

    if (!valid) return null;
    if (
      typeof payload.sub !== "string" || !payload.sub ||
      typeof payload.sid !== "string" || !payload.sid ||
      typeof payload.jti !== "string" || !payload.jti ||
      typeof payload.iss !== "string" || !payload.iss ||
      typeof payload.aud !== "string" || !payload.aud
    ) return null;
    if (!Number.isSafeInteger(payload.exp) || !Number.isSafeInteger(payload.iat)) return null;
    if (payload.exp <= now || payload.exp <= payload.iat) return null;
    if (payload.iat > now + MAX_CLOCK_SKEW_SECONDS) return null;

    return payload as AccessTokenClaims;
  } catch {
    return null;
  }
}

function base64UrlJson(value: unknown): string {
  return base64Url(Buffer.from(JSON.stringify(value), "utf8"));
}

function base64Url(value: Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}
