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

export function verifyAccessToken(token: string, publicKeyPem: string): AccessTokenClaims | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;

  try {
    const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8")) as { alg?: string; typ?: string };
    if (header.alg !== "EdDSA" || header.typ !== "JWT") return null;

    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")) as AccessTokenClaims;
    const valid = verify(
      null,
      Buffer.from(`${parts[0]}.${parts[1]}`),
      createPublicKey(publicKeyPem),
      Buffer.from(parts[2], "base64url"),
    );

    if (!valid || !payload.sub || !payload.sid || !payload.jti || !payload.iss || !payload.aud) return null;
    if (!Number.isSafeInteger(payload.exp) || payload.exp <= Math.floor(Date.now() / 1000)) return null;
    if (!Number.isSafeInteger(payload.iat)) return null;

    return payload;
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
