import { randomToken } from "./random.js";
import { sha256 } from "./hash.js";

export interface GeneratedToken {
  token: string;
  hash: string;
}

export function generateToken(bytes = 32): GeneratedToken {
  const token = randomToken(bytes);
  return {
    token,
    hash: sha256(token),
  };
}
