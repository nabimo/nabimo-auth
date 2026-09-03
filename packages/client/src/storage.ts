import type { AuthTokens, TokenStorage } from "./types.js";

export class MemoryTokenStorage implements TokenStorage {
  private tokens: AuthTokens | null = null;

  get(): AuthTokens | null {
    return this.tokens;
  }

  set(tokens: AuthTokens): void {
    this.tokens = { ...tokens };
  }

  clear(): void {
    this.tokens = null;
  }
}
