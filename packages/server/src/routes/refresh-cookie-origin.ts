const ALLOWED_PROTOCOLS = new Set(["http:", "https:"]);

export function normalizeOrigin(origin: string): string {
  const value = origin.trim();
  if (!value || value === "null") throw new TypeError("Invalid origin");

  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new TypeError("Invalid origin");
  }

  if (!ALLOWED_PROTOCOLS.has(parsed.protocol) || parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash) {
    throw new TypeError("Invalid origin");
  }

  return parsed.origin;
}

export function validateAllowedOrigins(origins: readonly string[]): string[] {
  return [...new Set(origins.map(normalizeOrigin))];
}

export function isAllowedOrigin(origin: string | undefined, allowedOrigins: readonly string[]): boolean {
  if (!origin) return false;
  try {
    return allowedOrigins.includes(normalizeOrigin(origin));
  } catch {
    return false;
  }
}
