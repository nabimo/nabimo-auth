import { createError, eventHandler, getHeader, type H3Event } from "h3";

export interface RefreshCookieOriginOptions {
  enabled: boolean;
  cookieName: string;
  sameSite: "Strict" | "Lax" | "None";
  allowedOrigins: readonly string[];
}

function normalizeOrigin(origin: string): string {
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    throw new TypeError(`Invalid allowed origin: ${origin}`);
  }

  if (url.protocol !== "http:" && url.protocol !== "https:" || url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
    throw new TypeError(`Invalid allowed origin: ${origin}`);
  }

  return url.origin;
}

export function normalizeAllowedOrigins(origins: readonly string[]): string[] {
  return [...new Set(origins.map((origin) => normalizeOrigin(origin.trim())))];
}

function hasRefreshCookie(event: H3Event, cookieName: string): boolean {
  const header = getHeader(event, "cookie");
  if (!header) return false;

  for (const part of header.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;
    if (part.slice(0, separator).trim() === cookieName) return true;
  }
  return false;
}

function isAllowedOrigin(origin: string, allowedOrigins: readonly string[]): boolean {
  try {
    return allowedOrigins.includes(new URL(origin).origin);
  } catch {
    return false;
  }
}

/**
 * Protects cookie-authenticated refresh requests from cross-origin state
 * changes. SameSite=None requires an explicit origin allowlist; when an
 * allowlist is configured, any supplied Origin must match it exactly.
 */
export function createRefreshCookieOriginMiddleware(options: RefreshCookieOriginOptions) {
  const allowedOrigins = normalizeAllowedOrigins(options.allowedOrigins);

  if (options.enabled && options.sameSite === "None" && allowedOrigins.length === 0) {
    throw new Error("Refresh cookie with SameSite=None requires at least one allowed origin");
  }

  return eventHandler((event) => {
    if (!options.enabled || event.node.req.method !== "POST" || !event.path.endsWith("/refresh")) return;
    if (!hasRefreshCookie(event, options.cookieName)) return;

    const origin = getHeader(event, "origin");
    if (options.sameSite === "None") {
      if (!origin || !isAllowedOrigin(origin, allowedOrigins)) {
        throw createError({ statusCode: 403, statusMessage: "Refresh request origin is not allowed", data: { code: "CSRF_ORIGIN_NOT_ALLOWED" } });
      }
      return;
    }

    if (origin && allowedOrigins.length > 0 && !isAllowedOrigin(origin, allowedOrigins)) {
      throw createError({ statusCode: 403, statusMessage: "Refresh request origin is not allowed", data: { code: "CSRF_ORIGIN_NOT_ALLOWED" } });
    }
  });
}
