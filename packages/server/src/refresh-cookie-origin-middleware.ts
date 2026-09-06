import { createError, eventHandler, getHeader, type H3Event } from "h3";
import { isAllowedOrigin, validateAllowedOrigins } from "./routes/refresh-cookie-origin.js";

export interface RefreshCookieOriginOptions {
  enabled?: boolean;
  sameSite?: "Strict" | "Lax" | "None";
  cookieName?: string;
  allowedOrigins?: readonly string[];
}

export function createRefreshCookieOriginMiddleware(options: RefreshCookieOriginOptions) {
  const sameSite = options.sameSite ?? "Lax";
  const cookieName = options.cookieName ?? "nabimo_refresh";
  const allowedOrigins = validateAllowedOrigins(options.allowedOrigins ?? []);

  if (sameSite === "None" && options.enabled === true && allowedOrigins.length === 0) {
    throw new Error("Refresh cookie with SameSite=None requires at least one allowed origin");
  }

  return eventHandler((event) => {
    if (options.enabled !== true || sameSite !== "None" || !hasCookie(event, cookieName)) return;

    const origin = getHeader(event, "origin");
    if (!isAllowedOrigin(origin, allowedOrigins)) {
      throw createError({
        statusCode: 403,
        statusMessage: "Refresh request origin is not allowed",
        data: { code: "CSRF_ORIGIN_NOT_ALLOWED" },
      });
    }
  });
}

function hasCookie(event: H3Event, name: string): boolean {
  const header = getHeader(event, "cookie");
  if (!header) return false;
  return header.split(";").some((part) => part.trimStart().startsWith(`${name}=`));
}
