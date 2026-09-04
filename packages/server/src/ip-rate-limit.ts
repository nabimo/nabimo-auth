import { isIP } from "node:net";
import type { H3Event } from "h3";
import { AuthError, RateLimiter } from "@nabimo-auth/core";
import { createError, eventHandler } from "h3";

export interface IpRateLimitPolicy {
  limit: number;
  windowSeconds: number;
}

export interface IpRateLimitOptions {
  trustedProxyIps?: readonly string[];
  policies: Record<string, IpRateLimitPolicy>;
  limiter: RateLimiter;
}

function normalizeIp(value: string): string {
  const trimmed = value.trim().replace(/^\[|\]$/g, "");
  return trimmed.startsWith("::ffff:") ? trimmed.slice(7) : trimmed;
}

function isValidIp(value: string): boolean {
  return isIP(normalizeIp(value)) !== 0;
}

function isTrustedProxy(ip: string, trustedProxyIps: readonly string[]): boolean {
  const normalized = normalizeIp(ip);
  return isValidIp(normalized) && trustedProxyIps.some((trusted) => normalizeIp(trusted) === normalized);
}

/**
 * Resolve the client IP without trusting forwarded headers unless the
 * immediate peer is explicitly listed as a trusted proxy. Trusted proxy
 * addresses are matched exactly; CIDR ranges are intentionally unsupported
 * until they can be implemented and tested without weakening this boundary.
 */
export function resolveClientIp(event: H3Event, trustedProxyIps: readonly string[] = []): string | undefined {
  const peer = event.node.req.socket.remoteAddress;
  if (!peer) return undefined;

  const normalizedPeer = normalizeIp(peer);
  if (!isTrustedProxy(normalizedPeer, trustedProxyIps)) return normalizedPeer;

  const forwarded = event.node.req.headers["x-forwarded-for"];
  const values = Array.isArray(forwarded) ? forwarded : forwarded ? forwarded.split(",") : [];
  const validValues = values.map(normalizeIp).filter(isValidIp);

  for (let index = validValues.length - 1; index >= 0; index -= 1) {
    const candidate = validValues[index];
    if (!isTrustedProxy(candidate, trustedProxyIps)) return candidate;
  }

  return validValues[0] ?? normalizedPeer;
}

function routeKey(event: H3Event): string | undefined {
  if (event.node.req.method !== "POST") return undefined;
  const path = event.path.startsWith("/auth/") ? event.path.slice("/auth".length) : event.path;
  switch (path) {
    case "/register": return "register";
    case "/login/password": return "login-password";
    case "/2fa/login": return "2fa-login";
    case "/verify/email/request": return "verify-email-request";
    case "/verify/phone/request": return "verify-phone-request";
    case "/verify/otp": return "verify-otp";
    case "/password/reset/request": return "password-reset-request";
    case "/password/reset/confirm": return "password-reset-confirm";
    case "/refresh": return "refresh";
    default: return undefined;
  }
}

export function createIpRateLimitMiddleware(options: IpRateLimitOptions) {
  return eventHandler(async (event) => {
    const key = routeKey(event);
    if (!key) return;

    const policy = options.policies[key];
    if (!policy) return;

    const ip = resolveClientIp(event, options.trustedProxyIps);
    if (!ip) return;

    try {
      await options.limiter.check(`ip:${ip}:${key}`, policy);
    } catch (error) {
      if (error instanceof AuthError && error.code === "RATE_LIMITED") {
        if (error.retryAfterSeconds !== undefined) {
          event.node.res.setHeader("Retry-After", String(error.retryAfterSeconds));
        }
        throw createError({
          statusCode: 429,
          statusMessage: error.message,
          data: { code: error.code, retryAfterSeconds: error.retryAfterSeconds },
        });
      }
      throw error;
    }
  });
}
