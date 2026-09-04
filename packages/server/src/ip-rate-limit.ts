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
  const trimmed = value.trim();
  if (trimmed.startsWith("::ffff:")) return trimmed.slice(7);
  return trimmed;
}

function isTrustedProxy(ip: string, trustedProxyIps: readonly string[]): boolean {
  const normalized = normalizeIp(ip);
  return trustedProxyIps.some((trusted) => normalizeIp(trusted) === normalized && isIP(normalized) !== 0);
}

/**
 * Resolves a client IP without trusting forwarded headers unless the immediate
 * peer is explicitly listed as a trusted proxy. X-Forwarded-For is processed
 * right-to-left, so a client cannot prepend a spoofed address and bypass the
 * limit when the trusted proxy appended the real client address.
 */
export function resolveClientIp(event: H3Event, trustedProxyIps: readonly string[] = []): string | undefined {
  const peer = event.node.req.socket.remoteAddress;
  if (!peer) return undefined;

  const normalizedPeer = normalizeIp(peer);
  if (!isTrustedProxy(normalizedPeer, trustedProxyIps)) return normalizedPeer;

  const forwarded = event.node.req.headers["x-forwarded-for"];
  const values = Array.isArray(forwarded) ? forwarded : forwarded ? forwarded.split(",") : [];
  for (let index = values.length - 1; index >= 0; index -= 1) {
    const candidate = normalizeIp(values[index]);
    if (isIP(candidate) !== 0) return candidate;
  }

  return normalizedPeer;
}

function routeKey(event: H3Event): string | undefined {
  if (event.node.req.method !== "POST") return undefined;
  const path = event.path;
  if (path === "/register") return "register";
  if (path === "/login/password") return "login-password";
  if (path === "/2fa/login") return "2fa-login";
  if (path === "/verify/email/request") return "verify-email-request";
  if (path === "/verify/phone/request") return "verify-phone-request";
  if (path === "/verify/otp") return "verify-otp";
  if (path === "/password/reset/request") return "password-reset-request";
  if (path === "/password/reset/confirm") return "password-reset-confirm";
  if (path === "/refresh") return "refresh";
  return undefined;
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
