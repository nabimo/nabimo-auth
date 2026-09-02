import { describe, expect, it } from "vitest";
import { SessionManagementService, isActive, type SessionManagementStore } from "./management.js";

describe("SessionManagementService", () => {
  const activeSession = {
    id: "session-1",
    userId: "user-1",
    expiresAt: new Date("2030-01-01T00:00:00.000Z"),
    revokedAt: null,
    createdAt: new Date("2026-01-01T00:00:00.000Z"),
    lastUsedAt: null,
    userAgent: "test-agent",
    ipAddress: "127.0.0.1",
  };

  const baseStore = (): SessionManagementStore => ({
    async getSession() { return activeSession; },
    async touchSession() {},
    async revokeSession() { return true; },
    async revokeAllSessions() { return 1; },
  });

  it("returns an active session", async () => {
    await expect(new SessionManagementService(baseStore()).getSession("session-1")).resolves.toEqual(activeSession);
  });

  it("rejects revoked and expired sessions", async () => {
    const store: SessionManagementStore = {
      ...baseStore(),
      async getSession() {
        return { ...activeSession, revokedAt: new Date("2026-09-02T00:00:00.000Z") };
      },
    };
    await expect(new SessionManagementService(store).getSession("session-1")).rejects.toThrow("Invalid credentials");
    expect(isActive({ ...activeSession, revokedAt: null }, new Date("2030-01-01T00:00:00.000Z"))).toBe(false);
  });

  it("touches an active session", async () => {
    let seen: Date | undefined;
    const store: SessionManagementStore = {
      ...baseStore(),
      async touchSession(sessionId, now) {
        expect(sessionId).toBe("session-1");
        seen = now;
      },
    };
    const now = new Date("2026-09-02T00:00:00.000Z");
    await new SessionManagementService(store).touchSession("session-1", now);
    expect(seen).toEqual(now);
  });

  it("does not touch a revoked session", async () => {
    const store: SessionManagementStore = {
      ...baseStore(),
      async getSession() { return { ...activeSession, revokedAt: new Date() }; },
    };
    await expect(new SessionManagementService(store).touchSession("session-1")).rejects.toThrow("Invalid credentials");
  });

  it("supports logout of one session", async () => {
    let called = false;
    const store: SessionManagementStore = {
      ...baseStore(),
      async revokeSession(sessionId) { called = sessionId === "session-1"; return true; },
    };
    await new SessionManagementService(store).logout("session-1");
    expect(called).toBe(true);
  });

  it("supports logout of all sessions", async () => {
    let userIdSeen = "";
    const store: SessionManagementStore = {
      ...baseStore(),
      async revokeAllSessions(userId) { userIdSeen = userId; return 3; },
    };
    await expect(new SessionManagementService(store).logoutAll("user-1")).resolves.toBe(3);
    expect(userIdSeen).toBe("user-1");
  });
});
