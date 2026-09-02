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

  it("returns an active session", async () => {
    const store: SessionManagementStore = {
      async getSession() { return activeSession; },
      async revokeSession() { return true; },
      async revokeAllSessions() { return 1; },
    };

    const service = new SessionManagementService(store);
    await expect(service.getSession("session-1")).resolves.toEqual(activeSession);
  });

  it("rejects revoked and expired sessions", async () => {
    const store: SessionManagementStore = {
      async getSession() {
        return { ...activeSession, revokedAt: new Date("2026-09-02T00:00:00.000Z") };
      },
      async revokeSession() { return true; },
      async revokeAllSessions() { return 0; },
    };

    const service = new SessionManagementService(store);
    await expect(service.getSession("session-1")).rejects.toThrow("Invalid credentials");

    expect(isActive({ ...activeSession, revokedAt: null }, new Date("2030-01-01T00:00:00.000Z"))).toBe(false);
  });

  it("revokes one session", async () => {
    let called = false;
    const store: SessionManagementStore = {
      async getSession() { return activeSession; },
      async revokeSession(sessionId, now) {
        called = sessionId === "session-1" && now instanceof Date;
        return true;
      },
      async revokeAllSessions() { return 0; },
    };

    await new SessionManagementService(store).revokeSession("session-1");
    expect(called).toBe(true);
  });

  it("revokes all sessions and returns the number affected", async () => {
    let userIdSeen = "";
    const store: SessionManagementStore = {
      async getSession() { return activeSession; },
      async revokeSession() { return true; },
      async revokeAllSessions(userId) { userIdSeen = userId; return 3; },
    };

    await expect(new SessionManagementService(store).revokeAllSessions("user-1")).resolves.toBe(3);
    expect(userIdSeen).toBe("user-1");
  });
});
