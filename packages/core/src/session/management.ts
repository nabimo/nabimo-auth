import { authErrors } from "../auth/errors.js";

export interface ManagedSessionRecord {
  id: string;
  userId: string;
  expiresAt: Date;
  revokedAt: Date | null;
  createdAt: Date;
  lastUsedAt: Date | null;
  userAgent: string | null;
  ipAddress: string | null;
}

export interface SessionManagementStore {
  getSession(sessionId: string): Promise<ManagedSessionRecord | null>;
  revokeSession(sessionId: string, now: Date): Promise<boolean>;
  revokeAllSessions(userId: string, now: Date): Promise<number>;
}

export class SessionManagementService {
  constructor(private readonly store: SessionManagementStore) {}

  async getSession(sessionId: string): Promise<ManagedSessionRecord> {
    const session = await this.store.getSession(sessionId);
    if (!session || !isActive(session, new Date())) {
      throw authErrors.invalidCredentials();
    }
    return session;
  }

  async revokeSession(sessionId: string, now = new Date()): Promise<void> {
    const revoked = await this.store.revokeSession(sessionId, now);
    if (!revoked) throw authErrors.invalidCredentials();
  }

  async revokeAllSessions(userId: string, now = new Date()): Promise<number> {
    if (typeof userId !== "string" || !userId) throw authErrors.invalidCredentials();
    return this.store.revokeAllSessions(userId, now);
  }
}

export function isActive(
  session: Pick<ManagedSessionRecord, "expiresAt" | "revokedAt">,
  now = new Date(),
): boolean {
  return session.revokedAt === null && session.expiresAt > now;
}
