export interface SessionRecord {
  id: string;
  userId: string;
  tokenFamilyId: string;
  createdAt: Date;
  expiresAt: Date;
  revokedAt?: Date | null;
}

export interface RefreshTokenPair {
  token: string;
  tokenHash: string;
  familyId: string;
}

export interface RefreshRotationResult {
  accessToken: string;
  refreshToken: string;
  sessionId: string;
}
