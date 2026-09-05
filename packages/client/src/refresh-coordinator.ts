import type { AuthenticationResponse } from "@nabimo-auth/protocol";

export interface RefreshCoordinator {
  run<T>(task: () => Promise<T>): Promise<T>;
}

/**
 * Describes how the client sends the refresh request. It deliberately only
 * creates request options; response parsing and token persistence stay in
 * AuthClient.
 */
export interface RefreshTransport {
  createRequest(refreshToken: string | null): RequestInit;
}

/** Sends the current refresh token in the JSON request body. */
export class BearerRefreshTransport implements RefreshTransport {
  createRequest(refreshToken: string | null): RequestInit {
    if (!refreshToken) {
      throw new Error("A refresh token is required for bearer refresh transport");
    }

    return {
      method: "POST",
      body: JSON.stringify({ refreshToken }),
      headers: { "Content-Type": "application/json" },
    };
  }
}

/**
 * Uses the browser's cookie jar for refresh authentication. The refresh token
 * is intentionally never exposed to JavaScript by this transport.
 */
export class CookieRefreshTransport implements RefreshTransport {
  constructor(private readonly credentials: RequestCredentials = "include") {}

  createRequest(_refreshToken: string | null): RequestInit {
    return {
      method: "POST",
      credentials: this.credentials,
    };
  }
}

/**
 * Coordinates refresh operations within a single AuthClient instance.
 *
 * Cross-context browser coordination is intentionally separate from this
 * primitive: refresh results contain credentials and must not be broadcast
 * through BroadcastChannel.
 */
export class InMemoryRefreshCoordinator implements RefreshCoordinator {
  private pending: Promise<unknown> | null = null;

  async run<T>(task: () => Promise<T>): Promise<T> {
    if (this.pending) return this.pending as Promise<T>;

    const pending = task();
    this.pending = pending;
    try {
      return await pending;
    } finally {
      if (this.pending === pending) this.pending = null;
    }
  }
}

export type RefreshResult = AuthenticationResponse;
