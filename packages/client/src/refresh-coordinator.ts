export interface RefreshCoordinator {
  run<T>(task: () => Promise<T>): Promise<T>;
}

/**
 * Coordinates refresh operations within a single AuthClient instance.
 *
 * Cross-context browser coordination is intentionally not implemented here:
 * refresh results contain credentials and must not be broadcast through
 * BroadcastChannel. A future browser adapter should use a credential-safe
 * transport (for example, an HttpOnly cookie-based refresh flow).
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
