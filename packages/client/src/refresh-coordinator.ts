export interface RefreshCoordinator {
  run<T>(task: () => Promise<T>): Promise<T>;
}

/**
 * Coordinates refresh operations within a single AuthClient instance.
 * Browser integrations can provide a cross-context coordinator (for example,
 * one backed by Web Locks or BroadcastChannel) when multiple tabs share tokens.
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
