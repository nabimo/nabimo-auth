export interface RefreshCoordinator {
  run<T>(task: () => Promise<T>): Promise<T>;
}

/**
 * Coordinates refresh operations within a single AuthClient instance.
 * Browser integrations can provide a cross-context coordinator when multiple
 * tabs share the same refresh token.
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

interface RefreshMessageStart {
  type: "start";
  id: string;
  createdAt: number;
}

interface RefreshMessageResult {
  type: "result";
  id: string;
  ok: true;
  value: unknown;
}

interface RefreshMessageError {
  type: "result";
  id: string;
  ok: false;
  error: { name: string; message: string };
}

type RefreshMessage = RefreshMessageStart | RefreshMessageResult | RefreshMessageError;

const DEFAULT_MAX_MESSAGE_AGE_MS = 30_000;

/**
 * Coordinates refreshes across same-origin browser contexts.
 *
 * Web Locks elects one leader; BroadcastChannel distributes the leader's
 * result so queued followers do not submit an already-rotated refresh token.
 * If either API is unavailable, it safely falls back to normal execution.
 */
export class BrowserRefreshCoordinator implements RefreshCoordinator {
  private readonly channel: BroadcastChannel | null;
  private pending: Promise<unknown> | null = null;
  private readonly maxMessageAgeMs: number;
  private remoteStarts = new Map<string, number>();
  private remoteResults = new Map<string, { ok: true; value: unknown } | { ok: false }>();
  private resolvers = new Map<string, (result: { received: boolean; value?: unknown }) => void>();

  constructor(
    private readonly channelName = "nabimo-auth-refresh",
    maxMessageAgeMs = DEFAULT_MAX_MESSAGE_AGE_MS,
  ) {
    if (!Number.isFinite(maxMessageAgeMs) || maxMessageAgeMs <= 0) {
      throw new RangeError("maxMessageAgeMs must be greater than zero");
    }
    this.maxMessageAgeMs = maxMessageAgeMs;
    this.channel = typeof BroadcastChannel === "undefined" ? null : new BroadcastChannel(channelName);
    this.channel?.addEventListener("message", this.onMessage);
  }

  async run<T>(task: () => Promise<T>): Promise<T> {
    if (this.pending) return this.pending as Promise<T>;
    if (!this.channel || typeof navigator === "undefined" || !navigator.locks) {
      return task();
    }

    const pending = this.runCrossContext(task);
    this.pending = pending;
    try {
      return await pending;
    } finally {
      if (this.pending === pending) this.pending = null;
    }
  }

  close(): void {
    this.channel?.removeEventListener("message", this.onMessage);
    this.channel?.close();
    this.remoteStarts.clear();
    this.remoteResults.clear();
    this.resolvers.clear();
  }

  private async runCrossContext<T>(task: () => Promise<T>): Promise<T> {
    this.pruneMessages();
    let observedStart = this.nextRemoteStart();
    const lockName = `nabimo-auth-refresh:${this.channelName}`;

    return navigator.locks.request(lockName, async () => {
      this.pruneMessages();
      observedStart ??= this.nextRemoteStart();

      if (observedStart) {
        const result = await this.waitForResult(observedStart);
        if (result.received) return result.value as T;
      }

      const id = crypto.randomUUID();
      this.channel!.postMessage({ type: "start", id, createdAt: Date.now() } satisfies RefreshMessageStart);
      try {
        const value = await task();
        this.channel!.postMessage({ type: "result", id, ok: true, value } satisfies RefreshMessageResult);
        return value;
      } catch (error) {
        this.channel!.postMessage({
          type: "result",
          id,
          ok: false,
          error: serializeError(error),
        } satisfies RefreshMessageError);
        throw error;
      }
    });
  }

  private nextRemoteStart(): string | undefined {
    this.pruneMessages();
    const first = this.remoteStarts.entries().next();
    if (first.done) return undefined;
    this.remoteStarts.delete(first.value[0]);
    return first.value[0];
  }

  private waitForResult(id: string): Promise<{ received: boolean; value?: unknown }> {
    const existing = this.remoteResults.get(id);
    if (existing) {
      return Promise.resolve(existing.ok ? { received: true, value: existing.value } : { received: false });
    }

    return new Promise((resolve) => {
      this.resolvers.set(id, resolve);
    });
  }

  private pruneMessages(): void {
    const cutoff = Date.now() - this.maxMessageAgeMs;
    for (const [id, createdAt] of this.remoteStarts) {
      if (createdAt < cutoff) this.remoteStarts.delete(id);
    }
  }

  private onMessage = (event: MessageEvent<RefreshMessage>): void => {
    const message = event.data;
    if (!message || typeof message !== "object") return;

    if (message.type === "start") {
      if (Date.now() - message.createdAt <= this.maxMessageAgeMs) {
        this.remoteStarts.set(message.id, message.createdAt);
      }
      return;
    }

    if (message.type !== "result") return;
    this.remoteStarts.delete(message.id);

    if (message.ok) {
      this.remoteResults.set(message.id, { ok: true, value: message.value });
      this.resolvers.get(message.id)?.({ received: true, value: message.value });
    } else {
      this.remoteResults.set(message.id, { ok: false });
      this.resolvers.get(message.id)?.({ received: false });
    }
    this.resolvers.delete(message.id);
  };
}

function serializeError(error: unknown): { name: string; message: string } {
  if (error instanceof Error) return { name: error.name, message: error.message };
  return { name: "Error", message: String(error) };
}
