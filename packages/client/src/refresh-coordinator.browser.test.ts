import { afterEach, describe, expect, it, vi } from "vitest";
import { BrowserRefreshCoordinator } from "./refresh-coordinator.js";

class FakeBroadcastChannel {
  static channels = new Map<string, Set<FakeBroadcastChannel>>();
  private listeners = new Set<(event: MessageEvent) => void>();

  constructor(readonly name: string) {
    const listeners = FakeBroadcastChannel.channels.get(name) ?? new Set();
    listeners.add(this);
    FakeBroadcastChannel.channels.set(name, listeners);
  }

  addEventListener(_type: "message", listener: (event: MessageEvent) => void): void {
    this.listeners.add(listener);
  }

  removeEventListener(_type: "message", listener: (event: MessageEvent) => void): void {
    this.listeners.delete(listener);
  }

  postMessage(data: unknown): void {
    queueMicrotask(() => {
      for (const channel of FakeBroadcastChannel.channels.get(this.name) ?? []) {
        if (channel === this) continue;
        for (const listener of channel.listeners) listener({ data } as MessageEvent);
      }
    });
  }

  close(): void {
    FakeBroadcastChannel.channels.get(this.name)?.delete(this);
  }
}

class FakeLockManager {
  private tail = Promise.resolve();

  request<T>(_name: string, callback: () => Promise<T>): Promise<T> {
    const previous = this.tail;
    let release!: () => void;
    this.tail = new Promise<void>((resolve) => { release = resolve; });
    return previous.then(async () => {
      try { return await callback(); }
      finally { release(); }
    });
  }
}

describe("BrowserRefreshCoordinator", () => {
  const originalBroadcastChannel = globalThis.BroadcastChannel;
  const originalNavigator = globalThis.navigator;

  afterEach(() => {
    vi.restoreAllMocks();
    Object.defineProperty(globalThis, "BroadcastChannel", { value: originalBroadcastChannel, configurable: true });
    Object.defineProperty(globalThis, "navigator", { value: originalNavigator, configurable: true });
    FakeBroadcastChannel.channels.clear();
  });

  it("shares the leader refresh result with a queued tab", async () => {
    Object.defineProperty(globalThis, "BroadcastChannel", { value: FakeBroadcastChannel, configurable: true });
    Object.defineProperty(globalThis, "navigator", { value: { locks: new FakeLockManager() }, configurable: true });

    const first = new BrowserRefreshCoordinator("test-refresh");
    const second = new BrowserRefreshCoordinator("test-refresh");
    const firstTask = vi.fn(async () => {
      await new Promise((resolve) => setTimeout(resolve, 10));
      return { accessToken: "access-2", refreshToken: "refresh-2" };
    });
    const secondTask = vi.fn(async () => ({ accessToken: "wrong", refreshToken: "wrong" }));

    const [firstResult, secondResult] = await Promise.all([
      first.run(firstTask),
      second.run(secondTask),
    ]);

    expect(firstResult).toEqual({ accessToken: "access-2", refreshToken: "refresh-2" });
    expect(secondResult).toEqual(firstResult);
    expect(firstTask).toHaveBeenCalledOnce();
    expect(secondTask).not.toHaveBeenCalled();

    first.close();
    second.close();
  });

  it("falls back when browser coordination APIs are unavailable", async () => {
    Object.defineProperty(globalThis, "BroadcastChannel", { value: undefined, configurable: true });
    const coordinator = new BrowserRefreshCoordinator("test-refresh");
    const task = vi.fn(async () => "ok");

    await expect(coordinator.run(task)).resolves.toBe("ok");
    expect(task).toHaveBeenCalledOnce();
    coordinator.close();
  });
});
