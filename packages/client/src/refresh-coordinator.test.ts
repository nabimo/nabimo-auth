import { describe, expect, it, vi } from "vitest";
import { BrowserRefreshCoordinator, InMemoryRefreshCoordinator, type WebLockManagerLike } from "./refresh-coordinator.js";

describe("InMemoryRefreshCoordinator", () => {
  it("deduplicates concurrent operations", async () => {
    const coordinator = new InMemoryRefreshCoordinator();
    let resolve!: (value: string) => void;
    const pending = new Promise<string>((resolvePromise) => { resolve = resolvePromise; });
    const task = vi.fn().mockReturnValue(pending);

    const first = coordinator.run(task);
    const second = coordinator.run(task);

    expect(task).toHaveBeenCalledOnce();
    resolve("done");
    await expect(Promise.all([first, second])).resolves.toEqual(["done", "done"]);
  });

  it("allows a new operation after the previous one settles", async () => {
    const coordinator = new InMemoryRefreshCoordinator();
    const task = vi.fn().mockResolvedValueOnce("first").mockResolvedValueOnce("second");

    await expect(coordinator.run(task)).resolves.toBe("first");
    await expect(coordinator.run(task)).resolves.toBe("second");
    expect(task).toHaveBeenCalledTimes(2);
  });

  it("releases coordination when an operation rejects", async () => {
    const coordinator = new InMemoryRefreshCoordinator();
    const task = vi.fn().mockRejectedValueOnce(new Error("failed")).mockResolvedValueOnce("recovered");

    await expect(coordinator.run(task)).rejects.toThrow("failed");
    await expect(coordinator.run(task)).resolves.toBe("recovered");
    expect(task).toHaveBeenCalledTimes(2);
  });
});

describe("BrowserRefreshCoordinator", () => {
  it("runs through the shared Web Lock", async () => {
    const request = vi.fn(async <T>(name: string, callback: () => Promise<T> | T) => {
      expect(name).toBe("nabimo-auth-refresh");
      return callback();
    });
    const locks: WebLockManagerLike = { request };
    const coordinator = new BrowserRefreshCoordinator(locks);

    await expect(coordinator.run(async () => "done")).resolves.toBe("done");
    expect(request).toHaveBeenCalledOnce();
  });

  it("uses a custom lock name", async () => {
    const request = vi.fn(async <T>(_name: string, callback: () => Promise<T> | T) => callback());
    const coordinator = new BrowserRefreshCoordinator({ request }, "custom-refresh-lock");

    await expect(coordinator.run(async () => "done")).resolves.toBe("done");
    expect(request).toHaveBeenCalledWith("custom-refresh-lock", expect.any(Function));
  });

  it("falls back to in-memory coordination when Web Locks are unavailable", async () => {
    let resolve!: (value: string) => void;
    const pending = new Promise<string>((resolvePromise) => { resolve = resolvePromise; });
    const task = vi.fn().mockReturnValue(pending);
    const coordinator = new BrowserRefreshCoordinator(undefined);

    const first = coordinator.run(task);
    const second = coordinator.run(task);
    expect(task).toHaveBeenCalledOnce();

    resolve("done");
    await expect(Promise.all([first, second])).resolves.toEqual(["done", "done"]);
  });
});
