import { describe, expect, it, vi } from "vitest";
import { InMemoryRefreshCoordinator } from "./refresh-coordinator.js";

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
    const task = vi.fn()
      .mockResolvedValueOnce("first")
      .mockResolvedValueOnce("second");

    await expect(coordinator.run(task)).resolves.toBe("first");
    await expect(coordinator.run(task)).resolves.toBe("second");
    expect(task).toHaveBeenCalledTimes(2);
  });

  it("releases coordination when an operation rejects", async () => {
    const coordinator = new InMemoryRefreshCoordinator();
    const task = vi.fn()
      .mockRejectedValueOnce(new Error("failed"))
      .mockResolvedValueOnce("recovered");

    await expect(coordinator.run(task)).rejects.toThrow("failed");
    await expect(coordinator.run(task)).resolves.toBe("recovered");
    expect(task).toHaveBeenCalledTimes(2);
  });
});
