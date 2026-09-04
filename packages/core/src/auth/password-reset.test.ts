import { describe, expect, it, vi } from "vitest";
import { sha256 } from "../crypto/hash.js";
import { PasswordResetService, type PasswordResetSender, type PasswordResetStore } from "./password-reset.js";

function createStore(): PasswordResetStore {
  return { create: vi.fn(), consumeAndSetPassword: vi.fn() };
}
function createSender(): PasswordResetSender { return { send: vi.fn() }; }

describe("PasswordResetService", () => {
  it("does not reveal unknown accounts", async () => {
    const store = createStore();
    const sender = createSender();
    const service = new PasswordResetService({
      store,
      sender,
      findUserByEmail: vi.fn().mockResolvedValue(null),
    });

    await expect(service.request("Unknown@Example.com")).resolves.toBeUndefined();
    expect(store.create).not.toHaveBeenCalled();
    expect(sender.send).not.toHaveBeenCalled();
  });

  it("creates a hashed opaque token and sends only the raw token", async () => {
    const store = createStore();
    const sender = createSender();
    const service = new PasswordResetService({
      store,
      sender,
      findUserByEmail: vi.fn().mockResolvedValue({ id: "user-1", email: "user@example.com" }),
    });

    await service.request(" USER@Example.com ");
    const created = vi.mocked(store.create).mock.calls[0][0];
    const sent = vi.mocked(sender.send).mock.calls[0][0];

    expect(created.target).toBe("user@example.com");
    expect(created.tokenHash).not.toBe(sent.token);
    expect(created.tokenHash).toBe(sha256(sent.token));
    expect(sent.token.length).toBeGreaterThanOrEqual(32);
    expect(created.expiresAt.getTime()).toBeGreaterThan(Date.now());
  });

  it("changes the password and relies on the store for atomic session revocation", async () => {
    const store = createStore();
    const sender = createSender();
    vi.mocked(store.consumeAndSetPassword).mockResolvedValue(true);
    const service = new PasswordResetService({
      store,
      sender,
      findUserByEmail: vi.fn(),
    });

    await service.confirm("a".repeat(64), "new-password-123");
    expect(store.consumeAndSetPassword).toHaveBeenCalledOnce();
    expect(vi.mocked(store.consumeAndSetPassword).mock.calls[0][0].passwordHash).not.toBe("new-password-123");
  });

  it("rejects an invalid or already-consumed token", async () => {
    const store = createStore();
    const sender = createSender();
    vi.mocked(store.consumeAndSetPassword).mockResolvedValue(false);
    const service = new PasswordResetService({ store, sender, findUserByEmail: vi.fn() });

    await expect(service.confirm("a".repeat(64), "new-password-123")).rejects.toMatchObject({ code: "INVALID_PASSWORD_RESET_TOKEN" });
  });
});
