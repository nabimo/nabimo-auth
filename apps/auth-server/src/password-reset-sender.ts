import type { PasswordResetSender } from "@nabimo-auth/core";

/** Development/default sender. Production applications should inject a real email provider. */
export class ConsolePasswordResetSender implements PasswordResetSender {
  async send(input: { target: string; token: string; expiresAt: Date }): Promise<void> {
    if (process.env.NODE_ENV === "production") {
      throw new Error("No password reset sender is configured for production");
    }
    console.info(`[nabimo-auth] password reset token for ${input.target}: ${input.token}`);
  }
}
