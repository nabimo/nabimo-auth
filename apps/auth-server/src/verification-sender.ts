import type { VerificationCodeSender } from "@nabimo-auth/core";

/**
 * Development/default sender. Production applications should inject an
 * email/SMS provider implementation instead of logging verification codes.
 */
export class ConsoleVerificationCodeSender implements VerificationCodeSender {
  async send(input: { type: "email_otp" | "phone_otp"; target: string; code: string }): Promise<void> {
    if (process.env.NODE_ENV === "production") {
      throw new Error("No verification code sender is configured for production");
    }
    console.info(`[nabimo-auth] ${input.type} verification code for ${input.target}: ${input.code}`);
  }
}
