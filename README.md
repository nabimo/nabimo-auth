# Nabimo Auth

Open-source, self-hosted authentication infrastructure for web and mobile applications.

## Status

Early development — v0.1.0.

The first release focuses on:

- Email + password authentication
- Email OTP
- Phone OTP
- Session management
- Access and refresh tokens
- Email and phone verification
- Password reset
- Two-factor authentication (TOTP + recovery codes)

Social login providers will be added later.

## Goals

Nabimo Auth is designed as a framework-agnostic authentication server. Client SDKs for Nuxt, React, Angular, Flutter, and other platforms will consume the same authentication API rather than reimplementing authentication logic.

The project is self-hosted and open source first, with the architecture intentionally kept compatible with a future Nabimo Auth Cloud offering.

## License

MIT
