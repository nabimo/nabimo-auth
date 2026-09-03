# @nabimo-auth/client

Framework-agnostic HTTP client for Nabimo Auth.

The client only speaks the Nabimo Auth HTTP protocol. It has no dependency on Nuxt, Nitro, Next.js, React, Vue, Express, NestJS, H3, or any other framework.

## Usage

```ts
import { createAuthClient } from "@nabimo-auth/client";

const auth = createAuthClient({
  baseUrl: "https://auth.example.com",
});

await auth.loginWithPassword("user@example.com", "password");

const data = await auth.request("/api/profile", {
  method: "GET",
  auth: true,
});
```

Token persistence is intentionally abstracted. The default storage is in-memory; applications that need persistence or secure platform storage should provide a `TokenStorage` implementation.
