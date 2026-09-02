import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "./generated/client.js";

export { PrismaClient } from "./generated/client.js";
export * from "./generated/client.js";
export * from "./user-repository.js";
export * from "./auth-transaction.js";
export * from "./prisma-registration-store.js";
export * from "./prisma-session-store.js";
export * from "./prisma-refresh-token-store.js";

let client: PrismaClient | undefined;

/** Return the process-wide Prisma client used by the Auth server. */
export function getDatabaseClient(databaseUrl = process.env.DATABASE_URL): PrismaClient {
  if (!databaseUrl) throw new Error("Missing required environment variable: DATABASE_URL");
  client ??= new PrismaClient({ adapter: new PrismaPg({ connectionString: databaseUrl }) });
  return client;
}

export async function disconnectDatabase(): Promise<void> {
  if (client) {
    await client.$disconnect();
    client = undefined;
  }
}
