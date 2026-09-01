import { PrismaClient } from "../generated/client.js";

let client: PrismaClient | undefined;

export function getDatabaseClient(databaseUrl = process.env.DATABASE_URL): PrismaClient {
  if (!databaseUrl) throw new Error("Missing required environment variable: DATABASE_URL");
  client ??= new PrismaClient({ datasources: { db: { url: databaseUrl } } });
  return client;
}

export async function disconnectDatabase(): Promise<void> {
  if (client) {
    await client.$disconnect();
    client = undefined;
  }
}
