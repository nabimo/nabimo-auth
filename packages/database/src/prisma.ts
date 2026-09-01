import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "./generated/client.js";

let client: PrismaClient | undefined;

export function getDatabaseClient(databaseUrl = process.env.DATABASE_URL): PrismaClient {
  if (!databaseUrl) throw new Error("Missing required environment variable: DATABASE_URL");

  if (!client) {
    const adapter = new PrismaPg({ connectionString: databaseUrl });
    client = new PrismaClient({ adapter });
  }

  return client;
}

export async function disconnectDatabase(): Promise<void> {
  if (client) {
    await client.$disconnect();
    client = undefined;
  }
}
