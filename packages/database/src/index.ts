import { PrismaClient } from "../generated/client";

export { PrismaClient } from "../generated/client";
export * from "../generated/client";

let client: PrismaClient | undefined;

/** Return the process-wide Prisma client used by the Auth server. */
export function getDatabaseClient(): PrismaClient {
  client ??= new PrismaClient();
  return client;
}

export async function disconnectDatabase(): Promise<void> {
  if (client) {
    await client.$disconnect();
    client = undefined;
  }
}
