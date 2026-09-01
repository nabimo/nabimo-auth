import { createAuthApp } from "./app.js";

export const { app, db } = createAuthApp();

export async function shutdown() {
  await db.$disconnect();
}
