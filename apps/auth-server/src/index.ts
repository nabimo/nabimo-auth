import { createApp, createRouter, eventHandler, listen } from "h3";

const app = createApp();
const router = createRouter();

router.get(
  "/health",
  eventHandler(() => ({
    status: "ok",
    service: "nabimo-auth",
    version: "0.1.0",
  })),
);

app.use(router);

const port = Number(process.env.PORT ?? 3000);

listen(app, { port });
console.log(`Nabimo Auth server listening on http://localhost:${port}`);
