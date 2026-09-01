import { createRouter, eventHandler, readBody } from "h3";

export const authRouter = createRouter();

authRouter.post(
  "/register",
  eventHandler(async (event) => {
    const body = await readBody<{ email?: string; password?: string }>(event);

    if (!body?.email || !body.password) {
      return {
        error: "INVALID_REQUEST",
        message: "Email and password are required",
      };
    }

    return {
      error: "NOT_IMPLEMENTED",
      message: "Registration service is not wired yet",
    };
  }),
);

authRouter.post(
  "/login/password",
  eventHandler(async (event) => {
    const body = await readBody<{ email?: string; password?: string }>(event);

    if (!body?.email || !body.password) {
      return {
        error: "INVALID_REQUEST",
        message: "Email and password are required",
      };
    }

    return {
      error: "NOT_IMPLEMENTED",
      message: "Password authentication service is not wired yet",
    };
  }),
);
