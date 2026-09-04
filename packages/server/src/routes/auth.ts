import { createError, defineEventHandler, getHeader, readBody } from "h3";
import type { H3Event } from "h3";
import type { AuthError } from "@nabimo-auth/core";
import { authErrorStatus } from "../errors.js";

// routes implementation unchanged
