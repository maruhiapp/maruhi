import { RequestAuth, SessionService, TokenService } from "@maruhi/core";
import type { Digest } from "effect/crypto";
import { HttpApiMiddleware } from "effect/http-api";

import { ForbiddenError, UnauthorizedError } from "./errors.package/index.ts";

export const CSRF_HEADER_NAME = "x-maruhi-csrf";

export class AuthMiddleware extends HttpApiMiddleware.Service<
  AuthMiddleware,
  {
    provides: RequestAuth;
    requires: SessionService | TokenService | Digest.Digest;
  }
>()("AuthMiddleware", { error: [UnauthorizedError, ForbiddenError] }) {}
