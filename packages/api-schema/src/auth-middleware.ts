// API contract of the authentication middleware (AUTH_SPEC §5 / §11-4).
//
// Endpoints requiring authentication declare this middleware, and the
// handler receives the authenticated principal from RequestAuth
// (@maruhi/core). The implementation (session / token resolution, the
// blanket check of the CSRF custom header) is provided by a Layer on the
// apps/server side.

import { RequestAuth, SessionService, TokenService } from "@maruhi/core";
import { HttpApiMiddleware } from "effect/unstable/httpapi";

import { ForbiddenError, UnauthorizedError } from "./errors/index.ts";

/**
 * Custom header name for CSRF defense (AUTH_SPEC §11-4: `x-maruhi-csrf:
 * 1`). A shared constant so the server middleware and the client sender
 * see the same name (one source of truth in api-schema, so renaming the
 * name cannot silently fall back into "CLI guidance text → generic
 * 403").
 */
export const CSRF_HEADER_NAME = "x-maruhi-csrf";

/**
 * Authentication middleware (AUTH_SPEC §5, §11-4): resolves the session cookie
 * or `Authorization: Bearer maruhi_pat_…` header into a `RequestAuth`
 * principal, failing with 401 for anonymous requests. Cookie-authenticated
 * write requests must carry the `x-maruhi-csrf: 1` header (403 otherwise).
 */
export class AuthMiddleware extends HttpApiMiddleware.Service<
  AuthMiddleware,
  { provides: RequestAuth; requires: SessionService | TokenService }
>()("AuthMiddleware", { error: [UnauthorizedError, ForbiddenError] }) {}
