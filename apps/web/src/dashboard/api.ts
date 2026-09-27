// A thin fetch layer for session-authenticated API consumption (rulings
// BP / BR — docs/notes/session-43.md).
//
// - Same-origin assumption (ruling BM: the dashboard is served by the
//   maruhi-server Worker. Under CSP connect-src 'self' and the __Host-
//   session cookie it only hits relative paths)
// - Maps HTTP status to typed results and centralizes the 401 / 403 /
//   404 / 410 branching and wording across all screens (display
//   discipline §4 — wording is limited to what the server reports)
// - Mutations (logout, revocation DELETEs — W3b) always carry the CSRF
//   header (AUTH_SPEC §11-4)
// - No Schema decoding (ruling BR — the web implements no validation;
//   its types are bound via type-only imports, and runtime defense is
//   optional access at the display layer)
import type { CSRF_HEADER_NAME } from "@maruhi/api-schema";

/**
 * The anti-CSRF custom header name (AUTH_SPEC §11-4). The source of
 * truth is api-schema's `CSRF_HEADER_NAME`; this file binds it at type
 * level (ruling CN — docs/notes/session-45.md): a value import would
 * pull api-schema executable code into the bundle (= the TCB), the
 * target of ruling CD's tripwire, so the literal is constrained with
 * type-only import + satisfies and a rename on the source-of-truth side
 * becomes a compile error.
 * The actual sent value is compared in test/unit/api.test.ts (a test
 * process may value-import).
 */
const CSRF_HEADER = "x-maruhi-csrf" satisfies typeof CSRF_HEADER_NAME;

/** A non-2xx (or unreachable) API outcome, classified for uniform screen handling. */
export type ApiFailure =
  | { readonly kind: "unauthorized" }
  | { readonly kind: "forbidden"; readonly reason: string | undefined }
  | { readonly kind: "not-found" }
  | { readonly kind: "gone"; readonly reason: string | undefined }
  | { readonly kind: "unreachable" };

/** Result of one API call: the parsed JSON body, or a classified failure. */
export type ApiResult<T> = { readonly kind: "ok"; readonly value: T } | ApiFailure;

const UNREACHABLE: ApiFailure = { kind: "unreachable" };

const STATUS_FAILURES: Readonly<Record<number, ApiFailure>> = {
  401: { kind: "unauthorized" },
  404: { kind: "not-found" },
};

/** Defensively extracts the typed reason (ForbiddenError / InviteGoneError) from a 403 / 410 response. */
function reasonOf(body: unknown): string | undefined {
  const reason = (body as { reason?: unknown } | null | undefined)?.reason;
  return typeof reason === "string" ? reason : undefined;
}

/** Failure kinds that carry a reason (403 = forbidden, 410 = gone — the concrete form accompanying ruling CN). */
const REASON_FAILURE_KINDS: Readonly<Record<number, "forbidden" | "gone">> = {
  403: "forbidden",
  410: "gone",
};

async function classifyWithReason(
  response: Response,
  kind: "forbidden" | "gone",
): Promise<ApiFailure> {
  const body: unknown = await response.json().catch((): undefined => undefined);
  return { kind, reason: reasonOf(body) };
}

/** Classification of a non-2xx response (2xx is undefined). */
async function classifyFailure(response: Response): Promise<ApiFailure | undefined> {
  const reasonKind = REASON_FAILURE_KINDS[response.status];
  if (reasonKind !== undefined) return classifyWithReason(response, reasonKind);
  return STATUS_FAILURES[response.status] ?? (response.ok ? undefined : UNREACHABLE);
}

/** Extracting a 2xx response body (204 = no body). */
async function parseBody<T>(response: Response): Promise<ApiResult<T>> {
  if (response.status === 204) return { kind: "ok", value: undefined as T };
  try {
    return { kind: "ok", value: (await response.json()) as T };
  } catch {
    return UNREACHABLE;
  }
}

async function request<T>(path: string, init: RequestInit): Promise<ApiResult<T>> {
  let response: Response;
  try {
    response = await fetch(path, init);
  } catch {
    // Network unreachability is mapped into a typed result (classification, not swallowing)
    return UNREACHABLE;
  }
  const failure = await classifyFailure(response);
  return failure ?? parseBody<T>(response);
}

/** GET a JSON resource (session-cookie authenticated, same origin). */
export function apiGet<T>(path: string): Promise<ApiResult<T>> {
  return request<T>(path, { headers: { accept: "application/json" } });
}

/**
 * POST a body-less mutation (logout is the only POST mutation this dashboard
 * performs). Carries the CSRF custom header (AUTH_SPEC §11-4).
 */
export function apiPost(path: string): Promise<ApiResult<void>> {
  return request<void>(path, { method: "POST", headers: { [CSRF_HEADER]: "1" } });
}

/**
 * DELETE a resource (the revocation surfaces — S8 invites / S9 tokens, W3b).
 * Carries the CSRF custom header (AUTH_SPEC §11-4).
 */
export function apiDelete(path: string): Promise<ApiResult<void>> {
  return request<void>(path, { method: "DELETE", headers: { [CSRF_HEADER]: "1" } });
}
