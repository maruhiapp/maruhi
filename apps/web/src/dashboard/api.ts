import type { CSRF_HEADER_NAME } from "@maruhi/api-schema";

const CSRF_HEADER = "x-maruhi-csrf" satisfies typeof CSRF_HEADER_NAME;

export type ApiFailure =
  | { readonly kind: "unauthorized" }
  | { readonly kind: "forbidden"; readonly reason: string | undefined }
  | { readonly kind: "not-found" }
  | { readonly kind: "gone"; readonly reason: string | undefined }
  | { readonly kind: "unreachable" };

export type ApiResult<T> = { readonly kind: "ok"; readonly value: T } | ApiFailure;

const UNREACHABLE: ApiFailure = { kind: "unreachable" };

const STATUS_FAILURES: Readonly<Record<number, ApiFailure>> = {
  401: { kind: "unauthorized" },
  404: { kind: "not-found" },
};

function reasonOf(body: unknown): string | undefined {
  const reason = (body as { reason?: unknown } | null | undefined)?.reason;
  return typeof reason === "string" ? reason : undefined;
}

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

async function classifyFailure(response: Response): Promise<ApiFailure | undefined> {
  const reasonKind = REASON_FAILURE_KINDS[response.status];
  if (reasonKind !== undefined) return classifyWithReason(response, reasonKind);
  return STATUS_FAILURES[response.status] ?? (response.ok ? undefined : UNREACHABLE);
}

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
    return UNREACHABLE;
  }
  const failure = await classifyFailure(response);
  return failure ?? parseBody<T>(response);
}

export function apiGet<T>(path: string): Promise<ApiResult<T>> {
  return request<T>(path, { headers: { accept: "application/json" } });
}

export function apiPost(path: string): Promise<ApiResult<void>> {
  return request<void>(path, { method: "POST", headers: { [CSRF_HEADER]: "1" } });
}

export function apiDelete(path: string): Promise<ApiResult<void>> {
  return request<void>(path, { method: "DELETE", headers: { [CSRF_HEADER]: "1" } });
}
