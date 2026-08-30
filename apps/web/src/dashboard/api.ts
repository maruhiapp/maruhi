// セッション認証つき API 消費の薄い fetch 層(裁定 BP・BR — docs/notes/session-43.md)。
//
// - 同一オリジン前提(裁定 BM: ダッシュボードは maruhi-server Worker が配信する。
//   CSP connect-src 'self' と __Host- セッションクッキーの下で相対パスのみを叩く)
// - HTTP 状態を型付きの結果に写し、401 / 403 / 404 の分岐と文言を全画面で
//   一元化する(表示規律 §4 — 文言はサーバー申告の言い回しに限る)
// - mutation(本 PR ではログアウトのみ)には CSRF ヘッダー `x-maruhi-csrf: 1` を
//   一律付与する(AUTH_SPEC §11-4)
// - Schema デコードは持たない(裁定 BR — 検証を実装しない Web の型は
//   type-only import で拘束し、ランタイム防御は表示層の optional アクセス)

/** A non-2xx (or unreachable) API outcome, classified for uniform screen handling. */
export type ApiFailure =
  | { readonly kind: "unauthorized" }
  | { readonly kind: "forbidden"; readonly reason: string | undefined }
  | { readonly kind: "not-found" }
  | { readonly kind: "unreachable" };

/** Result of one API call: the parsed JSON body, or a classified failure. */
export type ApiResult<T> = { readonly kind: "ok"; readonly value: T } | ApiFailure;

const UNREACHABLE: ApiFailure = { kind: "unreachable" };

const STATUS_FAILURES: Readonly<Record<number, ApiFailure>> = {
  401: { kind: "unauthorized" },
  404: { kind: "not-found" },
};

/** 403 応答から型付き reason(ForbiddenError — api-schema)を防御的に取り出す。 */
function forbiddenReason(body: unknown): string | undefined {
  const reason = (body as { reason?: unknown } | null | undefined)?.reason;
  return typeof reason === "string" ? reason : undefined;
}

/** 非 2xx 応答の分類(2xx は undefined)。 */
async function classifyFailure(response: Response): Promise<ApiFailure | undefined> {
  if (response.status === 403) {
    const body: unknown = await response.json().catch((): undefined => undefined);
    return { kind: "forbidden", reason: forbiddenReason(body) };
  }
  return STATUS_FAILURES[response.status] ?? (response.ok ? undefined : UNREACHABLE);
}

/** 2xx 応答のボディ取り出し(204 = ボディなし)。 */
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
    // ネットワーク到達不能は型付き結果へ写す(握り潰しではなく分類)
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
 * POST a body-less mutation (logout is the only session mutation this
 * dashboard performs). Carries the CSRF custom header (AUTH_SPEC §11-4).
 */
export function apiPost(path: string): Promise<ApiResult<void>> {
  return request<void>(path, { method: "POST", headers: { "x-maruhi-csrf": "1" } });
}
