// セッション認証つき API 消費の薄い fetch 層(裁定 BP・BR — docs/notes/session-43.md)。
//
// - 同一オリジン前提(裁定 BM: ダッシュボードは maruhi-server Worker が配信する。
//   CSP connect-src 'self' と __Host- セッションクッキーの下で相対パスのみを叩く)
// - HTTP 状態を型付きの結果に写し、401 / 403 / 404 / 410 の分岐と文言を全画面で
//   一元化する(表示規律 §4 — 文言はサーバー申告の言い回しに限る)
// - mutation(ログアウト・失効 DELETE — W3b)には CSRF ヘッダーを一律付与する
//   (AUTH_SPEC §11-4)
// - Schema デコードは持たない(裁定 BR — 検証を実装しない Web の型は
//   type-only import で拘束し、ランタイム防御は表示層の optional アクセス)
import type { CSRF_HEADER_NAME } from "@maruhi/api-schema";

/**
 * CSRF 対抗のカスタムヘッダー名(AUTH_SPEC §11-4)。真実源は api-schema の
 * `CSRF_HEADER_NAME` で、ここは型レベルで束縛する(裁定 CN —
 * docs/notes/session-45.md): 値 import はバンドル(= TCB)へ api-schema の
 * 実行コードを持ち込む(裁定 CD のトリップワイヤ対象)ため、type-only import +
 * satisfies でリテラルを拘束し、正の側のリネームをコンパイルエラーで割る。
 * 実送信の値照合は test/unit/api.test.ts(テストプロセスは値 import 可)。
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

/** 403 / 410 応答から型付き reason(ForbiddenError / InviteGoneError)を防御的に取り出す。 */
function reasonOf(body: unknown): string | undefined {
  const reason = (body as { reason?: unknown } | null | undefined)?.reason;
  return typeof reason === "string" ? reason : undefined;
}

/** reason を運ぶ失敗分類(403 = forbidden、410 = gone — 裁定 CN の付随具体化)。 */
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

/** 非 2xx 応答の分類(2xx は undefined)。 */
async function classifyFailure(response: Response): Promise<ApiFailure | undefined> {
  const reasonKind = REASON_FAILURE_KINDS[response.status];
  if (reasonKind !== undefined) return classifyWithReason(response, reasonKind);
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
