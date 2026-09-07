// `maruhi sync` の http ドライバ(SY2 第 2 段 — integration-options.md §3
// 補足 13 W1「CI と未導入時 = http」/ 補足 14 M2「プリセットは宣言的」/ 補足 15 X2
// 「統合トークンは普通の変数」)。
//
// ベンダー CLI が無い環境(CI・入れたくない人)で、maruhi 自身のコードがベンダーの
// HTTP API に一括 upsert する。exec ドライバ(sync-exec.ts)と同じ設定・同じ
// plan / apply に載る別のドライバであって、CLI を取りに行く代替ではない。
//
// 型で決めていること:
//   - 値のプレースホルダ({@link EntryToken} の `value`)は**本文のエントリ**にしか
//     置けない。URL のパス・クエリ・ヘッダのテンプレート({@link PathToken})に
//     値のトークンは存在しない
//   - 送る先はプリセットの宣言(`host`)で固定。設定でホストを差し替える口は無い
//   - 統合トークンは `Redacted` のまま `HttpClientRequest.bearerToken` に渡す
//     (上流が内側で剥がす — api.ts と同じ理由で手書きのヘッダー組み立てをしない)
//
// ベンダー API の実物(2026-09-07 に実装で確かめた):
//   - wrangler 4.128.0 `secret bulk` = `PATCH /accounts/{account}/workers/scripts/
//     {script}/secrets-bulk`、`Content-Type: application/merge-patch+json`、本文
//     `{"secrets": {NAME: {"name","text","type":"secret_text"} | null}}`(null =
//     削除)。`--env` はスクリプト名の合成 `<name>-<env>`(getLegacyScriptName)。
//     未デプロイの Worker はエラーコード 10007 / 10090(isWorkerNotFoundError)で
//     wrangler が draft Worker を作るが、http ドライバは作らず型付きエラーで案内する。
//     envelope は `{success, errors[{code,message}], messages, result}`
//   - Vercel CLI 59.11.7 `env add --force` = `POST /v10/projects/{id}/env?upsert=true`、
//     本文 `{type, key, value, target[], gitBranch}`(type = production / preview は
//     "sensitive"、development か --no-sensitive は "encrypted")。公開 REST docs は
//     同じエンドポイントに**配列**も受け(一括)、応答は `{created, failed[]}`。
//     `env rm` = `GET /v10/projects/{id}/env?target=&gitBranch=` で id を引いてから
//     `DELETE /v10/projects/{id}/env/{envId}`。team は `?teamId=`。
//     429 / Retry-After を CLI も再試行する(sleep + skew)
//
// 応答本文は値やトークンを echo しうる前提で扱う(Vercel の `created` は値を
// 返す): 成功時は捨て、失敗時は抽出した断片だけを sync-exec.ts の
// scrubVendorOutput(伏せてから切る)に通してから見せる。

import { Duration, Effect, Redacted } from "effect";
import { HttpClient, HttpClientRequest } from "effect/unstable/http";

import { decodeValueText, displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { scrubVendorOutput, type SyncWrite } from "./sync-exec.ts";
import type { OptionSpec, ResolvedOptions, ValueConstraints } from "./sync-types.ts";
import { CLI_VERSION } from "./version.ts";

/**
 * One token of a URL path or query. A literal or an option value — there is
 * deliberately no token for the variable name or the value here.
 */
export type PathToken =
  | string
  | { readonly kind: "option"; readonly option: string }
  /** 削除の 2 手目だけ: 一覧で引いた同期先側の ID。 */
  | { readonly kind: "id" };

/** One leaf of the per-variable entry template (the only place a value goes). */
export type EntryToken =
  | { readonly kind: "name" }
  | { readonly kind: "value" }
  | { readonly kind: "option"; readonly option: string };

/** JSON tree whose leaves may be literals or tokens of `T`. */
export type JsonTemplate<T> =
  | string
  | number
  | boolean
  | null
  | T
  | readonly JsonTemplate<T>[]
  | { readonly [key: string]: JsonTemplate<T> };

/** Tokens allowed in the request body outside the entries. */
export type BodyToken =
  | { readonly kind: "entries" }
  | { readonly kind: "option"; readonly option: string };

/** How a batch's entries are laid out inside the body. */
export type EntriesLayout = "object-by-name" | "array";

/** The write request of a preset (one request per batch of variables). */
export interface HttpWriteSpec {
  readonly method: "POST" | "PATCH" | "PUT";
  readonly path: readonly PathToken[];
  /** クエリ(値が undefined のオプションは省く)。 */
  readonly query: Readonly<Record<string, PathToken>>;
  readonly contentType: string;
  /** 本文全体(`{kind: "entries"}` を 1 か所含む)。 */
  readonly body: JsonTemplate<BodyToken>;
  readonly entries: EntriesLayout;
  /** 1 変数ぶんのエントリ(値のトークンはここだけ)。 */
  readonly entry: JsonTemplate<EntryToken>;
  /**
   * 削除のエントリ(object-by-name で書き込みと同居させる形 — Workers の merge-patch
   * では JSON の `null`)。`delete.kind === "in-write"` のプリセットだけが持つ。
   */
  readonly deletedEntry?: JsonTemplate<EntryToken>;
}

/** 削除の表現: 書き込みに同居(merge-patch の null)か、一覧で引いてから 1 件ずつ消す。 */
export type HttpDeleteSpec =
  | { readonly kind: "in-write" }
  | {
      readonly kind: "lookup";
      readonly list: {
        readonly path: readonly PathToken[];
        readonly query: Readonly<Record<string, PathToken>>;
        /** 応答のうち一覧が入るフィールド。 */
        readonly itemsField: string;
        readonly keyField: string;
        readonly idField: string;
        /**
         * 同期先側の環境の照合(名前が同じでも別の環境のものを消さない):
         * `targetField` の配列が `targetOption` の値を含み、`branchField` が
         * `branchOption` の値(無ければ未設定)と一致する項目だけを消す。
         */
        readonly match: {
          readonly targetField: string;
          readonly targetOption: string;
          readonly branchField: string;
          readonly branchOption: string;
        };
      };
      readonly remove: {
        readonly method: "DELETE";
        readonly path: readonly PathToken[];
        readonly query: Readonly<Record<string, PathToken>>;
      };
    };

/** 応答の読み方(閉集合 — 追加はここに 1 つ足す)。 */
export type ResponseKind = "cloudflare-v4" | "vercel-env";

/** A declarative http preset (data — no per-vendor request code). */
export interface HttpPreset {
  /** 送る先(固定。設定では変えられない)。 */
  readonly host: string;
  /** 人間向けの呼び名(文面用 — "the Vercel API")。 */
  readonly label: string;
  /** 1 リクエストに載せる最大件数。 */
  readonly batch: number;
  readonly write: HttpWriteSpec;
  readonly delete: HttpDeleteSpec;
  readonly response: ResponseKind;
  readonly constraints: ValueConstraints;
  readonly options: Readonly<Record<string, OptionSpec>>;
  /** 設定のオプションから導く値(スクリプト名・Vercel の type 等。値には触れない)。 */
  readonly derive: (options: ResolvedOptions) => Readonly<Record<string, string>>;
  /** 統合トークンの作り方の案内(エラー文面用。docs の節を指す)。 */
  readonly tokenHint: string;
}

const VERCEL_ENVIRONMENTS = ["production", "preview", "development"] as const;

// Vercel の 1 リクエストの件数上限は公開 docs に無い(CLI は 1 件ずつ)。総量の
// 上限(64 KB / deployment)には件数が効かないので、未知の上限に対して保守側に置く
const VERCEL_BATCH = 25;

/** Built-in http presets (same first-class targets as the exec presets). */
export const HTTP_PRESETS = {
  "cloudflare-workers": {
    host: "api.cloudflare.com",
    label: "the Cloudflare API",
    batch: 100,
    write: {
      method: "PATCH",
      path: [
        "/client/v4/accounts/",
        { kind: "option", option: "accountId" },
        "/workers/scripts/",
        { kind: "option", option: "scriptName" },
        "/secrets-bulk",
      ],
      query: {},
      contentType: "application/merge-patch+json",
      body: { secrets: { kind: "entries" } },
      entries: "object-by-name",
      entry: { name: { kind: "name" }, text: { kind: "value" }, type: "secret_text" },
      deletedEntry: null,
    },
    delete: { kind: "in-write" },
    response: "cloudflare-v4",
    constraints: { maxBytes: null, nonEmpty: false, refuseSingleLineTrailingNewline: false },
    options: {
      accountId: { type: "string", required: true },
      name: { type: "string", required: true },
      environment: { type: "string", required: false },
    },
    // wrangler の getLegacyScriptName: 名前付き環境は `<name>-<env>`
    derive: (options) => ({
      scriptName:
        typeof options["environment"] === "string"
          ? `${String(options["name"])}-${options["environment"]}`
          : String(options["name"]),
    }),
    tokenHint:
      "an API token scoped to the account with the Workers Scripts: Edit permission (see the Deploy targets page in the docs)",
  },
  vercel: {
    host: "api.vercel.com",
    label: "the Vercel API",
    batch: VERCEL_BATCH,
    write: {
      method: "POST",
      path: ["/v10/projects/", { kind: "option", option: "projectId" }, "/env"],
      query: { upsert: "true", teamId: { kind: "option", option: "teamId" } },
      contentType: "application/json",
      body: { kind: "entries" },
      entries: "array",
      entry: {
        key: { kind: "name" },
        value: { kind: "value" },
        type: { kind: "option", option: "type" },
        target: [{ kind: "option", option: "environment" }],
        gitBranch: { kind: "option", option: "gitBranch" },
      },
    },
    delete: {
      kind: "lookup",
      list: {
        path: ["/v10/projects/", { kind: "option", option: "projectId" }, "/env"],
        query: {
          target: { kind: "option", option: "environment" },
          gitBranch: { kind: "option", option: "gitBranch" },
          teamId: { kind: "option", option: "teamId" },
        },
        itemsField: "envs",
        keyField: "key",
        idField: "id",
        match: {
          targetField: "target",
          targetOption: "environment",
          branchField: "gitBranch",
          branchOption: "gitBranch",
        },
      },
      remove: {
        method: "DELETE",
        path: ["/v10/projects/", { kind: "option", option: "projectId" }, "/env/", { kind: "id" }],
        query: { teamId: { kind: "option", option: "teamId" } },
      },
    },
    response: "vercel-env",
    // API は値をそのまま保存する(CLI の stdin 由来の制約は無い)
    constraints: { maxBytes: null, nonEmpty: false, refuseSingleLineTrailingNewline: false },
    options: {
      environment: { type: "string", required: true, values: VERCEL_ENVIRONMENTS },
      gitBranch: { type: "string", required: false },
      projectId: { type: "string", required: true },
      teamId: { type: "string", required: false },
      sensitive: { type: "boolean", required: false },
    },
    // Vercel CLI の resolveFinalType: development は sensitive 不可、--no-sensitive
    // は encrypted(= 読み返せる値)。それ以外は sensitive
    derive: (options) => ({
      type:
        options["environment"] === "development" || options["sensitive"] === false
          ? "encrypted"
          : "sensitive",
    }),
    tokenHint:
      "an access token created in the Vercel dashboard, scoped to the team that owns the project (see the Deploy targets page in the docs)",
  },
} as const satisfies Readonly<Record<string, HttpPreset>>;

/** 統合トークン(復号済み — ヘッダーに載る直前まで包んだまま)。 */
export type IntegrationToken = Redacted.Redacted<string>;

/** リトライの調律(テストで短くする)。 */
export interface HttpRetryPolicy {
  /** 1 リクエストの試行回数(最初の 1 回を含む)。 */
  readonly attempts: number;
  readonly baseDelay: Duration.Duration;
  /** `Retry-After` を尊重する上限(それ以上は待たずに失敗させる)。 */
  readonly maxDelay: Duration.Duration;
}

/** 本番のリトライ: 3 回、0.5 s から倍々、Retry-After は 30 s まで尊重。 */
export const DEFAULT_HTTP_RETRY: HttpRetryPolicy = {
  attempts: 3,
  baseDelay: Duration.millis(500),
  maxDelay: Duration.seconds(30),
};

/** 1 リクエストの結果(値・トークンを含みうる本文は呼び出し側で捨てるか伏せる)。 */
interface HttpOutcome {
  readonly status: number;
  readonly text: string;
}

/** ベンダー API の応答本文の読み(壊れた JSON は null)。 */
function parseJson(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    // 本文が JSON でない(WAF のブロックページ等)= 読めない応答として扱う
    return null;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** パス / クエリのトークンの展開(値は決して載らない — トークンの型に無い)。 */
function renderPathToken(
  token: PathToken,
  options: ResolvedOptions,
  id: string | null,
): string | undefined {
  if (typeof token === "string") {
    return token;
  }
  if (token.kind === "id") {
    if (id === null) {
      throw new Error("preset uses an id token outside a delete request");
    }
    return encodeURIComponent(id);
  }
  const value = options[token.option];
  return typeof value === "string" ? encodeURIComponent(value) : undefined;
}

/** パスの展開(必須オプションが無いのは宣言と検証の不整合 = 内部エラー)。 */
function renderPath(
  path: readonly PathToken[],
  options: ResolvedOptions,
  id: string | null,
): string {
  return path
    .map((token) => {
      const rendered = renderPathToken(token, options, id);
      if (rendered === undefined) {
        throw new Error("preset path names an option the config does not resolve");
      }
      return rendered;
    })
    .join("");
}

/** クエリの展開(未設定のオプションは省く)。 */
function renderQuery(
  query: Readonly<Record<string, PathToken>>,
  options: ResolvedOptions,
): Readonly<Record<string, string>> {
  const params: Record<string, string> = {};
  for (const [key, token] of Object.entries(query)) {
    const rendered = renderPathToken(token, options, null);
    if (rendered !== undefined) {
      // クエリはこの後 UrlParams が符号化する(パス用の符号化を二重に掛けない)
      params[key] = typeof token === "string" ? rendered : decodeURIComponent(rendered);
    }
  }
  return params;
}

/**
 * 1 エントリの展開。値のトークンは `Redacted` から剥がした平文を JSON の葉に置く
 * (この関数の産物は送信本文の材料としてだけ使い、ログ・エラーへは流れない)。
 */
function renderEntry(
  template: JsonTemplate<EntryToken>,
  input: { readonly name: string; readonly text: string | null; readonly options: ResolvedOptions },
): unknown {
  if (template === null || typeof template !== "object") {
    return template;
  }
  if (Array.isArray(template)) {
    return (template as readonly JsonTemplate<EntryToken>[]).map((item) =>
      renderEntry(item, input),
    );
  }
  if (isToken(template)) {
    return renderEntryToken(template as EntryToken, input);
  }
  const rendered: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(template as Record<string, JsonTemplate<EntryToken>>)) {
    const item = renderEntry(value, input);
    // undefined(未設定のオプション)はキーごと省く(JSON.stringify も落とす)
    if (item !== undefined) {
      rendered[key] = item;
    }
  }
  return rendered;
}

/** テンプレートの葉がトークンか(`kind` を持つオブジェクト)。 */
function isToken(template: object): boolean {
  return "kind" in template && typeof (template as { kind?: unknown }).kind === "string";
}

/** 1 トークンの値(名前 / 値 / オプション。未設定のオプションは undefined = 省く)。 */
function renderEntryToken(
  token: EntryToken,
  input: { readonly name: string; readonly text: string | null; readonly options: ResolvedOptions },
): unknown {
  switch (token.kind) {
    case "name":
      return input.name;
    case "value":
      return input.text;
    case "option":
      return input.options[token.option];
  }
}

/** 本文全体の展開(`entries` の位置に展開済みのエントリ集合を置く)。 */
function renderBody(
  template: JsonTemplate<BodyToken>,
  entries: unknown,
  options: ResolvedOptions,
): unknown {
  if (template === null || typeof template !== "object") {
    return template;
  }
  if (Array.isArray(template)) {
    return (template as readonly JsonTemplate<BodyToken>[]).map((item) =>
      renderBody(item, entries, options),
    );
  }
  if (isToken(template)) {
    const token = template as BodyToken;
    return token.kind === "entries" ? entries : options[token.option];
  }
  const rendered: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(template as Record<string, JsonTemplate<BodyToken>>)) {
    const item = renderBody(value, entries, options);
    if (item !== undefined) {
      rendered[key] = item;
    }
  }
  return rendered;
}

/** One planned request of a target: the names it carries, and how to build it. */
export interface HttpBatch {
  readonly kind: "write" | "delete";
  readonly names: readonly string[];
  readonly writes: readonly SyncWrite[];
  readonly deletes: readonly string[];
}

/** 展開済みオプション(設定の値 + `derive` の産物)。 */
export function resolveOptions(preset: HttpPreset, options: ResolvedOptions): ResolvedOptions {
  return { ...options, ...preset.derive(options) };
}

/**
 * Splits writes (and, for presets whose delete rides along, deletes) into
 * batches of the preset's size. Pure — nothing is sent here.
 */
export function buildBatches(input: {
  readonly preset: HttpPreset;
  readonly writes: readonly SyncWrite[];
  readonly deletes: readonly string[];
}): readonly HttpBatch[] {
  const { preset } = input;
  const batches: HttpBatch[] = [];
  const inWrite = preset.delete.kind === "in-write";
  const items: (readonly [string, SyncWrite | null])[] = [
    ...input.writes.map((write) => [write.name, write] as const),
    ...(inWrite ? input.deletes.map((name) => [name, null] as const) : []),
  ];
  for (let start = 0; start < items.length; start += preset.batch) {
    const chunk = items.slice(start, start + preset.batch);
    batches.push({
      kind: "write",
      names: chunk.map(([name]) => name),
      writes: chunk.flatMap(([, write]) => (write === null ? [] : [write])),
      deletes: chunk.flatMap(([name, write]) => (write === null ? [name] : [])),
    });
  }
  if (!inWrite) {
    for (const name of input.deletes) {
      batches.push({ kind: "delete", names: [name], writes: [], deletes: [name] });
    }
  }
  return batches;
}

/** 状態を持つ送信部品の入力(ターゲット 1 つぶん)。 */
export interface HttpTargetInput {
  readonly preset: HttpPreset;
  readonly options: ResolvedOptions;
  readonly token: IntegrationToken;
  readonly retry: HttpRetryPolicy;
}

/** ベンダー API 1 リクエストの成否(本文は抽出済みの断片だけを外へ出す)。 */
export interface HttpRequestResult {
  /** 成功として届いた名前(部分成功の応答〔Vercel の failed〕はここで割れる)。 */
  readonly delivered: readonly string[];
  /** 失敗(null = 全件成功)。文面は伏せ字化済みで変数名と応答の断片だけを運ぶ。 */
  readonly failure: { readonly names: readonly string[]; readonly lines: readonly string[] } | null;
}

const RETRIABLE_STATUSES = new Set([429, 502, 503, 504]);

/** `Retry-After`(秒 or HTTP 日付)の解釈。読めなければ null。 */
function retryAfterOf(header: string | undefined, now: number): Duration.Duration | null {
  if (header === undefined) {
    return null;
  }
  const seconds = Number(header);
  if (Number.isFinite(seconds) && seconds >= 0) {
    return Duration.seconds(seconds);
  }
  const at = Date.parse(header);
  return Number.isNaN(at) ? null : Duration.millis(Math.max(0, at - now));
}

/**
 * Sends one request with the preset's bearer token, retrying transport
 * failures and 429 / 502 / 503 / 504 (upserts and deletes are idempotent, so a
 * re-send is safe). The response body is returned whole for the caller to
 * interpret and scrub — never logged here.
 */
function send(
  input: HttpTargetInput,
  request: HttpClientRequest.HttpClientRequest,
): Effect.Effect<HttpOutcome, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const client = yield* HttpClient.HttpClient;
    const prepared = request.pipe(
      HttpClientRequest.bearerToken(input.token),
      HttpClientRequest.setHeader("accept", "application/json"),
      HttpClientRequest.setHeader("user-agent", `maruhi-cli/${CLI_VERSION}`),
    );
    let lastFailure = "";
    for (let attempt = 1; attempt <= input.retry.attempts; attempt += 1) {
      const outcome = yield* client.execute(prepared).pipe(
        Effect.flatMap((response) =>
          Effect.map(response.text, (text) => ({
            kind: "response" as const,
            status: response.status,
            retryAfter: retryAfterOf(response.headers["retry-after"], Date.now()),
            text,
          })),
        ),
        // 通信層の失敗(DNS・接続・TLS)。文面は要求先の説明だけで、本文は無い
        Effect.catch((error) =>
          Effect.succeed({ kind: "transport" as const, message: describeTransport(error) }),
        ),
      );
      if (outcome.kind === "response" && !RETRIABLE_STATUSES.has(outcome.status)) {
        return { status: outcome.status, text: outcome.text };
      }
      lastFailure =
        outcome.kind === "transport"
          ? outcome.message
          : `${input.preset.label} answered ${outcome.status}`;
      if (attempt === input.retry.attempts) {
        break;
      }
      const backoff = Duration.times(input.retry.baseDelay, 2 ** (attempt - 1));
      const wait =
        outcome.kind === "response" && outcome.retryAfter !== null ? outcome.retryAfter : backoff;
      if (Duration.isGreaterThan(wait, input.retry.maxDelay)) {
        return yield* Effect.fail(
          cliError(
            `${input.preset.label} asked to retry after ${Math.ceil(Duration.toSeconds(wait))} seconds (Retry-After), longer than maruhi waits. Run \`maruhi sync apply\` again later`,
          ),
        );
      }
      yield* Effect.sleep(wait);
    }
    return yield* Effect.fail(
      cliError(`${lastFailure} (${input.retry.attempts} attempts). Check the network and retry`),
    );
  });
}

/** 通信層の失敗の説明(要求先のホストとエラーの種別だけ。本文・ヘッダーは無い)。 */
function describeTransport(error: unknown): string {
  const tag = isRecord(error) && typeof error["_tag"] === "string" ? error["_tag"] : "error";
  const description =
    isRecord(error) && typeof error["description"] === "string" ? `: ${error["description"]}` : "";
  return `Could not reach the vendor API (${tag}${displayText(description)})`;
}

/** 応答本文から見せてよい断片を取り出し、伏せ字化する(値・トークン)。 */
function scrubbed(
  lines: readonly string[],
  writes: readonly SyncWrite[],
  token: IntegrationToken,
): string[] {
  return scrubVendorOutput(lines.join("\n"), writes, [token]);
}

/** Cloudflare の envelope の errors / messages を行に。 */
function cloudflareLines(body: unknown, status: number): string[] {
  if (!isRecord(body)) {
    return [`HTTP ${status}`];
  }
  return [
    `HTTP ${status}`,
    ...recordsOf(body["errors"]).map(
      (entry) => `error ${String(entry["code"] ?? "")}: ${String(entry["message"] ?? "")}`,
    ),
    ...arrayOf(body["messages"]).map((message) =>
      typeof message === "string" ? message : String(isRecord(message) ? message["message"] : ""),
    ),
  ];
}

/** 配列でなければ空(応答の形の揺れを吸収する)。 */
function arrayOf(value: unknown): readonly unknown[] {
  return Array.isArray(value) ? value : [];
}

/** 配列のうちオブジェクトの要素だけ。 */
function recordsOf(value: unknown): readonly Record<string, unknown>[] {
  return arrayOf(value).filter(isRecord);
}

/** Cloudflare の errors[].code の集合。 */
function cloudflareCodes(body: unknown): Set<number> {
  const codes = new Set<number>();
  if (isRecord(body) && Array.isArray(body["errors"])) {
    for (const entry of body["errors"]) {
      if (isRecord(entry) && typeof entry["code"] === "number") {
        codes.add(entry["code"]);
      }
    }
  }
  return codes;
}

// wrangler の isWorkerNotFoundError(worker-not-found-error.ts)
const CLOUDFLARE_WORKER_NOT_FOUND = new Set([10007, 10090]);

/** Cloudflare v4 envelope の判定: 2xx かつ `success: true`。 */
function readCloudflare(
  outcome: HttpOutcome,
  batch: HttpBatch,
  input: HttpTargetInput,
): HttpRequestResult {
  const body = parseJson(outcome.text);
  if (outcome.status >= 200 && outcome.status < 300 && isRecord(body) && body["success"] === true) {
    return { delivered: batch.names, failure: null };
  }
  const codes = cloudflareCodes(body);
  const lines = cloudflareLines(body, outcome.status);
  if ([...codes].some((code) => CLOUDFLARE_WORKER_NOT_FOUND.has(code))) {
    lines.push(
      `No Worker named ${displayText(String(input.options["scriptName"]))} exists in this account. maruhi does not create one: deploy the Worker first (\`wrangler deploy\`), then apply again`,
    );
  }
  return {
    delivered: [],
    failure: { names: batch.names, lines: scrubbed(lines, batch.writes, input.token) },
  };
}

/** Vercel の `{created, failed[]}` の判定(部分成功を名前で割る)。 */
function readVercel(
  outcome: HttpOutcome,
  batch: HttpBatch,
  input: HttpTargetInput,
): HttpRequestResult {
  const body = parseJson(outcome.text);
  if (outcome.status < 200 || outcome.status >= 300 || !isRecord(body)) {
    return {
      delivered: [],
      failure: {
        names: batch.names,
        lines: scrubbed(vercelErrorLines(outcome.status, body), batch.writes, input.token),
      },
    };
  }
  const failed = recordsOf(body["failed"]);
  if (batch.kind === "delete" || failed.length === 0) {
    // failed が空なら全件届いたと読む(created の形は 1 件 / 配列で揺れる)
    return { delivered: batch.names, failure: null };
  }
  const created = body["created"];
  const createdKeys = new Set(keysOf(Array.isArray(created) ? created : [created]));
  const failures = failed.map(vercelFailureOf);
  const failedNames = new Set(failures.flatMap((entry) => (entry.key === null ? [] : [entry.key])));
  // 失敗した名前が特定できなければバッチ全体を未達とする(届いたと誤記録しない)
  const delivered =
    failedNames.size === 0
      ? []
      : batch.names.filter((name) => !failedNames.has(name) && createdKeys.has(name));
  const names = batch.names.filter((name) => !delivered.includes(name));
  const lines = [`HTTP ${outcome.status}`, ...failures.map((entry) => entry.line)];
  return { delivered, failure: { names, lines: scrubbed(lines, batch.writes, input.token) } };
}

/** Vercel の非 2xx 応答(`{error: {code, message}}`)の表示行。 */
function vercelErrorLines(status: number, body: unknown): string[] {
  const error = isRecord(body) && isRecord(body["error"]) ? body["error"] : null;
  return error === null
    ? [`HTTP ${status}`]
    : [`HTTP ${status}`, `error ${String(error["code"] ?? "")}: ${String(error["message"] ?? "")}`];
}

/** 応答のエントリの `key`(文字列のものだけ)。 */
function keysOf(entries: readonly unknown[]): readonly string[] {
  return entries.filter(isRecord).flatMap((entry) => {
    const key = entry["key"];
    return typeof key === "string" ? [key] : [];
  });
}

/** Vercel の `failed[]` 1 件 → 失敗した名前と表示行(伏せ字化は呼び出し側)。 */
function vercelFailureOf(entry: Record<string, unknown>): {
  readonly key: string | null;
  readonly line: string;
} {
  const error = isRecord(entry["error"]) ? entry["error"] : {};
  const named = [error["key"], error["envVarKey"]].find((value) => typeof value === "string");
  const key = typeof named === "string" ? named : null;
  return {
    key,
    line: `error ${String(error["code"] ?? "")}${key === null ? "" : ` (${key})`}: ${String(error["message"] ?? "")}`,
  };
}

function readResponse(
  kind: ResponseKind,
  outcome: HttpOutcome,
  batch: HttpBatch,
  input: HttpTargetInput,
) {
  return kind === "cloudflare-v4"
    ? readCloudflare(outcome, batch, input)
    : readVercel(outcome, batch, input);
}

/** 書き込みリクエストの組み立て(値はここで剥がして本文に置き、産物は送信にだけ渡す)。 */
function buildWriteRequest(
  input: HttpTargetInput,
  batch: HttpBatch,
): HttpClientRequest.HttpClientRequest {
  const { write } = input.preset;
  const entries: unknown[] = [];
  const byName: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const item of batch.writes) {
    // 剥がす理由: 本文のエントリの値の葉(値が maruhi を離れる直前。この産物は
    // リクエスト本文にしか流れず、失敗時の表示は応答から抽出して伏せた断片だけ)
    const text = decodeValueText(Redacted.value(item.value));
    if (text === null) {
      // prepareWork(sync-plan.ts)が送る前に弾いている前提の防衛線
      throw new Error("a value that is not valid UTF-8 reached the http driver");
    }
    const entry = renderEntry(write.entry, { name: item.name, text, options: input.options });
    entries.push(entry);
    byName[item.name] = entry;
  }
  for (const name of batch.deletes) {
    if (write.deletedEntry === undefined) {
      throw new Error("a delete rode along on a preset that has no deleted entry");
    }
    const entry = renderEntry(write.deletedEntry, { name, text: null, options: input.options });
    entries.push(entry);
    byName[name] = entry;
  }
  const body = renderBody(write.body, write.entries === "array" ? entries : byName, input.options);
  return HttpClientRequest.make(write.method)(
    `https://${input.preset.host}${renderPath(write.path, input.options, null)}`,
    { urlParams: renderQuery(write.query, input.options) },
  ).pipe(HttpClientRequest.bodyText(JSON.stringify(body), write.contentType));
}

/** 削除の 1 手目: 一覧で同期先側の ID を引く(値は読まずに捨てる)。 */
function lookupIds(
  input: HttpTargetInput,
  spec: Extract<HttpDeleteSpec, { kind: "lookup" }>,
  name: string,
): Effect.Effect<
  { readonly ids: readonly string[] } | { readonly failure: readonly string[] },
  CliError,
  HttpClient.HttpClient
> {
  return Effect.gen(function* () {
    const request = HttpClientRequest.get(
      `https://${input.preset.host}${renderPath(spec.list.path, input.options, null)}`,
      { urlParams: renderQuery(spec.list.query, input.options) },
    );
    const outcome = yield* send(input, request);
    const body = parseJson(outcome.text);
    if (outcome.status < 200 || outcome.status >= 300 || !isRecord(body)) {
      return {
        failure: scrubbed(
          [`HTTP ${outcome.status} while listing variables at the target`],
          [],
          input.token,
        ),
      };
    }
    const listed: unknown = body[spec.list.itemsField];
    const items: Record<string, unknown>[] = Array.isArray(listed) ? listed.filter(isRecord) : [];
    const target = input.options[spec.list.match.targetOption];
    const branch = input.options[spec.list.match.branchOption];
    const ids = items
      .filter((item) => item[spec.list.keyField] === name)
      .filter((item) => {
        const targets = item[spec.list.match.targetField];
        const itemBranch = item[spec.list.match.branchField];
        return (
          Array.isArray(targets) &&
          targets.includes(target) &&
          (typeof branch === "string"
            ? itemBranch === branch
            : itemBranch === undefined || itemBranch === null)
        );
      })
      .flatMap((item) => {
        const id = item[spec.list.idField];
        return typeof id === "string" ? [id] : [];
      });
    return { ids };
  });
}

/**
 * Runs one batch against the vendor API: the write request, or the
 * lookup-then-delete pair for presets whose delete does not ride along.
 */
export function runBatch(
  input: HttpTargetInput,
  batch: HttpBatch,
): Effect.Effect<HttpRequestResult, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    if (batch.kind === "write") {
      const outcome = yield* send(input, buildWriteRequest(input, batch));
      return readResponse(input.preset.response, outcome, batch, input);
    }
    const spec = input.preset.delete;
    if (spec.kind !== "lookup") {
      throw new Error("a delete batch was built for a preset whose deletes ride along");
    }
    const name = batch.names[0] ?? "";
    const looked = yield* lookupIds(input, spec, name);
    if ("failure" in looked) {
      return { delivered: [], failure: { names: batch.names, lines: looked.failure } };
    }
    // 一覧に無い = 同期先で既に消えている(読み戻しは ID の突合だけで、値は読まない)
    for (const id of looked.ids) {
      const request = HttpClientRequest.make(spec.remove.method)(
        `https://${input.preset.host}${renderPath(spec.remove.path, input.options, id)}`,
        { urlParams: renderQuery(spec.remove.query, input.options) },
      );
      const outcome = yield* send(input, request);
      // 404 = 並行して消された(一覧の直後)。消えていることに変わりはない
      if (outcome.status === 404) {
        continue;
      }
      const result = readResponse(input.preset.response, outcome, batch, input);
      if (result.failure !== null) {
        return result;
      }
    }
    return { delivered: batch.names, failure: null };
  });
}

/** C0 制御文字(改行を含む)か DEL を含むか(ヘッダー値に載らない文字)。 */
function hasControlCharacter(text: string): boolean {
  for (const character of text) {
    const code = character.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) {
      return true;
    }
  }
  return false;
}

/** 統合トークンの検査(ヘッダーに載る形か)。文面は変数名だけを運ぶ。 */
export function checkIntegrationToken(name: string, bytes: Uint8Array): CliError | string {
  const text = decodeValueText(bytes);
  if (text === null || text.length === 0) {
    return cliError(`The token variable ${displayText(name)} is empty or not valid UTF-8`);
  }
  // ヘッダー値に載らない文字(改行・制御文字)は `echo` の末尾改行が典型
  if (hasControlCharacter(text)) {
    return cliError(
      `The token variable ${displayText(name)} contains a newline or control character, so it cannot be sent as an Authorization header. Push the token without a trailing newline (\`printf %s\` instead of \`echo\`)`,
    );
  }
  return text;
}
