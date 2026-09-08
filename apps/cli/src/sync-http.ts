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
//   - Netlify(SY4 — 2026-09-08 に open-api.netlify.com の swagger 2.57.1・docs.netlify.com・
//     netlify-cli の `env:set` / `env:unset` で確かめた): base `https://api.netlify.com/api/v1`、
//     環境変数は**アカウント(チーム)単位**のエンドポイントに `site_id` クエリでサイトを
//     指す。`POST /accounts/{account_id}/env?site_id=`(配列。**新規作成**)、
//     `PATCH /accounts/{account_id}/env/{key}?site_id=`(本文 `{context, context_parameter?,
//     value}` = **既存 key** の 1 context の値を作る / 更新する。swagger 原文 "for an existing
//     environment variable")、`GET /accounts/{account_id}/env?site_id=`(配列。secret の値は
//     返らない)、`DELETE …/env/{key}`(key ごと = 全 context)、`DELETE …/env/{key}/value/{id}`
//     (1 context の値だけ)。netlify-cli 自身も一覧で有無を見てから「無ければ POST・あれば
//     PATCH(context 指定時)」に分岐する = 単独の upsert は無い。エラー本文は `{code, message}`。
//     secret(`is_secret`)は write-only で `all` / `dev` に置けず、`post_processing` scope を
//     持てない(CLI は builds / functions / runtime の 3 scope を明示して送る)。レート制限は
//     500 req / min(`X-RateLimit-*`。429 の `Retry-After` の有無は docs に無い)
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
 * One token of a URL path or query. A literal, an option value, the target-side
 * ID of a delete, or the variable name — there is deliberately no token for the
 * value here.
 */
export type PathToken =
  | string
  | { readonly kind: "option"; readonly option: string }
  /** 削除の 2 手目だけ: 一覧で引いた同期先側の ID。 */
  | { readonly kind: "id" }
  /** 1 変数だけを運ぶリクエスト(create-or-update の各手・removeItem)だけ: 変数名。 */
  | { readonly kind: "name" };

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

/**
 * How a batch's entries are laid out inside the body. `single` = the request
 * carries exactly one variable and the body's `entries` token is that entry.
 */
export type EntriesLayout = "object-by-name" | "array" | "single";

/** One write request (a batch of variables, or exactly one for `single`). */
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

/** A list request of the target's variables (used for the ID / key matching only — never for values). */
export interface HttpListSpec {
  readonly path: readonly PathToken[];
  readonly query: Readonly<Record<string, PathToken>>;
  /** 応答のうち一覧が入るフィールド(null = 本文そのものが配列)。 */
  readonly itemsField: string | null;
  readonly keyField: string;
  /**
   * 一覧が続きを持つことを示すフィールドの経路(Vercel = `pagination.next`)。省略 =
   * 一覧は常に完全。続きがあるのに名前が無い一覧は「消えている」の証拠にならず、
   * 「存在しない」の証拠にもならない(fail-closed)。
   */
  readonly nextPage?: readonly [string, string];
}

/**
 * How writes reach the target: one request upserts a batch (Workers / Vercel),
 * or the target has no upsert and the preset lists the existing keys once,
 * then creates the missing ones and updates the rest, one request per variable
 * (Netlify). The list is read for the key names only.
 */
export type HttpWriteStrategy =
  | { readonly kind: "upsert"; readonly request: HttpWriteSpec; readonly batch: number }
  | {
      readonly kind: "create-or-update";
      readonly list: HttpListSpec;
      /** 一覧に無い名前(`entries` は `array` か `single` で、1 リクエスト 1 変数)。 */
      readonly create: HttpWriteSpec;
      /** 一覧にある名前(同上)。 */
      readonly update: HttpWriteSpec;
      /**
       * update のリクエストでは**変えられない**属性の守り: 導いたオプションが true なら、
       * 一覧の項目の `field` も true でなければ書かない(Netlify の `is_secret` — PATCH は
       * 値しか取らないので、非 secret の変数に secret のつもりの値を黙って置かない)。
       */
      readonly updateGuards?: readonly {
        readonly field: string;
        readonly option: string;
        /** 文面の末尾(何をすればよいか)。 */
        readonly hint: string;
      }[];
    };

/** A DELETE request of the lookup delete (by ID, or by name for a whole item). */
export interface HttpRemoveSpec {
  readonly method: "DELETE";
  readonly path: readonly PathToken[];
  readonly query: Readonly<Record<string, PathToken>>;
}

/** 削除の表現: 書き込みに同居(merge-patch の null)か、一覧で引いてから 1 件ずつ消す。 */
export type HttpDeleteSpec =
  | { readonly kind: "in-write" }
  | {
      readonly kind: "lookup";
      readonly list: HttpListSpec;
      /**
       * 同期先側の環境の照合(名前が同じでも別の環境のものを消さない): 項目(または
       * `valuesField` の配列の各要素)のうち、`targetField` が `targetOption` の値と一致
       * する(配列なら含む)もの、かつ `branchField` が `branchOption` の値(無ければ
       * 未設定)と一致するものの `idField` を消す。
       */
      readonly match: {
        /** 項目の中で id を持つ要素の入れ子(Netlify の `values[]`)。無ければ項目自身。 */
        readonly valuesField?: string;
        readonly idField: string;
        readonly targetField: string;
        readonly targetOption: string;
        readonly branchField: string;
        readonly branchOption: string;
      };
      readonly remove: HttpRemoveSpec;
      /**
       * 照合した要素が項目の**全要素**だったときに代わりに送る、項目ごとの削除
       * (Netlify: 他の context の値が無い変数は key ごと消し、空の変数を残さない)。
       */
      readonly removeItem?: HttpRemoveSpec;
    };

/** 応答の読み方(閉集合 — 追加はここに 1 つ足す)。 */
export type ResponseKind = "cloudflare-v4" | "vercel-env" | "netlify-env";

/** 展開済みオプション(設定の値 + `derive` の産物。配列は本文の葉にだけ使う)。 */
export type DerivedOptions = Readonly<Record<string, string | boolean | readonly string[]>>;

/** A declarative http preset (data — no per-vendor request code). */
export interface HttpPreset {
  /** 送る先(固定。設定では変えられない)。 */
  readonly host: string;
  /** 人間向けの呼び名(文面用 — "the Vercel API")。 */
  readonly label: string;
  readonly write: HttpWriteStrategy;
  readonly delete: HttpDeleteSpec;
  readonly response: ResponseKind;
  readonly constraints: ValueConstraints;
  readonly options: Readonly<Record<string, OptionSpec>>;
  /**
   * 設定のオプション同士の整合(1 オプションの型・閉集合は `options` の宣言が検査する)。
   * 不正なら理由(設定の検証文面になる。打たれた値は出さない)。
   */
  readonly check?: (options: ResolvedOptions) => string | null;
  /** 設定のオプションから導く値(スクリプト名・Vercel の type 等。値には触れない)。 */
  readonly derive: (options: ResolvedOptions) => DerivedOptions;
  /** 統合トークンの作り方の案内(エラー文面用。docs の節を指す)。 */
  readonly tokenHint: string;
}

const VERCEL_ENVIRONMENTS = ["production", "preview", "development"] as const;

// Vercel の 1 リクエストの件数上限は公開 docs に無い(CLI は 1 件ずつ)。総量の
// 上限(64 KB / deployment)には件数が効かないので、未知の上限に対して保守側に置く
const VERCEL_BATCH = 25;

// Netlify の deploy context(swagger の `context` の閉集合。`branch` は `branch` オプションの
// ブランチ名を `context_parameter` に取る)
const NETLIFY_CONTEXTS = [
  "production",
  "deploy-preview",
  "branch-deploy",
  "branch",
  "dev",
  "dev-server",
  "all",
] as const;

// secret を置けない context(docs「Secret values must be set to explicit deploy contexts」・
// CLI「specify a non-development context」。`dev-server` は CLI の SUPPORTED_CONTEXTS には
// あり secret の判定は `dev` を含む名前で見る = dev-server も不可)
const NETLIFY_NON_SECRET_CONTEXTS = new Set(["all", "dev", "dev-server"]);

// secret の変数は post_processing scope を持てない(docs の Secrets Controller)。netlify-cli
// は残りの 3 scope を明示して作る — 同じ形を写す(secret でなければ scopes を送らず
// Netlify の既定 = 全 scope に任せる。scope の選択は Pro 以上)
const NETLIFY_SECRET_SCOPES = ["builds", "functions", "runtime"] as const;

const NETLIFY_ENV_PATH: readonly PathToken[] = [
  "/api/v1/accounts/",
  { kind: "option", option: "accountId" },
  "/env",
];
const NETLIFY_KEY_PATH: readonly PathToken[] = [...NETLIFY_ENV_PATH, "/", { kind: "name" }];
const NETLIFY_SITE_QUERY = { site_id: { kind: "option", option: "siteId" } } as const;

/** Netlify の一覧(書き込みの有無判定と削除の id 照合が同じ一覧を読む)。 */
const NETLIFY_LIST: HttpListSpec = {
  path: NETLIFY_ENV_PATH,
  query: NETLIFY_SITE_QUERY,
  itemsField: null,
  keyField: "key",
};

/** Built-in http presets (the same first-class targets as the exec presets, plus Netlify). */
export const HTTP_PRESETS = {
  "cloudflare-workers": {
    host: "api.cloudflare.com",
    label: "the Cloudflare API",
    write: {
      kind: "upsert",
      batch: 100,
      request: {
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
    write: {
      kind: "upsert",
      batch: VERCEL_BATCH,
      request: {
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
        nextPage: ["pagination", "next"],
      },
      match: {
        idField: "id",
        targetField: "target",
        targetOption: "environment",
        branchField: "gitBranch",
        branchOption: "gitBranch",
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
  netlify: {
    host: "api.netlify.com",
    label: "the Netlify API",
    // Netlify に upsert は無い(POST = 新規、PATCH = 既存 key の 1 context の値)。一覧で
    // 名前の有無を引き、1 変数 1 リクエスト(配列 POST の部分失敗の形は docs に無いので
    // 件数を 1 に固定し、届いた名前を正確に割る)
    write: {
      kind: "create-or-update",
      list: NETLIFY_LIST,
      create: {
        method: "POST",
        path: NETLIFY_ENV_PATH,
        query: NETLIFY_SITE_QUERY,
        contentType: "application/json",
        body: { kind: "entries" },
        entries: "array",
        entry: {
          key: { kind: "name" },
          is_secret: { kind: "option", option: "isSecret" },
          scopes: { kind: "option", option: "scopes" },
          values: [
            {
              context: { kind: "option", option: "context" },
              context_parameter: { kind: "option", option: "branch" },
              value: { kind: "value" },
            },
          ],
        },
      },
      update: {
        method: "PATCH",
        path: NETLIFY_KEY_PATH,
        query: NETLIFY_SITE_QUERY,
        contentType: "application/json",
        body: { kind: "entries" },
        entries: "single",
        entry: {
          context: { kind: "option", option: "context" },
          context_parameter: { kind: "option", option: "branch" },
          value: { kind: "value" },
        },
      },
      // PATCH は is_secret を変えられない(前提 (1))。非 secret で既にある変数に secret の
      // つもりの値を置かない(pullfrog 指摘 — 改訂 1)
      updateGuards: [
        {
          field: "is_secret",
          option: "isSecret",
          hint: "Netlify cannot turn an existing variable into a secret through the request that sets one context's value. Mark it as secret in the Netlify dashboard, delete it there and apply again, or set \"secret\": false in the target's options",
        },
      ],
    },
    // 削除はこのターゲットの context の値だけ(`DELETE …/value/{id}`)。それが変数の最後の
    // 値なら key ごと消す(空の変数を残さない)。他の context の値には触れない
    delete: {
      kind: "lookup",
      list: NETLIFY_LIST,
      match: {
        valuesField: "values",
        idField: "id",
        targetField: "context",
        targetOption: "context",
        branchField: "context_parameter",
        branchOption: "branch",
      },
      remove: {
        method: "DELETE",
        path: [...NETLIFY_KEY_PATH, "/value/", { kind: "id" }],
        query: NETLIFY_SITE_QUERY,
      },
      removeItem: { method: "DELETE", path: NETLIFY_KEY_PATH, query: NETLIFY_SITE_QUERY },
    },
    response: "netlify-env",
    // 値の上限は 5,000 文字(docs)— 超過は API の失敗として文面に出る(黙って切らない)
    constraints: { maxBytes: null, nonEmpty: false, refuseSingleLineTrailingNewline: false },
    options: {
      accountId: { type: "string", required: true },
      siteId: { type: "string", required: true },
      context: { type: "string", required: true, values: NETLIFY_CONTEXTS },
      branch: { type: "string", required: false },
      secret: { type: "boolean", required: false },
    },
    check: (options) => {
      if (options["context"] === "branch" && typeof options["branch"] !== "string") {
        return "branch is required when context is branch (the branch name)";
      }
      if (options["context"] !== "branch" && options["branch"] !== undefined) {
        return "branch applies only when context is branch";
      }
      if (
        options["secret"] === true &&
        NETLIFY_NON_SECRET_CONTEXTS.has(String(options["context"]))
      ) {
        return `secret cannot be true when context is ${String(options["context"])} (Netlify keeps secret values out of the all and dev contexts)`;
      }
      return null;
    },
    // 既定は secret(Netlify 側で読み返せない値 — Vercel の sensitive と同じ向き)。secret を
    // 置けない context では既定を false に倒す。secret は post_processing scope を持てない
    // ので CLI と同じ 3 scope を明示する
    derive: (options) => {
      const isSecret =
        options["secret"] ?? !NETLIFY_NON_SECRET_CONTEXTS.has(String(options["context"]));
      return isSecret === true ? { isSecret, scopes: NETLIFY_SECRET_SCOPES } : { isSecret: false };
    },
    tokenHint:
      "a personal access token from the Netlify user settings (Applications, Personal access tokens; see the Deploy targets page in the docs)",
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

/** パスに載せてよい、リクエスト固有の材料(削除の ID・1 変数リクエストの名前)。 */
interface PathSubject {
  readonly id: string | null;
  readonly name: string | null;
}

const NO_SUBJECT: PathSubject = { id: null, name: null };

/** パス / クエリのトークンの展開(値は決して載らない — トークンの型に無い)。 */
function renderPathToken(
  token: PathToken,
  options: DerivedOptions,
  subject: PathSubject,
): string | undefined {
  if (typeof token === "string") {
    return token;
  }
  if (token.kind === "id" || token.kind === "name") {
    const value = subject[token.kind];
    if (value === null) {
      throw new Error(`preset uses a ${token.kind} token in a request that has none`);
    }
    return encodeURIComponent(value);
  }
  const value = options[token.option];
  return typeof value === "string" ? encodeURIComponent(value) : undefined;
}

/** パスの展開(必須オプションが無いのは宣言と検証の不整合 = 内部エラー)。 */
function renderPath(
  path: readonly PathToken[],
  options: DerivedOptions,
  subject: PathSubject,
): string {
  return path
    .map((token) => {
      const rendered = renderPathToken(token, options, subject);
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
  options: DerivedOptions,
): Readonly<Record<string, string>> {
  const params: Record<string, string> = {};
  for (const [key, token] of Object.entries(query)) {
    const rendered = renderPathToken(token, options, NO_SUBJECT);
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
  input: { readonly name: string; readonly text: string | null; readonly options: DerivedOptions },
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
  input: { readonly name: string; readonly text: string | null; readonly options: DerivedOptions },
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
  options: DerivedOptions,
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
export function resolveOptions(preset: HttpPreset, options: ResolvedOptions): DerivedOptions {
  return { ...options, ...preset.derive(options) };
}

/**
 * Splits writes (and, for presets whose delete rides along, deletes) into
 * batches: one request's worth for an upsert preset, and one batch holding
 * every write for a create-or-update preset (it lists the target once, then
 * sends one request per variable — reported together). Pure — nothing is
 * sent here.
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
  const size = preset.write.kind === "upsert" ? preset.write.batch : Math.max(1, items.length);
  for (let start = 0; start < items.length; start += size) {
    const chunk = items.slice(start, start + size);
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
  readonly options: DerivedOptions;
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
  if (batch.kind === "delete") {
    return { delivered: batch.names, failure: null };
  }
  if (!("created" in body)) {
    // 書き込みの 2xx に `created` が無い = 期待した形の応答でない(schema の変化・
    // 中継の応答)。届いたと読まない(pullfrog 指摘)
    return {
      delivered: [],
      failure: {
        names: batch.names,
        lines: scrubbed(
          [`HTTP ${outcome.status} without a created field (unexpected response shape)`],
          batch.writes,
          input.token,
        ),
      },
    };
  }
  const failed = recordsOf(body["failed"]);
  if (failed.length === 0) {
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

/** Netlify の非 2xx 応答(`{code, message}`)の表示行(本文が JSON でなければ status だけ)。 */
function netlifyErrorLines(status: number, body: unknown): string[] {
  return isRecord(body) && typeof body["message"] === "string"
    ? [`HTTP ${status}`, `error ${String(body["code"] ?? status)}: ${body["message"]}`]
    : [`HTTP ${status}`];
}

/**
 * Netlify の判定: 2xx。書き込み(POST = 配列 / PATCH = 1 変数)は応答の `key` が運んだ
 * 名前を含むことまで見る(形の違う 2xx を「届いた」と読まない — Vercel の `created` と
 * 同じ姿勢)。削除は 204 で本文が無い。応答は値を echo する(捨てる)。
 */
function readNetlify(
  outcome: HttpOutcome,
  batch: HttpBatch,
  input: HttpTargetInput,
): HttpRequestResult {
  const body = parseJson(outcome.text);
  const failure = (lines: readonly string[]): HttpRequestResult => ({
    delivered: [],
    failure: { names: batch.names, lines: scrubbed(lines, batch.writes, input.token) },
  });
  if (outcome.status < 200 || outcome.status >= 300) {
    return failure(netlifyErrorLines(outcome.status, body));
  }
  if (batch.kind === "delete") {
    return { delivered: batch.names, failure: null };
  }
  const keys = new Set(keysOf(Array.isArray(body) ? body : [body]));
  return batch.names.every((name) => keys.has(name))
    ? { delivered: batch.names, failure: null }
    : failure([
        `HTTP ${outcome.status} without the variable in the response (unexpected response shape)`,
      ]);
}

function readResponse(
  kind: ResponseKind,
  outcome: HttpOutcome,
  batch: HttpBatch,
  input: HttpTargetInput,
) {
  switch (kind) {
    case "cloudflare-v4":
      return readCloudflare(outcome, batch, input);
    case "vercel-env":
      return readVercel(outcome, batch, input);
    case "netlify-env":
      return readNetlify(outcome, batch, input);
  }
}

/**
 * 書き込みリクエストの組み立て(値はここで剥がして本文に置き、産物は送信にだけ渡す)。
 * `single` の宣言は 1 変数だけを受け、その名前がパスの name トークンに載る。
 */
function buildWriteRequest(
  input: HttpTargetInput,
  write: HttpWriteSpec,
  batch: HttpBatch,
): HttpClientRequest.HttpClientRequest {
  const single = write.entries === "single";
  if (single && batch.names.length !== 1) {
    throw new Error("a single-variable write was built for a batch of another size");
  }
  const entries = renderEntries(write, batch, input.options);
  const laid =
    write.entries === "object-by-name"
      ? Object.fromEntries(entries)
      : single
        ? entries[0]?.[1]
        : entries.map(([, entry]) => entry);
  const body = renderBody(write.body, laid, input.options);
  const subject: PathSubject = { id: null, name: single ? (batch.names[0] ?? null) : null };
  return HttpClientRequest.make(write.method)(
    `https://${input.preset.host}${renderPath(write.path, input.options, subject)}`,
    { urlParams: renderQuery(write.query, input.options) },
  ).pipe(HttpClientRequest.bodyText(JSON.stringify(body), write.contentType));
}

/** バッチのエントリ(書き込み + 同居する削除)を名前つきで展開する(値はここで剥がす)。 */
function renderEntries(
  write: HttpWriteSpec,
  batch: HttpBatch,
  options: DerivedOptions,
): (readonly [string, unknown])[] {
  const entries: (readonly [string, unknown])[] = [];
  for (const item of batch.writes) {
    // 剥がす理由: 本文のエントリの値の葉(値が maruhi を離れる直前。この産物は
    // リクエスト本文にしか流れず、失敗時の表示は応答から抽出して伏せた断片だけ)
    const text = decodeValueText(Redacted.value(item.value));
    if (text === null) {
      // prepareWork(sync-plan.ts)が送る前に弾いている前提の防衛線
      throw new Error("a value that is not valid UTF-8 reached the http driver");
    }
    entries.push([item.name, renderEntry(write.entry, { name: item.name, text, options })]);
  }
  for (const name of batch.deletes) {
    if (write.deletedEntry === undefined) {
      throw new Error("a delete rode along on a preset that has no deleted entry");
    }
    entries.push([name, renderEntry(write.deletedEntry, { name, text: null, options })]);
  }
  return entries;
}

/** 一覧の読み(項目の配列と完全性)。失敗なら伏せ字化済みの行。 */
type Listing =
  | { readonly items: readonly Record<string, unknown>[]; readonly complete: boolean }
  | { readonly failure: readonly string[] };

/**
 * 一覧を 1 回読む(値は読まずに捨てる — 名前と ID の突合にだけ使う)。続きのページが
 * あるかも返す(続きがあれば「無い」を証拠にしない — fail-closed)。
 */
function fetchListing(
  input: HttpTargetInput,
  spec: HttpListSpec,
): Effect.Effect<Listing, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const request = HttpClientRequest.get(
      `https://${input.preset.host}${renderPath(spec.path, input.options, NO_SUBJECT)}`,
      { urlParams: renderQuery(spec.query, input.options) },
    );
    const outcome = yield* send(input, request);
    const body = parseJson(outcome.text);
    const listed: unknown =
      spec.itemsField === null ? body : isRecord(body) ? body[spec.itemsField] : undefined;
    if (outcome.status < 200 || outcome.status >= 300 || !Array.isArray(listed)) {
      return {
        failure: scrubbed(
          [`HTTP ${outcome.status} while listing variables at the target`],
          [],
          input.token,
        ),
      };
    }
    return { items: listed.filter(isRecord), complete: isListingComplete(spec, body) };
  });
}

/** 続きのページが無いか(Vercel の `pagination.next`。宣言が無い / null = 一覧は完全)。 */
function isListingComplete(spec: HttpListSpec, body: unknown): boolean {
  if (spec.nextPage === undefined || !isRecord(body)) {
    return true;
  }
  const [pageField, nextField] = spec.nextPage;
  const pagination = body[pageField];
  const next = isRecord(pagination) ? pagination[nextField] : undefined;
  return next === undefined || next === null || next === false;
}

/** 一覧の項目を名前で引ける形に(文字列の `keyField` を持つものだけ)。 */
function listedByKey(
  items: readonly Record<string, unknown>[],
  keyField: string,
): Map<string, Record<string, unknown>> {
  const byKey = new Map<string, Record<string, unknown>>();
  for (const item of items) {
    const key = item[keyField];
    if (typeof key === "string") {
      byKey.set(key, item);
    }
  }
  return byKey;
}

/**
 * update で変えられない属性の守り(`updateGuards`): 破っていれば文面(変数名と属性名
 * だけ。値は載らない)、守れていれば null。
 */
function guardUpdate(
  write: Extract<HttpWriteStrategy, { kind: "create-or-update" }>,
  name: string,
  item: Record<string, unknown>,
  options: DerivedOptions,
): string | null {
  for (const guard of write.updateGuards ?? []) {
    if (options[guard.option] === true && item[guard.field] !== true) {
      return `${displayText(name)} already exists at the target with ${guard.field} off, and the config asks for it on. ${guard.hint}`;
    }
  }
  return null;
}

/** 削除の照合: 要素が「このターゲットの環境」のものか(名前が同じでも別の環境は消さない)。 */
function matchesTarget(
  element: Record<string, unknown>,
  match: Extract<HttpDeleteSpec, { kind: "lookup" }>["match"],
  options: DerivedOptions,
): boolean {
  const target = options[match.targetOption];
  const branch = options[match.branchOption];
  const targets = element[match.targetField];
  const elementBranch = element[match.branchField];
  const targetMatches = Array.isArray(targets) ? targets.includes(target) : targets === target;
  const branchMatches =
    typeof branch === "string"
      ? elementBranch === branch
      : elementBranch === undefined || elementBranch === null;
  return targetMatches && branchMatches;
}

/**
 * 削除の 1 手目: 一覧で同期先側の ID を引く。`whole` = 照合した要素が、その名前の
 * 項目の全要素だった(項目ごと消してよい — `removeItem` のあるプリセットだけが使う)。
 */
function lookupIds(
  items: readonly Record<string, unknown>[],
  spec: Extract<HttpDeleteSpec, { kind: "lookup" }>,
  name: string,
  options: DerivedOptions,
): { readonly ids: readonly string[]; readonly whole: boolean } {
  const ids: string[] = [];
  let matchedItems = 0;
  let wholeItems = 0;
  for (const item of items.filter((entry) => entry[spec.list.keyField] === name)) {
    const { valuesField } = spec.match;
    const elements = valuesField === undefined ? [item] : recordsOf(item[valuesField]);
    const hits = elements.filter((element) => matchesTarget(element, spec.match, options));
    if (hits.length === 0) {
      continue;
    }
    matchedItems += 1;
    if (valuesField !== undefined && hits.length === elements.length) {
      wholeItems += 1;
    }
    for (const hit of hits) {
      const id = hit[spec.match.idField];
      if (typeof id === "string") {
        ids.push(id);
      }
    }
  }
  return { ids, whole: matchedItems > 0 && wholeItems === matchedItems };
}

/** 1 変数だけのバッチ(create-or-update の各手に readResponse を通す形)。 */
function singleBatch(write: SyncWrite): HttpBatch {
  return { kind: "write", names: [write.name], writes: [write], deletes: [] };
}

/**
 * create-or-update の書き込み: 一覧で名前の有無を引き、無い名前は create・ある名前は
 * update を 1 変数ずつ送る。最初の失敗で止め、届いた名前を返す(一覧と送信の間に
 * 同名が作られれば create が同期先の失敗として出る — 次の apply は update になる)。
 */
function createOrUpdate(
  input: HttpTargetInput,
  write: Extract<HttpWriteStrategy, { kind: "create-or-update" }>,
  batch: HttpBatch,
): Effect.Effect<HttpRequestResult, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const listing = yield* fetchListing(input, write.list);
    if ("failure" in listing) {
      return { delivered: [], failure: { names: batch.names, lines: listing.failure } };
    }
    if (!listing.complete) {
      // 続きがあるのに一覧で判定すると、既にある名前を create して失敗する(または
      // 同期先の規則で二重に作る)。何も送らずに止める
      return {
        delivered: [],
        failure: {
          names: batch.names,
          lines: [
            `${input.preset.label} returned a paginated list of variables, so maruhi could not tell which of them already exist at the target. Nothing was written; apply again later`,
          ],
        },
      };
    }
    return yield* writeOneByOne(
      input,
      write,
      batch,
      listedByKey(listing.items, write.list.keyField),
    );
  });
}

/** create-or-update の送信部: 1 変数ずつ、最初の失敗で止める。 */
function writeOneByOne(
  input: HttpTargetInput,
  write: Extract<HttpWriteStrategy, { kind: "create-or-update" }>,
  batch: HttpBatch,
  existing: ReadonlyMap<string, Record<string, unknown>>,
): Effect.Effect<HttpRequestResult, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const delivered: string[] = [];
    for (const item of batch.writes) {
      const one = singleBatch(item);
      const listed = existing.get(item.name);
      // 1 変数の送信が型付きエラーで落ちても(試行の使い切り・Retry-After 超過)、この
      // バッチで先に届いた名前を失わない: その変数の失敗として報告し、届いた分はレシートへ
      // (create-or-update は書き込み全部が 1 バッチなので、落とすと実行全体の進みが消える —
      // pullfrog 指摘・改訂 4)
      const result = yield* (
        listed === undefined
          ? createOrRecover(input, write, one)
          : updateOne(input, write, one, listed)
      ).pipe(
        Effect.catch((error: CliError) =>
          Effect.succeed({ delivered: [], failure: { names: one.names, lines: [error.message] } }),
        ),
      );
      if (result.failure !== null) {
        return { delivered, failure: result.failure };
      }
      delivered.push(item.name);
    }
    return { delivered, failure: null };
  });
}

/** 一覧にある名前: 守り(`updateGuards`)を通してから update を 1 件送る。 */
function updateOne(
  input: HttpTargetInput,
  write: Extract<HttpWriteStrategy, { kind: "create-or-update" }>,
  one: HttpBatch,
  listed: Record<string, unknown>,
): Effect.Effect<HttpRequestResult, CliError, HttpClient.HttpClient> {
  const refused = guardUpdate(write, one.names[0] ?? "", listed, input.options);
  if (refused !== null) {
    // 送らずに止める(値は残らない。届いた分はレシートへ)
    return Effect.succeed({ delivered: [], failure: { names: one.names, lines: [refused] } });
  }
  return Effect.map(send(input, buildWriteRequest(input, write.update, one)), (outcome) =>
    readResponse(input.preset.response, outcome, one, input),
  );
}

/**
 * 一覧に無い名前: create を送る。create は upsert でない(既存 key を拒む)ので、届いた
 * のに応答が失われて再送された形(`send` のリトライ)や、一覧と送信の間に同名が作られた
 * 競合では、同期先の失敗として返る。そのときは**一覧を引き直し**、名前があれば update に
 * 切り替える(応答の文言に依らない — Bugbot 指摘・改訂 2)。無ければ create の失敗をそのまま。
 */
function createOrRecover(
  input: HttpTargetInput,
  write: Extract<HttpWriteStrategy, { kind: "create-or-update" }>,
  one: HttpBatch,
): Effect.Effect<HttpRequestResult, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const outcome = yield* send(input, buildWriteRequest(input, write.create, one));
    const created = readResponse(input.preset.response, outcome, one, input);
    if (created.failure === null) {
      return created;
    }
    // 引き直しの一覧が失敗しても(通信層・試行の使い切り = 型付きエラー)create の失敗の
    // 報告に戻す: ここで落とすと、同じバッチで先に届いた名前がレシートに残らない(Bugbot 指摘)
    const listing = yield* fetchListing(input, write.list).pipe(
      Effect.catch((error: CliError) => Effect.succeed({ failure: [error.message] })),
    );
    if ("failure" in listing) {
      return withRecheckFailure(created, listing.failure);
    }
    if (!listing.complete) {
      return created;
    }
    const listed = listedByKey(listing.items, write.list.keyField).get(one.names[0] ?? "");
    return listed === undefined ? created : yield* updateOne(input, write, one, listed);
  });
}

/** create の失敗に、引き直しの一覧の失敗(伏せ字化済みの行)を添える。 */
function withRecheckFailure(
  created: HttpRequestResult,
  lines: readonly string[],
): HttpRequestResult {
  return created.failure === null
    ? created
    : {
        delivered: created.delivered,
        failure: {
          names: created.failure.names,
          lines: [
            ...created.failure.lines,
            `Could not re-check the target after the failed create: ${lines.join(" ")}`,
          ],
        },
      };
}

/**
 * Runs one batch against the vendor API: the write request(s), or the
 * lookup-then-delete pair for presets whose delete does not ride along.
 */
export function runBatch(
  input: HttpTargetInput,
  batch: HttpBatch,
): Effect.Effect<HttpRequestResult, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    if (batch.kind === "write") {
      const { write } = input.preset;
      if (write.kind === "create-or-update") {
        return yield* createOrUpdate(input, write, batch);
      }
      const outcome = yield* send(input, buildWriteRequest(input, write.request, batch));
      return readResponse(input.preset.response, outcome, batch, input);
    }
    const spec = input.preset.delete;
    if (spec.kind !== "lookup") {
      throw new Error("a delete batch was built for a preset whose deletes ride along");
    }
    return yield* lookupAndRemove(input, spec, batch);
  });
}

/** 削除バッチ(1 名前): 一覧で ID を引き、値ごと(または項目ごと)に消す。 */
function lookupAndRemove(
  input: HttpTargetInput,
  spec: Extract<HttpDeleteSpec, { kind: "lookup" }>,
  batch: HttpBatch,
): Effect.Effect<HttpRequestResult, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const name = batch.names[0] ?? "";
    const listing = yield* fetchListing(input, spec.list);
    if ("failure" in listing) {
      return { delivered: [], failure: { names: batch.names, lines: listing.failure } };
    }
    const looked = lookupIds(listing.items, spec, name, input.options);
    if (looked.ids.length === 0 && !listing.complete) {
      // 一覧に続きがあるのに名前が無い: 「消えている」とは言えない。届いたと記録せず
      // レシートに残す(次の apply が再び試す — pullfrog 指摘。fail-closed)
      return {
        delivered: [],
        failure: {
          names: batch.names,
          lines: [
            `${input.preset.label} returned a paginated list of variables, so maruhi could not confirm that ${displayText(name)} is gone from the target. It stays in the receipt; remove it at the target yourself, or apply again`,
          ],
        },
      };
    }
    // 完全な一覧に無い = 同期先で既に消えている(読み戻しは ID の突合だけで、値は読まない)
    if (looked.whole && spec.removeItem !== undefined) {
      return yield* removeOne(input, spec.removeItem, batch, { id: null, name });
    }
    return yield* removeByIds(input, spec, batch, name, looked.ids);
  });
}

/** 削除の 2 手目: 引いた ID を 1 件ずつ DELETE(404 = 一覧の直後に並行して消された)。 */
function removeByIds(
  input: HttpTargetInput,
  spec: Extract<HttpDeleteSpec, { kind: "lookup" }>,
  batch: HttpBatch,
  name: string,
  ids: readonly string[],
): Effect.Effect<HttpRequestResult, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    for (const id of ids) {
      const result = yield* removeOne(input, spec.remove, batch, { id, name });
      if (result.failure !== null) {
        return result;
      }
    }
    return { delivered: batch.names, failure: null };
  });
}

/** DELETE 1 件(ID か名前で)。404 は「既に消えている」= 成功扱い。 */
function removeOne(
  input: HttpTargetInput,
  spec: HttpRemoveSpec,
  batch: HttpBatch,
  subject: PathSubject,
): Effect.Effect<HttpRequestResult, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const request = HttpClientRequest.make(spec.method)(
      `https://${input.preset.host}${renderPath(spec.path, input.options, subject)}`,
      { urlParams: renderQuery(spec.query, input.options) },
    );
    const outcome = yield* send(input, request);
    return outcome.status === 404
      ? { delivered: batch.names, failure: null }
      : readResponse(input.preset.response, outcome, batch, input);
  });
}

/**
 * ヘッダー値に載らない文字を含むか: C0 制御文字(改行を含む)・DEL・ISO-8859-1 の
 * 外(fetch の `Headers` が TypeError で拒む — 型付きエラーにする)。
 */
function hasNonHeaderCharacter(text: string): boolean {
  for (const character of text) {
    const code = character.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f || code > 0xff) {
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
  if (hasNonHeaderCharacter(text)) {
    return cliError(
      `The token variable ${displayText(name)} contains a newline, a control character, or a character outside ISO-8859-1, so it cannot be sent as an Authorization header. Push the token without a trailing newline (\`printf %s\` instead of \`echo\`)`,
    );
  }
  return text;
}
