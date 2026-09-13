// 裏付け元 `github-signing-keys`(CRYPTO_SPEC §6.5 — IV2)。
//
// 相手(受諾者 / 招待者)の maruhi sig 公開鍵が、名指しした GitHub login の
// **SSH 署名鍵**一覧に含まれるかを、GitHub の公開 API で機械照合する。
//
// 不変条件:
// - 送る情報は **login だけ**(プロジェクト・鍵・値・利用状況を送らない)。
//   ホストは `api.github.com` 固定で、設定で差し替える口は持たない(テストの
//   差し替えは HttpClient の層 — sync-http.ts と同じ線引き)
// - 認証なし(maruhi CLI は GitHub のトークンを一切持たない — AUTH_SPEC §4)
// - **fail-closed**: 照合の**失敗**(鍵が無い)も**不能**(取得できない・上限・
//   オフライン・login 不明)も「儀式へ戻る」以上の効果を持たない。裏付け元は
//   儀式を**省く**根拠にしかならず、拒否の根拠にも免除の根拠にもならない。
//   よってこのモジュールは CliError を返さず、結果を閉じた型で返す
// - 応答は第三者データとして扱う: 形の検査は Effect Schema、鍵行の解析は
//   `packages/crypto` の parseOpenSshEd25519PublicKey(テストベクター固定)。
//   `ssh-ed25519` 以外の種別は照合対象外として読み飛ばす

import { decodeHex, encodeHex, parseOpenSshEd25519PublicKey } from "@maruhi/crypto";
import { Duration, Effect, Schema } from "effect";
import { HttpClient, HttpClientRequest } from "effect/unstable/http";

import { GITHUB_LOGIN } from "./invite-link.ts";
import { CLI_VERSION } from "./version.ts";

/** 固定ホスト(差し替え不可)。 */
const GITHUB_API_ORIGIN = "https://api.github.com";

/** 1 回の問い合わせに許す時間(照合は「省く根拠」なので長く待たない)。 */
const REQUEST_TIMEOUT = Duration.seconds(10);

/** GitHub の `GET /users/{login}/ssh_signing_keys` の 1 要素(必要な欄だけ)。 */
const SigningKeyEntry = Schema.Struct({ key: Schema.String });
const SigningKeysResponse = Schema.Array(SigningKeyEntry);
const decodeSigningKeys = Schema.decodeUnknownEffect(SigningKeysResponse);

/** 照合の結果(閉じた型 — 呼び出し側が儀式へ戻るか否かを決める)。 */
export type BackingVerdict =
  /** 名指しした login の署名鍵一覧に、対象の sig 公開鍵がバイト一致で含まれる。 */
  | { readonly kind: "match" }
  /** 一覧は取れたが、対象の鍵が無い(相手が未登録 / 別の鍵を登録)。 */
  | { readonly kind: "not-registered" }
  /** login が GitHub に存在しない(404)。 */
  | { readonly kind: "no-user" }
  /** 取得できない(オフライン・上限・応答の形が違う)。理由は表示用の短文。 */
  | { readonly kind: "unavailable"; readonly detail: string };

/** 一覧の取得結果(照合の前段 — 鍵行はまだ解析していない)。 */
type SigningKeysFetch =
  | { readonly kind: "entries"; readonly entries: readonly { readonly key: string }[] }
  | { readonly kind: "no-user" }
  | { readonly kind: "unavailable"; readonly detail: string };

/** `GET /users/{login}/ssh_signing_keys`(無認証・固定ホスト・タイムアウトつき)。 */
function fetchSigningKeys(
  login: string,
): Effect.Effect<SigningKeysFetch, never, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const client = yield* HttpClient.HttpClient;
    const request = HttpClientRequest.get(
      `${GITHUB_API_ORIGIN}/users/${encodeURIComponent(login)}/ssh_signing_keys`,
    ).pipe(
      HttpClientRequest.setHeader("accept", "application/vnd.github+json"),
      HttpClientRequest.setHeader("user-agent", `maruhi-cli/${CLI_VERSION}`),
    );
    const outcome = yield* client.execute(request).pipe(
      Effect.flatMap((response) =>
        Effect.map(response.text, (text) => ({ status: response.status, text })),
      ),
      Effect.timeout(REQUEST_TIMEOUT),
      Effect.map((value) => ({ ok: true, value }) as const),
      // 通信層の失敗・タイムアウト: 本文・ヘッダーは持ち込まない(短い種別だけ)
      Effect.catch((error) =>
        Effect.succeed({ ok: false, detail: describeFailure(error) } as const),
      ),
    );
    if (!outcome.ok) {
      return { kind: "unavailable", detail: outcome.detail } as const;
    }
    const { status, text } = outcome.value;
    if (status === 404) {
      return { kind: "no-user" } as const;
    }
    if (status !== 200) {
      const rateLimited = status === 403 || status === 429 ? " (rate limited)" : "";
      return {
        kind: "unavailable",
        detail: `github.com answered ${status}${rateLimited}`,
      } as const;
    }
    const entries = yield* parseEntries(text);
    return entries === null
      ? ({ kind: "unavailable", detail: "github.com's response had an unexpected shape" } as const)
      : ({ kind: "entries", entries } as const);
  });
}

/** 一覧の中に対象の Ed25519 鍵がバイト一致で含まれるか(ssh-ed25519 以外は読み飛ばす)。 */
function containsSigningKey(
  entries: readonly { readonly key: string }[],
  targetHex: string,
): boolean {
  return entries.some((entry) => {
    const parsed = parseOpenSshEd25519PublicKey(entry.key);
    // ssh-ed25519 以外(RSA / ECDSA / sk-*)や壊れた行は照合対象外
    return parsed.ok && encodeHex(parsed.value) === targetHex;
  });
}

/**
 * login の署名鍵一覧に `sigPubHex` の鍵が含まれるかを照合する。失敗も不能も
 * 型で返し、決して CliError にしない(上記の fail-closed 定義)。
 */
export function checkSigningKeyBacking(input: {
  readonly login: string;
  readonly sigPubHex: string;
}): Effect.Effect<BackingVerdict, never, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    if (!GITHUB_LOGIN.test(input.login)) {
      return { kind: "unavailable", detail: "the login is not a valid GitHub login" } as const;
    }
    const target = decodeHex(input.sigPubHex);
    if (target === null) {
      return { kind: "unavailable", detail: "the signing key to check is malformed" } as const;
    }
    const fetched = yield* fetchSigningKeys(input.login);
    if (fetched.kind !== "entries") {
      return fetched;
    }
    return containsSigningKey(fetched.entries, encodeHex(target))
      ? ({ kind: "match" } as const)
      : ({ kind: "not-registered" } as const);
  });
}

/** 応答本文の解釈(JSON 配列 + `key` 文字列。形が違えば null)。 */
function parseEntries(text: string): Effect.Effect<readonly { readonly key: string }[] | null> {
  return Effect.gen(function* () {
    let json: unknown;
    try {
      json = JSON.parse(text);
    } catch {
      return null;
    }
    return yield* decodeSigningKeys(json).pipe(
      Effect.map((entries) => entries as readonly { readonly key: string }[]),
      Effect.catch(() => Effect.succeed(null)),
    );
  });
}

/** 通信層の失敗の説明(種別だけ。本文・ヘッダー・URL は含めない)。 */
function describeFailure(error: unknown): string {
  const tag =
    typeof error === "object" && error !== null
      ? (error as Record<string, unknown>)["_tag"]
      : undefined;
  if (tag === "TimeoutError") {
    return "github.com did not answer in time";
  }
  return typeof tag === "string"
    ? `could not reach github.com (${tag})`
    : "could not reach github.com";
}

/** 照合結果の表示用の短文(儀式へ戻る理由の提示)。 */
export function describeBackingFallback(login: string, verdict: BackingVerdict): string {
  switch (verdict.kind) {
    case "match":
      return `the key is registered as a signing key on github.com/${login}`;
    case "not-registered":
      return `the key is not registered as a signing key on github.com/${login}`;
    case "no-user":
      return `github.com has no user named ${login}`;
    case "unavailable":
      return `the signing keys of github.com/${login} could not be fetched (${verdict.detail})`;
  }
}
