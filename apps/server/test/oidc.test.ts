// OIDC 検証と JWKS キャッシュ(AUTH_SPEC §14-1)の単体テスト。
//
// リースの統合テスト(lease.test.ts)が実経路の判定順を固定するのに対し、
// ここは「実経路では作りにくい状況」を固定する:
//   - JWKS が取得できない = 署名検証を実行できないときの fail-closed と、
//     その応答が 401 ではなく 503 `oidc-jwks-unavailable` であること
//   - TTL 内の再利用 / 未知 kid の強制リフレッシュ / クールダウン(鍵ローテーション追随)
//   - discovery ドキュメントの自己申告検査(issuer 一致・jwks_uri の同一オリジン)
//
// fetch はテスト内で差し替えて呼び出し回数を数える(実ネットワークへは出ない)。

import { Effect } from "effect";
import { afterEach, describe, expect, it } from "vitest";

import { makeJwksCache, makeOidcVerifier } from "../src/oidc.package/index.ts";
import { makeOidcToken } from "./support/lease.ts";
import { OIDC_DISCOVERY, OIDC_ISSUER, OIDC_JWKS, OIDC_KID } from "./support/oidc-issuer.ts";

const realFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = realFetch;
});

interface FetchLog {
  readonly urls: string[];
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/**
 * discovery / JWKS を返す fetch スタブ。`jwks` を差し替えると鍵ローテーションを、
 * `failJwks` を立てると issuer 側の障害を模せる。
 */
function stubFetch(
  options: {
    readonly jwks?: () => unknown;
    readonly failJwks?: () => boolean;
    readonly discovery?: unknown;
  } = {},
): FetchLog {
  const log: FetchLog = { urls: [] };
  globalThis.fetch = ((input: RequestInfo | URL) => {
    const url = String(input);
    log.urls.push(url);
    if (url.endsWith("/.well-known/openid-configuration")) {
      return Promise.resolve(json(options.discovery ?? OIDC_DISCOVERY));
    }
    if (url.endsWith("/.well-known/jwks")) {
      return options.failJwks?.() === true
        ? Promise.resolve(new Response("boom", { status: 503 }))
        : Promise.resolve(json(options.jwks?.() ?? OIDC_JWKS));
    }
    return Promise.resolve(new Response("unexpected", { status: 500 }));
  }) as typeof fetch;
  return log;
}

/** 成否をタグ付き値に畳む(Effect v4 beta には Effect.either がない)。 */
const run = <A, E>(effect: Effect.Effect<A, E>) =>
  Effect.runPromise(
    Effect.match(effect, {
      onSuccess: (value: A) => ({ ok: true as const, value }),
      onFailure: (error: E) => ({ ok: false as const, error }),
    }),
  );

describe("JWKS キャッシュ(§14-1)", () => {
  it("caches the discovery document and the JWKS across calls", async () => {
    const log = stubFetch();
    const cache = makeJwksCache();
    for (let index = 0; index < 3; index += 1) {
      const resolved = await Effect.runPromise(cache.resolveKey(OIDC_ISSUER, OIDC_KID));
      expect(resolved).not.toBeNull();
    }
    // 3 回の解決で往復は discovery 1 + JWKS 1 のみ(TTL 内は再利用)
    expect(log.urls.length).toBe(2);
  });

  it("force-refreshes once for an unknown kid, then respects the cooldown", async () => {
    let rotated = false;
    const log = stubFetch({
      jwks: () => (rotated ? { keys: [{ ...OIDC_JWKS.keys[0], kid: "rotated-in" }] } : OIDC_JWKS),
    });
    let currentMs = 1_000_000;
    const cache = makeJwksCache(() => currentMs);

    // 既知 kid で温める(discovery + JWKS)
    expect(await Effect.runPromise(cache.resolveKey(OIDC_ISSUER, OIDC_KID))).not.toBeNull();
    const afterWarmup = log.urls.length;

    // issuer 側で鍵がローテーションされた。未知 kid は 1 回だけ取り直す
    rotated = true;
    expect(await Effect.runPromise(cache.resolveKey(OIDC_ISSUER, "rotated-in"))).not.toBeNull();
    expect(log.urls.length).toBe(afterWarmup + 1);

    // クールダウン内の未知 kid は取り直さない(存在しない kid の連打で
    // issuer を叩き続けない)
    const afterRefresh = log.urls.length;
    expect(await Effect.runPromise(cache.resolveKey(OIDC_ISSUER, "never-existed"))).toBeNull();
    expect(log.urls.length).toBe(afterRefresh);

    // クールダウンを越えればもう一度だけ取り直す
    currentMs += 61_000;
    expect(await Effect.runPromise(cache.resolveKey(OIDC_ISSUER, "still-missing"))).toBeNull();
    expect(log.urls.length).toBe(afterRefresh + 1);
  });

  it("rejects a discovery document whose issuer does not match the requested issuer", async () => {
    stubFetch({ discovery: { ...OIDC_DISCOVERY, issuer: "https://evil.example" } });
    const result = await run(makeJwksCache().resolveKey(OIDC_ISSUER, OIDC_KID));
    expect(result.ok).toBe(false);
  });

  it("rejects a jwks_uri on another origin (key provenance is pinned to the issuer)", async () => {
    stubFetch({
      discovery: { ...OIDC_DISCOVERY, jwks_uri: "https://cdn.evil.example/.well-known/jwks" },
    });
    const result = await run(makeJwksCache().resolveKey(OIDC_ISSUER, OIDC_KID));
    expect(result.ok).toBe(false);
  });

  it("keeps a TTL-valid document — and advances the cooldown — when a forced refresh fails", async () => {
    let failing = false;
    const log = stubFetch({ failJwks: () => failing });
    const cache = makeJwksCache();

    // 既知 kid で温める(discovery + JWKS)
    expect(await Effect.runPromise(cache.resolveKey(OIDC_ISSUER, OIDC_KID))).not.toBeNull();

    // issuer 側の障害中に未知 kid(攻撃者が自由に指定できる)が強制
    // リフレッシュを誘発しても、TTL 内の旧ドキュメントを失わない:
    // 未知 kid は 401(null)、既知 kid は 503 に落ちず検証できたまま
    failing = true;
    expect(await Effect.runPromise(cache.resolveKey(OIDC_ISSUER, "never-existed"))).toBeNull();
    expect(await Effect.runPromise(cache.resolveKey(OIDC_ISSUER, OIDC_KID))).not.toBeNull();
    // 失敗した強制リフレッシュもクールダウンの起点になる(issuer を叩き続けない)
    const afterFailure = log.urls.length;
    expect(await Effect.runPromise(cache.resolveKey(OIDC_ISSUER, "still-missing"))).toBeNull();
    expect(log.urls.length).toBe(afterFailure);
  });

  it("does not cache a failed fetch permanently (retries once the cooldown lapses)", async () => {
    let failing = true;
    const log = stubFetch({ failJwks: () => failing });
    let currentMs = 1_000_000;
    const cache = makeJwksCache(() => currentMs);
    expect((await run(cache.resolveKey(OIDC_ISSUER, OIDC_KID))).ok).toBe(false);

    // good 値が無い状態でも失敗クールダウン中は叩き直さない(cold + issuer 障害
    // でも「1 リクエスト = 1 fetch」にしない)。この間は即座に失敗する
    failing = false;
    expect((await run(cache.resolveKey(OIDC_ISSUER, OIDC_KID))).ok).toBe(false);
    expect(log.urls.filter((url) => url.endsWith("/jwks")).length).toBe(1);

    // クールダウン明けには取り直し、失敗が居座っていないことが確かめられる
    currentMs += 61_000;
    expect(await Effect.runPromise(cache.resolveKey(OIDC_ISSUER, OIDC_KID))).not.toBeNull();
    expect(log.urls.filter((url) => url.endsWith("/jwks")).length).toBe(2);
  });

  it("serves the last good JWKS while a refresh keeps failing (stale-while-revalidate)", async () => {
    let failing = false;
    stubFetch({ failJwks: () => failing });
    let currentMs = 1_000_000;
    const cache = makeJwksCache(() => currentMs);
    expect(await Effect.runPromise(cache.resolveKey(OIDC_ISSUER, OIDC_KID))).not.toBeNull();

    // TTL(15 分)を越え、かつ issuer が落ちている状態
    failing = true;
    currentMs += 20 * 60 * 1000;
    expect(await Effect.runPromise(cache.resolveKey(OIDC_ISSUER, OIDC_KID))).not.toBeNull();

    // 猶予窓(6 時間)を越えたら、もう受理しない
    currentMs += 6 * 60 * 60 * 1000;
    expect((await run(cache.resolveKey(OIDC_ISSUER, OIDC_KID))).ok).toBe(false);
  });

  it("does not re-fetch on every request while the issuer stays down (増幅の遮断)", async () => {
    // TTL 切れ + issuer 障害では `isUsable` が TTL の分岐で false を返し、
    // 強制リフレッシュのクールダウンには到達しない。失敗側に独立の間隔が
    // ないと、猶予窓の残り(最長 6 時間弱)にわたって「未認証リクエスト 1 本 =
    // 外向き fetch 1 回」が続く(pullfrog 指摘 — PR #65)
    let failing = false;
    const log = stubFetch({ failJwks: () => failing });
    let currentMs = 1_000_000;
    const cache = makeJwksCache(() => currentMs);
    expect(await Effect.runPromise(cache.resolveKey(OIDC_ISSUER, OIDC_KID))).not.toBeNull();

    // TTL(15 分)を越え、issuer が落ちる
    failing = true;
    currentMs += 20 * 60 * 1000;
    expect(await Effect.runPromise(cache.resolveKey(OIDC_ISSUER, OIDC_KID))).not.toBeNull();
    const afterFirstFailure = log.urls.length;

    // 障害中の後続リクエストは stale で応じ、issuer を叩き直さない
    for (let attempt = 0; attempt < 5; attempt += 1) {
      expect(await Effect.runPromise(cache.resolveKey(OIDC_ISSUER, OIDC_KID))).not.toBeNull();
    }
    expect(log.urls.length).toBe(afterFirstFailure);

    // クールダウン(60 秒)明けには 1 回だけ再試行し、復旧を拾う
    currentMs += 61_000;
    failing = false;
    expect(await Effect.runPromise(cache.resolveKey(OIDC_ISSUER, OIDC_KID))).not.toBeNull();
    expect(log.urls.length).toBe(afterFirstFailure + 1);
  });

  it("aborts a hanging JWKS fetch instead of holding the request open", async () => {
    // 未認証経路から誘発される外部 fetch なので、応答しない issuer に
    // リクエストを張り付かせない(AbortSignal.timeout)
    globalThis.fetch = ((_input: RequestInfo | URL, init?: RequestInit) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => {
          reject(new Error("aborted"));
        });
      })) as typeof fetch;
    const result = await run(makeJwksCache().resolveKey(OIDC_ISSUER, OIDC_KID));
    expect(result.ok).toBe(false);
  }, 20_000);
});

const nowMs = (): number => Date.now();

describe("OIDC verifier(§14-1)", () => {
  it("fails closed with 503 oidc-jwks-unavailable when the JWKS cannot be fetched", async () => {
    stubFetch({ failJwks: () => true });
    const verifier = makeOidcVerifier(makeJwksCache());
    const result = await run(verifier.verify(await makeOidcToken(), nowMs()));
    expect(result.ok).toBe(false);
    // 一過性の障害を「資格情報が不正(401)」と伝えない — CI ジョブが
    // リトライ不能な失敗として扱ってしまうため(errors/lease.ts)
    expect(result.ok === false && result.error).toMatchObject({
      _tag: "LeaseUnavailable",
      reason: "oidc-jwks-unavailable",
    });
  });

  it("checks the issuer allowlist before any outbound fetch (未認証面からの増幅の遮断)", async () => {
    const log = stubFetch();
    const verifier = makeOidcVerifier(makeJwksCache());
    const result = await run(
      verifier.verify(await makeOidcToken({ issuer: "https://evil.example" }), nowMs()),
    );
    expect(result.ok === false && result.error).toMatchObject({ reason: "unsupported-issuer" });
    // 許可リスト外の issuer では 1 度も外へ出ない
    expect(log.urls.length).toBe(0);
  });

  it("accepts an array `aud` (RFC 7519) and normalizes it", async () => {
    stubFetch();
    const verifier = makeOidcVerifier(makeJwksCache());
    const token = await makeOidcToken({ audience: ["https://a.example", "https://b.example"] });
    const result = await run(verifier.verify(token, nowMs()));
    expect(result.ok).toBe(true);
    expect(result.ok === true && result.value.audiences).toEqual([
      "https://a.example",
      "https://b.example",
    ]);
  });

  it("accepts a token at the edge of the ±60s skew and rejects it just outside", async () => {
    stubFetch();
    const verifier = makeOidcVerifier(makeJwksCache());
    const expSeconds = Math.floor(Date.now() / 1000) - 30;
    const token = await makeOidcToken({ expSeconds });
    // exp が 30 秒前 = skew 内なのでまだ有効
    expect((await run(verifier.verify(token, Date.now()))).ok).toBe(true);
    // 同じトークンを skew を越えた時刻で検証すると期限切れ
    const later = await run(verifier.verify(token, Date.now() + 90_000));
    expect(later.ok === false && later.error).toMatchObject({ reason: "token-expired" });
  });

  it("rejects a token whose payload is not a JSON object", async () => {
    stubFetch();
    const verifier = makeOidcVerifier(makeJwksCache());
    // header.payload.signature の形は満たすが payload が JSON 配列
    const segment = btoa("[1,2,3]").replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
    const header = btoa(JSON.stringify({ alg: "ES256", kid: OIDC_KID }))
      .replaceAll("+", "-")
      .replaceAll("/", "_")
      .replaceAll("=", "");
    const result = await run(verifier.verify(`${header}.${segment}.AAAA`, nowMs()));
    expect(result.ok === false && result.error).toMatchObject({ reason: "malformed-token" });
  });

  it("rejects a JWS that declares a crit extension (RFC 7515 §4.1.11)", async () => {
    // crit は「理解できないなら受理してはならない拡張」の宣言であり、本実装は
    // 拡張を 1 つも持たないためいかなる crit 値も拒否する。この検査の欠落は
    // 2025〜2026 に Authlib / PyJWT / fast-jwt で CVE になっている
    stubFetch();
    const verifier = makeOidcVerifier(makeJwksCache());
    const token = await makeOidcToken({ crit: ["exp"] });
    const result = await run(verifier.verify(token, nowMs()));
    expect(result.ok === false && result.error).toMatchObject({ reason: "unsupported-crit" });
  });

  it("rejects a non-string sub / missing sub as a claim problem, not a signature problem", async () => {
    stubFetch();
    const verifier = makeOidcVerifier(makeJwksCache());
    const result = await run(
      verifier.verify(await makeOidcToken({ claims: { sub: 42 } }), nowMs()),
    );
    expect(result.ok === false && result.error).toMatchObject({ reason: "missing-claim" });
  });
});
