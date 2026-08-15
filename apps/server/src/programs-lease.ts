// ワークロードリースの Effect プログラム(AUTH_SPEC §14 = CRYPTO_SPEC §9.1)。
//
// **開封と再ラップを DO 内で行う理由**: リースは監査 3 種(server.dek_unwrapped /
// server.lease_issued / server.lease_denied — AUDIT_SPEC §3.5)を伴い、
// 「配布したものだけを記録する」ためには応答の材料を読む処理と監査追記が同一
// permit・同一同期ブロックに入っている必要がある。worker 側で開封すると
// 「ラップを取りに行く RPC」と「監査を書く RPC」に割れ、原子性が壊れる。
//
// 平文 DEK はこのプログラムにも現れない: 開封 + 再ラップは ServerKey の
// クロージャ内で一体に行われ(server-key.ts)、返るのはリースラップだけである。
//
// 判定順(§14-3。OIDC 検証は worker 側で完了済み = ここは認可以降):
//   1. チェーン導出の有効 grant(サーバー鍵 FP で同定)+ lease_policy の
//      存在量化 + 開示スコープ → いずれの不一致も一律 404(§11-2 の存在秘匿)
//   2. 環境の存在(削除済みは 404 — §12-4 と同じ扱い)
//   3. レート制限(429)— 認可の後(errors/lease.ts の論拠)
//   4. サーバー宛ラップの存在(欠落 = 503 server-wraps-missing)
//   5. 開封 → 再ラップ → 監査 → 応答

import type { ChainEntry } from "@maruhi/crypto";
import { Effect } from "effect";

import { AuditStore } from "./audit-store.ts";
import type { StateCache } from "./chain-store.ts";
import { ChainStore, deriveStoredState } from "./chain-store.ts";
import type { EnvironmentPullValue } from "./data-plane.ts";
import { currentEpochOf, loadInitializedChain } from "./data-plane.ts";
import { DataStore } from "./data-store.ts";
import { grantCoversEnvironment, leasePolicyAuthorizes } from "./lease-policy.ts";
import { MAX_LEASE_DENIED_ROWS_PER_WINDOW, MAX_LEASES_PER_WINDOW } from "./policy.ts";
import { requireActiveEnvironment } from "./quotas.ts";
import type { LeaseWrapOutput } from "./server-key.ts";
import { ServerKey } from "./server-key.ts";

/** worker が渡す、検証済み OIDC トークンのうち認可・束縛に必要な部分だけ。 */
export interface LeaseTokenFacts {
  readonly issuer: string;
  readonly subject: string;
  readonly audiences: readonly string[];
  /**
   * claim 制約の評価対象(§14-1)。RPC 境界を渡るため structured clone 安全な
   * 素のオブジェクトであること。**監査にも応答にも出さない**(外部識別子を
   * 持ち込まない — §14-4 / AUDIT_SPEC §1-2)。
   */
  readonly claims: Readonly<Record<string, unknown>>;
  /** CRYPTO_SPEC §9.1 の claims_digest_hex(worker が crypto で計算済み)。 */
  readonly claimsDigestHex: string;
}

/**
 * リース応答の RPC 値。値付き一括 pull(§12-7)の形から `deks` を落とし、
 * チェーン全体(§14-2 の同梱 — 非メンバーはチェーン API から 404 を受けるため
 * ここが唯一の配布経路)とリースラップを加えたもの。
 */
export interface LeaseValue extends Omit<EnvironmentPullValue, "deks"> {
  readonly chain: readonly ChainEntry[];
  readonly headSeq: number;
  readonly headHashHex: string;
  readonly leases: readonly LeaseWrapOutput[];
}

/** リース固有の拒否(データプレーンの DataRejection とは別語彙)。 */
export type LeaseRejection =
  | { readonly kind: "not-found" }
  | { readonly kind: "rate-limited"; readonly retryAfterSeconds: number }
  | {
      readonly kind: "unavailable";
      readonly reason: "server-wraps-missing" | "server-key-unconfigured";
    };

/** RPC 境界を渡るリース結果。 */
export type LeaseOutcome =
  | { readonly kind: "ok"; readonly value: LeaseValue }
  | { readonly kind: "rejected"; readonly rejection: LeaseRejection };

/**
 * server.lease_denied(AUDIT_SPEC §3.5): **OIDC 署名検証を通過した後の拒否のみ**
 * を、固定窓の全体上限つきで記録する(auth.login_failed と同じ規律)。
 * actor は `{ type: "system" }` — 外部ワークロードは maruhi 上の識別を持たず、
 * サーバー鍵の行使でもない。payload に載せるのは理由コードと claims_digest
 * だけで、リポジトリ名等の外部識別子は書かない(§14-4)。
 */
const recordDenied = (reason: string, claimsDigestHex: string, nowMs: number) =>
  Effect.gen(function* () {
    const store = yield* DataStore;
    const decision = yield* store.consumeLeaseWindow(
      "denied",
      MAX_LEASE_DENIED_ROWS_PER_WINDOW,
      nowMs,
    );
    if (!decision.allowed) {
      return;
    }
    const audit = yield* AuditStore;
    yield* Effect.sync(() => {
      audit.appendSync({
        event: "server.lease_denied",
        serverTs: nowMs,
        actorType: "system",
        payload: { reason, claimsDigest: claimsDigestHex },
      });
    });
  });

/** 拒否 + 監査記録を 1 つにまとめる(記録漏れの経路を作らない)。 */
const denyWithAudit = (reason: string, facts: LeaseTokenFacts, nowMs: number) =>
  Effect.gen(function* () {
    yield* recordDenied(reason, facts.claimsDigestHex, nowMs);
    return yield* Effect.fail<LeaseRejection>({ kind: "not-found" });
  });

export const leaseProgram = (
  environmentId: string,
  ephemeralPubHex: string,
  facts: LeaseTokenFacts,
  cache: StateCache,
): Effect.Effect<LeaseValue, LeaseRejection, ChainStore | DataStore | AuditStore | ServerKey> =>
  Effect.gen(function* () {
    const serverKey = yield* ServerKey;
    const serverKeyInfo = yield* serverKey.info;
    const nowMs = Date.now();
    // 0. サーバー鍵が未設定のデプロイメントは**プロジェクトを読む前**に落とす。
    // 順序が重要: チェーンのロード(未初期化 = 404)を先に置くと、鍵なし
    // デプロイメントで「未知 = 404 / 実在 = 503」の差ができてプロジェクトの
    // 存在が漏れる(§11-2)。先に落とせば全リクエストが一様に 503 になり、
    // 何も漏れない。理由が 404 でないのは、設定の欠落は「このプロジェクトは
    // 存在しない」ではないため(秘密鍵なしでは開封経路自体が存在しない)
    if (serverKeyInfo === null) {
      return yield* Effect.fail<LeaseRejection>({
        kind: "unavailable",
        reason: "server-key-unconfigured",
      });
    }
    // 未初期化プロジェクトは監査を残さず 404 にする: 未認証経路が任意の
    // プロジェクト ID で DO 行を作れると、監査ログの肥大 DoS になる
    // (プロジェクト ID は genesis ハッシュ = 実質ケーパビリティであり、
    // 存在するプロジェクトへのプローブは下の固定窓上限が束縛する)
    const chain = yield* loadInitializedChain.pipe(
      Effect.mapError((): LeaseRejection => ({ kind: "not-found" })),
    );
    // 導出は失敗しない(保存済みチェーンの検証失敗は defect — chain-store.ts)
    const { state } = yield* deriveStoredState(chain, cache);

    // 1. 認可: 自サーバー鍵の有効 grant × lease_policy(存在量化)× 開示スコープ。
    // 一致するのは常に「自分の FP の grant」— サーバーは自分宛ラップしか
    // 開封できないため、grant の同定に非決定性はない
    const grant = state.serverGrants.get(serverKeyInfo.serverKeyFingerprintHex);
    if (grant === undefined) {
      return yield* denyWithAudit("no-grant", facts, nowMs);
    }
    if (!leasePolicyAuthorizes(grant, facts)) {
      return yield* denyWithAudit("policy-mismatch", facts, nowMs);
    }
    if (!grantCoversEnvironment(grant, environmentId)) {
      return yield* denyWithAudit("scope-out-of-range", facts, nowMs);
    }

    // 2. 環境の存在(削除済み tombstone は 404)
    yield* requireActiveEnvironment(environmentId).pipe(
      Effect.matchEffect({
        onFailure: () => denyWithAudit("environment-not-found", facts, nowMs),
        onSuccess: () => Effect.void,
      }),
    );

    // 3. レート制限(認可の後 — 存在秘匿のため。errors/lease.ts)
    const store = yield* DataStore;
    const window = yield* store.consumeLeaseWindow("issued", MAX_LEASES_PER_WINDOW, nowMs);
    if (!window.allowed) {
      yield* recordDenied("rate-limited", facts.claimsDigestHex, nowMs);
      return yield* Effect.fail<LeaseRejection>({
        kind: "rate-limited",
        retryAfterSeconds: window.retryAfterSeconds,
      });
    }

    // 4. サーバー宛ラップの存在(欠落 = 503。grant 済みだが再ラップ未了の状態を
    // 不透明な失敗にしない — §14-3。A1 の裁定どおり、バックフィル漏れに対する
    // 最後の砦がここ)
    const serverWraps = yield* store.listServerWraps(
      environmentId,
      serverKeyInfo.serverKeyFingerprintHex,
    );
    const currentEpoch = currentEpochOf(state, environmentId);
    const statement = yield* store.environmentStatement(environmentId);
    if (statement === null) {
      return yield* Effect.die(new Error("environment meta statement row missing"));
    }
    const variables = yield* store.latestVersions(environmentId);
    const deletedVariables = yield* store.deletedVariableStatements(environmentId);

    // 応答内の最新値が使用する全エポック + 現エポック(§14-2)。過不足なく
    // 揃っていることを要求する — 1 つでも欠ければ復号できない値が応答に載る
    const neededEpochs = [
      ...new Set([currentEpoch, ...variables.map((variable) => variable.epoch)]),
    ].toSorted((a, b) => a - b);
    const available = new Map(serverWraps.map((wrap) => [wrap.epoch, wrap]));
    const usable = neededEpochs.map((epoch) => available.get(epoch));
    if (usable.some((wrap) => wrap === undefined)) {
      yield* recordDenied("server-wraps-missing", facts.claimsDigestHex, nowMs);
      return yield* Effect.fail<LeaseRejection>({
        kind: "unavailable",
        reason: "server-wraps-missing",
      });
    }
    const wraps = usable.filter((wrap) => wrap !== undefined);

    // 5. 開封 → 再ラップ(平文 DEK は ServerKey のクロージャ外へ出ない)
    const leases = yield* serverKey
      .reseal({
        projectId: chain.genesisHashHex,
        environmentId,
        claimsDigestHex: facts.claimsDigestHex,
        workloadPubHex: ephemeralPubHex,
        wraps,
      })
      .pipe(
        Effect.matchEffect({
          onFailure: (failure) =>
            Effect.gen(function* () {
              // 開封失敗 = 毒ラップ(§12-6 の修復経路の対象)、再ラップ失敗 =
              // ワークロード公開鍵が点として不正。どちらも「grant はあるが
              // 使える材料がない」状態であり、server-wraps-missing と同じ
              // 503 に畳む(理由の細分は運用者向けの監査行が持つ)
              yield* recordDenied(`reseal-${failure}`, facts.claimsDigestHex, nowMs);
              return yield* Effect.fail<LeaseRejection>({
                kind: "unavailable",
                reason: "server-wraps-missing",
              });
            }),
          onSuccess: (value) => Effect.succeed(value),
        }),
      );

    // 監査(AUDIT_SPEC §3.5): server.dek_unwrapped をエポックごと 1 行 +
    // server.lease_issued を環境単位 1 行。actor は `{ server, 鍵 FP }`。
    // **var.read は記録しない**(人間 actor の読み取りの証跡であり、
    // ワークロードへの開示は server.* 系が担う — §14-4)
    const audit = yield* AuditStore;
    yield* Effect.sync(() => {
      audit.appendManySync([
        ...leases.map((lease) => ({
          event: "server.dek_unwrapped",
          serverTs: nowMs,
          actorType: "server" as const,
          actorKeyFingerprintHex: serverKeyInfo.serverKeyFingerprintHex,
          environmentId,
          epoch: lease.epoch,
        })),
        {
          event: "server.lease_issued",
          serverTs: nowMs,
          actorType: "server" as const,
          actorKeyFingerprintHex: serverKeyInfo.serverKeyFingerprintHex,
          environmentId,
          payload: {
            // 一致した policy 要素はチェーン(grant payload)が保持しており、
            // grant_chain_seq + claims_digest で突合できる。外部識別子
            // (リポジトリ名等)は書かない(§14-4)
            grantChainSeq: grant.grantSeq,
            claimsDigest: facts.claimsDigestHex,
            epochs: leases.map((lease) => lease.epoch),
          },
        },
      ]);
    });

    return {
      environmentId,
      currentEpoch,
      chain: chain.entries,
      headSeq: chain.headSeq,
      headHashHex: chain.headHashHex,
      statement,
      variables,
      deletedVariables,
      leases,
    } satisfies LeaseValue;
  });
