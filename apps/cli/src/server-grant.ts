// `maruhi server grant`(CRYPTO_SPEC §9 / AUTH_SPEC §12-6 — Wave 2 A1)。
//
// grant_server をチェーンへ追記し、開示スコープ内の全環境 × 全エポックの
// サーバー宛ラップをバックフィルする(grant 実行者 = owner がラップ実行者 —
// CRYPTO_SPEC §7)。フロー:
//   1. owner 検査・環境の存在検査・duplicate-server-key / 再 grant 二層の早期検査
//   2. `/auth/config` からサーバー鍵の公開面を取得し、FP = SHA-256(enc_pub)[:16]
//      を再計算照合(輸送破損・設定飛びの機械検出)
//   3. サーバー鍵確認の儀式(§9): FP の BIP39 12 語表示 + 明示確認
//      (対話 = 最終語の再入力、非対話 = --expect-fingerprint の帯域外値照合)
//   4. grant_server 追記(親ヘッド CAS リトライ)
//   5. バックフィル: 環境ごとに全エポックのサーバー宛ラップを一括登録し、
//      409(登録済み)はエポック単位に落として続行 — **再実行が常に収束する**
//      (進捗ファイルなし。分散状態が再開状態 — env rotate と同じ規律)
//
// 中断復旧: grant がチェーンに載った後で落ちても、再実行が「同一内容の有効
// grant を検出 → 追記スキップ → バックフィル(409 = 登録済み)」で収束する。
// A2 のリースは不足時に 503 `server-wraps-missing` へ倒れる(AUTH_SPEC §14-3)。

import { ChainHeadConflictError, DekWrapExistsError, type WrappedDek } from "@maruhi/api-schema";
import type { EnvironmentId } from "@maruhi/core";
import type { ChainEntry, LeasePolicyIssuer, ServerGrant, SigningKeyPair } from "@maruhi/crypto";
import {
  computeServerKeyFingerprint,
  decodeHex,
  encodeHex,
  fingerprintToWords,
  signChainEntry,
  SUITE_ID,
} from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { wrapAndSignFor } from "./dek-wrap.ts";
import type { DekRecipient } from "./deks.ts";
import { environmentKeysFor } from "./deks.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo } from "./io.ts";
import { retryOnConflict } from "./retry.ts";
import { resyncExtended, type VerifiedProject } from "./sync.ts";

const MAX_ATTEMPTS = 5;
const CONFIRM_ATTEMPTS = 3;

/** サーバー鍵の公開面(`/auth/config` — AUTH_SPEC §4)。 */
interface ServerKeyConfig {
  readonly serverEncPubHex: string;
  readonly serverKeyFingerprintHex: string;
}

export interface GrantSummary {
  /** チェーンへ追記したか(false = 同一内容の有効 grant を検出してスキップ)。 */
  readonly appended: boolean;
  readonly serverKeyFingerprintHex: string;
  readonly scopeEnvironmentIds: readonly string[];
  readonly leasePolicyCount: number;
  /** バックフィルで新規登録したラップ数。 */
  readonly registered: number;
  /** 既に登録済みだったラップ数(再実行の収束)。 */
  readonly alreadyRegistered: number;
}

/** スコープの各環境がチェーン上に存在するか(不成立なら理由の文字列)。 */
function scopeExistsRejection(verified: VerifiedProject, scope: readonly string[]): string | null {
  for (const environmentId of scope) {
    if (!verified.state.environments.has(environmentId)) {
      return `環境 ${environmentId} はチェーン上に存在しません(create_environment 未観測)。--environments には存在する環境 ID を指定してください`;
    }
  }
  return null;
}

/**
 * duplicate-server-key(§6.2)の早期検査: サーバー enc 公開鍵が現メンバーの
 * enc 公開鍵と一致する grant は合意規則で無効になる。
 */
function duplicateServerKeyRejection(
  verified: VerifiedProject,
  serverEncPubHex: string,
): string | null {
  for (const chainMember of verified.state.members.values()) {
    if (chainMember.encPubHex === serverEncPubHex) {
      return "サーバー enc 公開鍵が現メンバーの enc 公開鍵と一致しています(合意規則 duplicate-server-key — CRYPTO_SPEC §6.2)。デプロイメントの鍵設定を確認してください";
    }
  }
  return null;
}

/**
 * 再 grant 二層(§6.3): scope は拡大のみ。縮小には revoke_server(全環境
 * ローテーション義務つき)を案内する。lease_policy は自由改訂。
 */
function scopeNarrowedRejection(
  existing: ServerGrant | null,
  scope: readonly string[],
): string | null {
  if (existing === null) {
    return null;
  }
  const missing = existing.scopeEnvironmentIds.filter((id) => !scope.includes(id));
  if (missing.length === 0) {
    return null;
  }
  return `開示スコープは拡大のみ可能です(再 grant 規則 — CRYPTO_SPEC §6.3)。既存 grant のスコープに含まれる環境が指定から欠けています: ${missing.join(", ")}。縮小するには maruhi server revoke(全環境ローテーションを伴う — §7)を実行してから grant し直してください`;
}

/** grant_server 実行前の検査一式(再同期後のリトライでも同じ検査を通す)。 */
function ensureGrantable(input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: string;
  readonly scope: readonly string[];
  readonly serverConfig: ServerKeyConfig;
}): Effect.Effect<{ readonly existing: ServerGrant | null }, CliError> {
  const member = input.verified.state.members.get(input.signerUserId);
  if (member === undefined || member.role !== "owner") {
    return Effect.fail(cliError("grant_server は owner のみが実行できます(CRYPTO_SPEC §6.2)"));
  }
  const existing =
    input.verified.state.serverGrants.get(input.serverConfig.serverKeyFingerprintHex) ?? null;
  const rejection =
    scopeExistsRejection(input.verified, input.scope) ??
    duplicateServerKeyRejection(input.verified, input.serverConfig.serverEncPubHex) ??
    scopeNarrowedRejection(existing, input.scope);
  return rejection !== null ? Effect.fail(cliError(rejection)) : Effect.succeed({ existing });
}

/** オブジェクトのキー順に依存しない正規形(配列形)で比較する。 */
function canonicalPolicyKey(policy: readonly LeasePolicyIssuer[]): string {
  return JSON.stringify(
    policy.map((element) => [
      element.issuerUrl,
      element.audience,
      element.claimConstraints.map((constraint) => [constraint.claimName, constraint.claimValue]),
    ]),
  );
}

function samePolicy(a: readonly LeasePolicyIssuer[], b: readonly LeasePolicyIssuer[]): boolean {
  return canonicalPolicyKey(a) === canonicalPolicyKey(b);
}

function sameScope(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((id, index) => b[index] === id);
}

/**
 * `/auth/config` のサーバー鍵公開面を取得し、FP を再計算照合する。FP の照合
 * 「対象」は帯域外の控え(儀式 — §9)であり、ここでの再計算は応答の自己整合
 * 検査(輸送破損・別ソースの取り違えの機械検出)である。
 */
function fetchServerKeyConfig(client: MaruhiClient): Effect.Effect<ServerKeyConfig, CliError> {
  return Effect.gen(function* () {
    const config = yield* client.auth.authConfig({}).pipe(Effect.mapError(toCliError));
    const encPubHex = config.serverEncPubHex;
    const fingerprintHex = config.serverKeyFingerprintHex;
    if (encPubHex === undefined || fingerprintHex === undefined) {
      return yield* Effect.fail(
        cliError(
          "サーバーにデプロイメント keypair が設定されていません(/auth/config に serverKeyFingerprintHex がありません)。docs/SELF_HOSTING.md の手順で SERVER_ENC_KEY_IKM を登録してください",
        ),
      );
    }
    const encPub = decodeHex(encPubHex);
    if (encPub === null || encPub.length !== 32) {
      return yield* Effect.fail(cliError("/auth/config の serverEncPubHex が不正な形式です"));
    }
    const computed = yield* Effect.tryPromise({
      try: () => computeServerKeyFingerprint(encPub),
      catch: () => cliError("サーバー鍵 FP の計算に失敗しました(暗号処理エラー)"),
    });
    if (!computed.ok || encodeHex(computed.value) !== fingerprintHex) {
      return yield* Effect.fail(
        cliError(
          "サーバー配布の enc 公開鍵と serverKeyFingerprintHex が一致しません(応答が自己矛盾しています)。デプロイメントの設定または経路を確認してください",
        ),
      );
    }
    return { serverEncPubHex: encPubHex, serverKeyFingerprintHex: fingerprintHex };
  });
}

/** FP の BIP39 12 語(§3)。表示・確認の材料。 */
function fingerprintWords(fingerprintHex: string): Effect.Effect<readonly string[], CliError> {
  return Effect.gen(function* () {
    const bytes = decodeHex(fingerprintHex);
    if (bytes === null) {
      return yield* Effect.fail(cliError("サーバー鍵 FP の形式が不正です"));
    }
    const words = yield* Effect.tryPromise({
      try: () => fingerprintToWords(bytes),
      catch: () => cliError("FP ワード表示の計算に失敗しました(暗号処理エラー)"),
    });
    if (!words.ok) {
      return yield* Effect.fail(cliError("FP ワード表示の計算に失敗しました"));
    }
    return words.value;
  });
}

/**
 * サーバー鍵確認の儀式(§9): FP のワード表示と、デプロイメントの公開設定との
 * 照合の明示確認。メンバー鍵に課している真正性確認(§6.5)をサーバー鍵にだけ
 * 免除しない — grant はサーバーを「メンバー N+1」にする操作である。
 *
 * 確認の形は 2 つ:
 * - `--expect-fingerprint <hex>`: 帯域外で控えた FP を引数で供給する(非対話の
 *   明示確認。デプロイ時の控えと一致しなければ即エラー)
 * - 対話: 12 語を表示し、**最終語の再入力**を要求する(リカバリーコードの
 *   保存確認 — recovery.ts — と同じ儀式。読まずに y を打つ形を塞ぐ)
 */
function confirmServerKey(input: {
  readonly fingerprintHex: string;
  readonly expectFingerprintHex: string | null;
}): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const words = yield* fingerprintWords(input.fingerprintHex);
    const lines = [
      "サーバー鍵フィンガープリント(SHA-256(enc 公開鍵) 先頭 16 バイト — CRYPTO_SPEC §9):",
      `  hex:  ${input.fingerprintHex}`,
      "  word: " + words.map((word, index) => `${String(index + 1).padStart(2)}.${word}`).join(" "),
      "この語列が、デプロイ時に控えたサーバー鍵 FP(docs/SELF_HOSTING.md の記録手順)と一致することを帯域外の記録で照合してください。",
    ];
    for (const line of lines) {
      yield* io.log(line);
    }
    if (input.expectFingerprintHex !== null) {
      if (input.expectFingerprintHex !== input.fingerprintHex) {
        return yield* Effect.fail(
          cliError(
            "--expect-fingerprint がサーバー配布の鍵の FP と一致しません。デプロイメントの鍵が想定と異なります — grant を中止しました(鍵が正しいか帯域外で確認してください)",
          ),
        );
      }
      yield* io.log(
        "--expect-fingerprint と一致しました(帯域外の控えとの照合済みとして続行します)",
      );
      return;
    }
    // AI エージェント環境では儀式を代行させない(照合は人間の帯域外確認 — §9 /
    // ADR-0014。値表示の拒否 — agent.ts — と同じ姿勢の grant 版)
    if (io.agentProfile().isAgent) {
      return yield* Effect.fail(
        cliError(
          "AI エージェント環境を検出したため、サーバー鍵確認の儀式を実行できません。人間が実行するか、帯域外で控えた FP を --expect-fingerprint で明示してください",
        ),
      );
    }
    const lastWord = words[words.length - 1];
    if (lastWord === undefined) {
      return yield* Effect.fail(cliError("FP ワード表示の計算に失敗しました"));
    }
    for (let attempt = 1; attempt <= CONFIRM_ATTEMPTS; attempt += 1) {
      const answer = yield* io.promptLine({
        prompt: `照合できたら、表示された 12 語の最後の語を入力してください(${attempt}/${CONFIRM_ATTEMPTS}): `,
      });
      if (answer.trim() === lastWord) {
        return;
      }
      yield* io.logError("入力が一致しません。表示された語列の最後の語を入力してください");
    }
    return yield* Effect.fail(
      cliError(
        "サーバー鍵 FP の確認に失敗しました(語の再入力が一致しません)。grant は実行していません — 帯域外の控えと照合できてから再実行してください",
      ),
    );
  });
}

/** grant_server エントリを現ヘッドの直後に署名する。 */
function signGrantEntry(input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  readonly serverConfig: ServerKeyConfig;
  readonly scope: readonly string[];
  readonly leasePolicy: readonly LeasePolicyIssuer[];
}): Effect.Effect<ChainEntry, CliError> {
  return Effect.gen(function* () {
    const member = input.verified.state.members.get(input.signerUserId);
    if (member === undefined) {
      return yield* Effect.fail(cliError("チェーン導出メンバーではありません"));
    }
    const signed = yield* Effect.tryPromise({
      try: () =>
        signChainEntry({
          entry: {
            suite: SUITE_ID,
            seq: input.verified.state.headSeq + 1,
            prevHashHex: input.verified.state.headHashHex,
            op: "grant_server",
            actor: { userId: member.userId, keyFingerprintHex: member.keyFingerprintHex },
            payload: {
              serverEncPubHex: input.serverConfig.serverEncPubHex,
              serverKeyFingerprintHex: input.serverConfig.serverKeyFingerprintHex,
              scopeEnvironmentIds: input.scope,
              leasePolicy: input.leasePolicy,
            },
            timestampMs: Date.now(),
          },
          signingKey: input.signingKeyPair.privateKey,
        }),
      catch: () => cliError("grant_server エントリの署名に失敗しました"),
    });
    if (!signed.ok) {
      return yield* Effect.fail(cliError("grant_server エントリの署名に失敗しました"));
    }
    return signed.value;
  });
}

/** バックフィル 1 環境分の結果。 */
interface BackfillResult {
  readonly registered: number;
  readonly alreadyRegistered: number;
}

/**
 * 1 環境の全エポック(1〜現エポック)のサーバー宛ラップを登録する。まず一括で
 * 送り、409(登録済みスロットあり)ならエポック単位に落として 409 = 登録済みと
 * して続行する(サーバー宛ラップの一覧 API は存在しない — 配布は本人宛のみ
 * §12-6 — ため、「409 を完了扱い」が唯一かつ十分な照合手段)。
 */
function backfillEnvironment(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly recipient: DekRecipient;
  readonly grant: ServerGrant;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<BackfillResult, CliError> {
  return Effect.gen(function* () {
    const keys = yield* environmentKeysFor({
      client: input.client,
      verified: input.verified,
      environmentId: input.environmentId,
      recipient: input.recipient,
    });
    const wraps: WrappedDek[] = [];
    for (let epoch = 1; epoch <= keys.currentEpoch; epoch += 1) {
      const dek = keys.deksByEpoch.get(epoch);
      if (dek === undefined) {
        // §7: 全メンバーは全エポックの DEK を受け取る。欠けは毒ラップ・欠落の
        // 兆候なので黙って飛ばさない(§12-6 の修復経路を案内)
        return yield* Effect.fail(
          cliError(
            `環境 ${input.environmentId} の epoch ${epoch} の DEK ラップが自分宛に存在しません(§7 の全エポック配布と矛盾)。修復経路(ラップの再登録)で解消してから再実行してください`,
          ),
        );
      }
      const built = yield* Effect.tryPromise({
        try: () =>
          wrapAndSignFor({
            projectId: input.verified.projectId,
            environmentId: input.environmentId,
            epoch,
            dek,
            recipient: { kind: "server", grant: input.grant },
            signerUserId: input.signerUserId,
            signingKeyPair: input.signingKeyPair,
          }),
        catch: () => cliError("サーバー宛 DEK ラップ生成が失敗しました(暗号処理エラー)"),
      });
      if (built.kind === "failed") {
        return yield* Effect.fail(
          cliError(`サーバー宛 DEK ラップ生成に失敗しました(${built.reason})`),
        );
      }
      wraps.push(built.wrap);
    }

    // 登録(409 = DekWrapExists は「登録済み」として吸収 — 再実行の収束)
    const register = (deks: readonly WrappedDek[]) =>
      input.client.deks
        .register({
          params: { projectId: input.verified.projectId, environmentId: input.environmentId },
          payload: { deks },
        })
        .pipe(
          Effect.map(() => ({ kind: "ok" }) as const),
          Effect.catch((error) =>
            error instanceof DekWrapExistsError
              ? Effect.succeed({ kind: "exists" } as const)
              : Effect.fail(toCliError(error)),
          ),
        );

    // 一括 → 409 ならエポック単位(バッチは原子的受理のため、部分登録済みの
    // 再実行では一括が 409 になる)
    const batch = yield* register(wraps);
    if (batch.kind === "ok") {
      return { registered: wraps.length, alreadyRegistered: 0 };
    }
    let registered = 0;
    let alreadyRegistered = 0;
    for (const wrap of wraps) {
      const single = yield* register([wrap]);
      if (single.kind === "ok") {
        registered += 1;
      } else {
        alreadyRegistered += 1;
      }
    }
    return { registered, alreadyRegistered };
  });
}

/** CAS リトライの状態。 */
interface GrantState {
  readonly verified: VerifiedProject;
}

export function serverGrantOp(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentIds: readonly EnvironmentId[];
  readonly leasePolicy: readonly LeasePolicyIssuer[];
  readonly expectFingerprintHex: string | null;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  readonly recipient: DekRecipient;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
}): Effect.Effect<GrantSummary, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    // スコープの正規化: コードポイント昇順・重複なし(§6.2 の SHOULD)
    const scope = [...new Set<string>(input.environmentIds)].toSorted();
    const serverConfig = yield* fetchServerKeyConfig(input.client);
    const { existing } = yield* ensureGrantable({
      verified: input.verified,
      signerUserId: input.signerUserId,
      scope,
      serverConfig,
    });

    const unchanged =
      existing !== null &&
      sameScope([...existing.scopeEnvironmentIds].toSorted(), scope) &&
      samePolicy(existing.leasePolicy, input.leasePolicy);

    // 儀式(§9)は追記の有無に関わらず行う(バックフィルだけの再実行でも、
    // これから開示し続ける鍵の照合を省略しない)
    yield* confirmServerKey({
      fingerprintHex: serverConfig.serverKeyFingerprintHex,
      expectFingerprintHex: input.expectFingerprintHex,
    });

    let verified = input.verified;
    if (unchanged) {
      yield* io.log(
        "同一内容(scope / lease_policy とも)の有効な grant が既に存在します — チェーン追記をスキップし、バックフィルのみ実行します(中断復旧)",
      );
    } else {
      const appended = yield* retryOnConflict<GrantState, VerifiedProject, "head-conflict">(
        { verified },
        {
          maxAttempts: MAX_ATTEMPTS,
          attempt: (state) =>
            Effect.gen(function* () {
              const entry = yield* signGrantEntry({
                verified: state.verified,
                signerUserId: input.signerUserId,
                signingKeyPair: input.signingKeyPair,
                serverConfig,
                scope,
                leasePolicy: input.leasePolicy,
              });
              yield* input.client.membership
                .append({
                  params: { projectId: state.verified.projectId },
                  payload: { parentHeadHashHex: state.verified.state.headHashHex, entry },
                })
                .pipe(
                  Effect.mapError((error) =>
                    error instanceof ChainHeadConflictError ? error : toCliError(error),
                  ),
                );
              return state.verified;
            }),
          classify: (error) => (error instanceof ChainHeadConflictError ? "head-conflict" : null),
          recover: (state) =>
            Effect.gen(function* () {
              // 延長検査付き再同期(短縮・分岐チェーンへの再署名を塞ぐ —
              // env create / rotate の CAS リトライと同じ規律)
              const resynced = yield* resyncExtended(input.resync, state.verified);
              yield* ensureGrantable({
                verified: resynced,
                signerUserId: input.signerUserId,
                scope,
                serverConfig,
              });
              return { verified: resynced };
            }),
          exhaustedMessage: `grant_server のチェーンヘッド競合が解消しません(${MAX_ATTEMPTS} 回試行)。時間をおいて再実行してください`,
        },
      );
      // 受理後の再同期で grant の掲載を確認する(サーバー申告を真実源にしない)
      verified = yield* resyncExtended(input.resync, appended);
      const granted = verified.state.serverGrants.get(serverConfig.serverKeyFingerprintHex);
      if (granted === undefined) {
        return yield* Effect.fail(
          cliError(
            "grant_server の受理後の再同期で grant を確認できません(サーバー応答の矛盾)。配布されたチェーンを調査してください",
          ),
        );
      }
      yield* io.log(
        `grant_server をチェーンへ追記しました(seq=${verified.state.headSeq}、scope=${scope.join(", ")})`,
      );
    }

    const grant = verified.state.serverGrants.get(serverConfig.serverKeyFingerprintHex);
    if (grant === undefined) {
      return yield* Effect.fail(cliError("有効な grant を確認できません(再同期の結果と矛盾)"));
    }

    // バックフィル(開示スコープ内の全環境 × 全エポック — AUTH_SPEC §12-6)
    let registered = 0;
    let alreadyRegistered = 0;
    for (const environmentId of grant.scopeEnvironmentIds) {
      const result = yield* backfillEnvironment({
        client: input.client,
        verified,
        environmentId,
        recipient: input.recipient,
        grant,
        signerUserId: input.signerUserId,
        signingKeyPair: input.signingKeyPair,
      });
      registered += result.registered;
      alreadyRegistered += result.alreadyRegistered;
    }

    return {
      appended: !unchanged,
      serverKeyFingerprintHex: serverConfig.serverKeyFingerprintHex,
      scopeEnvironmentIds: grant.scopeEnvironmentIds,
      leasePolicyCount: grant.leasePolicy.length,
      registered,
      alreadyRegistered,
    };
  });
}
