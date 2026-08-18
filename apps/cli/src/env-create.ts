// 環境作成の複合リクエスト(AUTH_SPEC §12-4。2026-08-03 の環境作成チェーン op 化):
// `create_environment` チェーンエントリ(エポック 1 の DEK コミットメント込み —
// CRYPTO_SPEC §5.2 / §6.2)+ `EnvironmentMetaStatement`(metaVersion 1 — §4.2。
// 表示名は署名前に NFC 正規化し、宣言ヘッドは追記前の現ヘッド = 同梱エントリの
// prev)+ エポック 1 の DEK ラップ完全集合を 1 リクエストで原子的に受理させる。
// 親ヘッド CAS の失敗(ChainHeadConflict)は再同期 → **エントリとステートメントの
// 両方を再署名**(seq / prev / 宣言ヘッド変更 — §12-4)してリトライする。
//
// ラップ集合の生成は dek-wrap.ts の共有実装(env-rotate.ts と共通)。
// grant_server が有効で作成環境が開示スコープに含まれる場合、完全集合は
// サーバー鍵宛ラップを含む(§12-4 — 2026-08-12 の受信者クラス server 実装)。

import type { WrappedDek } from "@maruhi/api-schema";
import { ChainHeadConflictError } from "@maruhi/api-schema";
import type { EnvironmentId } from "@maruhi/core";
import type { ChainEntry, ChainMember, SigningKeyPair } from "@maruhi/crypto";
import { computeDekCommitment, generateDek, signChainEntry, SUITE_ID } from "@maruhi/crypto";
import { Effect, Redacted } from "effect";

import type { MaruhiClient } from "./api.ts";
import { buildWrapCompleteSet, requireWritingMember, sameWrapRecipientSet } from "./dek-wrap.ts";
import { cliError, type CliError } from "./errors.ts";
import { signNextManifest } from "./manifest.ts";
import { signCreateStatement } from "./meta-statement.ts";
import { retryOnConflict } from "./retry.ts";
import { resyncExtended, type VerifiedProject } from "./sync.ts";

const MAX_ATTEMPTS = 5;

function ensureCreatable(
  verified: VerifiedProject,
  environmentId: string,
  signerUserId: string,
): Effect.Effect<ChainMember, CliError> {
  return Effect.gen(function* () {
    // メンバー性 + role は env rotate と共有。role をここで落とさないと、
    // reader は DEK 生成と全受信者分の HPKE ラップ・署名を済ませて複合を
    // 送ってから、サーバーの汎用 403 を受け取ることになる
    const member = yield* requireWritingMember({
      verified,
      environmentId,
      signerUserId,
      operation: "create an environment",
      forbidden:
        "A reader cannot create environments (create_environment requires the member role or above — CRYPTO_SPEC §6.2)",
    });
    // environment_id はチェーン履歴全体で一意(合意規則 duplicate-environment —
    // CRYPTO_SPEC §6.2)。サーバーの 422 を待たずクライアントでも早期検出する
    if (verified.state.environments.has(environmentId)) {
      return yield* Effect.fail(
        cliError(
          `Environment ID ${environmentId} is already used on the chain (a create_environment entry was observed — IDs of deleted environments cannot be reused either). Use a different ID`,
        ),
      );
    }
    return member;
  });
}

/** create_environment エントリを現ヘッドの直後(seq = head + 1)に署名する。 */
function signCreateEntry(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly dekCommitmentHex: string;
  readonly member: ChainMember;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<ChainEntry & { readonly op: "create_environment" }, CliError> {
  return Effect.gen(function* () {
    const signed = yield* Effect.tryPromise({
      try: () =>
        signChainEntry({
          entry: {
            suite: SUITE_ID,
            seq: input.verified.state.headSeq + 1,
            prevHashHex: input.verified.state.headHashHex,
            op: "create_environment",
            actor: {
              userId: input.member.userId,
              keyFingerprintHex: input.member.keyFingerprintHex,
            },
            payload: {
              environmentId: input.environmentId,
              dekCommitmentHex: input.dekCommitmentHex,
            },
            timestampMs: Date.now(),
          },
          signingKey: input.signingKeyPair.privateKey,
        }),
      catch: () => cliError("Failed to sign the create_environment entry"),
    });
    if (!signed.ok) {
      return yield* Effect.fail(cliError("Failed to sign the create_environment entry"));
    }
    // op の絞り込み(signChainEntry は入力の op を保存する)
    if (signed.value.op !== "create_environment") {
      return yield* Effect.fail(cliError("Failed to sign the create_environment entry"));
    }
    return signed.value;
  });
}

/** CAS リトライの状態: 検証ビュー・自分のメンバー行・エポック 1 のラップ集合。 */
interface CreateState {
  readonly verified: VerifiedProject;
  readonly member: ChainMember;
  readonly deks: readonly WrappedDek[];
}

/**
 * `maruhi env create`: create an environment through the §12-4 composite —
 * the signed `create_environment` entry (epoch-1 DEK commitment), the display
 * name and the epoch-1 wrap set, retrying head-CAS conflicts with a re-signed
 * entry (and a rebuilt wrap set only when the member set changed).
 */
export function envCreateOp(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly name: string;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  /** ChainHeadConflict 時の再同期(チェーン全再検証)。 */
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
}): Effect.Effect<{ readonly currentEpoch: number; readonly memberCount: number }, CliError> {
  return Effect.gen(function* () {
    const member = yield* ensureCreatable(input.verified, input.environmentId, input.signerUserId);
    // 正規化の実施主体は署名前のクライアント(§4.2 / §12-1)
    const name = input.name.normalize("NFC");
    // 生成直後に包む(以降 DEK は Redacted としてしか流れない)
    const dek = Redacted.make(generateDek(), { label: "dek" });
    const commitment = yield* Effect.tryPromise({
      try: () =>
        computeDekCommitment({
          context: {
            suite: SUITE_ID,
            projectId: input.verified.projectId,
            environmentId: input.environmentId,
            epoch: 1,
          },
          // 剥がす理由: コミットメント計算の入力(暗号境界)。産物はハッシュ
          dek: Redacted.value(dek),
        }),
      catch: () => cliError("Failed to compute the DEK commitment"),
    });
    if (!commitment.ok) {
      return yield* Effect.fail(cliError("Failed to compute the DEK commitment"));
    }
    const deks = yield* buildWrapCompleteSet({
      verified: input.verified,
      environmentId: input.environmentId,
      epoch: 1,
      dek,
      signerUserId: input.signerUserId,
      signingKeyPair: input.signingKeyPair,
    });

    return yield* retryOnConflict<
      CreateState,
      { readonly currentEpoch: number; readonly memberCount: number },
      "head-conflict"
    >(
      { verified: input.verified, member, deks },
      {
        maxAttempts: MAX_ATTEMPTS,
        // CAS リトライではエントリ(prev 変更)とステートメント(宣言ヘッド変更)の
        // **両方**を再署名する(§12-4)。ラップ集合はメンバー集合変化時のみ再構築
        attempt: (state) =>
          Effect.gen(function* () {
            const entry = yield* signCreateEntry({
              verified: state.verified,
              environmentId: input.environmentId,
              dekCommitmentHex: commitment.value,
              member: state.member,
              signingKeyPair: input.signingKeyPair,
            });
            // 宣言ヘッドは追記前の現ヘッド(= 同梱エントリの prev — §12-4)。
            // 共有実装(meta-statement.ts)— push.ts との差分は target のみ
            const { statement, metaSigHashHex } = yield* signCreateStatement({
              verified: state.verified,
              environmentId: input.environmentId,
              target: { kind: "environment" },
              name,
              authorUserId: input.signerUserId,
              signingKey: input.signingKeyPair.privateKey,
            });
            // 同梱マニフェスト(§12-4 — 2026-08-18): manifestVersion 1・変数
            // 空集合・epoch 1。envMeta は同梱ステートメント自身。CAS リトライでは
            // エントリ・ステートメント・マニフェストの全部を再署名する
            const signedManifest = yield* signNextManifest({
              verified: state.verified,
              environmentId: input.environmentId,
              epoch: 1,
              previous: null,
              entries: [],
              envMeta: { metaVersion: 1, sigHashHex: metaSigHashHex },
              issuerUserId: input.signerUserId,
              signingKey: input.signingKeyPair.privateKey,
              chainHead: {
                seq: state.verified.state.headSeq,
                hashHex: state.verified.state.headHashHex,
              },
            });
            // 作成複合のワイヤ形(manifestVersion 1・prev 空)への絞り込み
            const manifest = signedManifest.manifest;
            if (manifest.manifestVersion !== 1 || manifest.prevManifestSigHashHex !== "") {
              return yield* Effect.fail(cliError("Failed to sign the environment manifest"));
            }
            yield* input.client.environments.create({
              params: { projectId: state.verified.projectId },
              payload: {
                parentHeadHashHex: state.verified.state.headHashHex,
                entry,
                statement,
                deks: state.deks,
                manifest: {
                  ...manifest,
                  manifestVersion: 1,
                  prevManifestSigHashHex: "",
                },
              },
            });
            // 作成直後の現エポックは**構造的に 1**(§12-4 — 同梱エントリは
            // create_environment であり、サーバー側も 1 を返す)。応答申告の
            // currentEpoch は使わない: 受理後の事実をサーバーの自己申告から
            // 取ると、rotate 側で敷いた「申告を真実源にしない」規律が create
            // 側だけ緩む。ここに rotate のような再同期での照合を足す必要は
            // ない — この DEK を使う次のコマンドが、チェーン導出コミットメント
            // との照合(§5.2 / deks.ts)を必ず通すためである。
            //
            // メンバー数は**実際に登録したラップ集合**の大きさ(CAS リトライで
            // 作り直した場合、呼び出し側の古いビューのメンバー数とは食い違いうる)
            return { currentEpoch: 1, memberCount: state.deks.length };
          }),
        classify: (error) => (error instanceof ChainHeadConflictError ? "head-conflict" : null),
        // 親ヘッド CAS 失敗(並行追記): 再同期して新ヘッドでエントリを再署名する
        // (§12-4)。ラップ集合は現メンバー集合が変わった場合のみ作り直す。
        // 再同期で判明する定的エラー(並行作成による duplicate-environment 等)は
        // retryOnConflict の規約どおり最終試行後も表面化する
        recover: (state) =>
          Effect.gen(function* () {
            // 再同期は**延長検査付き**(§6.3-2b): ChainHeadConflict を返した
            // サーバーが、署名としては妥当な短縮・分岐チェーンを配ってきた場合に、
            // 巻き戻ったメンバー / grant 状態でエントリを再署名しラップ集合を
            // 作り直してしまう経路を塞ぐ(env-rotate の CAS リトライと同じ規律)
            const resynced = yield* resyncExtended(input.resync, state.verified);
            const rebuiltMember = yield* ensureCreatable(
              resynced,
              input.environmentId,
              input.signerUserId,
            );
            const rebuiltDeks = sameWrapRecipientSet(state.verified, resynced, input.environmentId)
              ? state.deks
              : yield* buildWrapCompleteSet({
                  verified: resynced,
                  environmentId: input.environmentId,
                  epoch: 1,
                  dek,
                  signerUserId: input.signerUserId,
                  signingKeyPair: input.signingKeyPair,
                });
            return { verified: resynced, member: rebuiltMember, deks: rebuiltDeks };
          }),
        exhaustedMessage: `The environment creation's chain-head conflict did not resolve (${MAX_ATTEMPTS} attempts). Wait a moment and re-run`,
      },
    );
  });
}
