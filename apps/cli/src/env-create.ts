// 環境作成の複合リクエスト(AUTH_SPEC §12-4。2026-08-03 の環境作成チェーン op 化):
// `create_environment` チェーンエントリ(エポック 1 の DEK コミットメント込み —
// CRYPTO_SPEC §5.2 / §6.2)+ `EnvironmentMetaStatement`(metaVersion 1 — §4.2。
// 表示名は署名前に NFC 正規化し、宣言ヘッドは追記前の現ヘッド = 同梱エントリの
// prev)+ エポック 1 の DEK ラップ完全集合を 1 リクエストで原子的に受理させる。
// 親ヘッド CAS の失敗(ChainHeadConflict)は再同期 → **エントリとステートメントの
// 両方を再署名**(seq / prev / 宣言ヘッド変更 — §12-4)してリトライする。
//
// 成功の定義(AUTH_SPEC §12-10 (3) — 1-E′): 2xx は輸送層の事実でしかない。
// 複合の効果確認は**チェーン同期**で行う — 検証済みチェーン上に自エントリ
// (エポック 1 の DEK commitment が自分の生成した DEK のもの)を確認してから、
// 自己発行マニフェスト込みの v1 床(空変数集合 — session-31 §3 M1-A3)を確立し、
// 成功を報告する。送信前には intent レコード(§6.3 記録規律 (ii) — 3-F)を
// 床ログへ追記する(応答消失・クラッシュ時は次の実行の照合が解決する)。
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
import { isServerRejection } from "./failure.ts";
import type { FloorHandle } from "./floor-check.ts";
import type { ManifestFloor } from "./floor.ts";
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

/** 受理された(2xx が返った)複合の、効果確認と床確立の材料。 */
interface AcceptedCreation {
  readonly state: CreateState;
  /** 自己発行 manifestVersion 1 の床記録(自計算値)。 */
  readonly manifest: ManifestFloor;
  /** 同梱ステートメント(metaVersion 1)の signed-bytes ハッシュ(v1 床の環境メタ)。 */
  readonly metaSigHashHex: string;
  /** 送信前に追記した intent(3-F)の id。 */
  readonly intentId: string;
}

/**
 * `maruhi env create`: create an environment through the §12-4 composite —
 * the signed `create_environment` entry (epoch-1 DEK commitment), the display
 * name and the epoch-1 wrap set, retrying head-CAS conflicts with a re-signed
 * entry (and a rebuilt wrap set only when the member set changed).
 *
 * 受理後はチェーン同期で効果を確認し(§12-10 (3) — チェーン上の自エントリの
 * エポック 1 commitment が自分の生成した DEK のもの)、確認を通過して初めて
 * v1 床(空変数集合 + 自己発行マニフェスト — M1-A3)を確立し成功を報告する。
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
  /** ローカル床(§6.3 — intent の追記と、受理確認後の v1 床確立)。 */
  readonly floor: FloorHandle;
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

    const accepted = yield* retryOnConflict<CreateState, AcceptedCreation, "head-conflict">(
      { verified: input.verified, member, deks },
      {
        maxAttempts: MAX_ATTEMPTS,
        // CAS リトライではエントリ(prev 変更)とステートメント(宣言ヘッド変更)の
        // **両方**を再署名する(§12-4)。ラップ集合はメンバー集合変化時のみ再構築
        attempt: (state) => attemptCreate(input, state, { name, commitmentHex: commitment.value }),
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
    // 効果確認(§12-10 (3))を通過して初めて床を確立し成功を報告する
    yield* confirmCreation(input, accepted, commitment.value);
    // 作成直後の現エポックは**構造的に 1**(§12-4 — 同梱エントリは
    // create_environment であり、上の確認がチェーン導出値で裏を取っている)。
    // メンバー数は**実際に登録したラップ集合**の大きさ(CAS リトライで作り直した
    // 場合、呼び出し側の古いビューのメンバー数とは食い違いうる)
    return { currentEpoch: 1, memberCount: accepted.state.deks.length };
  });
}

/** 1 試行分の署名(エントリ・ステートメント・マニフェスト)+ intent + 送信。 */
function attemptCreate(
  input: {
    readonly client: MaruhiClient;
    readonly environmentId: EnvironmentId;
    readonly signerUserId: string;
    readonly signingKeyPair: SigningKeyPair;
    readonly floor: FloorHandle;
  },
  state: CreateState,
  material: { readonly name: string; readonly commitmentHex: string },
): Effect.Effect<AcceptedCreation, unknown> {
  return Effect.gen(function* () {
    const entry = yield* signCreateEntry({
      verified: state.verified,
      environmentId: input.environmentId,
      dekCommitmentHex: material.commitmentHex,
      member: state.member,
      signingKeyPair: input.signingKeyPair,
    });
    // 宣言ヘッドは追記前の現ヘッド(= 同梱エントリの prev — §12-4)。
    // 共有実装(meta-statement.ts)— push.ts との差分は target のみ
    const { statement, metaSigHashHex } = yield* signCreateStatement({
      verified: state.verified,
      environmentId: input.environmentId,
      target: { kind: "environment" },
      name: material.name,
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
    // journal-before-send(3-F): 送信前に intent を追記する(永続化に失敗したら
    // 送信しない — fail-closed)。応答消失・クラッシュで失われるのは「成功した
    // という思い込み」ではなく「確認義務の記録」になる
    const intentId = yield* input.floor.appendIntent({
      op: "create_environment",
      environmentId: input.environmentId,
      epoch: 1,
      dekCommitmentHex: material.commitmentHex,
      variableId: null,
      manifestVersion: 1,
      manifestSigHashHex: signedManifest.manifestSigHashHex,
      declaredHead: {
        seq: state.verified.state.headSeq,
        hashHex: state.verified.state.headHashHex,
      },
    });
    yield* input.client.environments
      .create({
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
      })
      .pipe(
        Effect.tapError((error) =>
          // サーバー自身のエラー本文での拒否(CAS 409 含む)= 効果は生じて
          // いない(確定)— intent を閉じる。転送層の失敗(応答消失)は
          // 未解決のまま残し、次の実行の照合(チェーン同期)が解決する
          isServerRejection(error)
            ? Effect.ignore(input.floor.resolveIntent(intentId, "rejected"))
            : Effect.void,
        ),
      );
    return {
      state,
      manifest: {
        manifestVersion: 1,
        epoch: 1,
        manifestSigHashHex: signedManifest.manifestSigHashHex,
      },
      metaSigHashHex,
      intentId,
    };
  });
}

/**
 * 受理後の効果確認(§12-10 (3) — チェーン同期)と v1 床の確立(M1-A3)。
 * 確認を通過するまで床は前進させず、成功も報告しない。
 */
function confirmCreation(
  input: {
    readonly environmentId: EnvironmentId;
    readonly resync: Effect.Effect<VerifiedProject, CliError>;
    readonly floor: FloorHandle;
  },
  accepted: AcceptedCreation,
  commitmentHex: string,
): Effect.Effect<void, CliError> {
  return Effect.gen(function* () {
    const view = yield* resyncExtended(input.resync, accepted.state.verified).pipe(
      Effect.mapError((error) =>
        cliError(
          `The environment creation was accepted (2xx), but the chain sync for the post-acceptance confirmation failed (AUTH_SPEC §12-10 (3) — success is defined by the confirmed effect, not the 2xx): ${error.message}. Environment ${input.environmentId} may already exist — re-run any command against this project after restoring connectivity; the recorded intent will be reconciled against the chain`,
        ),
      ),
    );
    const environment = view.state.environments.get(input.environmentId);
    if (environment === undefined || environment.dekCommitments.get(1) !== commitmentHex) {
      // 2xx なのに検証済みチェーンに自エントリがない / 別 DEK の作成が載って
      // いる = サーバーの応答がチェーンと矛盾している(効果は確認できない)
      return yield* Effect.fail(
        cliError(
          `The environment creation was accepted (2xx), but the verified chain does not show this run's create_environment entry for ${input.environmentId} (the epoch-1 DEK commitment does not match the generated DEK's). The server response contradicts the chain — treating the creation as unconfirmed (AUTH_SPEC §12-10 (3))`,
        ),
      );
    }
    // 確認済み — v1 床の確立(M1-A3): 空変数集合の環境床。作成複合は変数
    // 空集合をエポック 1 で確立する(変数は環境より先に存在できない)ため、
    // 規則 (c) の pull 基準も値床カバレッジ(空)と原子的に 1 で確立できる。
    // journal-before-release: 床の永続化が成功報告に先行する
    yield* input.floor
      .commitPull(
        {
          pullEpoch: 1,
          observedEpoch: 1,
          metaVersion: 1,
          metaSigHashHex: accepted.metaSigHashHex,
          manifest: accepted.manifest,
          variables: {},
        },
        { seq: view.state.headSeq, hashHex: view.state.headHashHex },
      )
      .pipe(
        Effect.mapError((error) =>
          cliError(`The environment was created and confirmed on the chain, but ${error.message}`),
        ),
      );
    // resolution の追記失敗は握り潰してよい: intent が開いたまま残る方向は
    // 安全側(次の実行の照合が同じ判定をやり直すだけ)
    yield* Effect.ignore(input.floor.resolveIntent(accepted.intentId, "accepted"));
  });
}
