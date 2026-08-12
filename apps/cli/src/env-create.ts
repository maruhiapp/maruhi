// 環境作成の複合リクエスト(AUTH_SPEC §12-4。2026-08-03 の環境作成チェーン op 化):
// `create_environment` チェーンエントリ(エポック 1 の DEK コミットメント込み —
// CRYPTO_SPEC §5.2 / §6.2)+ `EnvironmentMetaStatement`(metaVersion 1 — §4.2。
// 表示名は署名前に NFC 正規化し、宣言ヘッドは追記前の現ヘッド = 同梱エントリの
// prev)+ エポック 1 の DEK ラップ完全集合を 1 リクエストで原子的に受理させる。
// 親ヘッド CAS の失敗(ChainHeadConflict)は再同期 → **エントリとステートメントの
// 両方を再署名**(seq / prev / 宣言ヘッド変更 — §12-4)してリトライする。
//
// ラップ集合の生成は dek-wrap.ts の共有実装(env-rotate.ts と共通)。
// grant_server が有効なプロジェクトは拒否する: サーバー宛ラップのデータ
// プレーンは Phase 2 未実装で、メンバー宛のみの登録は §7 の開示契約を
// 黙って破ることになるため。

import type { WrappedDek } from "@maruhi/api-schema";
import { ChainHeadConflictError } from "@maruhi/api-schema";
import type { EnvironmentId } from "@maruhi/core";
import type { ChainEntry, ChainMember, SigningKeyPair } from "@maruhi/crypto";
import { computeDekCommitment, generateDek, signChainEntry, SUITE_ID } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { buildWrapSetForMembers, ensureNoServerGrant, sameMemberSet } from "./dek-wrap.ts";
import { cliError, type CliError } from "./errors.ts";
import { signCreateStatement } from "./meta-statement.ts";
import { retryOnConflict } from "./retry.ts";
import type { VerifiedProject } from "./sync.ts";

const MAX_ATTEMPTS = 5;

function ensureCreatable(
  verified: VerifiedProject,
  environmentId: string,
  signerUserId: string,
): Effect.Effect<ChainMember, CliError> {
  return Effect.gen(function* () {
    yield* ensureNoServerGrant(verified, "環境作成");
    // environment_id はチェーン履歴全体で一意(合意規則 duplicate-environment —
    // CRYPTO_SPEC §6.2)。サーバーの 422 を待たずクライアントでも早期検出する
    if (verified.state.environments.has(environmentId)) {
      return yield* Effect.fail(
        cliError(
          `環境 ID ${environmentId} はチェーン上で使用済みです(create_environment 観測済み — 削除済み環境の ID も再利用できません)。別の ID を使ってください`,
        ),
      );
    }
    const member = verified.state.members.get(signerUserId);
    if (member === undefined) {
      return yield* Effect.fail(
        cliError("このプロジェクトのチェーン導出メンバーではありません(環境を作成できません)"),
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
      catch: () => cliError("create_environment エントリの署名に失敗しました"),
    });
    if (!signed.ok) {
      return yield* Effect.fail(cliError("create_environment エントリの署名に失敗しました"));
    }
    // op の絞り込み(signChainEntry は入力の op を保存する)
    if (signed.value.op !== "create_environment") {
      return yield* Effect.fail(cliError("create_environment エントリの署名に失敗しました"));
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
}): Effect.Effect<{ readonly currentEpoch: number }, CliError> {
  return Effect.gen(function* () {
    const member = yield* ensureCreatable(input.verified, input.environmentId, input.signerUserId);
    // 正規化の実施主体は署名前のクライアント(§4.2 / §12-1)
    const name = input.name.normalize("NFC");
    const dek = generateDek();
    const commitment = yield* Effect.tryPromise({
      try: () =>
        computeDekCommitment({
          context: {
            suite: SUITE_ID,
            projectId: input.verified.projectId,
            environmentId: input.environmentId,
            epoch: 1,
          },
          dek,
        }),
      catch: () => cliError("DEK コミットメントの計算に失敗しました"),
    });
    if (!commitment.ok) {
      return yield* Effect.fail(cliError("DEK コミットメントの計算に失敗しました"));
    }
    const deks = yield* buildWrapSetForMembers({
      verified: input.verified,
      environmentId: input.environmentId,
      epoch: 1,
      dek,
      signerUserId: input.signerUserId,
      signingKeyPair: input.signingKeyPair,
    });

    return yield* retryOnConflict<CreateState, { readonly currentEpoch: number }, "head-conflict">(
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
            const { statement } = yield* signCreateStatement({
              verified: state.verified,
              environmentId: input.environmentId,
              target: { kind: "environment" },
              name,
              authorUserId: input.signerUserId,
              signingKey: input.signingKeyPair.privateKey,
            });
            const created = yield* input.client.environments.create({
              params: { projectId: state.verified.projectId },
              payload: {
                parentHeadHashHex: state.verified.state.headHashHex,
                entry,
                statement,
                deks: state.deks,
              },
            });
            return { currentEpoch: created.currentEpoch };
          }),
        classify: (error) => (error instanceof ChainHeadConflictError ? "head-conflict" : null),
        // 親ヘッド CAS 失敗(並行追記): 再同期して新ヘッドでエントリを再署名する
        // (§12-4)。ラップ集合は現メンバー集合が変わった場合のみ作り直す。
        // 再同期で判明する定的エラー(並行作成による duplicate-environment 等)は
        // retryOnConflict の規約どおり最終試行後も表面化する
        recover: (state) =>
          Effect.gen(function* () {
            const resynced = yield* input.resync;
            const rebuiltMember = yield* ensureCreatable(
              resynced,
              input.environmentId,
              input.signerUserId,
            );
            const rebuiltDeks = sameMemberSet(state.verified, resynced)
              ? state.deks
              : yield* buildWrapSetForMembers({
                  verified: resynced,
                  environmentId: input.environmentId,
                  epoch: 1,
                  dek,
                  signerUserId: input.signerUserId,
                  signingKeyPair: input.signingKeyPair,
                });
            return { verified: resynced, member: rebuiltMember, deks: rebuiltDeks };
          }),
        exhaustedMessage: `環境作成のチェーンヘッド競合が解消しません(${MAX_ATTEMPTS} 回試行)。時間をおいて再実行してください`,
      },
    );
  });
}
