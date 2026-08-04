// 環境作成の複合リクエスト(AUTH_SPEC §12-4。2026-08-03 の環境作成チェーン op 化):
// `create_environment` チェーンエントリ(エポック 1 の DEK コミットメント込み —
// CRYPTO_SPEC §5.2 / §6.2)+ `EnvironmentMetaStatement`(metaVersion 1 — §4.2。
// 表示名は署名前に NFC 正規化し、宣言ヘッドは追記前の現ヘッド = 同梱エントリの
// prev)+ エポック 1 の DEK ラップ完全集合を 1 リクエストで原子的に受理させる。
// 親ヘッド CAS の失敗(ChainHeadConflict)は再同期 → **エントリとステートメントの
// 両方を再署名**(seq / prev / 宣言ヘッド変更 — §12-4)してリトライする。
//
// ラップ集合は検証済み ChainState の現メンバー集合と厳密一致させて生成する
// (CRYPTO_SPEC §6.3 のラップ先一致検査 = ゴーストメンバー対策のクライアント側。
// サーバーの §12-6 検証は補助線であり、こちらが本線 — session-07 §5)。
// ラップ生成 → signDekWrap → 登録は一続きで行う(署名者 = 呼び出し主体 —
// session-10 §5)。CAS リトライでの作り直しは、再同期で現メンバー集合が変わった
// 場合のみ(§12-4 — HPKE Seal はランダムなので不要な再ラップを避ける)。
//
// grant_server が有効なプロジェクトは拒否する: サーバー宛ラップのデータ
// プレーンは Phase 2 未実装で、メンバー宛のみの登録は §7 の開示契約を
// 黙って破ることになるため。

import type { WrappedDek } from "@maruhi/api-schema";
import { ChainHeadConflictError } from "@maruhi/api-schema";
import type { EnvironmentId } from "@maruhi/core";
import type { ChainEntry, ChainMember, SigningKeyPair } from "@maruhi/crypto";
import {
  computeDekCommitment,
  decodeHex,
  encodeHex,
  generateDek,
  importEncryptionPublicKey,
  signChainEntry,
  signDekWrap,
  signMetaStatement,
  SUITE_ID,
  wrapDek,
} from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import type { VerifiedProject } from "./sync.ts";

const MAX_ATTEMPTS = 5;

async function wrapAndSignFor(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly epoch: number;
  readonly dek: Uint8Array;
  readonly member: ChainMember;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
}): Promise<WrappedDek | null> {
  const { verified, environmentId, epoch, dek, member } = input;
  const recipientKeyBytes = decodeHex(member.encPubHex);
  if (recipientKeyBytes === null) {
    return null;
  }
  const recipientKey = await importEncryptionPublicKey(recipientKeyBytes);
  if (!recipientKey.ok) {
    return null;
  }
  const wrapped = await wrapDek({
    recipientPublicKey: recipientKey.value,
    dek,
    context: {
      projectId: verified.projectId,
      environmentId,
      epoch,
      recipientUserId: member.userId,
    },
  });
  if (!wrapped.ok) {
    return null;
  }
  const encHex = encodeHex(wrapped.value.enc);
  const ciphertextHex = encodeHex(wrapped.value.ciphertext);
  const signature = await signDekWrap({
    context: {
      suite: SUITE_ID,
      projectId: verified.projectId,
      environmentId,
      epoch,
      recipientUserId: member.userId,
      recipientEncPubHex: member.encPubHex,
      encHex,
      ciphertextHex,
      signerUserId: input.signerUserId,
    },
    signingKey: input.signingKeyPair.privateKey,
  });
  if (!signature.ok) {
    return null;
  }
  return {
    suite: SUITE_ID,
    epoch,
    recipientUserId: member.userId,
    recipientEncPubHex: member.encPubHex,
    encHex,
    ciphertextHex,
    signatureHex: signature.value,
  };
}

/**
 * Builds the wrap set for one epoch: exactly the verified current member set
 * (§6.3), each wrap signed by the caller (§5.1). Deterministic recipient
 * order (userId ascending) for reproducible requests.
 */
function buildWrapSetForMembers(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly epoch: number;
  readonly dek: Uint8Array;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<readonly WrappedDek[], CliError> {
  return Effect.gen(function* () {
    const members = [...input.verified.state.members.values()].toSorted((a, b) =>
      a.userId < b.userId ? -1 : 1,
    );
    const wraps: WrappedDek[] = [];
    for (const member of members) {
      const wrap = yield* Effect.promise(() => wrapAndSignFor({ ...input, member }));
      if (wrap === null) {
        return yield* Effect.fail(
          cliError(`メンバー ${member.userId} 宛の DEK ラップ生成に失敗しました`),
        );
      }
      wraps.push(wrap);
    }
    return wraps;
  });
}

/** 現メンバー集合(user_id → enc 公開鍵)の同一性。ラップ集合の再利用可否の判定。 */
function sameMemberSet(a: VerifiedProject, b: VerifiedProject): boolean {
  if (a.state.members.size !== b.state.members.size) {
    return false;
  }
  for (const [userId, member] of a.state.members) {
    if (b.state.members.get(userId)?.encPubHex !== member.encPubHex) {
      return false;
    }
  }
  return true;
}

function ensureCreatable(
  verified: VerifiedProject,
  environmentId: string,
  signerUserId: string,
): Effect.Effect<ChainMember, CliError> {
  if (verified.state.serverGrants.size > 0) {
    return Effect.fail(
      cliError(
        "このプロジェクトは grant_server が有効です。サーバー宛 DEK ラップは Phase 2 未実装のため、CLI からの環境作成は行えません",
      ),
    );
  }
  // environment_id はチェーン履歴全体で一意(合意規則 duplicate-environment —
  // CRYPTO_SPEC §6.2)。サーバーの 422 を待たずクライアントでも早期検出する
  if (verified.state.environments.has(environmentId)) {
    return Effect.fail(
      cliError(
        `環境 ID ${environmentId} はチェーン上で使用済みです(create_environment 観測済み — 削除済み環境の ID も再利用できません)。別の ID を使ってください`,
      ),
    );
  }
  const member = verified.state.members.get(signerUserId);
  if (member === undefined) {
    return Effect.fail(
      cliError("このプロジェクトのチェーン導出メンバーではありません(環境を作成できません)"),
    );
  }
  return Effect.succeed(member);
}

/**
 * 複合同梱の `EnvironmentMetaStatement`(metaVersion 1・active・prev 空)を
 * 著者署名する。宣言ヘッドは追記前の現ヘッド(= 同梱エントリの prev — §12-4)。
 * CAS リトライではエントリと共にここも再署名される。
 */
function signCreateStatement(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly name: string;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
}) {
  return Effect.gen(function* () {
    const signature = yield* Effect.promise(() =>
      signMetaStatement({
        context: {
          suite: SUITE_ID,
          projectId: input.verified.projectId,
          environmentId: input.environmentId,
          target: { kind: "environment" },
          name: input.name,
          status: "active",
          metaVersion: 1,
          prevMetaSigHashHex: "",
          authorUserId: input.signerUserId,
          chainHeadHashHex: input.verified.state.headHashHex,
          chainHeadSeq: input.verified.state.headSeq,
        },
        signingKey: input.signingKeyPair.privateKey,
      }),
    );
    if (!signature.ok) {
      return yield* Effect.fail(cliError("環境メタステートメントの署名に失敗しました"));
    }
    return {
      suite: SUITE_ID,
      environmentId: input.environmentId,
      name: input.name,
      status: "active",
      metaVersion: 1,
      prevMetaSigHashHex: "",
      chainHeadHashHex: input.verified.state.headHashHex,
      chainHeadSeq: input.verified.state.headSeq,
      signatureHex: signature.value,
    } as const;
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
    const signed = yield* Effect.promise(() =>
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
    );
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
    let verified = input.verified;
    let member = yield* ensureCreatable(verified, input.environmentId, input.signerUserId);
    // 正規化の実施主体は署名前のクライアント(§4.2 / §12-1)
    const name = input.name.normalize("NFC");
    const dek = generateDek();
    const commitment = yield* Effect.promise(() =>
      computeDekCommitment({
        context: {
          suite: SUITE_ID,
          projectId: verified.projectId,
          environmentId: input.environmentId,
          epoch: 1,
        },
        dek,
      }),
    );
    if (!commitment.ok) {
      return yield* Effect.fail(cliError("DEK コミットメントの計算に失敗しました"));
    }
    let deks = yield* buildWrapSetForMembers({
      verified,
      environmentId: input.environmentId,
      epoch: 1,
      dek,
      signerUserId: input.signerUserId,
      signingKeyPair: input.signingKeyPair,
    });

    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt += 1) {
      // CAS リトライではエントリ(prev 変更)とステートメント(宣言ヘッド変更)の
      // **両方**を再署名する(§12-4)。ラップ集合はメンバー集合変化時のみ再構築
      const entry = yield* signCreateEntry({
        verified,
        environmentId: input.environmentId,
        dekCommitmentHex: commitment.value,
        member,
        signingKeyPair: input.signingKeyPair,
      });
      const statement = yield* signCreateStatement({
        verified,
        environmentId: input.environmentId,
        name,
        signerUserId: input.signerUserId,
        signingKeyPair: input.signingKeyPair,
      });
      const outcome = yield* input.client.environments
        .create({
          params: { projectId: verified.projectId },
          payload: {
            parentHeadHashHex: verified.state.headHashHex,
            entry,
            statement,
            deks,
          },
        })
        .pipe(
          Effect.map((created) => ({ kind: "created", created }) as const),
          Effect.catch((error) =>
            error instanceof ChainHeadConflictError
              ? Effect.succeed({ kind: "head-conflict" } as const)
              : Effect.fail(toCliError(error)),
          ),
        );
      if (outcome.kind === "created") {
        return { currentEpoch: outcome.created.currentEpoch };
      }
      // 親ヘッド CAS 失敗(並行追記): 再同期して新ヘッドでエントリを再署名する
      // (§12-4)。ラップ集合は現メンバー集合が変わった場合のみ作り直す。
      // 最終試行後もここを実行する: 再同期で判明する定的エラー(並行作成による
      // duplicate-environment 等)は汎用の「競合が解消しません」より情報量が高い
      // (push.ts の nextState と同じ判断)
      const resynced = yield* input.resync;
      const rebuiltMember = yield* ensureCreatable(
        resynced,
        input.environmentId,
        input.signerUserId,
      );
      if (!sameMemberSet(verified, resynced)) {
        deks = yield* buildWrapSetForMembers({
          verified: resynced,
          environmentId: input.environmentId,
          epoch: 1,
          dek,
          signerUserId: input.signerUserId,
          signingKeyPair: input.signingKeyPair,
        });
      }
      verified = resynced;
      member = rebuiltMember;
    }
    return yield* Effect.fail(
      cliError(
        `環境作成のチェーンヘッド競合が解消しません(${MAX_ATTEMPTS} 回試行)。時間をおいて再実行してください`,
      ),
    );
  });
}
