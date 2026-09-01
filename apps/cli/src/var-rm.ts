// `maruhi var rm <NAME>` — 変数の削除(S3 PR #121 レビュー申し送りの採用)。
//
// ワイヤ・受理・検証は既存(DeleteVariableMetaStatement v1 / V2 + マニフェスト
// 複合 — AUTH_SPEC §12-5)。本モジュールは CLI 側の署名・送信・確認だけを足す:
//
//   - v1 変数の削除は v1 形のまま(レイアウトを勝手に上げない)。v2 変数の削除は
//     **スキーマ欄・レイアウトの直前 byte-exact 保持**(CRYPTO_SPEC §4.2 の削除
//     規約 — サーバーは不一致を 422 payload-mismatch で強制する)。name は
//     直前の active 名をそのまま保持する(削除で名前フィールドを空にしない)
//   - 削除は終端(deleted からの復帰は存在しない — §4.2)。active(値あり)の
//     削除は全バージョンの暗号文の即時削除を伴う(§12-5)。だから対話の明示
//     確認(変数名の再入力)を必須にし、非対話環境では --force なしに拒否する
//     (fail-closed)。declared(値なし)も黙っては消さない — 同じ確認に載せる
//   - メタ操作の既存規律に載せる: 3-F(journal-before-send — issueManifestWithIntent)
//     + 1-E′(効果確認 — confirmMetaMutation)+ 床の tombstone 前進(commitPush)
//
// コマンドを schema グループに置かない理由: 消えるのはスキーマでなく変数と
// 値そのもの(スキーマ欄はその一部にすぎない)。

import { ManifestVersionConflictError, MetaVersionConflictError } from "@maruhi/api-schema";
import type { EnvironmentId } from "@maruhi/core";
import { SUITE_ID } from "@maruhi/crypto";
import { Effect, Stdio } from "effect";

import type { MaruhiClient } from "./api.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import type { FloorHandle, VerifiedVariableStatement } from "./floor-check.ts";
import { rejectIntentOnServerRejection } from "./floor-check.ts";
import { CliIo } from "./io.ts";
import { confirmMetaMutation, issueManifestWithIntent } from "./meta-confirm.ts";
import { signStatementAndHash } from "./meta-statement.ts";
import { retryOnConflict } from "./retry.ts";
import { signDeleteStatementV2 } from "./schema-statement.ts";
import { resolveSchemaTarget, type SchemaSetState } from "./schema.ts";
import type { VerifiedProject } from "./sync.ts";
import type { VerifiedEnvironmentMetadata } from "./values.ts";

const MAX_ATTEMPTS = 5;

export interface VarRmInput {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  /** 変数名(NFC 正規化は本関数が行う — §12-1)。 */
  readonly name: string;
  /** true = 確認をスキップ(非対話の唯一の経路 — 明示のリスク受諾)。 */
  readonly force: boolean;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly floor: FloorHandle;
  readonly authorUserId: string;
  readonly signingKey: CryptoKey;
}

export interface VarRmSummary {
  readonly variableId: string;
  readonly metaVersion: number;
  /** 削除前の状態(active = 値も消えた / declared = 宣言のみ)。 */
  readonly previousStatus: "active" | "declared";
  readonly warnings: readonly string[];
}

/** 対象の解決(削除済み・未存在の言い分けは呼び出し前の状態で行う)。 */
function resolveDeletionTarget(
  input: VarRmInput,
  verified: VerifiedProject,
  name: string,
): Effect.Effect<SchemaSetState & { readonly target: VerifiedVariableStatement }, CliError> {
  return Effect.gen(function* () {
    const state = yield* resolveSchemaTarget(input, verified, name);
    const target = state.target;
    if (target !== null) {
      return { ...state, target };
    }
    if (state.tombstones.some((tombstone) => tombstone.name === name)) {
      // 削除は終端(§4.2)— 既に削除済みの名前への rm は「望んだ状態」ではあるが
      // 呼び出しの前提(この実行が消す)が成り立っていないので明示エラーにする
      return yield* Effect.fail(
        cliError(
          `Variable ${displayText(name)} is already deleted (deletion is terminal — a deleted variable cannot be restored). Nothing was changed by this run`,
        ),
      );
    }
    return yield* Effect.fail(
      cliError(`Variable ${displayText(name)} does not exist in this environment`),
    );
  });
}

/**
 * 削除の明示確認(fail-closed): --force なしでは、対話端末(stdin と stdout の
 * 両方が端末 — Stdio サービス経由)で**変数名の再入力**を要求する。非対話では
 * --force なしに拒否する。判定材料をサービス経由で取るのは CLAUDE.md の
 * 「process.* を直に読まない」規律。
 */
function ensureDeletionConfirmed(
  input: VarRmInput,
  target: VerifiedVariableStatement,
  name: string,
): Effect.Effect<void, CliError, CliIo | Stdio.Stdio> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const consequence =
      target.status === "active"
        ? "its value (every stored version) is deleted immediately and cannot be recovered"
        : "the declaration (no value was set) is removed";
    if (input.force) {
      // 明示フラグ = リスクの明示受諾。それでも事実は可視化する(黙って消さない)
      yield* io.logError(
        `Deleting ${displayText(name)} without confirmation (--force): ${consequence}. Deletion is terminal — the variable cannot be restored`,
      );
      return;
    }
    const stdio = yield* Stdio.Stdio;
    const interactive = (yield* stdio.stdinIsTerminal) && (yield* stdio.stdoutIsTerminal);
    if (!interactive) {
      return yield* Effect.fail(
        cliError(
          `Refusing to delete ${displayText(name)} in a non-interactive environment without --force (deletion is terminal and, for a variable with a value, destroys every stored version). Re-run with --force to accept that explicitly`,
        ),
      );
    }
    yield* io.logError(
      `You are about to delete ${displayText(name)}: ${consequence}. Deletion is terminal — the variable cannot be restored`,
    );
    const answer = yield* io.promptLine({
      prompt: `Type the variable name to confirm the permanent deletion: `,
    });
    if (answer.trim().normalize("NFC") !== name) {
      return yield* Effect.fail(
        cliError("Aborted: the typed name did not match (nothing was signed or sent)"),
      );
    }
  });
}

interface AcceptedDeletion {
  readonly variableId: string;
  readonly metaVersion: number;
  readonly metaSigHashHex: string;
  readonly previousStatus: "active" | "declared";
  readonly selfManifest: {
    readonly manifestVersion: number;
    readonly epoch: number;
    readonly manifestSigHashHex: string;
  };
  readonly intentId: string;
  readonly state: SchemaSetState;
}

/** v1 変数の削除ステートメント(v1 形のまま — レイアウトを勝手に上げない)。 */
function signDeleteStatementV1(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly target: VerifiedVariableStatement;
  readonly authorUserId: string;
  readonly signingKey: CryptoKey;
}) {
  return Effect.gen(function* () {
    // 署名対象 context は 1 回だけ構築し、ワイヤは機械的に導出する
    // (meta-statement.ts / schema-statement.ts と同じ規律)
    const context = {
      suite: SUITE_ID,
      projectId: input.verified.projectId,
      environmentId: input.environmentId,
      target: { kind: "variable", variableId: input.target.variableId },
      // name は直前の active 名をそのまま保持する(§4.2 — 削除で空にしない)
      name: input.target.name,
      status: "deleted",
      metaVersion: input.target.metaVersion + 1,
      prevMetaSigHashHex: input.target.metaSigHashHex,
      authorUserId: input.authorUserId,
      chainHeadHashHex: input.verified.state.headHashHex,
      chainHeadSeq: input.verified.state.headSeq,
    } as const;
    const signed = yield* signStatementAndHash(context, input.signingKey);
    return {
      statement: {
        suite: context.suite,
        environmentId: context.environmentId,
        variableId: context.target.variableId,
        name: context.name,
        status: context.status,
        metaVersion: context.metaVersion,
        prevMetaSigHashHex: context.prevMetaSigHashHex,
        chainHeadHashHex: context.chainHeadHashHex,
        chainHeadSeq: context.chainHeadSeq,
        signatureHex: signed.signatureHex,
      },
      metaSigHashHex: signed.metaSigHashHex,
    };
  });
}

/** 1 試行(署名・送信)。競合の分類は retryOnConflict の classify が担う。 */
function attemptDeletion(
  input: VarRmInput,
  state: SchemaSetState & { readonly target: VerifiedVariableStatement },
): Effect.Effect<AcceptedDeletion, unknown> {
  return Effect.gen(function* () {
    const target = state.target;
    const environment = state.verified.state.environments.get(input.environmentId);
    if (environment === undefined) {
      return yield* Effect.fail(
        cliError(
          `Environment ${displayText(input.environmentId)} does not exist on the verified chain`,
        ),
      );
    }
    if (target.status !== "active" && target.status !== "declared") {
      return yield* Effect.fail(
        cliError("The resolved deletion target is not a live variable (internal inconsistency)"),
      );
    }
    const previousStatus = target.status;
    // v2 変数の削除は v2 形(スキーマ欄・レイアウトの直前 byte-exact 保持 —
    // §12-5 の削除規約)、v1 変数の削除は v1 形のまま
    const signed =
      target.layoutVersion === 2 && target.schema !== null
        ? yield* signDeleteStatementV2({
            verified: state.verified,
            environmentId: input.environmentId,
            variableId: target.variableId,
            name: target.name,
            schema: target.schema,
            prev: { metaVersion: target.metaVersion, metaSigHashHex: target.metaSigHashHex },
            authorUserId: input.authorUserId,
            signingKey: input.signingKey,
          })
        : yield* signDeleteStatementV1({
            verified: state.verified,
            environmentId: input.environmentId,
            target,
            authorUserId: input.authorUserId,
            signingKey: input.signingKey,
          });
    // マニフェストは対象エントリを tombstone へ差し替える(§4.3 — ダイジェストは
    // tombstone を含む全ステートメントを覆う)。3-F intent は送信前に永続化する
    const { manifest, intentId } = yield* issueManifestWithIntent({
      verified: state.verified,
      environmentId: input.environmentId,
      epoch: environment.currentEpoch,
      previous: state.manifestBase.previous,
      entries: [
        ...state.manifestBase.entries.filter((entry) => entry.variableId !== target.variableId),
        {
          variableId: target.variableId,
          status: "deleted" as const,
          metaVersion: target.metaVersion + 1,
          metaSigHashHex: signed.metaSigHashHex,
        },
      ],
      envMeta: state.manifestBase.envMeta,
      issuerUserId: input.authorUserId,
      signingKey: input.signingKey,
      floor: input.floor,
      variableId: target.variableId,
    });
    yield* input.client.variables
      .remove({
        params: {
          projectId: state.verified.projectId,
          environmentId: input.environmentId,
          variableId: target.variableId,
        },
        payload: { statement: signed.statement, manifest: manifest.manifest },
      })
      .pipe(Effect.tapError(rejectIntentOnServerRejection(input.floor, intentId)));
    return {
      variableId: target.variableId,
      metaVersion: target.metaVersion + 1,
      metaSigHashHex: signed.metaSigHashHex,
      previousStatus,
      selfManifest: {
        manifestVersion: manifest.manifestVersion,
        epoch: manifest.epoch,
        manifestSigHashHex: manifest.manifestSigHashHex,
      },
      intentId,
      state,
    };
  });
}

type DeletionConflict = { readonly kind: "re-resolve" };

/** CAS 競合(§12-5)のリトライ可能な分類。それ以外は null(定的エラー)。 */
function classifyDeletionConflict(error: unknown): DeletionConflict | null {
  if (error instanceof MetaVersionConflictError || error instanceof ManifestVersionConflictError) {
    // 並行メタ操作は名前から解決し直す(§12-5 の再試行 = 再取得 → 検証 →
    // ステートメントとマニフェストの両方を再署名)。並行削除に負けた場合は
    // 再解決が「already deleted」の定的エラーとして表面化させる
    return { kind: "re-resolve" };
  }
  return null;
}

/**
 * Deletes one variable (declared or active — AUTH_SPEC §12-5): a signed
 * deletion statement (v1 stays v1; a v2 variable's deletion preserves its
 * schema fields and layout byte-exactly) + manifest composite, gated by an
 * explicit confirmation (interactive name re-entry, or --force), and
 * confirmed against the verified distribution (1-E′ — §12-10 (3)) before the
 * local floor advances to the tombstone.
 */
export function varRmOp(
  input: VarRmInput,
): Effect.Effect<VarRmSummary, CliError, CliIo | Stdio.Stdio> {
  return Effect.gen(function* () {
    // 正規化の実施主体は署名前のクライアント(§4.2 / §12-1)
    const name = input.name.normalize("NFC");
    const initial = yield* resolveDeletionTarget(input, input.verified, name);
    // 確認は署名・送信・リトライループより前に 1 回だけ(確認済みの意思を
    // CAS リトライが引き継ぐ — 再確認はしない: 対象は同一 variableId のまま)
    yield* ensureDeletionConfirmed(input, initial.target, name);
    const accepted = yield* retryOnConflict(initial, {
      maxAttempts: MAX_ATTEMPTS,
      attempt: (state) => attemptDeletion(input, state),
      classify: classifyDeletionConflict,
      recover: (state) => resolveDeletionTarget(input, state.verified, name),
      exhaustedMessage: `The deletion conflict did not resolve (after ${MAX_ATTEMPTS} attempts). Wait a moment and re-run the command`,
    });
    // 効果確認(1-E′ — §12-10 (3)): 成功の定義は検証可能な配布物での確認。
    // 削除の効果は tombstone(発行 metaVersion 以上。同版はハッシュ一致まで
    // 要求 — 並行操作に負けた 2xx を効果ありと誤読しない)
    const issued = { metaVersion: accepted.metaVersion, metaSigHashHex: accepted.metaSigHashHex };
    const tombstoneConfirms = (tombstone: {
      readonly metaVersion: number;
      readonly metaSigHashHex: string;
    }) =>
      tombstone.metaVersion > issued.metaVersion ||
      (tombstone.metaVersion === issued.metaVersion &&
        tombstone.metaSigHashHex === issued.metaSigHashHex);
    yield* confirmMetaMutation({
      client: input.client,
      verified: accepted.state.verified,
      environmentId: input.environmentId,
      resync: input.resync,
      floor: input.floor,
      selfManifest: accepted.selfManifest,
      intentId: accepted.intentId,
      describe: "variable deletion",
      effectVisible: (metadata: VerifiedEnvironmentMetadata) =>
        metadata.tombstones.some(
          (tombstone) =>
            tombstone.variableId === accepted.variableId && tombstoneConfirms(tombstone),
        ),
    });
    // 床の tombstone 前進(§6.3 — 以後の pull で削除の無断取り消しを検出できる。
    // journal-before-release: 成功報告より先)。削除自体は確認済みなので、床の
    // 書き込み失敗はその旨を明示する
    yield* input.floor
      .commitPush(
        accepted.variableId,
        {
          status: "deleted",
          metaVersion: accepted.metaVersion,
          metaSigHashHex: accepted.metaSigHashHex,
        },
        {
          seq: accepted.state.verified.state.headSeq,
          hashHex: accepted.state.verified.state.headHashHex,
        },
      )
      .pipe(
        Effect.mapError((error) => cliError(`The deletion was accepted, but ${error.message}`)),
      );
    return {
      variableId: accepted.variableId,
      metaVersion: accepted.metaVersion,
      previousStatus: accepted.previousStatus,
      warnings: accepted.state.warnings,
    };
  });
}
