// 暗号化 + 値署名付き push(AUTH_SPEC §12-5 = CRYPTO_SPEC §4.1。session-14 裁定 G)。
//
// - 通常 push: 既存変数でも pull で取得した最新値を §6.3 で全検証し、自前で
//   再構築した signed-bytes hash を prev にする(サーバー申告のハッシュに連鎖
//   署名しない)。version = 検証済み latest + 1、宣言ヘッド = 最後に検証した
//   チェーンヘッド、DEK は現エポックのコミットメント検証済み・nonce は fresh、
//   署名は自分の user id + master sig 鍵
// - 409 VersionConflict: currentVersion 番号だけで次 version / prev を決めない。
//   bulk pull を再取得 → winner 特定(既存変数は stable id、create の
//   duplicate-name race は現行 name の再解決)→ winner を値署名検証 → 自計算
//   hash を prev → fresh nonce で再暗号・再署名。pull が 409 より古ければ
//   不整合拒否、新しければ実 winner を採用。欠落・同一 version で異なる
//   signed bytes(equivocation の証拠)は拒否。上限 5 回
// - 409 EpochConflict: 延長検査付き再同期(サーバーの currentEpoch 申告を
//   真実源にしない)→ chain-derived epoch とコミットメント検証済み DEK で
//   再暗号・新ヘッドで再署名。prev は検証済み predecessor hash を維持
// - 値は stdin から読み、argv に載せない。平文はメモリ上のみ

import {
  EpochConflictError,
  VariableConflictError,
  VersionConflictError,
} from "@maruhi/api-schema";
import type { EnvironmentId } from "@maruhi/core";
import { encodeHex, encryptVariable, signValue, SUITE_ID } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { type DekRecipient, requireChainEnvironment, verifyAndUnwrapDeks } from "./deks.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { resyncExtended, type VerifiedProject } from "./sync.ts";
import { pullVerifiedEnvironment, type VerifiedPulledValue } from "./values.ts";

const MAX_ATTEMPTS = 5;

/** Result of an accepted push. */
export interface PushedVersion {
  readonly variableId: string;
  readonly version: number;
  readonly epoch: number;
}

/** クライアント採番の変数 ID(§12-1 形式)。名前とは独立な乱数 ID にする:
 * 表示名の変更・削除済み ID の再利用禁止(tombstone)と衝突しないため。 */
function generateVariableId(): string {
  return `v${encodeHex(crypto.getRandomValues(new Uint8Array(12)))}`;
}

interface PushTarget {
  readonly variableId: string;
  readonly create: boolean;
  /** 検証済みの現行最新値(create = 新規変数なら null)。prev と equivocation 検査の基準。 */
  readonly latest: VerifiedPulledValue | null;
}

function nextVersionOf(target: PushTarget): number {
  return target.latest === null ? 1 : target.latest.version + 1;
}

function prevHashOf(target: PushTarget): string {
  return target.latest === null ? "" : target.latest.signedBytesHashHex;
}

interface ResolvedTarget {
  readonly target: PushTarget;
  /** pull 検証で前進していることがあるビュー(future head の有界再同期)。 */
  readonly verified: VerifiedProject;
}

/**
 * 表示名から push 先を解決する。pull 応答の全値は §6.3 の値署名検証を通過して
 * おり(pullVerifiedEnvironment)、一致した変数の検証済み latest が次 version と
 * prev 連鎖の根拠になる。名前 → ID の解決自体は PR-3(メタステートメント)まで
 * 非認証のまま(既知の制約 — session-14.md)。
 */
function resolveTarget(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly name: string;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
}): Effect.Effect<ResolvedTarget, CliError> {
  return Effect.gen(function* () {
    const pulled = yield* pullVerifiedEnvironment(input);
    // 名前の一意性はサーバーが強制する(§12-1)が、push 先の同定が応答の
    // 並び順に依存しないようクライアントでも検査する(重複時に恣意的な
    // 1 件へ束縛しない)
    const matches = pulled.variables.filter((variable) => variable.name === input.name);
    if (matches.length > 1) {
      return yield* Effect.fail(
        cliError(`変数名が重複しています(サーバー応答の不整合): ${input.name}`),
      );
    }
    const existing = matches[0];
    const target: PushTarget =
      existing === undefined
        ? { variableId: generateVariableId(), create: true, latest: null }
        : { variableId: existing.variableId, create: false, latest: existing };
    return { target, verified: pulled.verified };
  });
}

function fetchDeks(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly recipient: DekRecipient;
}): Effect.Effect<ReadonlyMap<number, Uint8Array>, CliError> {
  return input.client.deks
    .listMine({
      params: { projectId: input.verified.projectId, environmentId: input.environmentId },
    })
    .pipe(
      Effect.mapError(toCliError),
      Effect.flatMap((response) =>
        verifyAndUnwrapDeks({
          verified: input.verified,
          environmentId: input.environmentId,
          recipient: input.recipient,
          deks: response.deks,
        }),
      ),
    );
}

/** 暗号化(fresh nonce)+ §4.1 の値署名。宣言ヘッドは検証済みビューの現ヘッド。 */
function encryptAndSignPayload(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly variableId: string;
  readonly epoch: number;
  readonly version: number;
  readonly prevValueSigHashHex: string;
  readonly dek: Uint8Array;
  readonly value: Uint8Array;
  readonly writerUserId: string;
  readonly signingKey: CryptoKey;
}) {
  const context = {
    projectId: input.verified.projectId,
    environmentId: input.environmentId,
    epoch: input.epoch,
    variableId: input.variableId,
    version: input.version,
  };
  return Effect.gen(function* () {
    const encrypted = yield* Effect.promise(() =>
      encryptVariable({ dek: input.dek, context, plaintext: input.value }),
    );
    if (!encrypted.ok) {
      return yield* Effect.fail(cliError("値の暗号化に失敗しました"));
    }
    const nonceHex = encodeHex(encrypted.value.nonce);
    const ciphertextHex = encodeHex(encrypted.value.ciphertext);
    const signature = yield* Effect.promise(() =>
      signValue({
        context: {
          suite: SUITE_ID,
          ...context,
          nonceHex,
          ciphertextHex,
          prevValueSigHashHex: input.prevValueSigHashHex,
          writerUserId: input.writerUserId,
          chainHeadHashHex: input.verified.state.headHashHex,
          chainHeadSeq: input.verified.state.headSeq,
        },
        signingKey: input.signingKey,
      }),
    );
    if (!signature.ok) {
      return yield* Effect.fail(cliError("値署名の作成に失敗しました"));
    }
    return {
      suite: SUITE_ID,
      aad: context,
      nonceHex,
      ciphertextHex,
      prevValueSigHashHex: input.prevValueSigHashHex,
      chainHeadHashHex: input.verified.state.headHashHex,
      chainHeadSeq: input.verified.state.headSeq,
      signatureHex: signature.value,
    } as const;
  });
}

interface AcceptedAttempt {
  readonly kind: "accepted";
  readonly accepted: {
    readonly variableId: string;
    readonly version: number;
    readonly epoch: number;
  };
}

type AttemptOutcome =
  | AcceptedAttempt
  | { readonly kind: "version-conflict"; readonly currentVersion: number }
  | { readonly kind: "epoch-conflict" }
  | { readonly kind: "variable-conflict" };

/** CAS 競合(§12-5)をリトライ可能な結果へ分類し、それ以外は CliError に写す。 */
function classifyAttempt<R>(
  attempt: Effect.Effect<
    { readonly variableId: string; readonly version: number; readonly epoch: number },
    unknown,
    R
  >,
): Effect.Effect<AttemptOutcome, CliError, R> {
  return attempt.pipe(
    Effect.map((accepted): AttemptOutcome => ({ kind: "accepted", accepted })),
    Effect.catch((error): Effect.Effect<AttemptOutcome, CliError> => {
      if (error instanceof VersionConflictError) {
        return Effect.succeed({ kind: "version-conflict", currentVersion: error.currentVersion });
      }
      if (error instanceof EpochConflictError) {
        return Effect.succeed({ kind: "epoch-conflict" });
      }
      if (error instanceof VariableConflictError) {
        // create の name 競合(並行作成)のみ再解決でリトライする。ID 競合は乱数
        // ID の衝突で実質起こらない(起きたら再解決でも新 ID が振られる)
        return Effect.succeed({ kind: "variable-conflict" });
      }
      return Effect.fail(toCliError(error));
    }),
  );
}

interface PushInput {
  readonly client: MaruhiClient;
  readonly environmentId: EnvironmentId;
  readonly recipient: DekRecipient;
  readonly name: string;
  readonly value: Uint8Array;
  readonly verified: VerifiedProject;
  /** 再同期(チェーン全再検証)。呼び出し側は resyncExtended で延長検査を通す。 */
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  /** 値署名の writer(自分の内部 user_id)と master sig 鍵(§4.1)。 */
  readonly writerUserId: string;
  readonly signingKey: CryptoKey;
}

interface PushState {
  readonly verified: VerifiedProject;
  readonly epoch: number;
  readonly deks: ReadonlyMap<number, Uint8Array>;
  readonly target: PushTarget;
}

function initialState(input: PushInput): Effect.Effect<PushState, CliError> {
  return Effect.gen(function* () {
    const resolved = yield* resolveTarget(input);
    const verified = resolved.verified;
    // 現エポックはチェーン導出値(§6.2 — 環境未作成の push はここで止まる)
    const epoch = (yield* requireChainEnvironment(verified, input.environmentId)).currentEpoch;
    const deks = yield* fetchDeks({ ...input, verified });
    return { verified, epoch, deks, target: resolved.target };
  });
}

function attemptOnce(input: PushInput, state: PushState): Effect.Effect<AttemptOutcome, CliError> {
  return Effect.gen(function* () {
    const dek = state.deks.get(state.epoch);
    if (dek === undefined) {
      return yield* Effect.fail(
        cliError(
          `現エポック ${state.epoch} の DEK が自分宛に登録されていません(ローテーション後の再ラップ待ちの可能性)`,
        ),
      );
    }
    const payload = yield* encryptAndSignPayload({
      verified: state.verified,
      environmentId: input.environmentId,
      variableId: state.target.variableId,
      epoch: state.epoch,
      version: nextVersionOf(state.target),
      prevValueSigHashHex: prevHashOf(state.target),
      dek,
      value: input.value,
      writerUserId: input.writerUserId,
      signingKey: input.signingKey,
    });
    const params = { projectId: state.verified.projectId, environmentId: input.environmentId };
    return yield* classifyAttempt(
      state.target.create
        ? input.client.variables.create({
            params,
            payload: { variableId: state.target.variableId, name: input.name, value: payload },
          })
        : input.client.variables.push({
            params: { ...params, variableId: state.target.variableId },
            payload: { value: payload },
          }),
    );
  });
}

/** エポックが変わった(または初出の)場合のみ DEK 集合を取り直す。 */
function refreshEpochState(
  input: PushInput,
  state: PushState,
  verified: VerifiedProject,
): Effect.Effect<Pick<PushState, "verified" | "epoch" | "deks">, CliError> {
  return Effect.gen(function* () {
    const epoch = (yield* requireChainEnvironment(verified, input.environmentId)).currentEpoch;
    if (state.deks.has(epoch)) {
      return { verified, epoch, deks: state.deks };
    }
    const deks = yield* fetchDeks({ ...input, verified });
    return { verified, epoch, deks };
  });
}

/**
 * 409 VersionConflict 後の winner 再取得(§12-5 の再試行手順): bulk pull を
 * 再取得し、stable id で winner を特定して検証し、その signed-bytes hash へ
 * prev を付け替える。409 応答に勝者のハッシュを要求しない。
 */
function adoptConflictWinner(
  input: PushInput,
  state: PushState,
  currentVersion: number,
): Effect.Effect<PushState, CliError> {
  return Effect.gen(function* () {
    const pulled = yield* pullVerifiedEnvironment({
      client: input.client,
      verified: state.verified,
      environmentId: input.environmentId,
      resync: input.resync,
    });
    const winner = pulled.variables.find(
      (variable) => variable.variableId === state.target.variableId,
    );
    if (winner === undefined) {
      return yield* Effect.fail(
        cliError(
          `バージョン競合の勝者(変数 ${state.target.variableId})が再取得した pull に存在しません(欠落 — サーバー応答の不整合)`,
        ),
      );
    }
    if (winner.version < currentVersion) {
      // 409 が申告した最新より古い値しか配布されない = 応答間の不整合
      return yield* Effect.fail(
        cliError(
          `再取得した pull の最新 version(${winner.version})が 409 の申告(${currentVersion})より古く、不整合です`,
        ),
      );
    }
    const known = state.target.latest;
    if (known !== null && winner.version === known.version) {
      if (winner.signedBytesHashHex !== known.signedBytesHashHex) {
        // 同一座標に内容の異なる 2 つの有効署名 = equivocation の暗号学的証拠
        return yield* Effect.fail(
          cliError(
            `変数 ${state.target.variableId} の version ${winner.version} に、検証済みの値と異なる signed bytes が配布されました(サーバー equivocation の証拠)`,
          ),
        );
      }
      // 内容も version も検証済みの値と同一(409 の申告だけが古い)。定的な
      // 矛盾とまでは断定できないため状態はそのまま再試行し、解消しなければ
      // 試行上限の打ち切りに任せる
    }
    const refreshed = yield* refreshEpochState(input, state, pulled.verified);
    return {
      ...refreshed,
      target: { ...state.target, create: false, latest: winner },
    };
  });
}

function reresolveTarget(input: PushInput, state: PushState): Effect.Effect<PushState, CliError> {
  return Effect.gen(function* () {
    const resolved = yield* resolveTarget({ ...input, verified: state.verified });
    const refreshed = yield* refreshEpochState(input, state, resolved.verified);
    return { ...refreshed, target: resolved.target };
  });
}

function nextState(
  input: PushInput,
  state: PushState,
  outcome: Exclude<AttemptOutcome, AcceptedAttempt>,
): Effect.Effect<PushState, CliError> {
  switch (outcome.kind) {
    case "version-conflict":
      // create 経路への VersionConflict は「並行作成された」を意味する
      // (自分の乱数 ID はサーバーに存在しない)ため、名前から解決し直す
      if (state.target.create) {
        return reresolveTarget(input, state);
      }
      return adoptConflictWinner(input, state, outcome.currentVersion);
    case "epoch-conflict":
      // エポックの真実源はチェーン(§6.3)。延長検査付きで再同期して導出値を
      // 使い、新エポックのコミットメント検証済み DEK を取得する。prev は
      // 検証済み predecessor hash のまま(値は変わっていない — 変わっていれば
      // 次の試行が VersionConflict になり上の手順へ入る)
      return Effect.gen(function* () {
        const verified = yield* resyncExtended(input.resync, state.verified);
        const epoch = (yield* requireChainEnvironment(verified, input.environmentId)).currentEpoch;
        if (epoch === state.epoch) {
          // 再同期してもチェーン導出エポックが変わらないなら、サーバーの
          // EpochConflict 申告はチェーンと矛盾している(リトライで解けない)
          return yield* Effect.fail(
            cliError(
              `サーバーがエポック競合を申告しましたが、チェーン上の現エポックは ${epoch} のままです(サーバー応答とチェーンの矛盾)`,
            ),
          );
        }
        const deks = yield* fetchDeks({ ...input, verified });
        return { ...state, verified, epoch, deks };
      });
    case "variable-conflict":
      return reresolveTarget(input, state);
  }
}

/**
 * Pushes one variable value: resolve the target by display name from a
 * fully verified pull, encrypt under the chain-derived current epoch with a
 * commitment-verified DEK, sign as the caller (§4.1: prev = the verified
 * latest value's signed-bytes hash, head = the last verified chain head),
 * and retry through the CAS conflicts (§12-5). The chain — not the server's
 * claim — stays the epoch authority.
 */
export function pushVariable(input: PushInput): Effect.Effect<PushedVersion, CliError> {
  return Effect.gen(function* () {
    let state = yield* initialState(input);
    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt += 1) {
      const outcome = yield* attemptOnce(input, state);
      if (outcome.kind === "accepted") {
        return {
          variableId: outcome.accepted.variableId,
          version: outcome.accepted.version,
          epoch: outcome.accepted.epoch,
        };
      }
      // 最終試行でも nextState を実行する: epoch-conflict の「サーバー応答と
      // チェーンの矛盾」や equivocation の証拠は定的(リトライで解けない)
      // エラーで、汎用の「競合が解消しません」より情報量が高い。定的エラー・
      // ネットワークエラーはそのまま伝播させ、再試行可能な状態が返った場合のみ
      // 次周回で使う(最終周回では未使用)。
      state = yield* nextState(input, state, outcome);
    }
    return yield* Effect.fail(
      cliError(`push の競合が解消しません(${MAX_ATTEMPTS} 回試行)。時間をおいて再実行してください`),
    );
  });
}
