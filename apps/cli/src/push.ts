// 暗号化 push(AUTH_SPEC §12-5 の CAS + session-07 §5 の申し送りの決着)。
//
// - version は AAD の一部でサーバーは採番できない → 409 VersionConflict は
//   currentVersion + 1 で再暗号化して再試行
// - 409 EpochConflict は再同期(チェーン全再検証)→ 現エポック DEK の
//   再取得・再検証 → 再暗号化 → 再試行。エポックの真実源はチェーン導出値
//   (サーバー申告の currentEpoch は使わない)
// - スキーマ外の素の 413(HTTP 生ボディ上限)は failure.ts の HttpClientError
//   分岐が「値が大きすぎる」に写す
// - 値は stdin から読み、argv に載せない(プロセス一覧への露出防止)。
//   平文はメモリ上のみ

import {
  EpochConflictError,
  VariableConflictError,
  VersionConflictError,
} from "@maruhi/api-schema";
import type { EnvironmentId } from "@maruhi/core";
import { encodeHex, encryptVariable, SUITE_ID } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { type DekRecipient, verifyAndUnwrapDeks } from "./deks.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import type { VerifiedProject } from "./sync.ts";

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
  /** null = 変数が存在しない(create 経路、version 1)。 */
  readonly nextVersion: number;
  readonly create: boolean;
}

function resolveTarget(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly name: string;
}): Effect.Effect<PushTarget, CliError> {
  return input.client.variables
    .pull({ params: { projectId: input.verified.projectId, environmentId: input.environmentId } })
    .pipe(
      Effect.mapError(toCliError),
      Effect.map((response) => {
        const existing = response.variables.find((variable) => variable.name === input.name);
        if (existing === undefined) {
          return { variableId: generateVariableId(), nextVersion: 1, create: true };
        }
        return {
          variableId: existing.variableId,
          nextVersion: existing.value.aad.version + 1,
          create: false,
        };
      }),
    );
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

function encryptPayload(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly variableId: string;
  readonly epoch: number;
  readonly version: number;
  readonly dek: Uint8Array;
  readonly value: Uint8Array;
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
    return {
      suite: SUITE_ID,
      aad: context,
      nonceHex: encodeHex(encrypted.value.nonce),
      ciphertextHex: encodeHex(encrypted.value.ciphertext),
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
  /** EpochConflict 時の再同期(チェーン全再検証)。 */
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
}

interface PushState {
  readonly verified: VerifiedProject;
  readonly epoch: number;
  readonly deks: ReadonlyMap<number, Uint8Array>;
  readonly target: PushTarget;
  readonly version: number;
}

function initialState(input: PushInput): Effect.Effect<PushState, CliError> {
  return Effect.gen(function* () {
    const verified = input.verified;
    const epoch = verified.state.environmentEpochs.get(input.environmentId) ?? 1;
    const deks = yield* fetchDeks({ ...input, verified });
    const target = yield* resolveTarget({ ...input, verified });
    return { verified, epoch, deks, target, version: target.nextVersion };
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
    const payload = yield* encryptPayload({
      verified: state.verified,
      environmentId: input.environmentId,
      variableId: state.target.variableId,
      epoch: state.epoch,
      version: state.version,
      dek,
      value: input.value,
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

function nextState(
  input: PushInput,
  state: PushState,
  outcome: Exclude<AttemptOutcome, AcceptedAttempt>,
): Effect.Effect<PushState, CliError> {
  switch (outcome.kind) {
    case "version-conflict":
      return Effect.succeed({
        ...state,
        version: outcome.currentVersion + 1,
        target: { ...state.target, create: false },
      });
    case "epoch-conflict":
      // エポックの真実源はチェーン(§6.3)。再同期して導出値を使い、
      // 新エポックの DEK を取得・再検証する
      return Effect.gen(function* () {
        const verified = yield* input.resync;
        const epoch = verified.state.environmentEpochs.get(input.environmentId) ?? 1;
        const deks = yield* fetchDeks({ ...input, verified });
        return { ...state, verified, epoch, deks };
      });
    case "variable-conflict":
      return Effect.gen(function* () {
        const target = yield* resolveTarget({ ...input, verified: state.verified });
        return { ...state, target, version: target.nextVersion };
      });
  }
}

/**
 * Pushes one variable value: resolve the target by display name, encrypt
 * under the chain-derived current epoch, and retry through the CAS conflicts
 * (§12-5). The chain — not the server's claim — is the epoch authority, so an
 * EpochConflict triggers a full re-sync before the retry.
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
      state = yield* nextState(input, state, outcome);
    }
    return yield* Effect.fail(
      cliError(`push の競合が解消しません(${MAX_ATTEMPTS} 回試行)。時間をおいて再実行してください`),
    );
  });
}
