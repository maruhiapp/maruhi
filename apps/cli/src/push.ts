// 暗号化 + 値署名 + メタステートメント付き push(AUTH_SPEC §12-5 =
// CRYPTO_SPEC §4.1 / §4.2。session-14 裁定 G の PR-3 拡張)。
//
// - 名前 → variableId の解決は**検証済みステートメント経由が必須**(§4.2 /
//   §12-7 — session-14 まで「非認証」と記録していた既知制約を閉じる)。
//   ルックアップキーは NFC 正規化してから byte-exact で照合する(§12-1)。
//   同名 active の重複は pullVerifiedEnvironment(values.ts)が拒否する
// - 新規作成: `VariableMetaStatement`(metaVersion 1・active・prev 空)を自分の
//   鍵で著者署名して version 1 の値と同梱する(§12-5)。名前は署名前に NFC
//   正規化する(正規化の実施主体はクライアント — §4.2)
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
//   signed bytes(equivocation の証拠)は拒否。上限 5 回。
//   **メタ側も同型の巻き戻し・fork 検査**(検証済み latest metaVersion からの
//   後退拒否・同一 metaVersion の signed bytes 相違 = equivocation 拒否)を
//   winner 採用時に行う。409 MetaVersionConflict(並行 rename との競合)は
//   名前から解決し直す(値と同型: 再取得 → 検証 → 再署名。再暗号化なし)
// - 409 EpochConflict: 延長検査付き再同期(サーバーの currentEpoch 申告を
//   真実源にしない)→ chain-derived epoch とコミットメント検証済み DEK で
//   再暗号・新ヘッドで再署名。prev は検証済み predecessor hash を維持
// - 値は stdin から読み、argv に載せない。平文はメモリ上のみ

import {
  EpochConflictError,
  MetaVersionConflictError,
  VariableConflictError,
  VersionConflictError,
} from "@maruhi/api-schema";
import type { EnvironmentId } from "@maruhi/core";
import {
  computeMetaSignedBytesHash,
  computeValueSignedBytesHash,
  encodeHex,
  encryptVariable,
  signMetaStatement,
  signValue,
  SUITE_ID,
} from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { type DekRecipient, requireChainEnvironment, verifyAndUnwrapDeks } from "./deks.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import type { FloorHandle } from "./floor-check.ts";
import type { VariableFloor } from "./floor.ts";
import { resyncExtended, type VerifiedProject } from "./sync.ts";
import { pullVerifiedEnvironment, type VerifiedPulledValue } from "./values.ts";

const MAX_ATTEMPTS = 5;

/** Result of an accepted push. */
export interface PushedVersion {
  readonly variableId: string;
  readonly version: number;
  readonly epoch: number;
  /** 検証中に収集した SHOULD 警告(非 NFC 名の配布等 — 呼び出し側が表示)。 */
  readonly warnings: readonly string[];
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
  readonly warnings: readonly string[];
}

/**
 * 表示名から push 先を解決する。pull 応答の全値・全ステートメントは §6.3 の
 * 検証を通過しており(pullVerifiedEnvironment — 同名 active の重複はそこで
 * 解決拒否済み)、名前の照合は**検証済みステートメントの name** に対する
 * byte-exact 比較で行う(ルックアップキーは呼び出し側で NFC 正規化済み —
 * §12-1)。一致した変数の検証済み latest が次 version と prev 連鎖の根拠になる。
 */
function resolveTarget(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly name: string;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  /** ローカル床(§6.3 — 解決に使う検証済み pull にも床検査・床コミットが掛かる)。 */
  readonly floor: FloorHandle;
}): Effect.Effect<ResolvedTarget, CliError> {
  return Effect.gen(function* () {
    const pulled = yield* pullVerifiedEnvironment(input);
    // 同名 active の重複は pullVerifiedEnvironment が拒否済みだが、push 先の
    // 同定が応答の並び順に依存しない防衛線として残す(§4.2 の解決拒否)
    const matches = pulled.variables.filter((variable) => variable.name === input.name);
    if (matches.length > 1) {
      return yield* Effect.fail(
        cliError(
          `同名の active ステートメントが複数検証に通りました(サーバー equivocation): ${input.name}。解決を拒否します`,
        ),
      );
    }
    const existing = matches[0];
    const target: PushTarget =
      existing === undefined
        ? { variableId: generateVariableId(), create: true, latest: null }
        : { variableId: existing.variableId, create: false, latest: existing };
    return { target, verified: pulled.verified, warnings: pulled.warnings };
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
    const signatureContext = {
      suite: SUITE_ID,
      ...context,
      nonceHex,
      ciphertextHex,
      prevValueSigHashHex: input.prevValueSigHashHex,
      writerUserId: input.writerUserId,
      chainHeadHashHex: input.verified.state.headHashHex,
      chainHeadSeq: input.verified.state.headSeq,
    } as const;
    const signature = yield* Effect.promise(() =>
      signValue({ context: signatureContext, signingKey: input.signingKey }),
    );
    if (!signature.ok) {
      return yield* Effect.fail(cliError("値署名の作成に失敗しました"));
    }
    // 自分の署名対象の signed bytes ハッシュ(受理されたらローカル床に昇格する
    // — サーバー申告ではなく自計算値。次 version の prev の根拠と同じ姿勢)
    const signedBytesHash = yield* Effect.promise(() =>
      computeValueSignedBytesHash(signatureContext),
    );
    if (!signedBytesHash.ok) {
      return yield* Effect.fail(cliError("値署名対象のハッシュ計算に失敗しました"));
    }
    return {
      payload: {
        suite: SUITE_ID,
        aad: context,
        nonceHex,
        ciphertextHex,
        prevValueSigHashHex: input.prevValueSigHashHex,
        chainHeadHashHex: input.verified.state.headHashHex,
        chainHeadSeq: input.verified.state.headSeq,
        signatureHex: signature.value,
      },
      signedBytesHashHex: signedBytesHash.value,
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
  /** 受理された自分の書き込みの床レコード(自計算値 — サーバー echo でない)。 */
  readonly floorVariable: VariableFloor;
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
  floorVariable: VariableFloor,
): Effect.Effect<AttemptOutcome, CliError, R> {
  return attempt.pipe(
    Effect.map((accepted): AttemptOutcome => ({ kind: "accepted", accepted, floorVariable })),
    Effect.catch((error): Effect.Effect<AttemptOutcome, CliError> => {
      if (error instanceof VersionConflictError) {
        return Effect.succeed({ kind: "version-conflict", currentVersion: error.currentVersion });
      }
      if (error instanceof EpochConflictError) {
        return Effect.succeed({ kind: "epoch-conflict" });
      }
      if (error instanceof VariableConflictError || error instanceof MetaVersionConflictError) {
        // create の name 競合 / metaVersion 競合(並行作成・並行 rename)は名前
        // から解決し直す(§12-5 のメタ再試行 = 再取得 → 検証 → 再署名。ID 競合は
        // 乱数 ID の衝突で実質起こらない — 起きたら再解決でも新 ID が振られる)
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
  /** ローカル床(§6.3 — 内部 pull の検査・コミットと、受理後の変数床前進)。 */
  readonly floor: FloorHandle;
}

interface PushState {
  readonly verified: VerifiedProject;
  readonly epoch: number;
  readonly deks: ReadonlyMap<number, Uint8Array>;
  readonly target: PushTarget;
  readonly warnings: readonly string[];
}

function initialState(input: PushInput): Effect.Effect<PushState, CliError> {
  return Effect.gen(function* () {
    const resolved = yield* resolveTarget(input);
    const verified = resolved.verified;
    // 現エポックはチェーン導出値(§6.2 — 環境未作成の push はここで止まる)
    const epoch = (yield* requireChainEnvironment(verified, input.environmentId)).currentEpoch;
    const deks = yield* fetchDeks({ ...input, verified });
    return { verified, epoch, deks, target: resolved.target, warnings: resolved.warnings };
  });
}

/**
 * 新規作成に同梱する `VariableMetaStatement`(metaVersion 1・active・prev 空 —
 * §12-5)を自分の鍵で著者署名する。宣言ヘッドは値署名と同じ「最後に検証した
 * チェーンヘッド」。CAS リトライで検証ビューが進めば作り直される(attemptOnce
 * ごとに署名するため)。
 */
function signCreateStatement(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly variableId: string;
  readonly name: string;
  readonly authorUserId: string;
  readonly signingKey: CryptoKey;
}) {
  return Effect.gen(function* () {
    const context = {
      suite: SUITE_ID,
      projectId: input.verified.projectId,
      environmentId: input.environmentId,
      target: { kind: "variable", variableId: input.variableId },
      name: input.name,
      status: "active",
      metaVersion: 1,
      prevMetaSigHashHex: "",
      authorUserId: input.authorUserId,
      chainHeadHashHex: input.verified.state.headHashHex,
      chainHeadSeq: input.verified.state.headSeq,
    } as const;
    const signature = yield* Effect.promise(() =>
      signMetaStatement({ context, signingKey: input.signingKey }),
    );
    if (!signature.ok) {
      return yield* Effect.fail(cliError("メタステートメントの署名に失敗しました"));
    }
    // 受理されたらローカル床のメタ記録になる自計算ハッシュ(§6.3)
    const metaSigHash = yield* Effect.promise(() => computeMetaSignedBytesHash(context));
    if (!metaSigHash.ok) {
      return yield* Effect.fail(cliError("メタステートメント署名対象のハッシュ計算に失敗しました"));
    }
    return {
      statement: {
        suite: SUITE_ID,
        environmentId: input.environmentId,
        variableId: input.variableId,
        name: input.name,
        status: "active",
        metaVersion: 1,
        prevMetaSigHashHex: "",
        chainHeadHashHex: input.verified.state.headHashHex,
        chainHeadSeq: input.verified.state.headSeq,
        signatureHex: signature.value,
      },
      metaSigHashHex: metaSigHash.value,
    } as const;
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
    const version = nextVersionOf(state.target);
    const signed = yield* encryptAndSignPayload({
      verified: state.verified,
      environmentId: input.environmentId,
      variableId: state.target.variableId,
      epoch: state.epoch,
      version,
      prevValueSigHashHex: prevHashOf(state.target),
      dek,
      value: input.value,
      writerUserId: input.writerUserId,
      signingKey: input.signingKey,
    });
    const valueFloor = {
      status: "active",
      version,
      epoch: state.epoch,
      valueSigHashHex: signed.signedBytesHashHex,
    } as const;
    const params = { projectId: state.verified.projectId, environmentId: input.environmentId };
    if (state.target.create) {
      // 作成 = version 1 の値 + metaVersion 1 のステートメントの同梱(§12-5)
      const created = yield* signCreateStatement({
        verified: state.verified,
        environmentId: input.environmentId,
        variableId: state.target.variableId,
        name: input.name,
        authorUserId: input.writerUserId,
        signingKey: input.signingKey,
      });
      return yield* classifyAttempt(
        input.client.variables.create({
          params,
          payload: { statement: created.statement, value: signed.payload },
        }),
        { ...valueFloor, metaVersion: 1, metaSigHashHex: created.metaSigHashHex },
      );
    }
    // 既存変数の push はメタを変更しない — 床のメタ記録は検証済み latest のまま
    const latest = state.target.latest;
    if (latest === null) {
      return yield* Effect.fail(
        cliError(`変数 ${state.target.variableId} の検証済み最新値がありません(内部不整合)`),
      );
    }
    return yield* classifyAttempt(
      input.client.variables.push({
        params: { ...params, variableId: state.target.variableId },
        payload: { value: signed.payload },
      }),
      {
        ...valueFloor,
        metaVersion: latest.metaVersion,
        metaSigHashHex: latest.metaSignedBytesHashHex,
      },
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
 * 検証済み既知 latest(このセッションで §6.3 検証を通した値)に対する winner の
 * 整合検査(レビューループ 1 [高]/[中])。正直サーバーでは latest_version は
 * 単調増加(バージョン行の個別削除なし。変数削除は tombstone + 全行削除 = 以後
 * 404)なので、後退はすべて巻き戻し・equivocation の証拠であり誤拒否はない。
 */
/**
 * 検証済み既知 latest(このセッションで §6.3 検証を通した値)に対する winner の
 * 後退・equivocation・連鎖の整合検査。正直サーバーでは latest_version は単調増加
 * (バージョン行の個別削除なし。変数削除は tombstone + 全行削除 = 以後 404)なので
 * 後退はすべて巻き戻し・equivocation の証拠であり、誤拒否はない。
 */
function winnerValueRegression(
  target: PushTarget,
  known: VerifiedPulledValue,
  winner: VerifiedPulledValue,
  currentVersion: number,
): string | null {
  if (currentVersion < known.version || winner.version < known.version) {
    // このセッションで検証済みの latest からの後退 = 巻き戻しの証拠。採用して
    // prev を付け替えると、巻き戻しブランチへ自分の署名で連鎖してしまう
    return `変数 ${target.variableId} の 409 応答 / 再取得(version ${Math.min(currentVersion, winner.version)})が検証済みの最新(version ${known.version})より古く、バージョン巻き戻しの証拠です`;
  }
  if (winner.version === known.version && winner.signedBytesHashHex !== known.signedBytesHashHex) {
    // 同一座標に内容の異なる 2 つの有効署名 = equivocation の暗号学的証拠
    return `変数 ${target.variableId} の version ${winner.version} に、検証済みの値と異なる signed bytes が配布されました(サーバー equivocation の証拠)`;
  }
  // エポック単調性(§4.1)は推移的なので、winner が検証済み latest より新しければ
  // 版番号のギャップに関わらず epoch 非減少を要求できる(レビューループ 2 [低] —
  // 版番号の選び方で隣接検査を迂回する旧エポック注入を塞ぐ)。正直サーバーは
  // 受理順にエポック非減少なので誤拒否はない
  if (winner.version > known.version && winner.epoch < known.epoch) {
    return `変数 ${target.variableId} の version ${winner.version} の epoch(${winner.epoch})が検証済みの直前 version(${known.epoch})から後退しています(§4.1 のエポック単調性違反)`;
  }
  // 隣接 predecessor を保持している場合は §6.3-6 の prev 実在一致も無償で検査できる
  // (レビューループ 1 [中] — pull の latest-only 制約の例外)
  if (
    winner.version === known.version + 1 &&
    winner.prevValueSigHashHex !== known.signedBytesHashHex
  ) {
    return `変数 ${target.variableId} の version ${winner.version} の prev が検証済みの直前 version の signed bytes ハッシュと一致しません(分岐した履歴への連鎖 — equivocation の証拠)`;
  }
  return null;
}

/**
 * メタ側の同型の巻き戻し・fork 検査(§12-5 のメタ再試行の規律。値の
 * winnerValueRegression の PR-3 拡張): 検証済み latest metaVersion からの後退と、
 * 同一 metaVersion の signed bytes 相違 = equivocation を拒否する。正直サーバー
 * では latest_meta_version も単調増加(ステートメント行の個別削除なし)のため
 * 誤拒否はない。
 */
function winnerMetaRegression(
  target: PushTarget,
  known: VerifiedPulledValue,
  winner: VerifiedPulledValue,
): string | null {
  if (winner.metaVersion < known.metaVersion) {
    return `変数 ${target.variableId} の再取得ステートメント(metaVersion ${winner.metaVersion})が検証済みの最新(metaVersion ${known.metaVersion})より古く、メタデータ巻き戻しの証拠です`;
  }
  if (
    winner.metaVersion === known.metaVersion &&
    winner.metaSignedBytesHashHex !== known.metaSignedBytesHashHex
  ) {
    return `変数 ${target.variableId} の metaVersion ${winner.metaVersion} に、検証済みのステートメントと異なる signed bytes が配布されました(サーバー equivocation の証拠)`;
  }
  // 隣接 predecessor を保持している場合は prev 連鎖の一致も無償で検査できる
  // (winnerValueRegression の §6.3-6 検査の同型 — レビュー② [minor])
  if (
    winner.metaVersion === known.metaVersion + 1 &&
    winner.prevMetaSigHashHex !== known.metaSignedBytesHashHex
  ) {
    return `変数 ${target.variableId} の metaVersion ${winner.metaVersion} の prev が検証済みの直前 metaVersion の signed bytes ハッシュと一致しません(分岐した履歴への連鎖 — equivocation の証拠)`;
  }
  return null;
}

function winnerRegression(
  target: PushTarget,
  known: VerifiedPulledValue,
  winner: VerifiedPulledValue,
  currentVersion: number,
): string | null {
  return (
    winnerValueRegression(target, known, winner, currentVersion) ??
    winnerMetaRegression(target, known, winner)
  );
}

/** 409 winner の整合検査(§12-5)。null = 採用可、非 null = 拒否理由。 */
function winnerInconsistency(
  target: PushTarget,
  winner: VerifiedPulledValue,
  currentVersion: number,
): string | null {
  if (winner.version < currentVersion) {
    // 409 が申告した最新より古い値しか配布されない = 応答間の不整合
    return `再取得した pull の最新 version(${winner.version})が 409 の申告(${currentVersion})より古く、不整合です`;
  }
  return target.latest === null
    ? null
    : winnerRegression(target, target.latest, winner, currentVersion);
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
      floor: input.floor,
    });
    const winner = pulled.variables.find(
      (variable) => variable.variableId === state.target.variableId,
    );
    if (winner === undefined) {
      return yield* Effect.fail(
        cliError(
          `バージョン競合の勝者(変数 ${state.target.variableId})が再取得した pull に存在しません(他メンバーによる並行削除、またはサーバー応答の不整合)`,
        ),
      );
    }
    const inconsistency = winnerInconsistency(state.target, winner, currentVersion);
    if (inconsistency !== null) {
      return yield* Effect.fail(cliError(inconsistency));
    }
    const refreshed = yield* refreshEpochState(input, state, pulled.verified);
    return {
      ...refreshed,
      target: { ...state.target, create: false, latest: winner },
      warnings: [...state.warnings, ...pulled.warnings],
    };
  });
}

function reresolveTarget(input: PushInput, state: PushState): Effect.Effect<PushState, CliError> {
  return Effect.gen(function* () {
    const resolved = yield* resolveTarget({ ...input, verified: state.verified });
    const refreshed = yield* refreshEpochState(input, state, resolved.verified);
    return {
      ...refreshed,
      target: resolved.target,
      warnings: [...state.warnings, ...resolved.warnings],
    };
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
 * Pushes one variable value: resolve the target by display name through the
 * verified metadata statements of a fully verified pull (§4.2 — the lookup
 * key is NFC-normalized, matching is byte-exact), encrypt under the
 * chain-derived current epoch with a commitment-verified DEK, sign as the
 * caller (§4.1: prev = the verified latest value's signed-bytes hash, head =
 * the last verified chain head; creation additionally author-signs a
 * metaVersion-1 statement), and retry through the CAS conflicts (§12-5).
 * The chain — not the server's claim — stays the epoch authority.
 */
export function pushVariable(input: PushInput): Effect.Effect<PushedVersion, CliError> {
  return Effect.gen(function* () {
    // 正規化の実施主体は署名前のクライアント(§4.2 / §12-1): ルックアップキーと
    // 新規作成時に署名する名前の両方を NFC 正規形にする
    const normalized: PushInput = { ...input, name: input.name.normalize("NFC") };
    let state = yield* initialState(normalized);
    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt += 1) {
      const outcome = yield* attemptOnce(normalized, state);
      if (outcome.kind === "accepted") {
        // 受理された自分の書き込みを床へ昇格する(§6.3 — 以後の pull で自分の
        // 書き込みの巻き戻しも検出できる)。規則 (c) 基準は動かさない。
        // push 自体は受理済みなので、床の書き込み失敗はその旨を明示する
        yield* input.floor
          .commitPush(
            // 床のキーは自分が署名した変数 ID(サーバー echo を信用しない)
            state.target.variableId,
            outcome.floorVariable,
            { seq: state.verified.state.headSeq, hashHex: state.verified.state.headHashHex },
          )
          .pipe(Effect.mapError((error) => cliError(`push は受理されましたが、${error.message}`)));
        return {
          variableId: outcome.accepted.variableId,
          version: outcome.accepted.version,
          epoch: outcome.accepted.epoch,
          warnings: state.warnings,
        };
      }
      // 最終試行でも nextState を実行する: epoch-conflict の「サーバー応答と
      // チェーンの矛盾」や equivocation の証拠は定的(リトライで解けない)
      // エラーで、汎用の「競合が解消しません」より情報量が高い。定的エラー・
      // ネットワークエラーはそのまま伝播させ、再試行可能な状態が返った場合のみ
      // 次周回で使う(最終周回では未使用)。
      state = yield* nextState(normalized, state, outcome);
    }
    return yield* Effect.fail(
      cliError(`push の競合が解消しません(${MAX_ATTEMPTS} 回試行)。時間をおいて再実行してください`),
    );
  });
}
