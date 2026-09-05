// 周期チェックポイントの発行(CRYPTO_SPEC §6.3 の発行 SHOULD / AUTH_SPEC §16-2
// — 2026-08-28 セッション 35 = PR-M2)。
//
// - 発行直前のビュー最新化 → 検証済みビュー(検証済み pull)からマニフェスト
//   参照・values_digest を構築する(サーバー申告値をそのまま署名しない —
//   §16-2)。カバー範囲は検証済みビュー内の全環境(SHOULD。検証済み削除
//   ステートメントのある環境は含めない)— 契機 (i)〔rotate + 再暗号化完了後〕は
//   当該環境 1 タプル(裁定は docs/notes/session-35.md)
// - 監査ヘッドの公証は実効権限 admin(min(トークンスコープ, チェーン role) —
//   §9-2)のみ。スコープは /auth/me の tokenScopes、role は検証済みビューから
//   **事前判定**する(403 を踏んでからフォールバックしない — §16-2)。申告の
//   取得は CAS 親(チェーンヘッド)の確定より後(§6.3 — audit-head-stale を
//   正直クライアントに事実上到達不能にする)
// - 422(CheckpointStateMismatch)の再試行は有界: ビューの再取得・再検証・
//   再署名(公証する場合は申告の取り直しを含む)。使い切った場合は受理時点
//   一致が確認できた環境の部分集合(直近 2 回の構築で不変だったタプル)で
//   1 回だけ発行を試みる(部分基準は基準ゼロより強い — §6.3)
// - 受理後照合(§12-10 (3)): 成功はチェーン同期で自エントリの着地を確認して
//   はじめて報告する(2xx は輸送層の事実でしかない)。intent(3-F)は
//   積まない — checkpoint はローカル状態を前進させず、未確認の着地が後続の
//   判断を汚す経路がない(裁定は docs/notes/session-35.md)

import {
  AuditHeadNotReadyError,
  ChainHeadConflictError,
  CheckpointStateMismatchError,
} from "@maruhi/api-schema";
import type { EnvironmentId } from "@maruhi/core";
import { scopePermissionFor } from "@maruhi/core";
import type {
  ChainEntry,
  CheckpointEnvironmentEntry,
  EnvValuesDigestEntry,
  SigningKeyPair,
} from "@maruhi/crypto";
import { computeChainEntryHash, computeEnvValuesDigest, SUITE_ID } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { signEntryAtHead } from "./chain-append.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { isServerRejection, toCliError } from "./failure.ts";
import type { FloorHandle } from "./floor-check.ts";
import { CliIo, type CliIoShape } from "./io.ts";
import { verifiedDeletedEnvironmentSet } from "./rotation-sweep.ts";
import type { VerifiedProject } from "./sync.ts";
import { pullVerifiedEnvironment } from "./values.ts";

/** 422 再試行の上限(使い切ったら部分集合発行を 1 回だけ試みる)。 */
const MAX_STATE_MISMATCH_ATTEMPTS = 3;
/** CAS 競合(409)の再署名リトライの上限(チェーン CAS の既存慣行と同水準)。 */
const MAX_HEAD_CONFLICT_ATTEMPTS = 5;
/**
 * AuditHeadNotReady(503 — 監査ヘッド派生列の有界伸長が未完了。AUDIT_SPEC
 * §5.1 / AUTH_SPEC §16-2)の再試行上限。1 回の失敗応答でもサーバー側は上限
 * いっぱい(1 万行)前進しているため、予算 × サーバー上限 = 1 実行あたり
 * 10 万行の伸長が保証される。枯渇はエラーにするが、進捗は保存済みなので
 * 再実行が続きから前進する(メッセージで案内 — session-38 裁定 AG)。
 */
const MAX_AUDIT_HEAD_NOT_READY_ATTEMPTS = 10;

/** AuditHeadNotReady 枯渇時の案内(fetch / 送信の両経路で共通)。 */
const AUDIT_HEAD_NOT_READY_EXHAUSTED = `The server is still materializing the audit-head hash column after ${MAX_AUDIT_HEAD_NOT_READY_ATTEMPTS} attempts (this happens once, on the first audit-head access of a project with a very large existing audit log). Progress is saved server-side and every attempt advances it — re-run the command to continue where it left off`;

/** 発行契機 (iii) の基準経過(7 日 — CRYPTO_SPEC §6.3 の起草値)。 */
const CHECKPOINT_PROPOSAL_AGE_MS = 7 * 24 * 60 * 60 * 1000;

/** 発行結果(表示・終了コードの材料)。 */
export interface CheckpointSummary {
  /** 公証した環境 ID(バイト昇順 = payload 順)。 */
  readonly environmentIds: readonly string[];
  /** 全環境カバー(SHOULD)から漏れた環境と理由(部分集合発行時のみ非空)。 */
  readonly skippedEnvironmentIds: readonly string[];
  /** 監査ヘッドを公証したか(実効権限 admin のみ — §16-2)。 */
  readonly attestedAuditHead: boolean;
  readonly headSeq: number;
  readonly warnings: readonly string[];
}

export interface CheckpointInput {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  /**
   * カバー対象。"all" = 検証済みビュー内の全環境(検証済み削除ステートメントの
   * ある環境を除く — §6.3)。明示リストは契機 (i)(rotate 完了後の当該環境)用。
   */
  readonly environmentIds: "all" | readonly EnvironmentId[];
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  /** 環境ごとの床ハンドル(検証済み pull の検査・コミット用)。 */
  readonly floorFor: (environmentId: EnvironmentId) => Effect.Effect<FloorHandle, CliError>;
}

/** UTF-8 バイト昇順の比較(payload の生成順 SHOULD — CRYPTO_SPEC §6.2)。 */
function compareUtf8Bytes(a: string, b: string): number {
  const encoder = new TextEncoder();
  const left = encoder.encode(a);
  const right = encoder.encode(b);
  const length = Math.min(left.length, right.length);
  for (let i = 0; i < length; i += 1) {
    const diff = (left[i] ?? 0) - (right[i] ?? 0);
    if (diff !== 0) {
      return diff;
    }
  }
  return left.length - right.length;
}

/** 1 環境ぶんの構築済みタプル(比較可能な形 — 部分集合退避の判定材料)。 */
interface BuiltTuple {
  readonly environmentId: string;
  readonly epoch: number;
  readonly manifestVersion: number;
  readonly manifestSigHashHex: string;
  readonly valuesDigestHex: string;
}

interface BuiltView {
  readonly view: VerifiedProject;
  readonly tuples: readonly BuiltTuple[];
  readonly warnings: readonly string[];
}

function sameTuple(a: BuiltTuple, b: BuiltTuple | undefined): boolean {
  return (
    b !== undefined &&
    a.epoch === b.epoch &&
    a.manifestVersion === b.manifestVersion &&
    a.manifestSigHashHex === b.manifestSigHashHex &&
    a.valuesDigestHex === b.valuesDigestHex
  );
}

/**
 * 実効権限 admin(min(トークンスコープ, チェーン role) — §9-2)の事前判定。
 * role は検証済みビュー、スコープは /auth/me の tokenScopes(欠落 = セッション
 * 主体 = 本人のフルパワー)から取り、403 を踏まない(§16-2)。
 */
function determineAuditAttestation(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly signerUserId: string;
}): Effect.Effect<boolean, CliError> {
  return Effect.gen(function* () {
    const member = input.verified.state.members.get(input.signerUserId);
    if (member === undefined || (member.role !== "admin" && member.role !== "owner")) {
      return false;
    }
    const me = yield* input.client.auth.me({}).pipe(Effect.mapError(toCliError));
    if (me.tokenScopes === undefined) {
      return true;
    }
    const granted = scopePermissionFor(me.tokenScopes, input.verified.projectId);
    return granted === "admin";
  });
}

/** カバー対象の確定("all" = チェーン導出環境 − 検証済み削除)。 */
function resolveTargets(input: CheckpointInput): Effect.Effect<readonly EnvironmentId[], CliError> {
  return Effect.gen(function* () {
    if (input.environmentIds !== "all") {
      return input.environmentIds;
    }
    const all = [...input.verified.state.environments.keys()];
    if (all.length === 0) {
      return [];
    }
    const deleted = yield* verifiedDeletedEnvironmentSet(input.client, input.verified);
    return all
      .filter((environmentId) => !deleted.has(environmentId))
      .toSorted(compareUtf8Bytes) as readonly EnvironmentId[];
  });
}

/**
 * 検証済みビューの構築: 対象環境を順に検証済み pull し、タプルを組み立てる。
 * ビューは pull の有界再同期で前進しうる — 最後の pull のビューを署名基準
 * (CAS 親)にし、タプルの epoch はそのビューのチェーン導出値を写す(合意規則の
 * エントリ時点厳密一致)。pull と署名の間の変化は受理段(409 / 422)が検出し、
 * 有界再試行が吸収する。
 */
function buildTuples(
  input: CheckpointInput,
  targets: readonly EnvironmentId[],
): Effect.Effect<BuiltView, CliError> {
  return Effect.gen(function* () {
    let view = yield* input.resync;
    const warnings: string[] = [];
    const pulls = new Map<
      string,
      {
        readonly manifestVersion: number;
        readonly manifestSigHashHex: string;
        readonly values: readonly EnvValuesDigestEntry[];
      }
    >();
    for (const environmentId of targets) {
      const floor = yield* input.floorFor(environmentId);
      const pulled = yield* pullVerifiedEnvironment({
        client: input.client,
        verified: view,
        environmentId,
        resync: input.resync,
        floor,
      }).pipe(
        Effect.mapError((error) =>
          cliError(
            `Cannot build the checkpoint for environment ${displayText(environmentId)}: ${error.message}`,
          ),
        ),
      );
      view = pulled.verified;
      warnings.push(...pulled.warnings);
      if (pulled.manifest === null) {
        // 通常経路の pull は欠落を拒否する(§6.3)ため到達しないが、型の上の
        // null を「マニフェストなしの公証」に潰さない(fail-closed)
        return yield* Effect.fail(
          cliError(
            `Environment ${displayText(environmentId)} has no verified manifest — run \`maruhi env rotate ${displayText(environmentId)} --init-manifest --reason <text>\` first (migration path)`,
          ),
        );
      }
      pulls.set(environmentId, {
        manifestVersion: pulled.manifest.manifestVersion,
        manifestSigHashHex: pulled.manifest.signedBytesHashHex,
        values: pulled.variables.map((value) => ({
          variableId: value.variableId,
          version: value.version,
          valueSigHashHex: value.signedBytesHashHex,
        })),
      });
    }
    const tuples: BuiltTuple[] = [];
    for (const environmentId of targets) {
      const pulled = pulls.get(environmentId);
      const environment = view.state.environments.get(environmentId);
      if (pulled === undefined || environment === undefined) {
        return yield* Effect.fail(
          cliError(
            `Environment ${displayText(environmentId)} disappeared from the verified chain while building the checkpoint — re-run`,
          ),
        );
      }
      const digest = yield* Effect.tryPromise({
        try: () => computeEnvValuesDigest(SUITE_ID, pulled.values),
        catch: () => cliError("Failed to compute the checkpoint values digest"),
      });
      if (!digest.ok) {
        return yield* Effect.fail(cliError("Failed to compute the checkpoint values digest"));
      }
      tuples.push({
        environmentId,
        epoch: environment.currentEpoch,
        manifestVersion: pulled.manifestVersion,
        manifestSigHashHex: pulled.manifestSigHashHex,
        valuesDigestHex: digest.value,
      });
    }
    return { view, tuples, warnings };
  });
}

/**
 * 監査ヘッド申告の取得(実効権限 admin の場合のみ呼ばれる — §16-2)。
 * AuditHeadNotReady(503 — 遅延実体化の有界伸長が未完了)は専用の有界再試行で
 * 吸収する: サーバー側の進捗は呼び出しごとに保存され必ず前進するため、即時
 * 再試行が生産的(バックオフ不要)。枯渇時は発生条件と再実行での解消を案内する
 * (黙って一般エラーに落とさない)。`maruhi audit reconcile` も共有する。
 */
export function fetchAuditHead(
  client: MaruhiClient,
  projectId: string,
): Effect.Effect<string, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    for (let attempt = 1; attempt <= MAX_AUDIT_HEAD_NOT_READY_ATTEMPTS; attempt += 1) {
      const outcome = yield* client.audit.auditHead({ params: { projectId } }).pipe(
        Effect.map((response) => ({ kind: "ok" as const, head: response.auditHeadHashHex })),
        Effect.catch((error) =>
          error instanceof AuditHeadNotReadyError
            ? Effect.succeed({ kind: "not-ready" as const })
            : Effect.fail(
                cliError(`Cannot fetch the audit head attestation (${toCliError(error).message})`),
              ),
        ),
      );
      if (outcome.kind === "ok") {
        return outcome.head;
      }
      if (attempt < MAX_AUDIT_HEAD_NOT_READY_ATTEMPTS) {
        yield* io.log(
          `The server is materializing the audit-head hash column — retrying (attempt ${attempt + 1} of ${MAX_AUDIT_HEAD_NOT_READY_ATTEMPTS})`,
        );
      }
    }
    return yield* Effect.fail(cliError(AUDIT_HEAD_NOT_READY_EXHAUSTED));
  });
}

/** 署名 → 追記 → 受理後照合(§12-10 (3))の 1 試行。 */
function sendCheckpoint(input: {
  readonly client: MaruhiClient;
  readonly view: VerifiedProject;
  readonly tuples: readonly BuiltTuple[];
  readonly auditHeadHashHex: string;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
}): Effect.Effect<
  { readonly headSeq: number },
  ChainHeadConflictError | CheckpointStateMismatchError | AuditHeadNotReadyError | CliError
> {
  return Effect.gen(function* () {
    const environments: CheckpointEnvironmentEntry[] = input.tuples.map((tuple) => ({
      environmentId: tuple.environmentId,
      epoch: tuple.epoch,
      manifestVersion: tuple.manifestVersion,
      manifestSigHashHex: tuple.manifestSigHashHex,
      valuesDigestHex: tuple.valuesDigestHex,
    }));
    const entry = yield* signEntryAtHead({
      verified: input.view,
      signerUserId: input.signerUserId,
      operation: {
        op: "checkpoint",
        payload: { environments, auditHeadHashHex: input.auditHeadHashHex },
      },
      signingKeyPair: input.signingKeyPair,
      failureText: "Failed to sign the checkpoint entry",
    });
    yield* appendCheckpoint(input.client, input.view, entry);
    // 受理後照合(§12-10 (3)): 検証済みチェーン上の自エントリの確認。2xx は
    // 輸送層の事実でしかない — 成功の報告はこの確認を通過した場合のみ
    yield* confirmAccepted(entry, input.resync);
    return { headSeq: entry.seq };
  });
}

/**
 * 追記の送信。409(CAS)と 422(CheckpointStateMismatch)は型のまま呼び出し
 * 側の再試行へ返す。転送層の失敗(応答消失)は「着地したかもしれない」を明示
 * して失敗にする — checkpoint はローカル状態を前進させず、着地済みでも未着地
 * でも再実行が安全(着地済みなら新しいヘッドでの再公証になるだけ)なので、
 * rotate のような着地 probe は要らない(裁定は docs/notes/session-35.md)。
 */
function appendCheckpoint(
  client: MaruhiClient,
  view: VerifiedProject,
  entry: ChainEntry,
): Effect.Effect<
  void,
  ChainHeadConflictError | CheckpointStateMismatchError | AuditHeadNotReadyError | CliError
> {
  return client.membership
    .append({
      params: { projectId: view.projectId },
      payload: { parentHeadHashHex: view.state.headHashHex, entry },
    })
    .pipe(
      Effect.asVoid,
      Effect.mapError((error) => {
        if (
          error instanceof ChainHeadConflictError ||
          error instanceof CheckpointStateMismatchError ||
          error instanceof AuditHeadNotReadyError
        ) {
          return error;
        }
        if (isServerRejection(error)) {
          return toCliError(error);
        }
        return cliError(
          `Sending the checkpoint failed (${toCliError(error).message}). The entry may or may not have landed — re-running \`maruhi project checkpoint\` is safe either way (a landed checkpoint simply becomes the baseline; a re-run notarizes the current view)`,
        );
      }),
    );
}

/**
 * 受理後照合(§12-10 (3)): 再同期した検証済みチェーンの当該 seq に自エントリの
 * ハッシュが載っていること。載っていなければ受理は確認できていない(2xx でも
 * 成功と報告しない)。
 */
function confirmAccepted(
  entry: ChainEntry,
  resync: Effect.Effect<VerifiedProject, CliError>,
): Effect.Effect<void, CliError> {
  return Effect.gen(function* () {
    const expectedHash = yield* Effect.tryPromise({
      try: () => computeChainEntryHash(entry),
      catch: () => cliError("Failed to compute the checkpoint entry hash"),
    });
    const view = yield* resync.pipe(
      Effect.mapError((error) =>
        cliError(
          `The checkpoint was submitted, but the post-acceptance chain sync failed (${error.message}). Re-run to confirm it landed`,
        ),
      ),
    );
    if (view.history.entryHashAt(entry.seq) !== expectedHash) {
      return yield* Effect.fail(
        cliError(
          "The server returned success, but the re-synced chain does not contain this checkpoint entry — do not trust this submission; re-run (the effect of a mutation is confirmed only through verifiable distribution — AUTH_SPEC §12-10)",
        ),
      );
    }
  });
}

/**
 * `maruhi project checkpoint`(契機 (ii))と rotate 完了後の周期分(契機 (i))の
 * 共有実装。CRYPTO_SPEC §6.3 の発行 SHOULD の再試行・部分集合退避を含む。
 */
export function issueCheckpoint(
  input: CheckpointInput,
): Effect.Effect<CheckpointSummary, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const targets = yield* resolveTargets(input);
    if (targets.length === 0) {
      return yield* Effect.fail(cliError("This project has no active environments to checkpoint"));
    }
    const attest = yield* determineAuditAttestation(input);
    const warnings: string[] = [];
    const counters: RetryCounters = { mismatch: 0, headConflict: 0, notReady: 0 };
    let previous: BuiltView | null = null;
    let subset: readonly EnvironmentId[] | null = null;
    for (;;) {
      // 型注釈は generator 内の自己参照推論(built → subset → built)を断つため
      const built: BuiltView = yield* buildTuples(input, subset ?? targets);
      warnings.push(...built.warnings);
      // 監査ヘッド申告は CAS 親(署名基準のチェーンヘッド)の確定より後に取得
      // する(§6.3 — 先に取ると間に着地した他者の checkpoint で audit-head-stale
      // に落ちる)。422 の再試行では申告も取り直す(§16-2)
      const auditHeadHashHex = attest
        ? yield* fetchAuditHead(input.client, input.verified.projectId)
        : "";
      const attempt = yield* sendCheckpoint({
        client: input.client,
        view: built.view,
        tuples: built.tuples,
        auditHeadHashHex,
        signerUserId: input.signerUserId,
        signingKeyPair: input.signingKeyPair,
        resync: input.resync,
      }).pipe(
        Effect.map((accepted) => ({ kind: "accepted" as const, accepted })),
        Effect.catch((error) => classifySendFailure(error)),
      );
      if (attempt.kind === "accepted") {
        return summarizeAccepted({
          targets,
          subset,
          attest,
          headSeq: attempt.accepted.headSeq,
          warnings,
        });
      }
      // 再試行可能な失敗の吸収(型注釈は built と同じ理由 — generator 内の
      // 自己参照推論を断つ): null = そのまま再試行、配列 = 部分集合へ退避
      const nextSubset: readonly EnvironmentId[] | null = yield* absorbSendFailure({
        failure: attempt,
        counters,
        built,
        baseline: subset === null ? previous : null,
        warnings,
        io,
      });
      if (nextSubset !== null) {
        subset = nextSubset;
      }
      previous = built;
    }
  });
}

/** issueCheckpoint の再試行カウンタ(失敗種別ごとの独立予算)。 */
interface RetryCounters {
  mismatch: number;
  headConflict: number;
  notReady: number;
}

/**
 * 送信失敗(再試行可能な 3 種)の吸収。返り値 null = ビューを取り直して
 * そのまま再試行、配列 = 部分集合へ退避(§6.3)。予算枯渇は種別ごとの案内で
 * 確定失敗にする。
 *
 * - head-conflict(409): 再署名して再試行(既存慣行の上限)
 * - audit-head-not-ready(503): 申告の取得と受理の間に大量の監査行(一括
 *   var.read 等)が追記され、受理側の再伸長が上限に達した形。失敗応答でも
 *   サーバーの伸長は前進済みなので、ビューと申告を取り直して再試行すれば
 *   収束する(進捗保存 — AUDIT_SPEC §5.1)。枯渇は黙らせず発生条件と再実行での
 *   解消を案内する(session-38 裁定 AG)
 * - state-mismatch(422): ビューの再取得で再試行し、上限到達後は直近 2 回の
 *   構築で不変だったタプルの部分集合で 1 回だけ発行する(§6.3 の退避経路)
 */
function absorbSendFailure(input: {
  readonly failure:
    | { readonly kind: "head-conflict" }
    | { readonly kind: "state-mismatch"; readonly reason: string }
    | { readonly kind: "audit-head-not-ready" };
  readonly counters: RetryCounters;
  readonly built: BuiltView;
  readonly baseline: BuiltView | null;
  readonly warnings: string[];
  readonly io: CliIoShape;
}): Effect.Effect<readonly EnvironmentId[] | null, CliError> {
  return Effect.gen(function* () {
    const { failure, counters, io } = input;
    if (failure.kind === "head-conflict") {
      counters.headConflict += 1;
      yield* ensureHeadConflictBudget(counters.headConflict);
      yield* io.log("The chain head advanced while the checkpoint was in flight — re-signing");
      return null;
    }
    if (failure.kind === "audit-head-not-ready") {
      counters.notReady += 1;
      yield* absorbAcceptanceNotReady(counters.notReady, io);
      return null;
    }
    counters.mismatch += 1;
    if (counters.mismatch < MAX_STATE_MISMATCH_ATTEMPTS) {
      yield* io.log(
        `The server-side state advanced past this checkpoint's view (${failure.reason}) — re-pulling and retrying (attempt ${counters.mismatch + 1} of ${MAX_STATE_MISMATCH_ATTEMPTS})`,
      );
      return null;
    }
    const stableIds = yield* stableSubsetOrFail({
      built: input.built,
      baseline: input.baseline,
      reason: failure.reason,
    });
    input.warnings.push(
      `Bounded retries were exhausted by concurrent writes; issuing a partial checkpoint covering the ${stableIds.length} stable environment(s) (a partial baseline is strictly stronger than none — CRYPTO_SPEC §6.3). Re-run \`maruhi project checkpoint\` later to cover the rest`,
    );
    yield* io.log(
      `Retrying with the stable subset of ${stableIds.length} environment(s) (bounded retries exhausted)`,
    );
    return stableIds;
  });
}

/** 受理後の要約(部分集合発行時は skipped で全環境カバー(SHOULD)の漏れを明示)。 */
function summarizeAccepted(input: {
  readonly targets: readonly EnvironmentId[];
  readonly subset: readonly EnvironmentId[] | null;
  readonly attest: boolean;
  readonly headSeq: number;
  readonly warnings: readonly string[];
}): CheckpointSummary {
  const covered = (input.subset ?? input.targets).map(String);
  return {
    environmentIds: covered,
    skippedEnvironmentIds: input.targets.map(String).filter((id) => !covered.includes(id)),
    attestedAuditHead: input.attest,
    headSeq: input.headSeq,
    warnings: [...new Set(input.warnings)],
  };
}

/**
 * 受理段の AuditHeadNotReady(503)の吸収: 申告の取得と受理の間に大量の監査行
 * (一括 var.read 等)が追記され、受理側の再伸長が上限に達した形。失敗応答でも
 * サーバーの伸長は前進済みなので、ビューと申告を取り直して再試行すれば収束する
 * (進捗保存 — AUDIT_SPEC §5.1)。枯渇は黙らせず発生条件と再実行での解消を
 * 案内する(session-38 裁定 AG)。
 */
function absorbAcceptanceNotReady(attempts: number, io: CliIoShape): Effect.Effect<void, CliError> {
  if (attempts >= MAX_AUDIT_HEAD_NOT_READY_ATTEMPTS) {
    return Effect.fail(cliError(AUDIT_HEAD_NOT_READY_EXHAUSTED));
  }
  return io.log(
    `The server is materializing the audit-head hash column — refetching the attestation and retrying (attempt ${attempts + 1} of ${MAX_AUDIT_HEAD_NOT_READY_ATTEMPTS})`,
  );
}

/** CAS 競合(409)の再署名リトライの残量検査(使い切ったら確定失敗)。 */
function ensureHeadConflictBudget(attempts: number): Effect.Effect<void, CliError> {
  return attempts >= MAX_HEAD_CONFLICT_ATTEMPTS
    ? Effect.fail(
        cliError(
          `The checkpoint's chain-head conflict did not resolve (${MAX_HEAD_CONFLICT_ATTEMPTS} attempts). Wait a moment and re-run \`maruhi project checkpoint\``,
        ),
      )
    : Effect.void;
}

/**
 * 部分集合退避(§6.3): 直近 2 回の構築(baseline / built)で不変だったタプルの
 * 環境 ID を返す。退避不能(既に部分集合で再失敗した = baseline なし、または
 * 安定な環境が 1 つもない)は確定失敗。
 */
function stableSubsetOrFail(input: {
  readonly built: BuiltView;
  readonly baseline: BuiltView | null;
  readonly reason: string;
}): Effect.Effect<readonly EnvironmentId[], CliError> {
  if (input.baseline === null) {
    return Effect.fail(
      cliError(
        `The checkpoint could not be issued: concurrent writes kept invalidating the acceptance-time match (${input.reason}) even for the stable subset. Wait for the writes to settle and re-run \`maruhi project checkpoint\``,
      ),
    );
  }
  const baseline = input.baseline;
  const stableIds = input.built.tuples
    .filter((tuple) =>
      sameTuple(
        tuple,
        baseline.tuples.find((candidate) => candidate.environmentId === tuple.environmentId),
      ),
    )
    .map((tuple) => tuple.environmentId as EnvironmentId);
  if (stableIds.length === 0) {
    return Effect.fail(
      cliError(
        `The checkpoint could not be issued: concurrent writes kept invalidating the acceptance-time match (${input.reason}) for every environment. Wait for the writes to settle and re-run \`maruhi project checkpoint\``,
      ),
    );
  }
  return Effect.succeed(stableIds);
}

/** sendCheckpoint の失敗の分類(再試行の型はここで判別、その他は確定失敗)。 */
function classifySendFailure(
  error: ChainHeadConflictError | CheckpointStateMismatchError | AuditHeadNotReadyError | CliError,
): Effect.Effect<
  | { readonly kind: "head-conflict" }
  | { readonly kind: "state-mismatch"; readonly reason: string }
  | { readonly kind: "audit-head-not-ready" },
  CliError
> {
  if (error instanceof ChainHeadConflictError) {
    return Effect.succeed({ kind: "head-conflict" as const });
  }
  if (error instanceof CheckpointStateMismatchError) {
    return Effect.succeed({ kind: "state-mismatch" as const, reason: error.reason });
  }
  if (error instanceof AuditHeadNotReadyError) {
    return Effect.succeed({ kind: "audit-head-not-ready" as const });
  }
  return Effect.fail(error);
}

// ---------------------------------------------------------------------------
// 発行契機 (iii): push / pull 成功時の提案(CRYPTO_SPEC §6.3 — 7 日超経過
// または未発行の検出)。基準は実効権限で分かれる: admin =「最新の公証あり
// (audit_head_hash 非空)チェックポイント」、それ以外 =「最新のチェック
// ポイント」— 分けないと member の発行が admin の契機を潰し、公証済み接頭辞が
// 前進しなくなる(第 5 ラウンド指摘)。
//
// **未発行の読み方(DP5 裁定 C)**: 「未発行」は基準が genesis のままである
// ことなので、経過日数は **genesis の時刻から**数える。境界チェックポイント
// (複合に同梱 — boundary-checkpoint.ts)は公証なしのため、この読み方をしない
// と実効権限 admin の利用者には**プロジェクト作成の当日から** push / pull の
// たびに提案が出る(公証すべき監査ログがまだ無い段階での提案 = 無視する訓練
// になる)。7 日の閾値は同じで、「発行済みの基準が古い」と「基準が無いまま
// 7 日過ぎた」を同じ節目で扱う。
// ---------------------------------------------------------------------------

/** 契機 (iii) の提案文(接頭辞 `Note:` は notice.ts が付ける)。 */
const PLAIN_BASELINE_PROPOSAL =
  "this project's checkpoint baseline is more than 7 days behind (or was never issued). Run `maruhi project checkpoint` to refresh the rollback-detection baseline (CRYPTO_SPEC §6.3)";
const ATTESTED_BASELINE_PROPOSAL =
  "this project's latest notarized checkpoint is more than 7 days behind (or was never issued). Run `maruhi project checkpoint` to advance the notarized audit prefix (AUDIT_SPEC §6)";

/**
 * 基準チェックポイント(無ければ genesis)が 7 日超古いか。基準が無ければ
 * genesis の時刻(entries[0])から数える(DP5 裁定 C)。エントリが 1 つも無い
 * 検証済みビューは存在しない(genesis 必須)が、型の上では undefined なので、
 * その場合は提案側(fail-open で 1 行の Note)に倒す。
 */
function baselineIsStale(
  entry: ChainEntry | null,
  verified: VerifiedProject,
  nowMs: number,
): boolean {
  const baselineMs = entry === null ? verified.entries[0]?.timestampMs : entry.timestampMs;
  return baselineMs === undefined || nowMs - baselineMs > CHECKPOINT_PROPOSAL_AGE_MS;
}

/** チェーン上の最新 checkpoint エントリ(公証あり限定の切り替え付き)。 */
function latestCheckpointEntry(
  verified: VerifiedProject,
  attestedOnly: boolean,
): ChainEntry | null {
  for (let index = verified.entries.length - 1; index >= 0; index -= 1) {
    const entry = verified.entries[index];
    if (entry === undefined || entry.op !== "checkpoint") {
      continue;
    }
    if (!attestedOnly || entry.payload.auditHeadHashHex !== "") {
      return entry;
    }
  }
  return null;
}

/**
 * push / pull 成功時の発行提案(契機 (iii))。提案するときだけ /auth/me を引く
 * (実効権限の確定はスコープを要するが、提案の頻度でスコープ取得の往復を
 * 増やさない — role が admin 未満なら公証なし基準で確定する)。返り値は
 * 表示すべき提案行(null = 提案なし)。timestampMs はクライアント申告時刻で、
 * 提案の閾値判定にのみ使う(検証には使わない)。
 */
export function checkpointProposal(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly signerUserId: string;
  readonly nowMs: number;
}): Effect.Effect<string | null, never> {
  return Effect.gen(function* () {
    const member = input.verified.state.members.get(input.signerUserId);
    if (member === undefined || member.role === "reader") {
      // 発行は member 以上(§6.2)。reader には提案しない
      return null;
    }
    const plainBasis = latestCheckpointEntry(input.verified, false);
    const stale = (entry: ChainEntry | null): boolean =>
      baselineIsStale(entry, input.verified, input.nowMs);
    const adminRole = member.role === "admin" || member.role === "owner";
    if (!adminRole) {
      return stale(plainBasis) ? PLAIN_BASELINE_PROPOSAL : null;
    }
    const attestedBasis = latestCheckpointEntry(input.verified, true);
    if (!stale(attestedBasis)) {
      return null;
    }
    // 公証あり基準が古い: 実効権限(スコープ半分)を確かめてから提案の文面を
    // 決める。/auth/me は提案が成立しかけたときにだけ引く
    const effectiveAdmin = yield* determineAuditAttestation(input).pipe(
      Effect.catch(() => Effect.succeed(false)),
    );
    if (effectiveAdmin) {
      return ATTESTED_BASELINE_PROPOSAL;
    }
    return stale(plainBasis) ? PLAIN_BASELINE_PROPOSAL : null;
  });
}

/**
 * アンカー更新の提案(session-25 §8 / CRYPTO_SPEC §6.3 (b) SHOULD の後半)。
 * rotate 成功時は無条件(アンカーのエポック床が古くなる — アンカーの中核の
 * 検出材料)、push 成功時は契機 (iii) の提案と**同じ 1 行**に同梱する(裁定は
 * docs/notes/session-35.md — アンカー使用の有無をローカルで知れないため、
 * push ごとの無条件出力は提案を無視させる訓練になる。DP5 裁定 C で 2 行 →
 * 1 行に畳んだ)。
 */
export const ANCHOR_REFRESH_PROPOSAL =
  "If this project commits a repository anchor for CI (CRYPTO_SPEC §6.3), refresh it afterwards: `maruhi project anchor > <anchor-file>` and commit the update";

/** rotate 成功時のアンカー提案(エポックが進んだ = アンカーは確実に古い)。 */
export const ANCHOR_STALE_AFTER_ROTATION =
  "the epoch advanced, so a committed repository anchor (if any) is now stale. Refresh it: `maruhi project anchor > <anchor-file>` and commit the update (CRYPTO_SPEC §6.3)";
