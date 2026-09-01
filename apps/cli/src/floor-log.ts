// ローカル床の保存形: 追記専用の観測ログ + fold(CRYPTO_SPEC §6.3 —
// 2026-08-19 セッション 32 改訂の 3-E / 3-E′ / 3-F)。
//
// - 床ファイルは「検証済み観測の追記専用ログ(1 観測 = 1 行の JSONL)」であり、
//   床 = ログを fold した join として**導出**する。上書き更新の保存形
//   (読み・merge・書き戻し)は用いない — 並行プロセスの観測は両方ログに残り、
//   同座標 conflict は fold 時に typed conflict として顕在化する(**上書きに
//   よる証拠喪失が「禁止」から「表現不能」になる**)。M1 ではプロセス間ロック
//   自体が存在しない(追記のみ)
// - 追記は追記モード(O_APPEND 相当)のみ・**fsync 相当の永続化まで待つ**
//   (3-E′ — journal-before-release / before-send の「記録」基準)
// - 破損レコード(クラッシュ・電源断の torn write)は fold が無視する
//   (自己回復)。追記は常に改行を**前置**するため、torn 行が後続レコードを
//   壊すことはない(末尾検査は行わない — appendRecords の JSDoc)
// - コンパクションは「現在の fold 結果 + 畳んだ接頭辞の終端位置」を
//   **スナップショットレコードとして追記**する形でのみ行う(契機 = 最新
//   スナップショットレコード以降に積まれた相対量の閾値超過)。書き直し・
//   切り詰め・物理回収は M1 では行わない(M2 の checkpoint 基準接続と同時に
//   設計する)。同座標 conflict の証拠はスナップショットに畳まれても消えない
// - intent / resolution レコード(3-F)は join の格子に入れない別クラス —
//   fold は未解決 intent を「要照合」として表面化する
//
// 旧保存形(<projectId>.json の単一スナップショット — PR #33)は読み出し時に
// 互換読みし、最初の追記でスナップショットレコードとしてログへ移行する
// (旧ファイルはフォレンジック材料としてそのまま残す — 追記専用の規律)。

import { mkdir, open, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { isEnvironmentId, isProjectId, isVariableId } from "@maruhi/core";
import { Effect } from "effect";

import { cliError, type CliError } from "./errors.ts";
import { formatFloorConflicts } from "./floor-evidence.ts";
import {
  type AttestationEvidenceRecord,
  type ChainHeadFloor,
  emptyEnvironmentFloor,
  type EnvironmentFloor,
  type FloorConflict,
  type FloorIntent,
  type FloorIntentInput,
  type FloorIntentOutcome,
  type FloorLoadResult,
  floorRecordGet,
  type FloorStoreShape,
  joinChainHead,
  joinEnvironmentFloor,
  type ManifestCommit,
  type ManifestFloor,
  type MetadataCommit,
  type ProjectFloor,
  type PullCommit,
  type PushCommit,
  type VariableFloor,
} from "./floor.ts";

/**
 * コンパクション契機: 最新スナップショットレコード以降に積まれたレコード数の
 * 閾値(相対量 — 総ファイルサイズ基準は一度超えると恒久成立するため使わない)。
 * fold コストの有界化はこの相対基準そのものが担う。
 */
const DEFAULT_COMPACTION_THRESHOLD = 256;

/** 1 論理 append の全長書き直し再試行の上限(short write — appendRecords)。 */
const MAX_APPEND_WRITE_ATTEMPTS = 3;

/** スナップショットレコードの中身(= fold 結果。conflicts / intents 込み)。 */
interface SnapshotState {
  readonly chainHead: ChainHeadFloor | null;
  readonly environments: Readonly<Record<string, EnvironmentFloor>>;
  readonly conflicts: readonly FloorConflict[];
  readonly intents: readonly FloorIntent[];
}

/** 観測ログのレコード(1 行 = 1 レコード)。 */
type FloorLogRecord =
  | { readonly r: "head"; readonly head: ChainHeadFloor }
  | {
      readonly r: "pull";
      readonly head: ChainHeadFloor;
      readonly environmentId: string;
      readonly environment: EnvironmentFloor;
    }
  | {
      readonly r: "push";
      readonly head: ChainHeadFloor;
      readonly environmentId: string;
      readonly variableId: string;
      readonly variable: VariableFloor;
    }
  | {
      readonly r: "meta";
      readonly head: ChainHeadFloor;
      readonly environmentId: string;
      readonly observedEpoch: number;
      readonly metaVersion: number;
      readonly metaSigHashHex: string;
      readonly manifest: ManifestFloor;
    }
  | {
      readonly r: "manifest";
      readonly head: ChainHeadFloor;
      readonly environmentId: string;
      readonly manifest: ManifestFloor;
    }
  | { readonly r: "intent"; readonly intent: FloorIntent }
  | {
      readonly r: "resolution";
      readonly intentId: string;
      readonly outcome: FloorIntentOutcome;
    }
  | {
      /**
       * コンパクション: `folded` は畳んだ接頭辞の終端位置(このレコードより
       * 前の解読可能レコードのうち fold 済みの個数)。fold は「スナップショットの
       * state ⊔ 位置 `folded` 以降の全レコード」— 並行追記がスナップショットの
       * 読みと追記の間に着地しても、join の冪等性・可換性により二重畳みは無害で
       * 取りこぼしは位置基準が防ぐ。位置が壊れていれば全レコード fold へ
       * フォールバックする(正しさは変わらない — §6.3)。
       */
      readonly r: "snapshot";
      readonly folded: number;
      readonly state: SnapshotState;
    };

// ---- 厳格デコード(1 レコード単位。壊れた行は fold が無視する = 自己回復) ----

const HEX_64 = /^[0-9a-f]{64}$/;
const INTENT_ID = /^[0-9a-f]{16}$/;

function isNonNegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isPositiveInteger(value: unknown): value is number {
  return isNonNegativeInteger(value) && value > 0;
}

function isHex64(value: unknown): value is string {
  return typeof value === "string" && HEX_64.test(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// @maruhi/core の ID ガードは string 引数 — unknown からの 2 段ガードをここで包む
function isEnvironmentIdValue(value: unknown): value is string {
  return typeof value === "string" && isEnvironmentId(value);
}

function isVariableIdValue(value: unknown): value is string {
  return typeof value === "string" && isVariableId(value);
}

function isString(value: unknown): value is string {
  return typeof value === "string";
}

const isNullOr =
  (check: (value: unknown) => boolean) =>
  (value: unknown): boolean =>
    value === null || check(value);

/**
 * フィールド仕様の一括検査。strict デコードの `||` 連鎖(1 条件 = 1 分岐)を
 * データへ畳む — fallow の複雑度ゲート対応であると同時に、仕様の列挙が
 * 見た目にもフィールド表になる。
 */
function fieldsValid(
  record: Record<string, unknown>,
  spec: Readonly<Record<string, (value: unknown) => boolean>>,
): boolean {
  return Object.entries(spec).every(([key, check]) => check(record[key]));
}

/** 全要素が strict にデコードできた場合のみ配列を返す(1 件でも壊れていれば null)。 */
function decodeList<T>(value: unknown, decode: (item: unknown) => T | null): T[] | null {
  if (!Array.isArray(value)) {
    return null;
  }
  const items: T[] = [];
  for (const raw of value) {
    const item = decode(raw);
    if (item === null) {
      return null;
    }
    items.push(item);
  }
  return items;
}

function decodeChainHead(value: unknown): ChainHeadFloor | null {
  if (!isRecord(value) || !isPositiveInteger(value["seq"]) || !isHex64(value["hashHex"])) {
    return null;
  }
  return { seq: value["seq"], hashHex: value["hashHex"] };
}

function decodeVariableFloor(value: unknown): VariableFloor | null {
  if (!isRecord(value)) {
    return null;
  }
  if (!isPositiveInteger(value["metaVersion"]) || !isHex64(value["metaSigHashHex"])) {
    return null;
  }
  const meta = {
    metaVersion: value["metaVersion"],
    metaSigHashHex: value["metaSigHashHex"],
  };
  if (value["status"] === "deleted") {
    return { status: "deleted", ...meta };
  }
  // declared(レイアウト v2 の値未設定宣言 — §4.2)はメタ側のみ(値床は空)
  if (value["status"] === "declared") {
    return { status: "declared", ...meta };
  }
  if (
    value["status"] !== "active" ||
    !isPositiveInteger(value["version"]) ||
    !isPositiveInteger(value["epoch"]) ||
    !isHex64(value["valueSigHashHex"])
  ) {
    return null;
  }
  return {
    status: "active",
    version: value["version"],
    epoch: value["epoch"],
    valueSigHashHex: value["valueSigHashHex"],
    ...meta,
  };
}

function decodeManifestFloor(value: unknown): ManifestFloor | null {
  if (
    !isRecord(value) ||
    !isPositiveInteger(value["manifestVersion"]) ||
    !isPositiveInteger(value["epoch"]) ||
    !isHex64(value["manifestSigHashHex"])
  ) {
    return null;
  }
  return {
    manifestVersion: value["manifestVersion"],
    epoch: value["epoch"],
    manifestSigHashHex: value["manifestSigHashHex"],
  };
}

// レコードキー(environmentId / variableId)は §12-1 の受理形式を要求する。
// 正規の床は wire スキーマ検証済み(または CLI 採番)の ID しか書かないため、
// 形式外のキー = 破損として行単位で拒否する。これは `__proto__`(先頭 `_` で
// 形式外)を構造的に排除する。`constructor` / `prototype` は正当な ID であり
// 拒否しない(参照側は floorRecordGet の own-property 参照で守る)
function decodeVariablesRecord(value: unknown): Record<string, VariableFloor> | null {
  if (!isRecord(value)) {
    return null;
  }
  const variables: Record<string, VariableFloor> = {};
  for (const [variableId, raw] of Object.entries(value)) {
    const variable = decodeVariableFloor(raw);
    if (variable === null || !isVariableId(variableId)) {
      return null;
    }
    variables[variableId] = variable;
  }
  return variables;
}

/** manifest(省略可)+ variables の共通デコード(新形と旧形が共有する尾部)。 */
function decodeManifestAndVariables(
  value: Record<string, unknown>,
): { readonly manifest?: ManifestFloor; readonly variables: Record<string, VariableFloor> } | null {
  const manifest =
    value["manifest"] === undefined ? undefined : decodeManifestFloor(value["manifest"]);
  const variables = decodeVariablesRecord(value["variables"]);
  if (manifest === null || variables === null) {
    return null;
  }
  return { ...(manifest === undefined ? {} : { manifest }), variables };
}

/** 環境床(新形 — bottom 座標を許す: pullEpoch / observedEpoch / metaVersion = 0)。 */
function decodeEnvironmentFloor(value: unknown): EnvironmentFloor | null {
  if (
    !isRecord(value) ||
    !fieldsValid(value, {
      pullEpoch: isNonNegativeInteger,
      observedEpoch: isNonNegativeInteger,
      metaVersion: isNonNegativeInteger,
    })
  ) {
    return null;
  }
  const metaSigHashHex = value["metaSigHashHex"];
  const metaValid = value["metaVersion"] === 0 ? metaSigHashHex === "" : isHex64(metaSigHashHex);
  const tail = decodeManifestAndVariables(value);
  if (!metaValid || tail === null) {
    return null;
  }
  return {
    pullEpoch: value["pullEpoch"] as number,
    observedEpoch: value["observedEpoch"] as number,
    metaVersion: value["metaVersion"] as number,
    metaSigHashHex: metaSigHashHex as string,
    ...tail,
  };
}

function decodeEnvironmentsRecord(value: unknown): Record<string, EnvironmentFloor> | null {
  if (!isRecord(value)) {
    return null;
  }
  const environments: Record<string, EnvironmentFloor> = {};
  for (const [environmentId, raw] of Object.entries(value)) {
    const environment = decodeEnvironmentFloor(raw);
    if (environment === null || !isEnvironmentId(environmentId)) {
      return null;
    }
    environments[environmentId] = environment;
  }
  return environments;
}

const CONFLICT_KINDS: readonly FloorConflict["kind"][] = [
  "chain-head",
  "value",
  "variable-meta",
  "environment-meta",
  "manifest",
  "undeletion",
];

function decodeConflict(value: unknown): FloorConflict | null {
  if (
    !isRecord(value) ||
    !fieldsValid(value, {
      kind: (kind) => CONFLICT_KINDS.includes(kind as FloorConflict["kind"]),
      environmentId: isNullOr(isEnvironmentIdValue),
      variableId: isNullOr(isVariableIdValue),
      firstVersion: isNonNegativeInteger,
      firstHashHex: isString,
      secondVersion: isNonNegativeInteger,
      secondHashHex: isString,
    })
  ) {
    return null;
  }
  return {
    kind: value["kind"] as FloorConflict["kind"],
    environmentId: value["environmentId"] as string | null,
    variableId: value["variableId"] as string | null,
    firstVersion: value["firstVersion"] as number,
    firstHashHex: value["firstHashHex"] as string,
    secondVersion: value["secondVersion"] as number,
    secondHashHex: value["secondHashHex"] as string,
  };
}

const INTENT_OPS: readonly FloorIntent["op"][] = ["create_environment", "rotate_epoch", "meta-op"];
const INTENT_OUTCOMES: readonly FloorIntentOutcome[] = [
  "accepted",
  "accepted-superseded",
  "rejected",
  "not-accepted",
  "superseded",
];

function decodeIntent(value: unknown): FloorIntent | null {
  if (
    !isRecord(value) ||
    !fieldsValid(value, {
      id: (id) => isString(id) && INTENT_ID.test(id),
      op: (op) => INTENT_OPS.includes(op as FloorIntent["op"]),
      environmentId: isEnvironmentIdValue,
      epoch: isPositiveInteger,
      dekCommitmentHex: isNullOr(isHex64),
      variableId: isNullOr(isVariableIdValue),
      manifestVersion: isPositiveInteger,
      manifestSigHashHex: isHex64,
    })
  ) {
    return null;
  }
  const declaredHead = decodeChainHead(value["declaredHead"]);
  if (declaredHead === null) {
    return null;
  }
  return {
    id: value["id"] as string,
    op: value["op"] as FloorIntent["op"],
    environmentId: value["environmentId"] as string,
    epoch: value["epoch"] as number,
    dekCommitmentHex: value["dekCommitmentHex"] as string | null,
    variableId: value["variableId"] as string | null,
    manifestVersion: value["manifestVersion"] as number,
    manifestSigHashHex: value["manifestSigHashHex"] as string,
    declaredHead,
  };
}

function decodeSnapshotState(value: unknown): SnapshotState | null {
  if (!isRecord(value)) {
    return null;
  }
  const chainHead = value["chainHead"] === null ? null : decodeChainHead(value["chainHead"]);
  if (chainHead === null && value["chainHead"] !== null) {
    return null;
  }
  const environments = decodeEnvironmentsRecord(value["environments"]);
  const conflicts = decodeList(value["conflicts"], decodeConflict);
  const intents = decodeList(value["intents"], decodeIntent);
  if (environments === null || conflicts === null || intents === null) {
    return null;
  }
  return { chainHead, environments, conflicts, intents };
}

/** 環境座標を持つレコードの共通部(head + environmentId)のデコード。 */
function decodeScoped(
  value: Record<string, unknown>,
): { readonly head: ChainHeadFloor; readonly environmentId: string } | null {
  const head = decodeChainHead(value["head"]);
  if (head === null || !isEnvironmentIdValue(value["environmentId"])) {
    return null;
  }
  return { head, environmentId: value["environmentId"] as string };
}

function decodePullRecord(value: Record<string, unknown>): FloorLogRecord | null {
  const scoped = decodeScoped(value);
  const environment = decodeEnvironmentFloor(value["environment"]);
  if (scoped === null || environment === null) {
    return null;
  }
  return { r: "pull", ...scoped, environment };
}

function decodePushRecord(value: Record<string, unknown>): FloorLogRecord | null {
  const scoped = decodeScoped(value);
  const variable = decodeVariableFloor(value["variable"]);
  if (scoped === null || variable === null || !isVariableIdValue(value["variableId"])) {
    return null;
  }
  return { r: "push", ...scoped, variableId: value["variableId"] as string, variable };
}

function decodeMetaRecord(value: Record<string, unknown>): FloorLogRecord | null {
  const scoped = decodeScoped(value);
  const manifest = decodeManifestFloor(value["manifest"]);
  const valid = fieldsValid(value, {
    observedEpoch: isPositiveInteger,
    metaVersion: isPositiveInteger,
    metaSigHashHex: isHex64,
  });
  if (scoped === null || manifest === null || !valid) {
    return null;
  }
  return {
    r: "meta",
    ...scoped,
    observedEpoch: value["observedEpoch"] as number,
    metaVersion: value["metaVersion"] as number,
    metaSigHashHex: value["metaSigHashHex"] as string,
    manifest,
  };
}

function decodeManifestRecord(value: Record<string, unknown>): FloorLogRecord | null {
  const scoped = decodeScoped(value);
  const manifest = decodeManifestFloor(value["manifest"]);
  if (scoped === null || manifest === null) {
    return null;
  }
  return { r: "manifest", ...scoped, manifest };
}

function decodeHeadRecord(value: Record<string, unknown>): FloorLogRecord | null {
  const head = decodeChainHead(value["head"]);
  return head === null ? null : { r: "head", head };
}

function decodeIntentRecord(value: Record<string, unknown>): FloorLogRecord | null {
  const intent = decodeIntent(value["intent"]);
  return intent === null ? null : { r: "intent", intent };
}

function decodeResolutionRecord(value: Record<string, unknown>): FloorLogRecord | null {
  const valid = fieldsValid(value, {
    intentId: (id) => isString(id) && INTENT_ID.test(id),
    outcome: (outcome) => INTENT_OUTCOMES.includes(outcome as FloorIntentOutcome),
  });
  if (!valid) {
    return null;
  }
  return {
    r: "resolution",
    intentId: value["intentId"] as string,
    outcome: value["outcome"] as FloorIntentOutcome,
  };
}

function decodeSnapshotRecord(value: Record<string, unknown>): FloorLogRecord | null {
  const state = decodeSnapshotState(value["state"]);
  if (state === null || !isNonNegativeInteger(value["folded"])) {
    return null;
  }
  return { r: "snapshot", folded: value["folded"], state };
}

// r タグ → デコーダの対応(Map — 素の Record だと `constructor` 等の r 値が
// 継承プロパティの関数へ解決されて破損レコードが通る)
const RECORD_DECODERS = new Map<string, (value: Record<string, unknown>) => FloorLogRecord | null>([
  ["head", decodeHeadRecord],
  ["pull", decodePullRecord],
  ["push", decodePushRecord],
  ["meta", decodeMetaRecord],
  ["manifest", decodeManifestRecord],
  ["intent", decodeIntentRecord],
  ["resolution", decodeResolutionRecord],
  ["snapshot", decodeSnapshotRecord],
]);

/** 1 行の厳格デコード。null = 解読不能(fold が無視する — 自己回復)。 */
function decodeLogRecord(line: string): FloorLogRecord | null {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    return null;
  }
  if (!isRecord(value) || !isString(value["r"])) {
    return null;
  }
  const decode = RECORD_DECODERS.get(value["r"]);
  return decode === undefined ? null : decode(value);
}

// ---- fold(観測ログ → 床)----

interface FoldState {
  chainHead: ChainHeadFloor | null;
  readonly environments: Map<string, EnvironmentFloor>;
  readonly conflicts: Map<string, FloorConflict>;
  readonly intents: Map<string, FloorIntent>;
}

function conflictKey(conflict: FloorConflict): string {
  // 同一 conflict の再導出(fold は毎回走る)とスナップショット由来の重複を
  // 座標 + 両証拠で同一視する。証拠の並びは join の代表選択と独立に正規化する
  const pair = [
    `${conflict.firstVersion}:${conflict.firstHashHex}`,
    `${conflict.secondVersion}:${conflict.secondHashHex}`,
  ].toSorted();
  return `${conflict.kind}|${conflict.environmentId ?? ""}|${conflict.variableId ?? ""}|${pair.join("|")}`;
}

function addConflict(state: FoldState, conflict: FloorConflict): void {
  const key = conflictKey(conflict);
  if (!state.conflicts.has(key)) {
    state.conflicts.set(key, conflict);
  }
}

function joinEnvironmentInto(
  state: FoldState,
  environmentId: string,
  incoming: EnvironmentFloor,
): void {
  const sink = (conflict: FloorConflict) => addConflict(state, conflict);
  state.environments.set(
    environmentId,
    joinEnvironmentFloor(environmentId, state.environments.get(environmentId), incoming, sink),
  );
}

function applyRecord(state: FoldState, record: FloorLogRecord): void {
  const sink = (conflict: FloorConflict) => addConflict(state, conflict);
  switch (record.r) {
    case "head":
      state.chainHead = joinChainHead(state.chainHead, record.head, sink);
      return;
    case "pull":
      state.chainHead = joinChainHead(state.chainHead, record.head, sink);
      joinEnvironmentInto(state, record.environmentId, record.environment);
      return;
    case "push":
      state.chainHead = joinChainHead(state.chainHead, record.head, sink);
      joinEnvironmentInto(state, record.environmentId, {
        ...emptyEnvironmentFloor(),
        variables: { [record.variableId]: record.variable },
      });
      return;
    case "meta":
      state.chainHead = joinChainHead(state.chainHead, record.head, sink);
      joinEnvironmentInto(state, record.environmentId, {
        ...emptyEnvironmentFloor(),
        observedEpoch: record.observedEpoch,
        metaVersion: record.metaVersion,
        metaSigHashHex: record.metaSigHashHex,
        manifest: record.manifest,
      });
      return;
    case "manifest":
      state.chainHead = joinChainHead(state.chainHead, record.head, sink);
      joinEnvironmentInto(state, record.environmentId, {
        ...emptyEnvironmentFloor(),
        // マニフェストは検証済み観測なので、その epoch は環境水準のエポック
        // 観測(座標 (ii))としても join する(pull 基準 (i) は動かさない)
        observedEpoch: record.manifest.epoch,
        manifest: record.manifest,
      });
      return;
    case "intent":
      state.intents.set(record.intent.id, record.intent);
      return;
    case "resolution":
      state.intents.delete(record.intentId);
      return;
    case "snapshot":
      // fold 側では no-op(基点の選択は foldRecords が行う — 二重畳みは無害)
      return;
  }
}

interface FoldOutcome {
  readonly floor: ProjectFloor;
  /** 解読できたレコード総数(スナップショットの `folded` の基準位置)。 */
  readonly decodedRecords: number;
  /** 解読できなかった非空行の数(torn 行の自己回復 — 診断用)。 */
  readonly droppedLines: number;
  /** 最新スナップショットレコード以降に積まれたレコード数(コンパクション契機)。 */
  readonly recordsSinceSnapshot: number;
}

function baseStateOf(snapshot: { folded: number; state: SnapshotState } | null): FoldState {
  if (snapshot === null) {
    return { chainHead: null, environments: new Map(), conflicts: new Map(), intents: new Map() };
  }
  const state: FoldState = {
    chainHead: snapshot.state.chainHead,
    environments: new Map(Object.entries(snapshot.state.environments)),
    conflicts: new Map(),
    intents: new Map(snapshot.state.intents.map((intent) => [intent.id, intent])),
  };
  for (const conflict of snapshot.state.conflicts) {
    addConflict(state, conflict);
  }
  return state;
}

/**
 * 行 → 解読できたレコード列 + 落とした非空行の位置(torn 行の自己回復)。
 * 位置 = その行の直前までに解読できたレコード数 — fold 基点(スナップショットの
 * folded)より前の落ちた行は「畳まれた接頭辞の中」なので警告の対象から外れる
 * (コンパクションが警告を自然に retire する — 恒久的に鳴り続けるノイズを
 * equivocation 警告と同じ帯域へ載せない)。
 */
function parseLogLines(lines: readonly string[]): {
  readonly records: FloorLogRecord[];
  readonly droppedAtRecordCount: readonly number[];
} {
  const records: FloorLogRecord[] = [];
  const droppedAtRecordCount: number[] = [];
  for (const line of lines) {
    if (line.trim() === "") {
      continue;
    }
    const record = decodeLogRecord(line);
    if (record === null) {
      // torn 行(クラッシュした並行プロセスの書きかけ)の自己回復。conflict の
      // 証拠行は正しい JSON なのでここでは失われない
      droppedAtRecordCount.push(records.length);
      continue;
    }
    records.push(record);
  }
  return { records, droppedAtRecordCount };
}

/**
 * fold の基点 = 最新の有効なスナップショット。「畳んだ接頭辞の終端位置
 * (folded)」がスナップショット自身の位置を超えている(壊れている)場合は
 * 全レコード fold へフォールバックする — join の冪等性・可換性により正しさは
 * 不変(コストだけが変わる — §6.3)。
 */
function foldBase(records: readonly FloorLogRecord[]): {
  readonly foldFrom: number;
  readonly snapshotIndex: number;
  readonly state: FoldState;
} {
  for (let index = records.length - 1; index >= 0; index -= 1) {
    const record = records[index];
    if (record?.r === "snapshot") {
      const usable = record.folded <= index;
      return {
        foldFrom: usable ? record.folded : 0,
        snapshotIndex: index,
        state: baseStateOf(usable ? record : null),
      };
    }
  }
  return { foldFrom: 0, snapshotIndex: -1, state: baseStateOf(null) };
}

function foldRecords(lines: readonly string[]): FoldOutcome {
  const { records, droppedAtRecordCount } = parseLogLines(lines);
  const { foldFrom, snapshotIndex, state } = foldBase(records);
  for (let index = foldFrom; index < records.length; index += 1) {
    applyRecord(state, records[index] as FloorLogRecord);
  }
  return {
    floor: {
      chainHead: state.chainHead,
      environments: Object.fromEntries(state.environments),
      conflicts: [...state.conflicts.values()],
      intents: [...state.intents.values()],
    },
    decodedRecords: records.length,
    // fold 基点より後の落ちた行だけを数える(基点より前はスナップショットへ
    // 畳まれた接頭辞 — 警告済みの古い torn 行を恒久的に鳴らさない)
    droppedLines: droppedAtRecordCount.filter((position) => position >= foldFrom).length,
    recordsSinceSnapshot: snapshotIndex >= 0 ? records.length - 1 - snapshotIndex : records.length,
  };
}

// ---- 旧保存形(単一 JSON スナップショット)の互換読み ----

interface LegacyEnvironmentFloor {
  readonly pullEpoch: number;
  readonly metaVersion: number;
  readonly metaSigHashHex: string;
  readonly manifest?: ManifestFloor;
  readonly variables: Record<string, VariableFloor>;
}

function decodeLegacyEnvironment(value: unknown): LegacyEnvironmentFloor | null {
  if (
    !isRecord(value) ||
    !fieldsValid(value, {
      pullEpoch: isPositiveInteger,
      metaVersion: isPositiveInteger,
      metaSigHashHex: isHex64,
    })
  ) {
    return null;
  }
  const tail = decodeManifestAndVariables(value);
  if (tail === null) {
    return null;
  }
  return {
    pullEpoch: value["pullEpoch"] as number,
    metaVersion: value["metaVersion"] as number,
    metaSigHashHex: value["metaSigHashHex"] as string,
    ...tail,
  };
}

/** 旧環境床 → 新形(環境水準観測は既知の検証済み事実から保守的に導出)。 */
function convertLegacyEnvironment(legacy: LegacyEnvironmentFloor): EnvironmentFloor {
  return {
    pullEpoch: legacy.pullEpoch,
    // 旧形式は環境水準観測(座標 (ii))を持たない — 既知の検証済み事実
    // (pull 基準と床マニフェスト自身の epoch)から保守的に導出する
    observedEpoch: Math.max(legacy.pullEpoch, legacy.manifest?.epoch ?? 0),
    metaVersion: legacy.metaVersion,
    metaSigHashHex: legacy.metaSigHashHex,
    ...(legacy.manifest === undefined ? {} : { manifest: legacy.manifest }),
    variables: legacy.variables,
  };
}

function decodeLegacyEnvironments(value: unknown): Record<string, EnvironmentFloor> | null {
  if (!isRecord(value)) {
    return null;
  }
  const environments: Record<string, EnvironmentFloor> = {};
  for (const [environmentId, raw] of Object.entries(value)) {
    const legacy = decodeLegacyEnvironment(raw);
    if (legacy === null || !isEnvironmentId(environmentId)) {
      return null;
    }
    environments[environmentId] = convertLegacyEnvironment(legacy);
  }
  return environments;
}

/** 旧形式(v1 単一スナップショット)→ 新しい床(fold 結果と同形)への変換。 */
function decodeLegacyProjectFloor(json: string): ProjectFloor | null {
  let value: unknown;
  try {
    value = JSON.parse(json);
  } catch {
    return null;
  }
  if (!isRecord(value) || value["v"] !== 1) {
    return null;
  }
  const chainHead = decodeChainHead(value["chainHead"]);
  const environments = decodeLegacyEnvironments(value["environments"]);
  if (chainHead === null || environments === null) {
    return null;
  }
  return { chainHead, environments, conflicts: [], intents: [] };
}

// ---- ファイルストア ----

function isFileMissingError(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    (error as NodeJS.ErrnoException).code === "ENOENT"
  );
}

function encodeRecord(record: FloorLogRecord): string {
  return `${JSON.stringify(record)}\n`;
}

function randomIntentId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** commit 系の返り値: fold 済み床から当該環境の床(未観測なら bottom)。 */
function environmentOf(floor: ProjectFloor, environmentId: string): EnvironmentFloor {
  return floorRecordGet(floor.environments, environmentId) ?? emptyEnvironmentFloor();
}

export interface FileFloorStoreOptions {
  /** コンパクション契機(最新スナップショット以降のレコード数)。テスト用の上書き。 */
  readonly compactionThreshold?: number;
}

/** File-backed append-only floor store rooted at `dir` (production and tests share this). */
export function makeFileFloorStore(dir: string, options?: FileFloorStoreOptions): FloorStoreShape {
  const compactionThreshold = options?.compactionThreshold ?? DEFAULT_COMPACTION_THRESHOLD;

  const pathOf = (projectId: string): string => {
    // projectId は genesis ハッシュ(hex 64)のはずだが、ファイル名に使う前に
    // 形式を強制する(パス組み立てへの信頼できない文字列の混入を防ぐ)
    if (!isProjectId(projectId)) {
      throw new Error(`invalid project id for floor path: ${projectId}`);
    }
    return join(dir, `${projectId}.jsonl`);
  };
  const legacyPathOf = (projectId: string): string => join(dir, `${projectId}.json`);

  /** 旧形式ファイルの読み(存在しなければ null。破損は corrupt として区別)。 */
  const readLegacy = async (
    projectId: string,
  ): Promise<{ readonly floor: ProjectFloor | null; readonly corrupt: boolean }> => {
    let json: string;
    try {
      json = await readFile(legacyPathOf(projectId), "utf8");
    } catch (error) {
      if (isFileMissingError(error)) {
        return { floor: null, corrupt: false };
      }
      throw error;
    }
    const floor = decodeLegacyProjectFloor(json);
    return floor === null ? { floor: null, corrupt: true } : { floor, corrupt: false };
  };

  /**
   * 追記(O_APPEND 相当)+ fsync 相当の永続化(3-E′)。空のログへの最初の
   * 追記は、旧形式スナップショットがあればそれをスナップショットレコードとして
   * 先頭に移行する。
   *
   * 書き込みは常に改行を**前置**する: 並行プロセスの torn 行(改行なしの
   * 書きかけ)が直前に着地していても、自分のレコードは必ず新しい行として
   * 隔離される(fold は空行を無視する)。「末尾バイトを読んで判定する」形は
   * 検査と O_APPEND 書き込みの間に torn 行が割り込むレースを持つため使わない
   * (割り込まれると自分の完全なレコードが 1 行に連結されて失われ、
   * journal-before-release が無言で破れる)。write は short write に備えて
   * 全バイト書けるまでループする(datasync が永続化の基準 — 3-E′)。
   */
  const appendRecords = async (
    projectId: string,
    records: readonly FloorLogRecord[],
  ): Promise<void> => {
    const path = pathOf(projectId);
    await mkdir(dir, { recursive: true, mode: 0o700 });
    const handle = await open(path, "a", 0o600);
    try {
      const { size } = await handle.stat();
      const lines: FloorLogRecord[] = [...records];
      if (size === 0) {
        const legacy = await readLegacy(projectId);
        if (legacy.floor !== null) {
          lines.unshift({
            r: "snapshot",
            folded: 0,
            state: {
              chainHead: legacy.floor.chainHead,
              environments: legacy.floor.environments,
              conflicts: [],
              intents: [],
            },
          });
        }
      }
      const payload = Buffer.from(`\n${lines.map(encodeRecord).join("")}`, "utf8");
      // 1 論理 append = 1 write syscall(O_APPEND の原子性が及ぶ単位)。short
      // write の**残りを継ぎ足さない**: 継ぎ足しの 2 回目の write は別プロセスの
      // 追記と交錯し、1 レコードが 2 つの不正断片に分裂して無言で失われる
      // (成功を返してはならない形)。断片は改行前置で隔離済みの torn 行として
      // fold が捨てるので、payload **全体**を先頭から書き直す — join は冪等な
      // ため重複レコードは無害。書き切れないまま尽きたら失敗として投げる
      // (mutate が床エラーへ変換し、呼び出し側は「永続化済み」と扱わない)
      for (let attempt = 1; ; attempt += 1) {
        const result = await handle.write(payload, 0, payload.length);
        if (result.bytesWritten === payload.length) {
          break;
        }
        if (result.bytesWritten === 0 || attempt >= MAX_APPEND_WRITE_ATTEMPTS) {
          throw new Error(
            `short write on the floor log (${result.bytesWritten}/${payload.length} bytes)`,
          );
        }
      }
      await handle.datasync();
    } finally {
      await handle.close();
    }
  };

  const readAndFold = async (projectId: string): Promise<FoldOutcome> => {
    const raw = await readFile(pathOf(projectId), "utf8");
    return foldRecords(raw.split("\n"));
  };

  /** 追記 → fold。fold が conflict を持てば typed エラー(証拠はログに残っている)。 */
  const mutate = (
    projectId: string,
    records: readonly FloorLogRecord[],
  ): Effect.Effect<ProjectFloor, CliError> =>
    Effect.tryPromise({
      try: async () => {
        await appendRecords(projectId, records);
        let outcome = await readAndFold(projectId);
        if (outcome.recordsSinceSnapshot > compactionThreshold) {
          // コンパクション = スナップショットレコードの追記のみ(書き直さない)。
          // 並行スナップショット 2 本は無害(fold は最新の 1 本を基点にし、
          // 位置基準 + join の冪等性で二重畳みも正しい)
          await appendRecords(projectId, [
            {
              r: "snapshot",
              folded: outcome.decodedRecords,
              state: {
                chainHead: outcome.floor.chainHead,
                environments: outcome.floor.environments,
                conflicts: outcome.floor.conflicts,
                intents: outcome.floor.intents,
              },
            },
          ]);
          outcome = await readAndFold(projectId);
        }
        return outcome.floor;
      },
      catch: () =>
        cliError(
          `Cannot write the local floor log: ${join(dir, `${projectId}.jsonl`)} (aborting because rollback detection cannot continue)`,
        ),
    }).pipe(
      Effect.flatMap((floor) =>
        floor.conflicts.length > 0
          ? Effect.fail(cliError(formatFloorConflicts(projectId, floor.conflicts)))
          : Effect.succeed(floor),
      ),
    );

  const attestedPathOf = (projectId: string): string => {
    if (!isProjectId(projectId)) {
      throw new Error(`invalid project id for attested-head path: ${projectId}`);
    }
    return join(dir, `${projectId}.attested.json`);
  };

  const evidencePathOf = (projectId: string): string => {
    if (!isProjectId(projectId)) {
      throw new Error(`invalid project id for attestation-evidence path: ${projectId}`);
    }
    return join(dir, `${projectId}.attestation-evidence.jsonl`);
  };

  /**
   * 証拠の追記(床ログと同じ規律: O_APPEND + 改行前置 + datasync まで待つ)。
   * 床ログの appendRecords と分かれているのは、あちらが床レコード型と旧形式
   * 移行に固有だから — 追記の物理規律(改行前置・short write の全長書き直し)は
   * 同じ形を写す。
   */
  const appendJsonLine = async (path: string, value: AttestationEvidenceRecord): Promise<void> => {
    await mkdir(dir, { recursive: true, mode: 0o700 });
    const handle = await open(path, "a", 0o600);
    try {
      const payload = Buffer.from(`\n${JSON.stringify(value)}\n`, "utf8");
      for (let attempt = 1; ; attempt += 1) {
        const result = await handle.write(payload, 0, payload.length);
        if (result.bytesWritten === payload.length) {
          break;
        }
        if (result.bytesWritten === 0 || attempt >= MAX_APPEND_WRITE_ATTEMPTS) {
          throw new Error(
            `short write on the attestation-evidence log (${result.bytesWritten}/${payload.length} bytes)`,
          );
        }
      }
      await handle.datasync();
    } finally {
      await handle.close();
    }
  };

  /** 旧形式の互換読み(ログ未作成 / 空ログ)。最初の追記でログへ移行される。 */
  const loadLegacy = async (projectId: string): Promise<FloorLoadResult> => {
    const legacy = await readLegacy(projectId);
    if (legacy.corrupt) {
      return { floor: null, state: "corrupt", droppedRecords: 0 };
    }
    return legacy.floor === null
      ? { floor: null, state: "missing", droppedRecords: 0 }
      : { floor: legacy.floor, state: "loaded", droppedRecords: 0 };
  };

  return {
    load: (projectId) =>
      Effect.tryPromise({
        try: async (): Promise<FloorLoadResult> => {
          let raw: string;
          try {
            raw = await readFile(pathOf(projectId), "utf8");
          } catch (error) {
            if (!isFileMissingError(error)) {
              throw error;
            }
            return loadLegacy(projectId);
          }
          const outcome = foldRecords(raw.split("\n"));
          if (outcome.decodedRecords === 0) {
            if (raw.trim() !== "") {
              // 非空なのに 1 件も解読できない = 全体破損
              return { floor: null, state: "corrupt", droppedRecords: outcome.droppedLines };
            }
            // 空ファイルは open("a") と write の間で落ちた残骸でもありうる —
            // 有効な旧形式が残っていればそれを読む(missing = 初回に潰すと
            // 旧床が 1 run ぶん不可視になり、事実と違う first sync 通知が出る)
            return loadLegacy(projectId);
          }
          return { floor: outcome.floor, state: "loaded", droppedRecords: outcome.droppedLines };
        },
        catch: () =>
          cliError(`Cannot read the local floor log: ${join(dir, `${projectId}.jsonl`)}`),
      }),
    commitHead: (projectId, head) => Effect.asVoid(mutate(projectId, [{ r: "head", head }])),
    commitPull: (projectId, commit: PullCommit) =>
      mutate(projectId, [
        {
          r: "pull",
          head: commit.chainHead,
          environmentId: commit.environmentId,
          environment: commit.environment,
        },
      ]).pipe(Effect.map((floor) => environmentOf(floor, commit.environmentId))),
    commitPush: (projectId, commit: PushCommit) =>
      mutate(projectId, [
        {
          r: "push",
          head: commit.chainHead,
          environmentId: commit.environmentId,
          variableId: commit.variableId,
          variable: commit.variable,
        },
      ]).pipe(Effect.map((floor) => environmentOf(floor, commit.environmentId))),
    commitMetadata: (projectId, commit: MetadataCommit) =>
      mutate(projectId, [
        {
          r: "meta",
          head: commit.chainHead,
          environmentId: commit.environmentId,
          observedEpoch: commit.observedEpoch,
          metaVersion: commit.metaVersion,
          metaSigHashHex: commit.metaSigHashHex,
          manifest: commit.manifest,
        },
      ]).pipe(Effect.map((floor) => environmentOf(floor, commit.environmentId))),
    commitManifest: (projectId, commit: ManifestCommit) =>
      mutate(projectId, [
        {
          r: "manifest",
          head: commit.chainHead,
          environmentId: commit.environmentId,
          manifest: commit.manifest,
        },
      ]).pipe(Effect.map((floor) => environmentOf(floor, commit.environmentId))),
    appendIntent: (projectId, input: FloorIntentInput) => {
      const intent: FloorIntent = { id: randomIntentId(), ...input };
      return mutate(projectId, [{ r: "intent", intent }]).pipe(Effect.map(() => intent.id));
    },
    resolveIntent: (projectId, intentId, outcome) =>
      // resolution は intent を閉じる帳簿レコード(join の格子外)。既存 conflict の
      // 検査で失敗させない — 解決の記録自体は証拠を増やす方向にしか働かない
      Effect.asVoid(
        Effect.tryPromise({
          try: () => appendRecords(projectId, [{ r: "resolution", intentId, outcome }]),
          catch: () =>
            cliError(
              `Cannot write the local floor log: ${join(dir, `${projectId}.jsonl`)} (aborting because rollback detection cannot continue)`,
            ),
        }),
      ),
    loadAttestedHead: (projectId) =>
      Effect.tryPromise({
        try: async () => {
          let raw: string;
          try {
            raw = await readFile(attestedPathOf(projectId), "utf8");
          } catch (error) {
            if (isFileMissingError(error)) {
              return null;
            }
            throw error;
          }
          // 破損は null(前回申告の追跡はベストエフォート — 喪失の帰結は
          // 同一 seq の再提出で、サーバー側の冪等 204 が吸収する)
          let value: unknown;
          try {
            value = JSON.parse(raw);
          } catch {
            return null;
          }
          return decodeChainHead(isRecord(value) ? value["head"] : undefined);
        },
        catch: () => cliError(`Cannot read the attested-head file: ${attestedPathOf(projectId)}`),
      }),
    saveAttestedHead: (projectId, head) =>
      Effect.tryPromise({
        try: async () => {
          await mkdir(dir, { recursive: true, mode: 0o700 });
          // tmp → rename の置換(部分書き込みを読み手に見せない)。追跡は
          // 上書き可の別クラス(検証済み観測ではない — floor.ts の doc)
          const path = attestedPathOf(projectId);
          const tmp = `${path}.tmp`;
          await writeFile(tmp, `${JSON.stringify({ v: 1, head })}\n`, { mode: 0o600 });
          await rename(tmp, path);
        },
        catch: () => cliError(`Cannot write the attested-head file: ${attestedPathOf(projectId)}`),
      }),
    appendAttestationEvidence: (projectId, evidence) =>
      Effect.tryPromise({
        try: async () => {
          const path = evidencePathOf(projectId);
          await appendJsonLine(path, evidence);
          return path;
        },
        catch: () =>
          cliError(`Cannot write the attestation-evidence log: ${evidencePathOf(projectId)}`),
      }),
  };
}
