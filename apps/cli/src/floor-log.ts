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
// - 破損した末尾レコード(クラッシュ・電源断の torn write)は fold が無視する
//   (自己回復)。次の追記は末尾の改行欠けを検出して改行を前置するため、
//   torn 行が後続レコードを壊すことはない
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

import { mkdir, open, readFile } from "node:fs/promises";
import { join } from "node:path";

import { isEnvironmentId, isProjectId, isVariableId } from "@maruhi/core";
import { Effect } from "effect";

import { cliError, type CliError } from "./errors.ts";
import { formatFloorConflicts } from "./floor-evidence.ts";
import {
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

/** 環境床(新形 — bottom 座標を許す: pullEpoch / observedEpoch / metaVersion = 0)。 */
function decodeEnvironmentFloor(value: unknown): EnvironmentFloor | null {
  if (
    !isRecord(value) ||
    !isNonNegativeInteger(value["pullEpoch"]) ||
    !isNonNegativeInteger(value["observedEpoch"]) ||
    !isNonNegativeInteger(value["metaVersion"])
  ) {
    return null;
  }
  const metaSigHashHex = value["metaSigHashHex"];
  if (value["metaVersion"] === 0 ? metaSigHashHex !== "" : !isHex64(metaSigHashHex)) {
    return null;
  }
  const manifest = value["manifest"] === undefined ? undefined : decodeManifestFloor(value["manifest"]);
  if (manifest === null) {
    return null;
  }
  const variables = decodeVariablesRecord(value["variables"]);
  if (variables === null) {
    return null;
  }
  return {
    pullEpoch: value["pullEpoch"],
    observedEpoch: value["observedEpoch"],
    metaVersion: value["metaVersion"],
    metaSigHashHex: metaSigHashHex as string,
    ...(manifest === undefined ? {} : { manifest }),
    variables,
  };
}

function decodeEnvironmentsRecord(
  value: unknown,
): Record<string, EnvironmentFloor> | null {
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
    !CONFLICT_KINDS.includes(value["kind"] as FloorConflict["kind"]) ||
    !isNonNegativeInteger(value["firstVersion"]) ||
    !isNonNegativeInteger(value["secondVersion"]) ||
    typeof value["firstHashHex"] !== "string" ||
    typeof value["secondHashHex"] !== "string"
  ) {
    return null;
  }
  const environmentId = value["environmentId"];
  const variableId = value["variableId"];
  if (environmentId !== null && !isEnvironmentIdValue(environmentId)) {
    return null;
  }
  if (variableId !== null && !isVariableIdValue(variableId)) {
    return null;
  }
  return {
    kind: value["kind"] as FloorConflict["kind"],
    environmentId: environmentId as string | null,
    variableId: variableId as string | null,
    firstVersion: value["firstVersion"],
    firstHashHex: value["firstHashHex"],
    secondVersion: value["secondVersion"],
    secondHashHex: value["secondHashHex"],
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
    typeof value["id"] !== "string" ||
    !INTENT_ID.test(value["id"]) ||
    !INTENT_OPS.includes(value["op"] as FloorIntent["op"]) ||
    !isEnvironmentIdValue(value["environmentId"]) ||
    !isPositiveInteger(value["epoch"]) ||
    !isPositiveInteger(value["manifestVersion"]) ||
    !isHex64(value["manifestSigHashHex"])
  ) {
    return null;
  }
  const dekCommitmentHex = value["dekCommitmentHex"];
  if (dekCommitmentHex !== null && !isHex64(dekCommitmentHex)) {
    return null;
  }
  const variableId = value["variableId"];
  if (variableId !== null && !isVariableIdValue(variableId)) {
    return null;
  }
  const declaredHead = decodeChainHead(value["declaredHead"]);
  if (declaredHead === null) {
    return null;
  }
  return {
    id: value["id"],
    op: value["op"] as FloorIntent["op"],
    environmentId: value["environmentId"] as string,
    epoch: value["epoch"],
    dekCommitmentHex: dekCommitmentHex as string | null,
    variableId: variableId as string | null,
    manifestVersion: value["manifestVersion"],
    manifestSigHashHex: value["manifestSigHashHex"],
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
  if (environments === null || !Array.isArray(value["conflicts"]) || !Array.isArray(value["intents"])) {
    return null;
  }
  const conflicts: FloorConflict[] = [];
  for (const raw of value["conflicts"]) {
    const conflict = decodeConflict(raw);
    if (conflict === null) {
      return null;
    }
    conflicts.push(conflict);
  }
  const intents: FloorIntent[] = [];
  for (const raw of value["intents"]) {
    const intent = decodeIntent(raw);
    if (intent === null) {
      return null;
    }
    intents.push(intent);
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

function decodeEnvironmentRecord(value: Record<string, unknown>): FloorLogRecord | null {
  const scoped = decodeScoped(value);
  if (scoped === null) {
    return null;
  }
  if (value["r"] === "pull") {
    const environment = decodeEnvironmentFloor(value["environment"]);
    return environment === null ? null : { r: "pull", ...scoped, environment };
  }
  if (value["r"] === "push") {
    const variable = decodeVariableFloor(value["variable"]);
    if (variable === null || !isVariableIdValue(value["variableId"])) {
      return null;
    }
    return { r: "push", ...scoped, variableId: value["variableId"] as string, variable };
  }
  if (value["r"] === "meta") {
    const manifest = decodeManifestFloor(value["manifest"]);
    if (
      manifest === null ||
      !isPositiveInteger(value["observedEpoch"]) ||
      !isPositiveInteger(value["metaVersion"]) ||
      !isHex64(value["metaSigHashHex"])
    ) {
      return null;
    }
    return {
      r: "meta",
      ...scoped,
      observedEpoch: value["observedEpoch"],
      metaVersion: value["metaVersion"],
      metaSigHashHex: value["metaSigHashHex"],
      manifest,
    };
  }
  const manifest = decodeManifestFloor(value["manifest"]);
  return manifest === null ? null : { r: "manifest", ...scoped, manifest };
}

/** 1 行の厳格デコード。null = 解読不能(fold が無視する — 自己回復)。 */
function decodeLogRecord(line: string): FloorLogRecord | null {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    return null;
  }
  if (!isRecord(value)) {
    return null;
  }
  switch (value["r"]) {
    case "head": {
      const head = decodeChainHead(value["head"]);
      return head === null ? null : { r: "head", head };
    }
    case "pull":
    case "push":
    case "meta":
    case "manifest":
      return decodeEnvironmentRecord(value);
    case "intent": {
      const intent = decodeIntent(value["intent"]);
      return intent === null ? null : { r: "intent", intent };
    }
    case "resolution": {
      if (
        typeof value["intentId"] !== "string" ||
        !INTENT_ID.test(value["intentId"]) ||
        !INTENT_OUTCOMES.includes(value["outcome"] as FloorIntentOutcome)
      ) {
        return null;
      }
      return {
        r: "resolution",
        intentId: value["intentId"],
        outcome: value["outcome"] as FloorIntentOutcome,
      };
    }
    case "snapshot": {
      const state = decodeSnapshotState(value["state"]);
      if (state === null || !isNonNegativeInteger(value["folded"])) {
        return null;
      }
      return { r: "snapshot", folded: value["folded"], state };
    }
    default:
      return null;
  }
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

function foldRecords(lines: readonly string[]): FoldOutcome {
  const records: FloorLogRecord[] = [];
  let droppedLines = 0;
  for (const line of lines) {
    if (line.trim() === "") {
      continue;
    }
    const record = decodeLogRecord(line);
    if (record === null) {
      // torn 行(クラッシュした並行プロセスの書きかけ)の自己回復。conflict の
      // 証拠行は正しい JSON なのでここでは失われない
      droppedLines += 1;
      continue;
    }
    records.push(record);
  }
  // 最新の有効なスナップショットを基点にし、その「畳んだ接頭辞の終端位置」
  // 以降のレコードだけを join する。位置が壊れている(範囲外)場合は全レコード
  // fold へフォールバックする — join の冪等性・可換性により正しさは不変
  let snapshotIndex = -1;
  for (let index = records.length - 1; index >= 0; index -= 1) {
    if (records[index]?.r === "snapshot") {
      snapshotIndex = index;
      break;
    }
  }
  const snapshot = snapshotIndex >= 0 ? (records[snapshotIndex] as { folded: number; state: SnapshotState }) : null;
  const foldFrom = snapshot !== null && snapshot.folded <= snapshotIndex ? snapshot.folded : 0;
  const state = baseStateOf(snapshot !== null && snapshot.folded <= snapshotIndex ? snapshot : null);
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
    droppedLines,
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
    !isPositiveInteger(value["pullEpoch"]) ||
    !isPositiveInteger(value["metaVersion"]) ||
    !isHex64(value["metaSigHashHex"])
  ) {
    return null;
  }
  const manifest = value["manifest"] === undefined ? undefined : decodeManifestFloor(value["manifest"]);
  if (manifest === null) {
    return null;
  }
  const variables = decodeVariablesRecord(value["variables"]);
  if (variables === null) {
    return null;
  }
  return {
    pullEpoch: value["pullEpoch"],
    metaVersion: value["metaVersion"],
    metaSigHashHex: value["metaSigHashHex"],
    ...(manifest === undefined ? {} : { manifest }),
    variables,
  };
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
  if (chainHead === null || !isRecord(value["environments"])) {
    return null;
  }
  const environments: Record<string, EnvironmentFloor> = {};
  for (const [environmentId, raw] of Object.entries(value["environments"])) {
    const legacy = decodeLegacyEnvironment(raw);
    if (legacy === null || !isEnvironmentId(environmentId)) {
      return null;
    }
    environments[environmentId] = {
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
   * 先頭に移行する。末尾に改行がない(torn 行)場合は改行を前置し、torn 行を
   * それ自身の(解読不能な)1 行として隔離する — 自己回復の前提。
   */
  const appendRecords = async (projectId: string, records: readonly FloorLogRecord[]): Promise<void> => {
    const path = pathOf(projectId);
    await mkdir(dir, { recursive: true, mode: 0o700 });
    const handle = await open(path, "a+", 0o600);
    try {
      const { size } = await handle.stat();
      let prefix = "";
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
      } else {
        const tail = Buffer.alloc(1);
        await handle.read(tail, 0, 1, size - 1);
        if (tail[0] !== 0x0a) {
          prefix = "\n";
        }
      }
      await handle.write(`${prefix}${lines.map(encodeRecord).join("")}`);
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

  const environmentOf = (floor: ProjectFloor, environmentId: string): EnvironmentFloor =>
    floorRecordGet(floor.environments, environmentId) ?? emptyEnvironmentFloor();

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
            // ログ未作成 — 旧形式(PR #33)の互換読み(最初の追記で移行される)
            const legacy = await readLegacy(projectId);
            if (legacy.corrupt) {
              return { floor: null, state: "corrupt" };
            }
            return legacy.floor === null
              ? { floor: null, state: "missing" }
              : { floor: legacy.floor, state: "loaded" };
          }
          const outcome = foldRecords(raw.split("\n"));
          if (outcome.decodedRecords === 0) {
            // 解読可能なレコードがない: 空ファイルは初回相当、非空は全体破損
            return raw.trim() === ""
              ? { floor: null, state: "missing" }
              : { floor: null, state: "corrupt" };
          }
          return { floor: outcome.floor, state: "loaded" };
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
  };
}
