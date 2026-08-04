// ローカル床の永続化層(CRYPTO_SPEC §6.3 のローカル床 — SHOULD・規範)。
//
// セッションを跨ぐ巻き戻し・欠落・前進注入(値のみ)の永続検出のため、
// 「最後に検証した状態」の非機密ダイジェストをディスクに保存する。保存するのは
// §6.3 の列挙どおり: チェーンヘッド(hash + seq)・変数ごとの最新 version /
// その version の epoch / metaVersion / 各 signed bytes ハッシュ・環境ごとの
// 「最後に成功した pull(検証込み)時点のチェーン導出現エポック」(規則 (c) の
// 基準)。**平文値・鍵素材・変数名・環境名は書かない**(キーはすべて ID —
// ディスクレス不変条件と両立)。
//
// 置き場は設定と同系の非機密ローカル状態(<config dir>/floor/<projectId>.json。
// projectId = genesis ハッシュはグローバル一意なのでサーバー origin をキーに
// 含めない — セッション 16 裁定)。OS キーチェーンには置かない(非機密であり、
// キーチェーンの容量・可用性制約を避ける)。
//
// 原子性: 書き込みは temp + rename(§6.3 の「変数床と同一トランザクション」
// 規範 — 規則 (c) 基準と変数床が別々に見える中間状態を作らない)。更新は
// read-merge-write で、チェーンヘッドは seq の大きい側が勝つ(並行 CLI との
// lost update を最小化する。完全な排他はしない — 床は SHOULD であり、取りうる
// 損失は「検出材料が一世代分新しくならない」だけで誤検出は生まない)。
//
// fail-open: ファイル不在(初回)・破損はどちらも「床なし」として続行し、
// 呼び出し側が区別可能な警告を出す(ローカル状態を消せる攻撃者は床の外 —
// §14.3-3 の非保証に帰着)。書き込み失敗は fail-open にしない(検出機構の
// 無効化を不可視にしない — 設定ファイルと同じ扱い)。

import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import { Context, Effect } from "effect";

import { cliError, type CliError } from "./errors.ts";

/** 最後に検証したチェーンヘッド(§6.3 床の保存項目)。 */
export interface ChainHeadFloor {
  readonly seq: number;
  readonly hashHex: string;
}

/** 変数 1 つ分の床(active = 最新値 + 最新ステートメント、deleted = tombstone)。 */
export type VariableFloor =
  | {
      readonly status: "active";
      readonly version: number;
      /** その version の epoch(§4.1 単調性・規則 (c) の検査材料)。 */
      readonly epoch: number;
      /** 最新 version の value signed bytes ハッシュ(規則 (b) の比較対象)。 */
      readonly valueSigHashHex: string;
      readonly metaVersion: number;
      /** 最新 metaVersion の signed bytes ハッシュ(メタ床は巻き戻し検出のみ — §14.3-5)。 */
      readonly metaSigHashHex: string;
    }
  | {
      readonly status: "deleted";
      readonly metaVersion: number;
      readonly metaSigHashHex: string;
    };

/** 環境 1 つ分の床。 */
export interface EnvironmentFloor {
  /**
   * 規則 (c) の基準: 最後に成功した pull(検証込み)時点でチェーン導出されて
   * いた現エポック。**チェーン同期単独で前進させてはならない**(§6.3 の規範 —
   * ローテーション直後の正当な旧エポック値の誤拒否と、基準欠落による検出喪失の
   * 両縁。セッション 12 ノート §12 ループ 2)。
   */
  readonly pullEpoch: number;
  /** 環境メタステートメントの床(巻き戻し検出のみ — 前進注入は非保証 §14.3-5)。 */
  readonly metaVersion: number;
  readonly metaSigHashHex: string;
  /** キーは variableId(名前を書かない)。 */
  readonly variables: Readonly<Record<string, VariableFloor>>;
}

/** プロジェクト 1 つ分の床ファイル(floor/<projectId>.json)。 */
export interface ProjectFloor {
  readonly v: 1;
  readonly chainHead: ChainHeadFloor;
  /** キーは environmentId。 */
  readonly environments: Readonly<Record<string, EnvironmentFloor>>;
}

/** 床ファイルの読み込み結果(fail-open — 呼び出し側が状態別の警告を出す)。 */
export interface FloorLoadResult {
  readonly floor: ProjectFloor | null;
  /** missing = 初回同期(床なし)、corrupt = 破損(初回として扱うが区別して警告)。 */
  readonly state: "loaded" | "missing" | "corrupt";
}

/** pull 成功時の原子コミット(規則 (c) 基準 + 変数床 + チェーンヘッド)。 */
export interface PullCommit {
  readonly chainHead: ChainHeadFloor;
  readonly environmentId: string;
  readonly environment: EnvironmentFloor;
}

/** push 受理時のコミット(自分が署名した最新 version を床に昇格)。 */
export interface PushCommit {
  readonly chainHead: ChainHeadFloor;
  readonly environmentId: string;
  readonly variableId: string;
  readonly variable: VariableFloor;
}

/** Load / commit boundary for the local floor files (§6.3). */
export interface FloorStoreShape {
  readonly load: (projectId: string) => Effect.Effect<FloorLoadResult, CliError>;
  /** チェーン同期成功時のヘッド前進(規則 (c) 基準は動かさない)。 */
  readonly commitHead: (projectId: string, head: ChainHeadFloor) => Effect.Effect<void, CliError>;
  /** 検証済み pull の床コミット(環境床の置き換え + ヘッド前進を 1 書き込みで)。 */
  readonly commitPull: (projectId: string, commit: PullCommit) => Effect.Effect<void, CliError>;
  /** 受理された push の変数床前進(規則 (c) 基準 pullEpoch は動かさない)。 */
  readonly commitPush: (projectId: string, commit: PushCommit) => Effect.Effect<void, CliError>;
}

export class FloorStore extends Context.Service<FloorStore, FloorStoreShape>()("cli/FloorStore") {}

/** 床ディレクトリ(設定と同系の置き場: <config.json の親>/floor)。 */
export function floorDirOf(configPath: string): string {
  return join(dirname(configPath), "floor");
}

const HEX_64 = /^[0-9a-f]{64}$/;
const PROJECT_ID = HEX_64;

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

function decodeEnvironmentFloor(value: unknown): EnvironmentFloor | null {
  if (
    !isRecord(value) ||
    !isPositiveInteger(value["pullEpoch"]) ||
    !isPositiveInteger(value["metaVersion"]) ||
    !isHex64(value["metaSigHashHex"]) ||
    !isRecord(value["variables"])
  ) {
    return null;
  }
  const variables: Record<string, VariableFloor> = {};
  for (const [variableId, raw] of Object.entries(value["variables"])) {
    const variable = decodeVariableFloor(raw);
    if (variable === null) {
      return null;
    }
    variables[variableId] = variable;
  }
  return {
    pullEpoch: value["pullEpoch"],
    metaVersion: value["metaVersion"],
    metaSigHashHex: value["metaSigHashHex"],
    variables,
  };
}

/**
 * 床ファイルの厳格デコード。スキーマ不一致は全体を破損扱い(部分読みしない —
 * 半端な床は「検査した」と「していない」の区別を曖昧にする)。
 */
export function decodeProjectFloor(json: string): ProjectFloor | null {
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
    const environment = decodeEnvironmentFloor(raw);
    if (environment === null) {
      return null;
    }
    environments[environmentId] = environment;
  }
  return { v: 1, chainHead, environments };
}

/** チェーンヘッドの前進マージ(seq の大きい側が勝つ。後退はさせない)。 */
function mergeHead(existing: ChainHeadFloor, incoming: ChainHeadFloor): ChainHeadFloor {
  return incoming.seq > existing.seq ? incoming : existing;
}

type FloorMerge = (current: ProjectFloor | null) => ProjectFloor;

function applyHead(head: ChainHeadFloor): FloorMerge {
  return (current) =>
    current === null
      ? { v: 1, chainHead: head, environments: {} }
      : { ...current, chainHead: mergeHead(current.chainHead, head) };
}

function applyPull(commit: PullCommit): FloorMerge {
  return (current) => {
    const base = applyHead(commit.chainHead)(current);
    return {
      ...base,
      environments: { ...base.environments, [commit.environmentId]: commit.environment },
    };
  };
}

function applyPush(commit: PushCommit): FloorMerge {
  return (current) => {
    const base = applyHead(commit.chainHead)(current);
    const environment = base.environments[commit.environmentId];
    if (environment === undefined) {
      // 環境床がない(並行破損等)場合、変数床だけの環境レコードを作らない:
      // 規則 (c) 基準(pullEpoch)は pull でしか確定できず、ここで捏造すると
      // 「チェーン同期単独で基準を前進させない」規範に反する。ヘッド前進のみ
      // 反映する(床は SHOULD — 検出材料が一世代分薄くなるだけで誤検出はない)
      return base;
    }
    const existing = environment.variables[commit.variableId];
    if (
      existing !== undefined &&
      existing.status === "active" &&
      commit.variable.status === "active" &&
      existing.version >= commit.variable.version
    ) {
      // 並行プロセスが先に進めていたら後退させない
      return base;
    }
    return {
      ...base,
      environments: {
        ...base.environments,
        [commit.environmentId]: {
          ...environment,
          variables: { ...environment.variables, [commit.variableId]: commit.variable },
        },
      },
    };
  };
}

async function readFloorFile(path: string): Promise<FloorLoadResult> {
  let json: string;
  try {
    json = await readFile(path, "utf8");
  } catch {
    return { floor: null, state: "missing" };
  }
  const floor = decodeProjectFloor(json);
  return floor === null ? { floor: null, state: "corrupt" } : { floor, state: "loaded" };
}

/** File-backed floor store rooted at `dir` (production and tests share this). */
export function makeFileFloorStore(dir: string): FloorStoreShape {
  const pathOf = (projectId: string): string => {
    // projectId は genesis ハッシュ(hex 64)のはずだが、ファイル名に使う前に
    // 形式を強制する(パス組み立てへの信頼できない文字列の混入を防ぐ)
    if (!PROJECT_ID.test(projectId)) {
      throw new Error(`invalid project id for floor path: ${projectId}`);
    }
    return join(dir, `${projectId}.json`);
  };

  const write = (projectId: string, merge: FloorMerge): Effect.Effect<void, CliError> =>
    Effect.tryPromise({
      try: async () => {
        const path = pathOf(projectId);
        // read-merge-write: コミット直前に最新のファイル内容へマージする
        // (同一プロジェクトの並行 CLI との lost update を最小化)。破損して
        // いた場合は作り直す(読み込み時に警告済み — fail-open の帰結)
        const current = (await readFloorFile(path)).floor;
        const next = merge(current);
        await mkdir(dirname(path), { recursive: true, mode: 0o700 });
        // temp + rename の原子的置き換え(§6.3 の同一トランザクション規範):
        // 規則 (c) 基準と変数床が別々に見える中間状態をディスク上に作らない
        const temp = `${path}.${process.pid}.tmp`;
        await writeFile(temp, `${JSON.stringify(next, null, 2)}\n`, { mode: 0o600 });
        await rename(temp, path);
      },
      catch: () =>
        cliError(
          `ローカル床ファイルを書き込めません: ${join(dir, `${projectId}.json`)}(巻き戻し検出を継続できないため中断します)`,
        ),
    });

  return {
    load: (projectId) =>
      Effect.tryPromise({
        try: () => readFloorFile(pathOf(projectId)),
        catch: () =>
          cliError(`ローカル床ファイルを読み取れません: ${join(dir, `${projectId}.json`)}`),
      }),
    commitHead: (projectId, head) => write(projectId, applyHead(head)),
    commitPull: (projectId, commit) => write(projectId, applyPull(commit)),
    commitPush: (projectId, commit) => write(projectId, applyPush(commit)),
  };
}
