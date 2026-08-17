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

import { isEnvironmentId, isProjectId, isVariableId } from "@maruhi/core";
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
  /**
   * 検証済み pull の床コミット(環境床の単調マージ + ヘッド前進を 1 書き込みで)。
   * **ディスクへ書いた後の(マージ済み)環境床**を返す — 呼び出し側のプロセス内
   * キャッシュはこれを採用し、並行 CLI が確立した検出材料(union・deleted 終端・
   * より新しい version / pullEpoch)をコマンド実行中に取りこぼさない。
   */
  readonly commitPull: (
    projectId: string,
    commit: PullCommit,
  ) => Effect.Effect<EnvironmentFloor, CliError>;
  /**
   * 受理された push の変数床前進(規則 (c) 基準 pullEpoch は動かさない)。
   * マージ済み環境床(環境レコードがディスクにない場合は null)を返す。
   */
  readonly commitPush: (
    projectId: string,
    commit: PushCommit,
  ) => Effect.Effect<EnvironmentFloor | null, CliError>;
}

export class FloorStore extends Context.Service<FloorStore, FloorStoreShape>()("cli/FloorStore") {}

/** 床ディレクトリ(設定と同系の置き場: <config.json の親>/floor)。 */
export function floorDirOf(configPath: string): string {
  return join(dirname(configPath), "floor");
}

const HEX_64 = /^[0-9a-f]{64}$/;

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

// レコードキー(environmentId / variableId)は §12-1 の受理形式
// (@maruhi/core の isEnvironmentId / isVariableId)を要求する。正規の床は wire
// スキーマ検証済み(または CLI 採番)の ID しか書かないため、形式外のキー =
// 破損として全体拒否してよい。これは `__proto__`(先頭 `_` で形式外 — ブラケット
// 代入でプロトタイプ設定になりエントリが黙って欠落する)を構造的に排除する。
// **`constructor` / `prototype` は正当な ID であり拒否しない**(レビュー①再指摘 —
// 参照側は floorRecordGet の own-property 参照で継承プロパティへの解決を防ぐ)

/**
 * Own-property lookup for floor records. `constructor` / `prototype` は §12-1 の
 * 正当な ID なので、素のブラケット参照だと「レコードに存在しない ID」が
 * Object.prototype の継承プロパティ(関数)に解決されて誤動作する。床レコードの
 * 動的キー参照は必ずこれを使う。
 */
export function floorRecordGet<T>(
  record: Readonly<Record<string, T>> | undefined,
  key: string,
): T | undefined {
  return record !== undefined && Object.hasOwn(record, key) ? record[key] : undefined;
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
    if (variable === null || !isVariableId(variableId)) {
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
    if (environment === null || !isEnvironmentId(environmentId)) {
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

/**
 * 変数床の単調マージ。ディスク上の床は**決して後退させない**(read-merge-write
 * の窓で古いコミットが後に着地しても、並行プロセスが確立した検出材料を失わ
 * ない — 悪意サーバーが応答遅延で着地順を制御しても床を過去世代へ戻せない):
 * deleted は終端状態(active で上書きしない・metaVersion の大きい側のみ採用)、
 * active 同士は値側(version)とメタ側(metaVersion)を独立に単調マージする。
 * どちらの入力も §6.3 検証を通過した床レコードなので、この規則は健全。
 */
function mergeVariableFloor(
  existing: VariableFloor | undefined,
  incoming: VariableFloor,
): VariableFloor {
  if (existing === undefined) {
    return incoming;
  }
  if (existing.status === "deleted" || incoming.status === "deleted") {
    // 削除は終端状態(§4.2 / session-15 §2-2): deleted 記録は active で上書き
    // せず、tombstone 同士・active → deleted は metaVersion の前進のみ受け入れる
    if (incoming.status === "deleted" && incoming.metaVersion > existing.metaVersion) {
      return incoming;
    }
    return existing;
  }
  const value = incoming.version >= existing.version ? incoming : existing;
  const meta = incoming.metaVersion >= existing.metaVersion ? incoming : existing;
  return {
    status: "active",
    version: value.version,
    epoch: value.epoch,
    valueSigHashHex: value.valueSigHashHex,
    metaVersion: meta.metaVersion,
    metaSigHashHex: meta.metaSigHashHex,
  };
}

/** 環境床の単調マージ(pullEpoch は max・メタは metaVersion の大きい側・変数は単調 union)。 */
function mergeEnvironmentFloor(
  existing: EnvironmentFloor | undefined,
  incoming: EnvironmentFloor,
): EnvironmentFloor {
  if (existing === undefined) {
    return incoming;
  }
  const meta = incoming.metaVersion >= existing.metaVersion ? incoming : existing;
  // union: 正当な床の変数キーは消えない(削除も tombstone レコードとして残る)
  // ため、片側にしかない変数は保持する
  const variables: Record<string, VariableFloor> = { ...existing.variables };
  for (const [variableId, variable] of Object.entries(incoming.variables)) {
    variables[variableId] = mergeVariableFloor(
      floorRecordGet(existing.variables, variableId),
      variable,
    );
  }
  return {
    pullEpoch: Math.max(existing.pullEpoch, incoming.pullEpoch),
    metaVersion: meta.metaVersion,
    metaSigHashHex: meta.metaSigHashHex,
    variables,
  };
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
      environments: {
        ...base.environments,
        [commit.environmentId]: mergeEnvironmentFloor(
          floorRecordGet(base.environments, commit.environmentId),
          commit.environment,
        ),
      },
    };
  };
}

function applyPush(commit: PushCommit): FloorMerge {
  return (current) => {
    const base = applyHead(commit.chainHead)(current);
    const environment = floorRecordGet(base.environments, commit.environmentId);
    if (environment === undefined) {
      // 環境床がない(並行破損等)場合、変数床だけの環境レコードを作らない:
      // 規則 (c) 基準(pullEpoch)は pull でしか確定できず、ここで捏造すると
      // 「チェーン同期単独で基準を前進させない」規範に反する。ヘッド前進のみ
      // 反映する(床は SHOULD — 検出材料が一世代分薄くなるだけで誤検出はない)
      return base;
    }
    return {
      ...base,
      environments: {
        ...base.environments,
        [commit.environmentId]: {
          ...environment,
          variables: {
            ...environment.variables,
            [commit.variableId]: mergeVariableFloor(
              floorRecordGet(environment.variables, commit.variableId),
              commit.variable,
            ),
          },
        },
      },
    };
  };
}

function isFileMissingError(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    (error as NodeJS.ErrnoException).code === "ENOENT"
  );
}

/**
 * 床ファイルの読み込み。missing は **ENOENT のみ**: それ以外の I/O エラー
 * (EACCES / EIO 等)を「初回」と同一視すると、読めないだけの床を次のコミットが
 * 空から作り直して全消去する(検出機構の不可視な無効化)ため、例外として投げて
 * 呼び出し側のエラーにする。
 */
async function readFloorFile(path: string): Promise<FloorLoadResult> {
  let json: string;
  try {
    json = await readFile(path, "utf8");
  } catch (error) {
    if (isFileMissingError(error)) {
      return { floor: null, state: "missing" };
    }
    throw error;
  }
  const floor = decodeProjectFloor(json);
  return floor === null ? { floor: null, state: "corrupt" } : { floor, state: "loaded" };
}

/** File-backed floor store rooted at `dir` (production and tests share this). */
export function makeFileFloorStore(dir: string): FloorStoreShape {
  const pathOf = (projectId: string): string => {
    // projectId は genesis ハッシュ(hex 64)のはずだが、ファイル名に使う前に
    // 形式を強制する(パス組み立てへの信頼できない文字列の混入を防ぐ)
    if (!isProjectId(projectId)) {
      throw new Error(`invalid project id for floor path: ${projectId}`);
    }
    return join(dir, `${projectId}.json`);
  };

  const write = (projectId: string, merge: FloorMerge): Effect.Effect<ProjectFloor, CliError> =>
    Effect.tryPromise({
      try: async () => {
        const path = pathOf(projectId);
        // read-merge-write: コミット直前に最新のファイル内容へマージする
        // (同一プロジェクトの並行 CLI と競合しても、マージ規則の単調性により
        // ディスク上の床は後退しない)。missing 以外の読み取り失敗は throw され、
        // 空からの作り直しによる床の無警告全消去を防ぐ
        const loaded = await readFloorFile(path);
        if (loaded.state === "corrupt") {
          // 破損床は作り直す(読み込み時に警告済み — fail-open の帰結)前に
          // 退避する: 床ファイルは証拠の半分であり、破損の形自体もフォレンジック
          // 材料になる(上書きで消さない)
          await rename(path, `${path}.corrupt-${Date.now()}`);
        }
        const next = merge(loaded.floor);
        await mkdir(dirname(path), { recursive: true, mode: 0o700 });
        // temp + rename の原子的置き換え(§6.3 の同一トランザクション規範):
        // 規則 (c) 基準と変数床が別々に見える中間状態をディスク上に作らない
        const temp = `${path}.${process.pid}.tmp`;
        await writeFile(temp, `${JSON.stringify(next, null, 2)}\n`, { mode: 0o600 });
        await rename(temp, path);
        return next;
      },
      catch: () =>
        cliError(
          `Cannot write the local floor file: ${join(dir, `${projectId}.json`)} (aborting because rollback detection cannot continue)`,
        ),
    });

  return {
    load: (projectId) =>
      Effect.tryPromise({
        try: () => readFloorFile(pathOf(projectId)),
        catch: () =>
          cliError(`Cannot read the local floor file: ${join(dir, `${projectId}.json`)}`),
      }),
    commitHead: (projectId, head) => Effect.asVoid(write(projectId, applyHead(head))),
    commitPull: (projectId, commit) =>
      write(projectId, applyPull(commit)).pipe(
        // マージ済み(= ディスクへ書いた)環境床を返す。applyPull がレコードを
        // 必ず作るため own-property 参照は常に存在する
        Effect.map(
          (next) => floorRecordGet(next.environments, commit.environmentId) ?? commit.environment,
        ),
      ),
    commitPush: (projectId, commit) =>
      write(projectId, applyPush(commit)).pipe(
        Effect.map((next) => floorRecordGet(next.environments, commit.environmentId) ?? null),
      ),
  };
}
