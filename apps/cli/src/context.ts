// コマンド前段の共通化: ID 検証 → セッション → master 鍵 → §6.3 同期検査 →
// 床検査 → 環境床ハンドル。config ファイルはコマンドごとに前段で 1 回だけ読む
// (旧 cli.ts はコマンド本体 / openProject / openSession で 3 回読んでいた)。

import { type EnvironmentId, isEnvironmentId, isProjectId } from "@maruhi/core";
import { Effect } from "effect";
import type { HttpClient } from "effect/unstable/http";

import { makeApiClient, type MaruhiClient } from "./api.ts";
import type { CliConfig } from "./config.ts";
import { ConfigStore } from "./config.ts";
import type { DekRecipient } from "./deks.ts";
import { cliError, type CliError, usageError } from "./errors.ts";
import { checkChainFloor, type FloorHandle, makeFloorHandle } from "./floor-check.ts";
import { formatFloorViolation } from "./floor-evidence.ts";
import { floorRecordGet, FloorStore, type ProjectFloor } from "./floor.ts";
import { CliIo } from "./io.ts";
import type { Keychain } from "./keychain.ts";
import type { ProcessRunner } from "./run.ts";
import {
  type CliSession,
  loadMasterKeys,
  type MasterKeys,
  resolveServerOrigin,
  resolveSession,
} from "./session.ts";
import { resyncExtended, syncProject, type VerifiedProject } from "./sync.ts";

/** Services every CLI command may need (production wiring lives in live.ts). */
export type CliServices =
  | Keychain
  | ConfigStore
  | FloorStore
  | CliIo
  | ProcessRunner
  | HttpClient.HttpClient;

/** データ系コマンド共通のフラグ(サーバー / プロジェクト / 環境の上書き)。 */
export interface CommonFlags {
  readonly server?: string | undefined;
  readonly project?: string | undefined;
  readonly env?: string | undefined;
}

// ID の形式検証(AUTH_SPEC §12-1 のクライアント側早期検証)は @maruhi/core の
// isProjectId / isEnvironmentId を使う(パターンの重複定義を持たない)

export function resolveProjectId(
  flag: string | undefined,
  config: CliConfig,
): Effect.Effect<string, CliError> {
  const value = flag ?? config.defaultProject;
  if (value === undefined) {
    return Effect.fail(
      cliError(
        "プロジェクトが未指定です。--project <id> か `maruhi config set defaultProject <id>` を使ってください",
      ),
    );
  }
  if (!isProjectId(value)) {
    // 指定値そのものは返さない(フラグにも値が書かれうる — args.ts の規律)。
    // 出所で分ける: コマンドラインなら書き方の誤り(2)、config なら直す先は
    // 設定ファイルなので実行の失敗(1)として、どこを直すかを言う
    const shape = "プロジェクト ID の形式が正しくありません(64 桁の 16 進数)";
    return Effect.fail(
      flag === undefined
        ? cliError(`${shape} — config の defaultProject を直してください`)
        : usageError(shape),
    );
  }
  return Effect.succeed(value);
}

function resolveEnvironmentId(
  flag: string | undefined,
  config: CliConfig,
): Effect.Effect<string, CliError> {
  const value = flag ?? config.defaultEnvironment;
  if (value === undefined) {
    return Effect.fail(
      cliError(
        "環境が未指定です。--env <id> か `maruhi config set defaultEnvironment <id>` を使ってください",
      ),
    );
  }
  if (!isEnvironmentId(value)) {
    const shape = "環境 ID の形式が正しくありません(英数字で始まり、英数字と _ - が続く 64 字まで)";
    return Effect.fail(
      flag === undefined
        ? cliError(`${shape} — config の defaultEnvironment を直してください`)
        : usageError(shape),
    );
  }
  return Effect.succeed(value);
}

export interface SessionContext {
  readonly config: CliConfig;
  readonly origin: string;
  readonly session: CliSession;
  readonly client: MaruhiClient;
}

/** ロード済み config からのセッション解決(config の再読込をしない内側)。 */
function openSessionWith(
  config: CliConfig,
  serverFlag: string | undefined,
): Effect.Effect<SessionContext, CliError, CliServices> {
  return Effect.gen(function* () {
    const origin = yield* resolveServerOrigin(serverFlag, config);
    const session = yield* resolveSession(origin);
    const client = yield* makeApiClient({ baseUrl: origin, token: session.token });
    return { config, origin, session, client };
  });
}

export function openSession(
  serverFlag: string | undefined,
): Effect.Effect<SessionContext, CliError, CliServices> {
  return Effect.gen(function* () {
    const store = yield* ConfigStore;
    return yield* openSessionWith(yield* store.load, serverFlag);
  });
}

/**
 * 鍵素材を要さない前段の成果(ID 検証 → セッション → §6.3 同期検査 → 床検査)。
 * 平文メタデータしか読まないコマンドはここまでで足りる(env diff)。
 */
export interface ProjectContextBase extends SessionContext {
  readonly projectId: string;
  readonly verified: VerifiedProject;
  /** openProject 時点のローカル床(§6.3。床なし = null)。 */
  readonly floor: ProjectFloor | null;
  /** 再同期(チェーン全再検証)。pull / push / env create が競合・future head 時に使う。 */
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
}

export interface ProjectContext extends ProjectContextBase {
  readonly masterKeys: MasterKeys;
  readonly recipient: DekRecipient;
}

export interface CheckedFloor {
  readonly floor: ProjectFloor | null;
  /** チェーン床検査を通過したビュー(短縮疑い時の有界再同期で前進していることがある)。 */
  readonly verified: VerifiedProject;
}

/**
 * ローカル床の読み込み(fail-open — 初回と破損を区別して知らせる)+ チェーン床
 * 検査(§6.3 規則 (a) のチェーン部分)+ 検証済みヘッドの床前進。規則 (c) の
 * 基準(pullEpoch)はここでは動かさない(チェーン同期単独で前進させない規範)。
 *
 * 床ヘッドが自ビューより先(headSeq の後退)は、同期と床ロードの間に兄弟
 * プロセスが床を前進させた正直なレースでも起きるため、即時証拠にせず
 * §6.3-2b と同型の有界再同期(1 回)で解決を試みる。床 seq 位置のハッシュ
 * 不一致は 2 つの検証済み成果物の矛盾(硬い証拠)なので即時拒否のまま。
 */
export function loadCheckedFloor(
  projectId: string,
  verified: VerifiedProject,
  resync: Effect.Effect<VerifiedProject, CliError>,
): Effect.Effect<CheckedFloor, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const store = yield* FloorStore;
    const loaded = yield* store.load(projectId);
    if (loaded.state === "missing") {
      yield* io.logError(
        "注意: このプロジェクトのローカル床がまだありません(初回同期)。巻き戻し・欠落の永続検出は次回以降の実行から有効になります",
      );
    } else if (loaded.state === "corrupt") {
      yield* io.logError(
        "警告: ローカル床ファイルを読み取れません(破損)。床なしとして続行します — ローカル状態が意図せず改変・削除された可能性があります。心当たりがない場合は注意してください",
      );
    }
    let view = verified;
    if (loaded.floor !== null) {
      let violation = checkChainFloor(loaded.floor, view);
      if (violation !== null && violation.kind === "chain-shortened") {
        // 延長検査付き再同期: 初回ビューが単に古いだけなら再同期ビューの接頭辞に
        // なっているはず。延長でなければ、初回ビュー自体が分岐していた
        // (短縮 + 分岐の複合)証拠として拒否する(レビュー②)
        view = yield* resyncExtended(resync, view);
        violation = checkChainFloor(loaded.floor, view);
      }
      if (violation !== null) {
        // 拒否 + 提示可能な証拠(床の記録ヘッドと今回の同期ヘッド)
        return yield* Effect.fail(cliError(formatFloorViolation({ projectId }, violation)));
      }
    }
    yield* store.commitHead(projectId, {
      seq: view.state.headSeq,
      hashHex: view.state.headHashHex,
    });
    return { floor: loaded.floor, verified: view };
  });
}

/**
 * セッション確立後の共通前段: §6.3 同期 → チェーン床検査 → 床ヘッドの前進。
 * 鍵の有無で分かれるのは呼び出し側だけで、床の意味論はここに一本化する
 * (2 系統に割ると、いずれ黙って食い違う)。
 */
function attachProject(
  context: SessionContext,
  projectId: string,
): Effect.Effect<ProjectContextBase, CliError, CliServices> {
  return Effect.gen(function* () {
    const resync = syncProject(context.client, projectId);
    const synced = yield* resync;
    const checked = yield* loadCheckedFloor(projectId, synced, resync);
    return { ...context, projectId, verified: checked.verified, floor: checked.floor, resync };
  });
}

/** データ系コマンド共通の前段(ロード済み config 版)。 */
function openProjectWith(
  config: CliConfig,
  flags: CommonFlags,
): Effect.Effect<ProjectContext, CliError, CliServices> {
  return Effect.gen(function* () {
    // プロジェクト ID の形式検証はネットワークアクセスより先に行う
    const projectId = yield* resolveProjectId(flags.project, config);
    const context = yield* openSessionWith(config, flags.server);
    // master 鍵の読み込みは同期(通信)・床の前進より**前**のまま置く: 鍵の無い
    // 端末で実行された書き込み系コマンドを、サーバーへ 1 往復してから落とさない
    const masterKeys = yield* loadMasterKeys(context.session);
    const base = yield* attachProject(context, projectId);
    const recipient: DekRecipient = {
      userId: context.session.userId,
      encPubHex: masterKeys.record.encPubHex,
      encKeyPair: masterKeys.encKeyPair,
    };
    return { ...base, masterKeys, recipient };
  });
}

/**
 * 平文メタデータしか読まないコマンドの前段(**master 鍵を要求しない**)。
 *
 * openProject との差は loadMasterKeys の有無だけで、同期・床検査は attachProject
 * に一本化してある。鍵を要求しないのは「復号しないから」だけが理由ではない:
 * MARUHI_TOKEN 経由のセッション(キーチェーンを持たない実行 — session.ts)でも
 * パリティチェックを走らせられるようにするためで、`project verify` が既に
 * 同じ形の鍵なし読み取りコマンドである。
 */
function openMetadataProjectWith(
  config: CliConfig,
  flags: CommonFlags,
): Effect.Effect<ProjectContextBase, CliError, CliServices> {
  return Effect.gen(function* () {
    const projectId = yield* resolveProjectId(flags.project, config);
    const context = yield* openSessionWith(config, flags.server);
    return yield* attachProject(context, projectId);
  });
}

/** データ系コマンド共通の前段: ID 検証 → セッション → master 鍵 → §6.3 同期検査 → 床検査。 */
export function openProject(
  flags: CommonFlags,
): Effect.Effect<ProjectContext, CliError, CliServices> {
  return Effect.gen(function* () {
    const store = yield* ConfigStore;
    return yield* openProjectWith(yield* store.load, flags);
  });
}

/** 環境単位の床ハンドル(コマンド内の pull / push が検査・コミットに使う)。 */
function floorHandleFor(
  context: ProjectContextBase,
  environmentId: string,
): Effect.Effect<FloorHandle, never, CliServices> {
  return Effect.map(FloorStore, (store) =>
    makeFloorHandle({
      store,
      projectId: context.projectId,
      environmentId,
      // own-property 参照(環境 ID `constructor` 等の正当な ID が継承プロパティに
      // 解決されるのを防ぐ — floor.ts の floorRecordGet 参照)
      initial: floorRecordGet(context.floor?.environments, environmentId) ?? null,
    }),
  );
}

export interface EnvironmentContext extends ProjectContext {
  readonly environmentId: string;
  /** 環境単位の床ハンドル(§6.3 — pull / push の検査・コミット)。 */
  readonly floorHandle: FloorHandle;
}

/**
 * 環境系コマンド(pull / push / run)共通の前段: 環境 ID の形式検証(ネット
 * ワークより先)→ openProject → 環境床ハンドル。config はここで 1 回だけ読む。
 */
export function openEnvironment(
  flags: CommonFlags,
): Effect.Effect<EnvironmentContext, CliError, CliServices> {
  return Effect.gen(function* () {
    const store = yield* ConfigStore;
    const config = yield* store.load;
    const environmentId = yield* resolveEnvironmentId(flags.env, config);
    const context = yield* openProjectWith(config, flags);
    const floorHandle = yield* floorHandleFor(context, environmentId);
    return { ...context, environmentId, floorHandle };
  });
}

/** 1 環境ぶんの床ハンドル(環境 ID と組で持ち、取り違えを書けなくする)。 */
export interface EnvironmentHandle {
  readonly environmentId: EnvironmentId;
  /** 環境単位の床ハンドル(§6.3)。 */
  readonly floorHandle: FloorHandle;
}

/** 2 環境を 1 つのプロジェクト前段で開いた結果(env diff)。 */
export interface EnvironmentPairContext extends ProjectContextBase {
  readonly first: EnvironmentHandle;
  readonly second: EnvironmentHandle;
}

/**
 * 2 環境をまたぐメタデータのみコマンド(env diff)の前段: **1 プロジェクト +
 * 環境ごとの床ハンドル**。config はここで 1 回だけ読む。
 *
 * openEnvironment を環境ごとに呼ぶと、チェーン同期と §6.3 検証が環境の数だけ
 * 走る。**食い違う 2 つの検証済みビュー**で比較すると、その比較結果がどの
 * 履歴に対するものなのか言えなくなる(片方だけが再同期で前進した状態を
 * 「差分」として報告しかねない)。プロジェクト前段は 1 回だけにする。
 *
 * 環境 ID の形式検証は呼び出し側(位置引数を受ける側)が済ませている前提で、
 * 型(EnvironmentId)がそれを要求する。
 */
export function openMetadataEnvironmentPair(
  flags: CommonFlags,
  first: EnvironmentId,
  second: EnvironmentId,
): Effect.Effect<EnvironmentPairContext, CliError, CliServices> {
  return Effect.gen(function* () {
    const store = yield* ConfigStore;
    const config = yield* store.load;
    const context = yield* openMetadataProjectWith(config, flags);
    return {
      ...context,
      first: { environmentId: first, floorHandle: yield* floorHandleFor(context, first) },
      second: { environmentId: second, floorHandle: yield* floorHandleFor(context, second) },
    };
  });
}
