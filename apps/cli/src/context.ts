// コマンド前段の共通化: ID 検証 → セッション → master 鍵 → §6.3 同期検査 →
// 床検査 → 環境床ハンドル。config ファイルはコマンドごとに前段で 1 回だけ読む
// (旧 cli.ts はコマンド本体 / openProject / openSession で 3 回読んでいた)。

import { isEnvironmentId, isProjectId } from "@maruhi/core";
import { Effect } from "effect";
import type { HttpClient } from "effect/unstable/http";

import { makeApiClient, type MaruhiClient } from "./api.ts";
import type { CliConfig } from "./config.ts";
import { ConfigStore } from "./config.ts";
import type { DekRecipient } from "./deks.ts";
import { cliError, type CliError } from "./errors.ts";
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
    return Effect.fail(cliError(`プロジェクト ID の形式が不正です: ${value}`));
  }
  return Effect.succeed(value);
}

export function resolveEnvironmentId(
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
    return Effect.fail(cliError(`環境 ID の形式が不正です: ${value}`));
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

export interface ProjectContext extends SessionContext {
  readonly masterKeys: MasterKeys;
  readonly recipient: DekRecipient;
  readonly projectId: string;
  readonly verified: VerifiedProject;
  /** openProject 時点のローカル床(§6.3。床なし = null)。 */
  readonly floor: ProjectFloor | null;
  /** 再同期(チェーン全再検証)。pull / push / env create が競合・future head 時に使う。 */
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
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

/** データ系コマンド共通の前段(ロード済み config 版)。 */
function openProjectWith(
  config: CliConfig,
  flags: CommonFlags,
): Effect.Effect<ProjectContext, CliError, CliServices> {
  return Effect.gen(function* () {
    // プロジェクト ID の形式検証はネットワークアクセスより先に行う
    const projectId = yield* resolveProjectId(flags.project, config);
    const context = yield* openSessionWith(config, flags.server);
    const masterKeys = yield* loadMasterKeys(context.session);
    const resync = syncProject(context.client, projectId);
    const synced = yield* resync;
    const checked = yield* loadCheckedFloor(projectId, synced, resync);
    const recipient: DekRecipient = {
      userId: context.session.userId,
      encPubHex: masterKeys.record.encPubHex,
      encKeyPair: masterKeys.encKeyPair,
    };
    return {
      ...context,
      masterKeys,
      recipient,
      projectId,
      verified: checked.verified,
      floor: checked.floor,
      resync,
    };
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
  context: ProjectContext,
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
