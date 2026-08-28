// コマンド前段の共通化: ID 検証 → セッション → master 鍵 → §6.3 同期検査 →
// 床検査 → 環境床ハンドル。config ファイルはコマンドごとに前段で 1 回だけ読む
// (旧 cli.ts はコマンド本体 / openProject / openSession で 3 回読んでいた)。
//
// 前段は master 鍵の要否で 2 つに分かれるが、**同期と床の意味論は attachProject
// に一本化**してある:
//   openProjectWith         = 鍵あり(値を暗号化・復号・署名するコマンド)
//   openMetadataProjectWith = 鍵なし(平文メタデータしか読まないコマンド — env diff)

import { type EnvironmentId, isEnvironmentId, isProjectId } from "@maruhi/core";
import type { ChainEntry } from "@maruhi/crypto";
import { Effect, type Stdio } from "effect";
import type { HttpClient } from "effect/unstable/http";

import { makeApiClient, type MaruhiClient } from "./api.ts";
import {
  reconcileDistributedAttestations,
  submitHeadAttestationIfAdvanced,
} from "./attestation.ts";
import type { CliConfig } from "./config.ts";
import { ConfigStore } from "./config.ts";
import type { DekRecipient } from "./deks.ts";
import { cliError, type CliError, usageError } from "./errors.ts";
import { checkChainFloor, type FloorHandle, makeFloorHandle } from "./floor-check.ts";
import { formatFloorConflicts, formatFloorViolation } from "./floor-evidence.ts";
import {
  type FloorIntent,
  floorRecordGet,
  FloorStore,
  type FloorStoreShape,
  type ProjectFloor,
} from "./floor.ts";
import { CliIo } from "./io.ts";
import type { Keychain } from "./keychain.ts";
import { type InviteAnchor, PinStore } from "./pins.ts";
import { warnUnconvergedMandates } from "./rotation-sweep.ts";
import type { ProcessRunner } from "./run.ts";
import {
  type CliSession,
  loadMasterKeys,
  type MasterKeys,
  resolveServerOrigin,
  resolveSession,
} from "./session.ts";
import { resyncExtended, syncProject, type VerifiedProject } from "./sync.ts";

/**
 * Services every CLI command may need (production wiring lives in live.ts).
 *
 * `Stdio` は引数層(ADR-0016)の判定材料 — argv と端末の有無 — の出所。
 * `process.argv` / `process.stdout.isTTY` を直に読まないための境界で、値の
 * 表示可否(agent-gate.ts)がこれを要求するため、コマンド本体からも見える
 * ここに置く。本番は `@effect/platform-bun`、テストは `Stdio.layerTest`。
 */
export type CliServices =
  | Keychain
  | ConfigStore
  | FloorStore
  | PinStore
  | CliIo
  | ProcessRunner
  | Stdio.Stdio
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
        "No project specified. Use --project <id> or `maruhi config set defaultProject <id>`",
      ),
    );
  }
  if (!isProjectId(value)) {
    // 指定値そのものは返さない(フラグにも値が書かれうる — args.ts の規律)。
    // 出所で分ける: コマンドラインなら書き方の誤り(2)、config なら直す先は
    // 設定ファイルなので実行の失敗(1)として、どこを直すかを言う
    const shape = "Invalid project ID (64 hex digits)";
    return Effect.fail(
      flag === undefined
        ? cliError(`${shape} — fix defaultProject in your config`)
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
        "No environment specified. Use --env <id> or `maruhi config set defaultEnvironment <id>`",
      ),
    );
  }
  if (!isEnvironmentId(value)) {
    const shape =
      "Invalid environment ID (must start with an alphanumeric character, followed by up to 63 alphanumerics, _ or -)";
    return Effect.fail(
      flag === undefined
        ? cliError(`${shape} — fix defaultEnvironment in your config`)
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

/** 値を扱うコマンドの前段の成果(上記 + master 鍵と自分宛ラップの受信者)。 */
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
        "Note: this project has no local floor yet (first sync). Persistent rollback / omission detection takes effect from the next run",
      );
    } else if (loaded.state === "corrupt") {
      yield* io.logError(
        "Warning: cannot read the local floor file (it is corrupt). Continuing without a floor — your local state may have been modified or deleted unintentionally. Be careful if you do not recognize this",
      );
    } else if (loaded.droppedRecords > 0) {
      // 部分的な破損は fold の自己回復で続行できるが、無言にはしない: 落ちた
      // 行が最新の head / manifest 観測だった場合、その座標の検出材料は次の
      // 検証済み観測まで一世代薄くなる(旧保存形の corrupt 警告と同じ可視化水準)
      yield* io.logError(
        `Warning: ${loaded.droppedRecords} record(s) in the local floor log could not be decoded and were skipped (a torn write from an interrupted process is self-healing, but if you do not recognize an interruption, the log may have been damaged). Rollback detection for the affected coordinates resumes from the next verified observation`,
      );
    }
    let view = verified;
    if (loaded.floor !== null) {
      if (loaded.floor.conflicts.length > 0) {
        // fold が表面化した同座標 conflict(§6.3 — 同一版・異ハッシュの検証済み
        // 観測の対)は equivocation の硬い証拠。床の使用・前進を拒否する
        return yield* Effect.fail(
          cliError(formatFloorConflicts(projectId, loaded.floor.conflicts)),
        );
      }
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
 * intent の複合エントリの照合結果。accepted / rejected は宣言ヘッド位置の
 * エントリ同一性で確定し、**pending(スロットが空)は確定させない**: チェーンが
 * まだ宣言ヘッドのままなら、送信済みの複合が着地する前に別 CLI が同期しただけの
 * 可能性があり、そこで not-accepted に潰すと後からエントリが載っても誰も
 * マニフェストを昇格しない(送信者がクラッシュしていた場合の回収を失う)。
 */
type IntentEntryState = "accepted" | "rejected" | "pending";

/**
 * intent の複合エントリがチェーン上に**その試行のものとして**存在するか。
 * (environment, epoch) の DEK commitment の一致だけでは判定しない: CAS
 * リトライは同一 DEK(= 同一 commitment)のまま宣言ヘッドとマニフェストを
 * 再署名するため、拒否された旧試行の intent(resolution の追記失敗・クラッシュで
 * 残ったもの)を後続試行の受理と commitment だけでは区別できず、旧試行の
 * マニフェスト(同版・異ハッシュ)を昇格させると typed conflict として床を
 * 恒久拒否に落とす。複合の受理位置は宣言ヘッドが一意に決める(エントリの
 * prev = 宣言ヘッド・seq = 宣言ヘッド + 1 — §12-4 の CAS。prev は署名対象
 * なので別位置への着地は存在しない)ため、その位置のエントリが本 intent の
 * op・座標・commitment を持てば accepted、**別のエントリに占有されていれば**
 * rejected(この試行はもう着地しえない)、空なら pending。
 */
function intentEntryState(verified: VerifiedProject, intent: FloorIntent): IntentEntryState {
  // entries は seq 順(entries[0].seq === 1)— 宣言ヘッド + 1 の位置を見る
  const entry = verified.entries[intent.declaredHead.seq];
  if (entry === undefined) {
    return "pending";
  }
  if (entry.prevHashHex !== intent.declaredHead.hashHex) {
    return "rejected";
  }
  return intentEntryMatches(entry, intent) ? "accepted" : "rejected";
}

/** スロットのエントリが intent の複合(op・座標・commitment)そのものか。 */
function intentEntryMatches(entry: ChainEntry, intent: FloorIntent): boolean {
  if (intent.op === "create_environment") {
    return (
      entry.op === "create_environment" &&
      entry.payload.environmentId === intent.environmentId &&
      entry.payload.dekCommitmentHex === intent.dekCommitmentHex
    );
  }
  return (
    entry.op === "rotate_epoch" &&
    entry.payload.environmentId === intent.environmentId &&
    entry.payload.newEpoch === intent.epoch &&
    entry.payload.dekCommitmentHex === intent.dekCommitmentHex
  );
}

/**
 * 未解決の複合 intent(create / rotate — 3-F)の起動時照合。複合の効果確認は
 * チェーン同期(§12-10 (3))であり、コマンド前段は毎回チェーンを全検証する
 * ため、ここで解決できる: intent の複合エントリがチェーン上に存在すれば
 * 受理済み — 自己発行マニフェストを床へ昇格する(M1-A4 の「エラー終了・
 * クラッシュを跨いだ床コミット」の回収)。存在しなければ受理されていない
 * (チェーンは全同期済み = 完全な真実源)。meta-op intent はチェーンに痕跡を
 * 残さないため、次の検証済み pull(values.ts)が照合する。
 */
function reconcileCompositeIntents(input: {
  readonly store: FloorStoreShape;
  readonly projectId: string;
  readonly verified: VerifiedProject;
  readonly intents: readonly FloorIntent[];
}): Effect.Effect<boolean, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    let resolved = false;
    for (const intent of input.intents) {
      if (intent.op === "meta-op" || intent.dekCommitmentHex === null) {
        continue;
      }
      const state = intentEntryState(input.verified, intent);
      if (state === "pending") {
        // スロットが空 = 送信前のクラッシュか、複合が着地する前に自分が同期した
        // だけかを区別できない。確定させず要照合のまま残す(チェーンが宣言
        // ヘッドを越えて進めば次の照合で accepted / rejected が確定する)
        yield* io.logError(
          `Note: an earlier ${intent.op} for environment ${intent.environmentId} is still awaiting confirmation (its chain slot is empty — the request may not have been sent, or may still be in flight). It will be reconciled once the chain advances`,
        );
        continue;
      }
      const environment = input.verified.state.environments.get(intent.environmentId);
      if (state === "accepted") {
        // 受理済みと確認 — 自己発行マニフェストの床昇格(検証済み事実の join)
        yield* input.store.commitManifest(input.projectId, {
          chainHead: {
            seq: input.verified.state.headSeq,
            hashHex: input.verified.state.headHashHex,
          },
          environmentId: intent.environmentId,
          manifest: {
            manifestVersion: intent.manifestVersion,
            epoch: intent.epoch,
            manifestSigHashHex: intent.manifestSigHashHex,
          },
        });
        yield* input.store.resolveIntent(
          input.projectId,
          intent.id,
          environment !== undefined && environment.currentEpoch === intent.epoch
            ? "accepted"
            : "accepted-superseded",
        );
        yield* io.logError(
          `Note: an earlier ${intent.op} for environment ${intent.environmentId} (interrupted before its confirmation) is confirmed as accepted on the chain. The local floor has been advanced with its manifest (manifestVersion ${intent.manifestVersion})`,
        );
      } else {
        yield* input.store.resolveIntent(input.projectId, intent.id, "not-accepted");
        yield* io.logError(
          `Note: an earlier ${intent.op} for environment ${intent.environmentId} (interrupted before its confirmation) is not on the verified chain — it was not accepted. No floor change`,
        );
      }
      resolved = true;
    }
    return resolved;
  });
}

/**
 * 招待リンクアンカーの機械照合(CRYPTO_SPEC §6.3 帯域外アンカー (a) / §6.5)。
 * 受諾時にピン留めした「genesis(= projectId、syncProject の genesis 一致検査が
 * 担う)・招待者の検証済みヘッド・招待者 user_id + 鍵 FP」を、検証済みチェーン
 * と突合する:
 *   (i) ヘッド包含 — 配布チェーンがピン留めヘッドを当該 seq に含むこと
 *   (ii) 招待者 FP — ピン留めヘッド時点で招待者がその鍵でメンバーであること
 * add_member 前(非メンバー)は同期自体が 404 のためここへ到達しない — 初回
 * 同期がそのまま初回照合になる(§11-2 のタイミング制約に従う設計)。アンカーが
 * 存在する限り毎同期検査する(検査は 2 参照のみで、常時検査が厳密に強い)。
 */
export function checkInviteAnchor(
  projectId: string,
  verified: VerifiedProject,
): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const store = yield* PinStore;
    const loaded = yield* store.load(projectId);
    if (loaded.state === "corrupt") {
      yield* io.logError(
        "Warning: cannot read the invite-pin file (it is corrupt). Continuing without the anchor check — your local state may have been modified or deleted unintentionally. Be careful if you do not recognize this",
      );
      return;
    }
    const anchor: InviteAnchor | null = loaded.pins?.anchor ?? null;
    if (anchor === null) {
      return;
    }
    // 拒否文言には検証材料の所在(ピンファイル)まで含める: 硬い証拠での恒久
    // 停止に対し、調査・復旧(帯域外確認のうえでの手動対処)へ辿り着ける導線を
    // 残す(pullfrog レビュー反映)
    const evidenceHint = `The verification material is invites/${projectId}.json (the pinned anchor) in the config directory, plus the distributed chain`;
    if (verified.history.entryHashAt(anchor.headSeq) !== anchor.headHashHex) {
      return yield* Effect.fail(
        cliError(
          `Invite-link anchor check failed: the distributed chain does not contain the verified head pinned in the invite link (seq=${anchor.headSeq}) (CRYPTO_SPEC §6.3 out-of-band anchor (a)). This suggests a server-side rollback or fork distribution — do not trust this chain; confirm with the inviter out of band. ${evidenceHint}`,
        ),
      );
    }
    const inviter = verified.history.memberStateAt(anchor.inviterUserId, anchor.headSeq);
    if (inviter === undefined || inviter.keyFingerprintHex !== anchor.inviterKeyFingerprintHex) {
      return yield* Effect.fail(
        cliError(
          `Invite-link anchor check failed: the link's inviter (user_id + key FP) does not match the chain member at the pinned head (the CRYPTO_SPEC §6.5 mechanical check). The invite link or the distributed chain may be forged — do not trust this chain; confirm with the inviter out of band. ${evidenceHint}`,
        ),
      );
    }
    if (anchor.verifiedAtSeq === null) {
      yield* io.log(
        "Invite-link anchor check passed (genesis match, head inclusion, inviter FP — CRYPTO_SPEC §6.3 / §6.5)",
      );
      yield* store.saveAnchor(projectId, { ...anchor, verifiedAtSeq: verified.state.headSeq });
    }
  });
}

/**
 * 前段のオプション。`quietMandateWarning` は未収束ローテーション義務の常時警告
 * (rotation-sweep.ts — B2 裁定)の抑制で、**収束系コマンド専用**(member
 * remove / change-role / server revoke / env rotate — 自分の sweep 報告が
 * 同じ事実をより正確に伝えるため、同期時点の警告は二重表示のノイズになる)。
 */
export interface OpenProjectOptions {
  readonly quietMandateWarning?: boolean;
}

/**
 * ヘッドゴシップの照合(§6.3 / §6.6): 矛盾申告 = 硬い証拠で中断、future 申告は
 * 有界再同期(1 回)で解決を試みる。ビューが前進したら床ヘッドを追いかけ、
 * アンカー機械照合も新ビューで再適用する(検査は 2 参照のみ)。
 */
function reconcileGossip(
  projectId: string,
  verified: VerifiedProject,
  resync: Effect.Effect<VerifiedProject, CliError>,
): Effect.Effect<VerifiedProject, CliError, CliServices> {
  return Effect.gen(function* () {
    const reconciled = yield* reconcileDistributedAttestations({
      projectId,
      view: verified,
      resync,
    });
    if (reconciled === verified) {
      return verified;
    }
    const store = yield* FloorStore;
    yield* store.commitHead(projectId, {
      seq: reconciled.state.headSeq,
      hashHex: reconciled.state.headHashHex,
    });
    yield* checkInviteAnchor(projectId, reconciled);
    return reconciled;
  });
}

/**
 * セッション確立後の共通前段: §6.3 同期 → チェーン床検査 → アンカー機械照合 →
 * ヘッドゴシップの照合(§6.3 / §6.6 — 矛盾申告は成果物の使用を中断)→
 * 床ヘッドの前進 → 未収束ローテーション義務の常時警告(§7 / B2 裁定 — §9 の
 * 開示常時明示と同じ規律)→ 検証済みヘッドの申告提出(SHOULD — 署名鍵を持つ
 * 前段のみ)。鍵の有無で分かれるのは呼び出し側だけで、床とゴシップの意味論は
 * ここに一本化する(2 系統に割ると、いずれ黙って食い違う)。床ヘッドの前進は
 * 全コマンド共通で、env diff のような値を読まないコマンドでも従来どおり行う。
 *
 * `attester` は申告提出の署名材料(openProjectWith が master 鍵から渡す)。
 * 渡されない前段(openMetadataProjectWith — master 鍵を要求しないコマンド)は
 * 照合のみ行い提出しない(提出は SHOULD であり、鍵なし実行 — MARUHI_TOKEN — を
 * 提出のために壊さない)。
 */
function attachProject(
  context: SessionContext,
  projectId: string,
  options?: OpenProjectOptions,
  attester?: { readonly userId: string; readonly signingKey: CryptoKey },
): Effect.Effect<ProjectContextBase, CliError, CliServices> {
  return Effect.gen(function* () {
    const resync = syncProject(context.client, projectId);
    const synced = yield* resync;
    const checked = yield* loadCheckedFloor(projectId, synced, resync);
    yield* checkInviteAnchor(projectId, checked.verified);
    const verified = yield* reconcileGossip(projectId, checked.verified, resync);
    // 未解決の複合 intent(3-F)は「同一環境への次の mutation・成功報告の前に
    // 照合で解決する」— 前段は毎回チェーンを全同期・全検証するので、ここが
    // その照合点になる(受理済みなら床のマニフェスト前進もここで回収する)
    let floor = checked.floor;
    if (floor !== null && floor.intents.length > 0) {
      const store = yield* FloorStore;
      const resolved = yield* reconcileCompositeIntents({
        store,
        projectId,
        verified,
        intents: floor.intents,
      });
      if (resolved) {
        // 照合が床を前進させた可能性がある — fold を読み直す。読み直した床にも
        // conflict 検査を再適用する: 照合中・直後に並行プロセスが同座標の矛盾
        // 観測を追記していた場合、検査なしで進むとこのコマンドの残りが
        // equivocation 証拠を無視した代表値で走る(loadCheckedFloor と同じ
        // fail-closed を、床を読み直すすべての点で崩さない)
        const reloaded = (yield* store.load(projectId)).floor;
        if (reloaded !== null && reloaded.conflicts.length > 0) {
          return yield* Effect.fail(cliError(formatFloorConflicts(projectId, reloaded.conflicts)));
        }
        floor = reloaded;
      }
    }
    if (options?.quietMandateWarning !== true) {
      yield* warnUnconvergedMandates({ client: context.client, verified });
    }
    // 検証済みヘッドの申告提出(§6.3 ヘッドゴシップ — SHOULD。照合を全部
    // 通過したビューだけを申告する。失敗は非失敗の警告 — attestation.ts)
    if (attester !== undefined) {
      yield* submitHeadAttestationIfAdvanced({
        client: context.client,
        projectId,
        view: verified,
        attesterUserId: attester.userId,
        signingKey: attester.signingKey,
      });
    }
    return { ...context, projectId, verified, floor, resync };
  });
}

/** データ系コマンド共通の前段(ロード済み config 版)。 */
function openProjectWith(
  config: CliConfig,
  flags: CommonFlags,
  options?: OpenProjectOptions,
): Effect.Effect<ProjectContext, CliError, CliServices> {
  return Effect.gen(function* () {
    // プロジェクト ID の形式検証はネットワークアクセスより先に行う
    const projectId = yield* resolveProjectId(flags.project, config);
    const context = yield* openSessionWith(config, flags.server);
    // master 鍵の読み込みは同期(通信)・床の前進より**前**のまま置く: 鍵の無い
    // 端末で実行された書き込み系コマンドを、サーバーへ 1 往復してから落とさない
    const masterKeys = yield* loadMasterKeys(context.session);
    const base = yield* attachProject(context, projectId, options, {
      userId: context.session.userId,
      signingKey: masterKeys.sigKeyPair.privateKey,
    });
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
  options?: OpenProjectOptions,
): Effect.Effect<ProjectContext, CliError, CliServices> {
  return Effect.gen(function* () {
    const store = yield* ConfigStore;
    return yield* openProjectWith(yield* store.load, flags, options);
  });
}

/**
 * 平文メタデータ・チェーンしか読まないコマンドの前段(master 鍵を要求しない)。
 * invite create / list / revoke が使う: リンク材料(ヘッド・自分の FP)は
 * すべてチェーン導出であり、鍵素材なしの端末(MARUHI_TOKEN 実行)でも
 * 招待の発行・管理を行える(env diff / project verify と同じ鍵なしクラス)。
 */
export function openMetadataProject(
  flags: CommonFlags,
): Effect.Effect<ProjectContextBase, CliError, CliServices> {
  return Effect.gen(function* () {
    const store = yield* ConfigStore;
    return yield* openMetadataProjectWith(yield* store.load, flags);
  });
}

/** 環境単位の床ハンドル(コマンド内の pull / push が検査・コミットに使う)。 */
export function floorHandleFor(
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
      // この環境の未解決 intent(前段の照合後に残るのは meta-op のみ —
      // 検証済み pull の到達時に values.ts が照合する)
      intents:
        context.floor?.intents.filter((intent) => intent.environmentId === environmentId) ?? [],
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
  options?: OpenProjectOptions,
): Effect.Effect<EnvironmentContext, CliError, CliServices> {
  return Effect.gen(function* () {
    const store = yield* ConfigStore;
    const config = yield* store.load;
    const environmentId = yield* resolveEnvironmentId(flags.env, config);
    const context = yield* openProjectWith(config, flags, options);
    const floorHandle = yield* floorHandleFor(context, environmentId);
    return { ...context, environmentId, floorHandle };
  });
}

/**
 * 検証済みビューのチェーンヘッドを床へ記録する(§6.3 規則 (a) の材料)。
 * `mergeHead` は単調なので後退はせず、冪等。
 *
 * pull / push は commitPull / commitPush の中で同じヘッドを書くが、**値を
 * 読まないコマンドはその経路を通らない**。有界再同期でビューが前進した場合、
 * 記録しないと「検証済みの最新ヘッド」が openProject 時点のまま残り、
 * その間への巻き戻しを次回以降に検出できない(床は SHOULD だが、pull / push が
 * 保っている材料をこのコマンドだけ落とす理由はない)。
 */
export function commitVerifiedHead(
  projectId: string,
  verified: VerifiedProject,
): Effect.Effect<void, CliError, CliServices> {
  return Effect.flatMap(FloorStore, (store) =>
    store.commitHead(projectId, {
      seq: verified.state.headSeq,
      hashHex: verified.state.headHashHex,
    }),
  );
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
 * 環境 ID の形式検証は呼び出し側(位置引数を受ける側)が済ませている前提。
 * ただし `EnvironmentId` は**ブランド付きではない**(Schema.String.check の
 * 別名)ので、型は検証を強制しない — 表示側は環境 ID も displayText を通す
 * (env-diff.ts)。
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
