// ローカル床の検出規則(CRYPTO_SPEC §6.3 の (a)(b)(c))と更新順序の規範。
//
// 検査対象はすべて §6.3 の署名検証を通過済みの配布データ(values.ts)。床との
// 不一致は「正規署名済みデータ同士の矛盾」なので、検出はサーバーの equivocation
// または(在籍区間内の鍵による)偽造の否認不能な証拠であり、誤検出の懸念がない
// — よって全件を拒否とする(§6.3 の「拒否・警告」の強い側)。
//
// - 規則 (a): チェーンの短縮、version / metaVersion / エポックの後退、削除の
//   無断取り消し
// - 規則 (b): 床と同一 version / metaVersion に対する signed bytes の相違
//   (内容差し替え・分岐の証拠)
// - 規則 (c): 床の version より新しい version の epoch が、当該環境の pull 時点
//   エポック基準(pullEpoch)より小さい配布の拒否(削除済みメンバーの鍵による
//   「前進 version への旧エポック注入」の検出 — §14.3-5)。基準は前回成功 pull
//   の値を使い、チェーン同期単独では前進させない(誤拒否と検出喪失の両縁 —
//   セッション 12 ノート §12 ループ 2)
//
// **メタステートメントの床は巻き戻し検出のみ**: メタはエポックアンカーを
// 持たないため(§4.2)、前進 metaVersion の注入は床を持っても検出されない
// (§14.3-5 — 最重要の非保証。「検出済み」と誤認する検査をここに置かない)。

import { Effect } from "effect";

import type { CliError } from "./errors.ts";
import { isServerRejection } from "./failure.ts";
import {
  type ChainHeadFloor,
  type EnvironmentFloor,
  type FloorIntent,
  type FloorIntentInput,
  type FloorIntentOutcome,
  floorRecordGet,
  type FloorStoreShape,
  joinEnvironmentFloor,
  type ManifestFloor,
  type MetadataCommit,
  type ProjectFloor,
  type VariableFloor,
} from "./floor.ts";
import type { VerifiedManifest } from "./manifest.ts";
import type { VerifiedProject } from "./sync.ts";
import type { VerifiedPulledValue } from "./values.ts";

/** deleted を含む検証済みメタステートメントの証拠材料。 */
export interface VerifiedMetaEvidence {
  readonly status: "active" | "deleted";
  readonly metaVersion: number;
  readonly metaSigHashHex: string;
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string;
  /** 配布された著者署名と帰属(証拠の自己完結性 — §14.2-5)。 */
  readonly signatureHex: string;
  readonly authorUserId: string;
  readonly authorKeyFingerprintHex: string;
}

/** 検証済み tombstone(deleted ステートメント)。 */
export interface VerifiedTombstone extends VerifiedMetaEvidence {
  readonly variableId: string;
  /** 検証済み deleted ステートメントの name(直前 active 名を保持 — §4.2)。 */
  readonly name: string;
}

/** 床検査の入力(§6.3 の検証を全通過した pull 応答のダイジェスト)。 */
export interface VerifiedPullSnapshot {
  readonly environment: VerifiedMetaEvidence;
  readonly variables: readonly VerifiedPulledValue[];
  readonly tombstones: readonly VerifiedTombstone[];
  /**
   * 検証済みマニフェスト(§4.3)。null は移行経路(--init-manifest)が欠落を
   * 許容した場合のみ — 通常経路の欠落は values.ts が床検査の前に拒否している。
   */
  readonly manifest: VerifiedManifest | null;
}

/**
 * メタデータのみ pull(§12-7)の検証済みダイジェスト。値を運ばないため、
 * 床検査はメタ水準(規則 (a)(b) のメタ部分 + 欠落・削除取り消し)に限られる —
 * 値の巻き戻し・equivocation・規則 (c) はこの形からは検査できない
 * (検査済みと偽らない: 値水準の床検査は値を運ぶ pull の領分)。
 */
export interface VerifiedMetadataSnapshot {
  readonly environment: VerifiedMetaEvidence;
  readonly variables: readonly VerifiedActiveStatement[];
  readonly tombstones: readonly VerifiedTombstone[];
  /** 検証済みマニフェスト(欠落は values.ts が拒否済み — メタのみ pull に移行許容はない)。 */
  readonly manifest: VerifiedManifest;
}

/** 検証済みのアクティブ変数ステートメント(メタデータのみ pull の 1 変数)。 */
export interface VerifiedActiveStatement extends VerifiedMetaEvidence {
  readonly variableId: string;
  /** 検証済みステートメントの name(名前解決はこれ以外を信用しない — §12-2)。 */
  readonly name: string;
}

/** 配布された値側の証拠材料(座標・ハッシュ・宣言ヘッド・署名と帰属)。 */
export interface PulledValueEvidence {
  readonly version: number;
  readonly epoch: number;
  readonly valueSigHashHex: string;
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string;
  /** 配布された writer 署名と帰属(証拠の自己完結性 — §14.2-5)。 */
  readonly signatureHex: string;
  readonly writerUserId: string;
  readonly writerKeyFingerprintHex: string;
}

/** 床側(過去に検証済み)のメタ記録。 */
export interface FloorMetaEvidence {
  readonly metaVersion: number;
  readonly metaSigHashHex: string;
}

/** active な変数床(値側の証拠比較の基準)。 */
export type ActiveVariableFloor = Extract<VariableFloor, { status: "active" }>;

/** 床検査で検出した不整合(拒否 + 証拠表示の材料 — floor-evidence.ts が整形)。 */
export type FloorViolation =
  | {
      readonly kind: "chain-shortened";
      readonly floorHead: ChainHeadFloor;
      readonly syncedHead: ChainHeadFloor;
    }
  | {
      readonly kind: "chain-diverged";
      readonly floorHead: ChainHeadFloor;
      readonly actualHashHex: string;
      readonly syncedHead: ChainHeadFloor;
    }
  | {
      readonly kind: "variable-omitted";
      readonly variableId: string;
      readonly floor: VariableFloor;
    }
  | {
      readonly kind: "value-rollback";
      readonly variableId: string;
      readonly floor: ActiveVariableFloor;
      readonly pulled: PulledValueEvidence;
    }
  | {
      readonly kind: "value-equivocation";
      readonly variableId: string;
      readonly floor: ActiveVariableFloor;
      readonly pulled: PulledValueEvidence;
    }
  | {
      readonly kind: "value-epoch-regression";
      readonly variableId: string;
      readonly floor: ActiveVariableFloor;
      readonly pulled: PulledValueEvidence;
    }
  | {
      readonly kind: "stale-epoch-injection";
      readonly variableId: string;
      /** 規則 (c) の基準(前回成功 pull 時点のチェーン導出現エポック)。 */
      readonly baselineEpoch: number;
      readonly floorVersion: number;
      readonly pulled: PulledValueEvidence;
    }
  | {
      readonly kind: "meta-rollback";
      readonly target: "variable" | "environment";
      readonly variableId: string | null;
      readonly floor: FloorMetaEvidence;
      readonly pulled: VerifiedMetaEvidence;
    }
  | {
      readonly kind: "meta-equivocation";
      readonly target: "variable" | "environment";
      readonly variableId: string | null;
      readonly floor: FloorMetaEvidence;
      readonly pulled: VerifiedMetaEvidence;
    }
  | {
      readonly kind: "deletion-revoked";
      readonly variableId: string;
      readonly floor: FloorMetaEvidence;
      readonly pulled: VerifiedMetaEvidence;
    }
  | {
      readonly kind: "tombstone-mismatch";
      readonly variableId: string;
      readonly floor: FloorMetaEvidence;
      readonly pulled: VerifiedMetaEvidence;
    }
  | {
      readonly kind: "manifest-rollback";
      readonly floor: ManifestFloor;
      readonly pulled: VerifiedManifest;
    }
  | {
      readonly kind: "manifest-equivocation";
      readonly floor: ManifestFloor;
      readonly pulled: VerifiedManifest;
    }
  | {
      // マニフェスト床の確立後にマニフェストが配布されない形(--init-manifest の
      // 欠落許容下でも、一度確立した床に対する欠落は握り潰しの証拠)
      readonly kind: "manifest-omitted";
      readonly floor: ManifestFloor;
    }
  | {
      // 規則 (c) のマニフェスト適用(§6.3 — 2026-08-18): 床の manifest_version
      // より新しいマニフェストの epoch が pull 時点エポック床より小さい配布
      readonly kind: "stale-manifest-injection";
      readonly baselineEpoch: number;
      readonly floorManifestVersion: number;
      readonly pulled: VerifiedManifest;
    };

/** 拒否メッセージの種別ラベル(証拠の整形は floor-evidence.ts)。 */
export function floorViolationLabel(violation: FloorViolation): string {
  switch (violation.kind) {
    case "chain-shortened":
      return "chain shortening (a rollback)";
    case "chain-diverged":
      return "distribution of a branch diverging from the verified chain head (immediate evidence of equivocation)";
    case "variable-omitted":
      return "omission of a verified variable (selective response truncation)";
    case "value-rollback":
      return "a value-version rollback";
    case "value-equivocation":
      return "different signed bytes served for the same version (evidence of equivocation)";
    case "value-epoch-regression":
      return "an epoch regression (a §4.1 monotonicity violation)";
    case "stale-epoch-injection":
      return "an advanced version below the pull-time epoch baseline (evidence of forward injection with an old epoch key)";
    case "meta-rollback":
      return "a meta-statement rollback";
    case "meta-equivocation":
      return "different signed bytes served for the same metaVersion (evidence of equivocation)";
    case "deletion-revoked":
      return "an unauthorized undeletion";
    case "tombstone-mismatch":
      return "replacement of a deleted variable's tombstone";
    case "manifest-rollback":
      return "an environment-manifest rollback";
    case "manifest-equivocation":
      return "different signed bytes served for the same manifestVersion (evidence of equivocation)";
    case "manifest-omitted":
      return "omission of the environment manifest after one was verified (manifest suppression)";
    case "stale-manifest-injection":
      return "an advanced manifestVersion below the epoch baseline (evidence of forward meta injection with an old epoch key)";
  }
}

/**
 * チェーン床の検査(規則 (a) のチェーン部分)。同期・検証済みのチェーンが
 * 床に記録したヘッドを含む延長であることを要求する: (1) 短縮(headSeq の
 * 後退)、(2) 床 seq 位置のハッシュ不一致(= 床のヘッドが載っていない別分岐 —
 * prev_hash 連鎖により床 seq 一致は床以下の全エントリ一致を意味する)。
 * seq が床より先へ進むのは正常(他メンバーの追記)。
 */
export function checkChainFloor(
  floor: ProjectFloor,
  verified: VerifiedProject,
): FloorViolation | null {
  const floorHead = floor.chainHead;
  if (floorHead === null) {
    // ヘッド観測がまだない床(intent だけのログ等)— 検査対象がない
    return null;
  }
  const syncedHead: ChainHeadFloor = {
    seq: verified.state.headSeq,
    hashHex: verified.state.headHashHex,
  };
  if (verified.state.headSeq < floorHead.seq) {
    return { kind: "chain-shortened", floorHead, syncedHead };
  }
  const actualHashHex = verified.history.entryHashAt(floorHead.seq);
  if (actualHashHex !== floorHead.hashHex) {
    return {
      kind: "chain-diverged",
      floorHead,
      actualHashHex: actualHashHex ?? "",
      syncedHead,
    };
  }
  return null;
}

function valueEvidenceOf(value: VerifiedPulledValue): PulledValueEvidence {
  return {
    version: value.version,
    epoch: value.epoch,
    valueSigHashHex: value.signedBytesHashHex,
    chainHeadSeq: value.valueChainHeadSeq,
    chainHeadHashHex: value.valueChainHeadHashHex,
    signatureHex: value.valueSignatureHex,
    writerUserId: value.writerUserId,
    writerKeyFingerprintHex: value.writerKeyFingerprintHex,
  };
}

function metaEvidenceOf(value: VerifiedPulledValue): VerifiedMetaEvidence {
  return {
    status: "active",
    metaVersion: value.metaVersion,
    metaSigHashHex: value.metaSignedBytesHashHex,
    chainHeadSeq: value.metaChainHeadSeq,
    chainHeadHashHex: value.metaChainHeadHashHex,
    signatureHex: value.metaSignatureHex,
    authorUserId: value.authorUserId,
    authorKeyFingerprintHex: value.authorKeyFingerprintHex,
  };
}

/** 変数メタの床検査(後退 = (a)・同一 metaVersion の相違 = (b)。前進は非保証)。 */
function checkMetaAgainstFloor(
  target: "variable" | "environment",
  variableId: string | null,
  floor: FloorMetaEvidence,
  pulled: VerifiedMetaEvidence,
): FloorViolation | null {
  if (pulled.metaVersion < floor.metaVersion) {
    return { kind: "meta-rollback", target, variableId, floor, pulled };
  }
  if (pulled.metaVersion === floor.metaVersion && pulled.metaSigHashHex !== floor.metaSigHashHex) {
    return { kind: "meta-equivocation", target, variableId, floor, pulled };
  }
  return null;
}

/**
 * マニフェスト床の検査(規則 (a)(b) のマニフェスト部分 + 確立後の欠落)。
 * 床にマニフェスト記録がない(マニフェスト導入前の床)場合は検査対象がない —
 * 記録の確立は検証成功後の床コミットが担う。
 */
function checkManifestAgainstFloor(
  floor: EnvironmentFloor,
  manifest: VerifiedManifest | null,
): FloorViolation | null {
  const manifestFloor = floor.manifest;
  if (manifestFloor === undefined) {
    return null;
  }
  if (manifest === null) {
    // 一度確立したマニフェスト床に対する欠落は、移行経路(--init-manifest)の
    // 許容下でも握り潰しの証拠(初期化済み環境のマニフェストは消えない)
    return { kind: "manifest-omitted", floor: manifestFloor };
  }
  if (manifest.manifestVersion < manifestFloor.manifestVersion) {
    return { kind: "manifest-rollback", floor: manifestFloor, pulled: manifest };
  }
  if (
    manifest.manifestVersion === manifestFloor.manifestVersion &&
    manifest.signedBytesHashHex !== manifestFloor.manifestSigHashHex
  ) {
    // epoch を含む全署名対象が signed bytes に入るため、同一 manifestVersion の
    // 内容相違はこの 1 検査で覆われる(§4.3 の署名対象全列挙)
    return { kind: "manifest-equivocation", floor: manifestFloor, pulled: manifest };
  }
  return null;
}

/**
 * 規則 (c) のマニフェスト適用(§6.3 — 2026-08-18): 床の manifest_version より
 * 新しいマニフェストの epoch が基準より小さい配布は、旧エポック鍵による前進
 * manifestVersion 注入の証拠。マニフェスト床がない場合は version 0 相当
 * (値の「床にない変数」と同型 — 導入後の正当な初回マニフェストの epoch は
 * 発行時点の現エポック ≥ 基準)。
 *
 * 基準は pull 時点エポック床・**床マニフェスト自身の epoch**・**環境水準の
 * エポック観測(§6.3 座標 (ii) — 出所を問わず join される observedEpoch)**の
 * 最大値: マニフェスト連鎖のエポックは非減少(§4.3 の epoch-regressed —
 * 検証済み)なので、床が検証済みの epoch E を知っている以上、それより新しい
 * manifestVersion の正当なマニフェストの epoch は E 以上でしかありえない
 * (推移形)。pullEpoch だけを基準にすると、rotate 直後(commitManifest は
 * 前進するが pullEpoch は pull まで動かない)や有界再同期の形(pullEpoch は
 * 応答取得前ビュー)で、床が知っている epoch より古い焼き込みが素通りする。
 * observedEpoch は値を誤拒否する経路を持たないため、この baseline には
 * 制約なく参加できる(値規則 (c) には使わない — 座標の型が分ける)。
 */
function checkManifestEpochBaseline(
  floor: EnvironmentFloor,
  manifest: VerifiedManifest | null,
): FloorViolation | null {
  if (manifest === null) {
    return null;
  }
  const floorVersion = floor.manifest?.manifestVersion ?? 0;
  const baselineEpoch = Math.max(floor.pullEpoch, floor.observedEpoch, floor.manifest?.epoch ?? 0);
  if (manifest.manifestVersion > floorVersion && manifest.epoch < baselineEpoch) {
    return {
      kind: "stale-manifest-injection",
      baselineEpoch,
      floorManifestVersion: floorVersion,
      pulled: manifest,
    };
  }
  return null;
}

/** active な床 × active な配布値の検査(規則 (a)(b) の値・変数メタ部分)。 */
function checkActiveVariable(
  floor: ActiveVariableFloor,
  value: VerifiedPulledValue,
): FloorViolation | null {
  const variableId = value.variableId;
  const pulled = valueEvidenceOf(value);
  if (value.version < floor.version) {
    return { kind: "value-rollback", variableId, floor, pulled };
  }
  if (value.version === floor.version && value.signedBytesHashHex !== floor.valueSigHashHex) {
    // epoch を含む全署名対象が signed bytes に入るため、同一 version の内容
    // 相違はこの 1 検査で覆われる(§4.1 の署名対象全列挙)
    return { kind: "value-equivocation", variableId, floor, pulled };
  }
  if (value.version > floor.version && value.epoch < floor.epoch) {
    // §4.1 のエポック単調性(推移的 — 版番号のギャップに関わらず要求できる)
    return { kind: "value-epoch-regression", variableId, floor, pulled };
  }
  return checkMetaAgainstFloor("variable", variableId, floor, metaEvidenceOf(value));
}

/** 床が active と記録している変数のメタ水準検査(active / tombstone / 欠落の 3 分岐)。 */
function checkFloorActiveMeta(
  variableId: string,
  floor: ActiveVariableFloor,
  active: VerifiedMetaEvidence | undefined,
  tombstone: VerifiedTombstone | undefined,
): FloorViolation | null {
  if (active !== undefined) {
    return checkMetaAgainstFloor("variable", variableId, floor, active);
  }
  if (tombstone !== undefined) {
    // metaVersion が床より進んだ deleted は正当な削除。同一 metaVersion で
    // status が違えば signed bytes も違う = (b) の証拠。後退は (a)
    return checkMetaAgainstFloor("variable", variableId, floor, tombstone);
  }
  return { kind: "variable-omitted", variableId, floor };
}

/** 床が active と記録している変数の検査(値水準 + メタ水準)。 */
function checkFloorActive(
  variableId: string,
  floor: ActiveVariableFloor,
  active: VerifiedPulledValue | undefined,
  tombstone: VerifiedTombstone | undefined,
): FloorViolation | null {
  if (active !== undefined) {
    return checkActiveVariable(floor, active);
  }
  return checkFloorActiveMeta(variableId, floor, undefined, tombstone);
}

/** 床が deleted と記録している変数の検査(削除は終端状態 — §4.2 / session-15 §2-2)。 */
function checkFloorDeleted(
  variableId: string,
  floor: Extract<VariableFloor, { status: "deleted" }>,
  active: VerifiedMetaEvidence | undefined,
  tombstone: VerifiedTombstone | undefined,
): FloorViolation | null {
  if (active !== undefined) {
    // 削除の無断取り消し(規則 (a))。deleted 後の再 active 化は正当な経路が
    // 存在しない(サーバー受理も predecessor 検証も拒否する — session-15 §2-2)
    return { kind: "deletion-revoked", variableId, floor, pulled: active };
  }
  if (tombstone === undefined) {
    return { kind: "variable-omitted", variableId, floor };
  }
  if (
    tombstone.metaVersion !== floor.metaVersion ||
    tombstone.metaSigHashHex !== floor.metaSigHashHex
  ) {
    // deleted は終端状態で正当な後続ステートメントが存在しないため、床との
    // 厳密一致を要求する(後退 = (a)、相違 = (b)、前進 = deleted 後の偽造)
    return { kind: "tombstone-mismatch", variableId, floor, pulled: tombstone };
  }
  return null;
}

/**
 * 環境メタ検査 + 床にある変数ごとの検査(欠落・後退・相違・削除取り消し)の
 * 共通骨格。active 側の検査だけが形(値付き / メタのみ)で差し替わる。
 * active / deleted の同一 ID 併置は values.ts が拒否済み。
 */
function checkFloorCommon<T extends { readonly variableId: string }>(
  floor: EnvironmentFloor,
  environment: VerifiedMetaEvidence,
  activeList: readonly T[],
  tombstoneList: readonly VerifiedTombstone[],
  checkActive: (
    variableId: string,
    variableFloor: ActiveVariableFloor,
    active: T | undefined,
    tombstone: VerifiedTombstone | undefined,
  ) => FloorViolation | null,
  toMeta: (active: T) => VerifiedMetaEvidence,
): FloorViolation | null {
  const actives = new Map(activeList.map((value) => [value.variableId, value]));
  const tombstones = new Map(tombstoneList.map((tombstone) => [tombstone.variableId, tombstone]));
  const environmentViolation = checkMetaAgainstFloor(
    "environment",
    null,
    { metaVersion: floor.metaVersion, metaSigHashHex: floor.metaSigHashHex },
    environment,
  );
  if (environmentViolation !== null) {
    return environmentViolation;
  }
  for (const [variableId, variableFloor] of Object.entries(floor.variables)) {
    const active = actives.get(variableId);
    const violation =
      variableFloor.status === "active"
        ? checkActive(variableId, variableFloor, active, tombstones.get(variableId))
        : checkFloorDeleted(
            variableId,
            variableFloor,
            active === undefined ? undefined : toMeta(active),
            tombstones.get(variableId),
          );
    if (violation !== null) {
      return violation;
    }
  }
  return null;
}

/**
 * 環境 1 つ分の床検査(規則 (a)(b)(c))。床なし(初回)は検査対象がない —
 * その場合に何が保証されないかは §14.3-3(初回同期クライアント)。
 * 返すのは最初に見つかった不整合 1 件(すべて拒否条件なので列挙は不要)。
 */
export function checkEnvironmentPull(
  floor: EnvironmentFloor | null,
  snapshot: VerifiedPullSnapshot,
): FloorViolation | null {
  if (floor === null) {
    return null;
  }
  const violation = checkFloorCommon(
    floor,
    snapshot.environment,
    snapshot.variables,
    snapshot.tombstones,
    checkFloorActive,
    metaEvidenceOf,
  );
  if (violation !== null) {
    return violation;
  }
  // マニフェスト床の規則 (a)(b) + 確立後の欠落 + 規則 (c) のマニフェスト適用
  const manifestViolation =
    checkManifestAgainstFloor(floor, snapshot.manifest) ??
    checkManifestEpochBaseline(floor, snapshot.manifest);
  if (manifestViolation !== null) {
    return manifestViolation;
  }
  // 規則 (c): 床の version より新しい version(床にない変数は version 0 相当 —
  // 前回 pull 以降に正当に作られた変数は当時の現エポック以上でしか書けない)の
  // epoch が pull 時点エポック基準より小さい配布は前進注入の証拠。基準「以上」は
  // 受理する(ローテーション直後・再暗号化完了前の正当な旧エポック値 — §12-7)
  for (const value of snapshot.variables) {
    const variableFloor = floorRecordGet(floor.variables, value.variableId);
    const floorVersion = variableFloor?.status === "active" ? variableFloor.version : 0;
    if (value.version > floorVersion && value.epoch < floor.pullEpoch) {
      return {
        kind: "stale-epoch-injection",
        variableId: value.variableId,
        baselineEpoch: floor.pullEpoch,
        floorVersion,
        pulled: valueEvidenceOf(value),
      };
    }
  }
  return null;
}

/**
 * メタデータのみ pull(§12-7)の床検査: 規則 (a)(b) のメタ部分(環境・変数
 * ステートメントの後退 / 同一 metaVersion の相違)、検証済み変数の欠落、
 * 削除の無断取り消し・tombstone の差し替え。値を運ばない形のため値水準の
 * 検査と規則 (c) は対象外。検査合格後の**環境水準の床コミット**(M1-A3 —
 * チェーンヘッド・環境メタ床・マニフェスト床・座標 (ii) のみ。値床は捏造
 * しない・pull 基準は前進させない)は呼び出し側(enforceMetadataFloor)が行う。
 */
export function checkEnvironmentMetadataPull(
  floor: EnvironmentFloor | null,
  snapshot: VerifiedMetadataSnapshot,
): FloorViolation | null {
  if (floor === null) {
    return null;
  }
  const violation = checkFloorCommon(
    floor,
    snapshot.environment,
    snapshot.variables,
    snapshot.tombstones,
    checkFloorActiveMeta,
    (statement) => statement,
  );
  if (violation !== null) {
    return violation;
  }
  // マニフェストはメタのみモードでも配布される(§12-7 — メタ検証の完全性は
  // 同水準)ため、床の規則 (a)(b) と規則 (c) のマニフェスト適用はここでも検査
  // する(値水準の規則 (c) と床コミットが値付き pull の領分であることは不変)
  return (
    checkManifestAgainstFloor(floor, snapshot.manifest) ??
    checkManifestEpochBaseline(floor, snapshot.manifest)
  );
}

/**
 * 検証成功した pull 応答から次の環境床を組み立てる(§6.3 の更新順序: 検査は
 * 前回基準で行い、規則 (c) 基準の前進 = 今回のチェーン導出現エポックは検証
 * 成功後に変数床と原子的にコミットされる — 呼び出し側が commitPull で書く)。
 */
export function buildEnvironmentFloor(
  chainCurrentEpoch: number,
  snapshot: VerifiedPullSnapshot,
): EnvironmentFloor {
  const variables: Record<string, VariableFloor> = {};
  for (const value of snapshot.variables) {
    variables[value.variableId] = {
      status: "active",
      version: value.version,
      epoch: value.epoch,
      valueSigHashHex: value.signedBytesHashHex,
      metaVersion: value.metaVersion,
      metaSigHashHex: value.metaSignedBytesHashHex,
    };
  }
  for (const tombstone of snapshot.tombstones) {
    variables[tombstone.variableId] = {
      status: "deleted",
      metaVersion: tombstone.metaVersion,
      metaSigHashHex: tombstone.metaSigHashHex,
    };
  }
  return {
    pullEpoch: chainCurrentEpoch,
    // 環境水準のエポック観測(座標 (ii))も同じ検証済み観測から確立する
    observedEpoch: chainCurrentEpoch,
    metaVersion: snapshot.environment.metaVersion,
    metaSigHashHex: snapshot.environment.metaSigHashHex,
    ...(snapshot.manifest === null
      ? {}
      : {
          manifest: {
            manifestVersion: snapshot.manifest.manifestVersion,
            epoch: snapshot.manifest.epoch,
            manifestSigHashHex: snapshot.manifest.signedBytesHashHex,
          },
        }),
    variables,
  };
}

/**
 * 1 コマンド実行中の環境床ハンドル。プロセス内で pull が複数回起きる場合
 * (push の再試行ループ)に、直前の pull がコミットした床を次の検査の基準に
 * する。プロセス内キャッシュはコミットのたびに**ストアが fold した(= ログへ
 * 永続化済みの)環境床**へ同期する(単なる送信スナップショットではない):
 * 追記専用ログの join が取り込んだ並行 CLI の検出材料(union・deleted 終端・
 * より新しい version / pullEpoch)を、同一コマンド内の後続検査が取りこぼさない
 * ため。ディスクの床は自 CLI が §6.3 検証済みレコードしか書かないので、fold
 * 結果の採用は検査基準として健全(ローカル状態を書ける攻撃者は床の外)。
 *
 * intent(3-F)も環境スコープでここが窓口になる: openProject 時点の未解決
 * intent + 自プロセスが追記した intent を保持し、効果確認(§12-10 (3))を
 * 通過した経路が resolution で閉じる。
 */
export interface FloorHandle {
  /** 現在の環境床(初回 pull 前は openProject 時に読んだスナップショット)。 */
  readonly current: () => EnvironmentFloor | null;
  /** この環境の未解決 intent(要照合 — §6.3 記録規律 (ii))。 */
  readonly unresolvedIntents: () => readonly FloorIntent[];
  /** 検証済み pull の原子コミット(規則 (c) 基準 + 変数床 + ヘッドを 1 レコードで)。 */
  readonly commitPull: (
    environment: EnvironmentFloor,
    head: ChainHeadFloor,
  ) => Effect.Effect<void, CliError>;
  /** 受理された push の変数床前進(pullEpoch は動かさない)。 */
  readonly commitPush: (
    variableId: string,
    variable: VariableFloor,
    head: ChainHeadFloor,
  ) => Effect.Effect<void, CliError>;
  /**
   * metadata-only pull の環境水準コミット(M1-A3 — 値床は捏造しない・pull
   * 基準は前進させない。環境メタ床・マニフェスト床・座標 (ii) のみ)。
   */
  readonly commitMetadata: (
    commit: Omit<MetadataCommit, "chainHead" | "environmentId">,
    head: ChainHeadFloor,
  ) => Effect.Effect<void, CliError>;
  /**
   * 受理確認済みの自己発行マニフェストの床昇格(M1-A4 — pullEpoch・変数床は
   * 動かさない)。怠ると受理後の床が旧 manifestVersion のままになり、旧版を
   * 配布し続けるサーバーを規則 (a) が検出できない窓が生まれる。
   */
  readonly commitManifest: (
    manifest: ManifestFloor,
    head: ChainHeadFloor,
  ) => Effect.Effect<void, CliError>;
  /**
   * security-critical mutation の送信前 intent(3-F)。永続化(fsync 相当)の
   * 成功まで送信しない(fail-closed)。返り値は resolution 用の intent id。
   */
  readonly appendIntent: (input: FloorIntentInput) => Effect.Effect<string, CliError>;
  /** 効果確認の結果で intent を閉じる(未知 / 解決済み id は no-op — 冪等)。 */
  readonly resolveIntent: (
    intentId: string,
    outcome: FloorIntentOutcome,
  ) => Effect.Effect<void, CliError>;
}

/**
 * 送信の失敗がサーバー自身のエラー本文での拒否(= 効果は生じていない — 確定)
 * なら intent(3-F)を rejected で閉じる `Effect.tapError` 用コールバック。
 * 転送層の失敗(応答消失)は未解決のまま残す — 次の照合機会(チェーン同期 /
 * metadata-only pull)が解決する。resolution の追記失敗は握り潰してよい:
 * intent が開いたまま残る方向は安全側(要照合が残るだけ)。
 */
export function rejectIntentOnServerRejection(
  floor: FloorHandle,
  intentId: string,
): (error: unknown) => Effect.Effect<void> {
  return (error) =>
    isServerRejection(error)
      ? Effect.ignore(floor.resolveIntent(intentId, "rejected"))
      : Effect.void;
}

/** 床ストアに対する環境床ハンドルを作る。 */
export function makeFloorHandle(input: {
  readonly store: FloorStoreShape;
  readonly projectId: string;
  readonly environmentId: string;
  readonly initial: EnvironmentFloor | null;
  /** openProject 時点の、この環境の未解決 intent(fold の表面化 — 3-F)。 */
  readonly intents?: readonly FloorIntent[];
}): FloorHandle {
  let current = input.initial;
  const intents = new Map((input.intents ?? []).map((intent) => [intent.id, intent]));
  const adopt = (merged: EnvironmentFloor): void => {
    current = merged;
  };
  return {
    current: () => current,
    unresolvedIntents: () => [...intents.values()],
    commitPull: (environment, head) =>
      input.store
        .commitPull(input.projectId, {
          chainHead: head,
          environmentId: input.environmentId,
          environment,
        })
        .pipe(Effect.map(adopt)),
    commitPush: (variableId, variable, head) =>
      input.store
        .commitPush(input.projectId, {
          chainHead: head,
          environmentId: input.environmentId,
          variableId,
          variable,
        })
        .pipe(Effect.map(adopt)),
    commitMetadata: (commit, head) =>
      input.store
        .commitMetadata(input.projectId, {
          chainHead: head,
          environmentId: input.environmentId,
          ...commit,
        })
        .pipe(Effect.map(adopt)),
    commitManifest: (manifest, head) =>
      Effect.suspend(() => {
        // プロセス内の基準は**ディスク書き込みの成否に関わらず先に**前進させる:
        // 自分が受理させた manifestVersion を知っている事実は、書き込みに失敗
        // しても同一実行内の再走査の検出材料であり続ける(受理後に旧版を配布し
        // 続けるサーバーの検出)。前進はディスク側と同一の join 実装で行う
        // (M1-A5 — `>=` 後勝ちの別実装を持たない)。プロセス内 join の conflict
        // 検出はディスク側の fold が同じ規則で担うため、ここでは捨ててよい
        if (current !== null) {
          current = joinEnvironmentFloor(
            input.environmentId,
            current,
            {
              pullEpoch: 0,
              observedEpoch: manifest.epoch,
              metaVersion: 0,
              metaSigHashHex: "",
              manifest,
              variables: {},
            },
            () => {},
          );
        }
        return input.store
          .commitManifest(input.projectId, {
            chainHead: head,
            environmentId: input.environmentId,
            manifest,
          })
          .pipe(Effect.map(adopt));
      }),
    appendIntent: (intentInput) =>
      input.store.appendIntent(input.projectId, intentInput).pipe(
        Effect.tap((id) =>
          Effect.sync(() => {
            intents.set(id, { id, ...intentInput });
          }),
        ),
      ),
    resolveIntent: (intentId, outcome) =>
      Effect.suspend(() => {
        if (!intents.has(intentId)) {
          return Effect.void;
        }
        intents.delete(intentId);
        return input.store.resolveIntent(input.projectId, intentId, outcome);
      }),
  };
}
