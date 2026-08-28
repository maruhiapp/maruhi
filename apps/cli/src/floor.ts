// ローカル床の意味論(CRYPTO_SPEC §6.3 — 2026-08-19 セッション 32 改訂)。
//
// 床 = **これまでに検証へ成功した事実の単調 join(結合半束)**であり、
// 「最後に成功した pull のスナップショット」ではない(3-D)。保存形は
// 追記専用の観測ログ + fold(3-E — floor-log.ts)で、本モジュールは
// 格子の型と join 演算だけを持つ。ディスク上のマージとプロセス内マージが
// **同一の join 実装**を共有する(session-31 §3 M1-A5 — `>=` 後勝ちの
// 重複実装が同版異ハッシュの証拠を上書きした温床の構造的解消)。
//
// エポック観測は型付きの 2 座標として分けて join する(§6.3 規範):
//   (i) 値規則 (c) の pull 基準(pullEpoch)— 値床カバレッジと原子的に
//       確立された観測のみが前進させる(チェーン同期単独で前進させない)
//   (ii) 環境水準のエポック観測(observedEpoch)— マニフェスト規則 (c)
//       baseline・巻き戻し検出に使い、出所を問わず join する
//
// 同座標で比較不能な事実(同一版・異ハッシュ)には join が定義されない =
// **typed conflict** として両観測の証拠を保存する(規則 (b) がマージ意味論
// そのものになる)。conflict を持つ床の使用・更新は呼び出し側が拒否する。
//
// 各座標は bottom(0 / 空文字列 / レコードなし)を持つ半束であり、部分的な
// 観測(metadata-only pull の環境水準・push だけの変数床)を不可能状態なしに
// 表現する — bottom に対する検査規則は構造的に発火しない(誤検出ゼロ)。
//
// **平文値・鍵素材・変数名・環境名は書かない**(キーはすべて ID、内容は
// ハッシュ・連番・op 種別のみ — ディスクレス不変条件と両立)。

import { dirname, join } from "node:path";

import { Context, type Effect } from "effect";

import type { CliError } from "./errors.ts";

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

/**
 * 環境マニフェストの床(CRYPTO_SPEC §6.3 — manifest_version / その epoch /
 * signed_bytes ハッシュ)。規則 (a) の後退・(b) の同版相違・(c) のマニフェスト
 * 適用(前進 manifestVersion への旧エポック注入)の検出材料。
 */
export interface ManifestFloor {
  readonly manifestVersion: number;
  /** そのマニフェストが焼き込んだ epoch(規則 (c) のマニフェスト適用の材料)。 */
  readonly epoch: number;
  readonly manifestSigHashHex: string;
}

/**
 * 環境 1 つ分の床。各座標は独立に join される半束で、bottom(pullEpoch /
 * observedEpoch / metaVersion = 0)は「その座標の観測がまだない」ことを表す。
 */
export interface EnvironmentFloor {
  /**
   * 規則 (c) の基準: 値床カバレッジと原子的に確立された観測(検証済み pull・
   * 環境作成の受理確認〔空変数集合〕)のみが前進させる。**チェーン同期単独で
   * 前進させてはならない**(§6.3 の規範 — ローテーション直後の正当な旧エポック
   * 値の誤拒否と、基準欠落による検出喪失の両縁)。0 = 未確立。
   */
  readonly pullEpoch: number;
  /**
   * 環境水準のエポック観測(§6.3 の座標 (ii))。マニフェスト規則 (c) baseline に
   * 使い、出所を問わず join する(metadata-only pull・受理確認・値付き pull)。
   * 値を誤拒否する経路を持たないため pull 基準より広く前進する。0 = 観測なし。
   */
  readonly observedEpoch: number;
  /** 環境メタステートメントの床(巻き戻し検出のみ — 前進注入は非保証 §14.3-5)。0 = 観測なし。 */
  readonly metaVersion: number;
  readonly metaSigHashHex: string;
  /** 環境マニフェストの床(§6.3)。欠落 = マニフェスト観測なし。 */
  readonly manifest?: ManifestFloor;
  /** キーは variableId(名前を書かない)。 */
  readonly variables: Readonly<Record<string, VariableFloor>>;
}

/**
 * 同座標で比較不能な 2 観測(join 未定義)= equivocation の typed conflict。
 * 両観測の証拠(版とハッシュ)を保存する — 上書きによる証拠喪失は保存形
 * (追記専用ログ)により表現不能で、fold がこの形で顕在化させる(§6.3)。
 */
export interface FloorConflict {
  readonly kind:
    | "chain-head"
    | "value"
    | "variable-meta"
    | "environment-meta"
    | "manifest"
    | "undeletion";
  readonly environmentId: string | null;
  readonly variableId: string | null;
  /** 観測 1(seq / version / metaVersion / manifestVersion とその signed bytes ハッシュ)。 */
  readonly firstVersion: number;
  readonly firstHashHex: string;
  /** 観測 2。 */
  readonly secondVersion: number;
  readonly secondHashHex: string;
}

/** security-critical mutation の intent レコードの op 種別(§6.3 記録規律 (ii))。 */
export type FloorIntentOp = "create_environment" | "rotate_epoch" | "meta-op";

/** intent の解決(§12-10 (3) の効果確認の結果)。 */
export type FloorIntentOutcome =
  | "accepted"
  | "accepted-superseded"
  | "rejected"
  | "not-accepted"
  | "superseded";

/**
 * 送信前 intent レコード(3-F — journal-before-send)。非機密座標のみ:
 * op 種別・環境 ID・manifest_version + signed_bytes ハッシュ・宣言ヘッド、
 * および効果確認の照合材料(複合 = DEK コミットメント、メタ操作 = 変数 ID)。
 * intent は検証済み事実ではないため join の格子に入れない — fold は未解決
 * intent を「要照合」として表面化する。
 */
export interface FloorIntent {
  readonly id: string;
  readonly op: FloorIntentOp;
  readonly environmentId: string;
  /** 複合が確立するエポック(create = 1 / rotate = new_epoch)。メタ操作 = 発行時点の現エポック。 */
  readonly epoch: number;
  /** 複合の効果確認材料(チェーン上の自エントリの §5.2 コミットメント)。メタ操作 = null。 */
  readonly dekCommitmentHex: string | null;
  /** メタ操作(変数作成)の照合座標。複合 = null。 */
  readonly variableId: string | null;
  readonly manifestVersion: number;
  readonly manifestSigHashHex: string;
  readonly declaredHead: ChainHeadFloor;
}

/** intent レコードの入力(id はストアが採番する)。 */
export type FloorIntentInput = Omit<FloorIntent, "id">;

/** プロジェクト 1 つ分の床 = 観測ログの fold 結果(導出値)。 */
export interface ProjectFloor {
  /** null = ヘッド観測がまだない(intent だけのログ等)。 */
  readonly chainHead: ChainHeadFloor | null;
  /** キーは environmentId。 */
  readonly environments: Readonly<Record<string, EnvironmentFloor>>;
  /** 同座標 conflict の証拠(スナップショットに畳まれても消えない — §6.3)。 */
  readonly conflicts: readonly FloorConflict[];
  /** 未解決の intent(要照合 — 同一環境への次の mutation・成功報告の前に解決する)。 */
  readonly intents: readonly FloorIntent[];
}

/**
 * 矛盾ヘッド申告の証拠レコード(CRYPTO_SPEC §6.6 照合 (a) / §14.2-5 —
 * 2026-08-28 PR-M4)。申告全文(署名込み — §6.6 検証を通過した否認不能な材料)+
 * 自ビューのチェーンダイジェストを対で保存する。**床の join 格子には入れない**:
 * 申告は他メンバーの署名済み宣言であって「自分の検証済み観測」ではなく、格子へ
 * 流し込むと 1 メンバーの偽ヘッド申告(鍵漏洩)が全コマンドの恒久拒否を招く。
 * 保存は追記専用の証拠ファイル(floor-log.ts — <projectId>.attestation-evidence.jsonl)。
 * 平文値・鍵素材は含まない(ID・ハッシュ・署名のみ)。
 */
export interface AttestationEvidenceRecord {
  /** 配布された申告そのもの(§6.6 検証を通過済み — 署名が証拠の本体)。 */
  readonly attestation: {
    readonly suite: string;
    readonly attesterUserId: string;
    readonly attesterKeyFingerprintHex: string;
    readonly chainHeadHashHex: string;
    readonly chainHeadSeq: number;
    readonly signatureHex: string;
  };
  /** 照合時点の自ビュー(検証済みチェーン)のダイジェスト。 */
  readonly localView: {
    readonly headSeq: number;
    readonly headHashHex: string;
    /** 申告 seq 位置の自ビューのエントリハッシュ(空 = 申告 seq が自ヘッドより先)。 */
    readonly entryHashAtAttestedSeq: string;
  };
  /** 検出契機(mismatch = seq ≤ 自ヘッドの不一致、unresolved = 有界再同期後も未解決)。 */
  readonly kind: "head-mismatch" | "unresolved-after-resync";
  /** ローカル検出時刻(フォレンジック用 — 配布されない非機密ローカル状態)。 */
  readonly detectedAtMs: number;
}

/** 床ログの読み込み結果(fail-open — 呼び出し側が状態別の警告を出す)。 */
export interface FloorLoadResult {
  readonly floor: ProjectFloor | null;
  /** missing = 初回同期(床なし)、corrupt = 破損(初回として扱うが区別して警告)。 */
  readonly state: "loaded" | "missing" | "corrupt";
  /**
   * 解読できず読み飛ばした非空行の数(torn 行の自己回復の痕跡)。0 でなければ
   * 呼び出し側が警告する — 部分的な破損を無言の「検出材料の目減り」にしない
   * (旧保存形の corrupt 警告と同じ可視化の水準)。
   */
  readonly droppedRecords: number;
}

/** pull 成功時の原子コミット(規則 (c) 基準 + 変数床 + チェーンヘッドを 1 レコードで)。 */
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

/**
 * metadata-only pull の環境水準コミット(session-31 §3 M1-A3)。値床は
 * 捏造しない・pull 基準(規則 (c))は前進させない — 前進するのは環境メタ床・
 * マニフェスト床・環境水準エポック観測(座標 (ii))・チェーンヘッドのみ。
 */
export interface MetadataCommit {
  readonly chainHead: ChainHeadFloor;
  readonly environmentId: string;
  /** チェーン導出の現エポック(座標 (ii) — 出所を問わず join)。 */
  readonly observedEpoch: number;
  readonly metaVersion: number;
  readonly metaSigHashHex: string;
  readonly manifest: ManifestFloor;
}

/**
 * 受理確認済みの自己発行マニフェストの床昇格(session-31 §3 M1-A4)。
 * pullEpoch・変数床は動かさない。環境水準エポック観測はマニフェストの
 * epoch で join される(検証済み観測 — 座標 (ii))。
 */
export interface ManifestCommit {
  readonly chainHead: ChainHeadFloor;
  readonly environmentId: string;
  readonly manifest: ManifestFloor;
}

/**
 * Load / commit boundary for the local floor log (§6.3). すべての commit は
 * 「追記(fsync 相当の永続化まで — 3-E′)→ fold」であり、fold が同座標
 * conflict を検出したら typed エラーで失敗する(証拠はログに残っている)。
 */
export interface FloorStoreShape {
  readonly load: (projectId: string) => Effect.Effect<FloorLoadResult, CliError>;
  /** チェーン同期成功時のヘッド前進(規則 (c) 基準は動かさない)。 */
  readonly commitHead: (projectId: string, head: ChainHeadFloor) => Effect.Effect<void, CliError>;
  /** 検証済み pull の床コミット。fold 済み(= ログへ永続化済み)の環境床を返す。 */
  readonly commitPull: (
    projectId: string,
    commit: PullCommit,
  ) => Effect.Effect<EnvironmentFloor, CliError>;
  /** 受理された push の変数床前進(規則 (c) 基準 pullEpoch は動かさない)。 */
  readonly commitPush: (
    projectId: string,
    commit: PushCommit,
  ) => Effect.Effect<EnvironmentFloor, CliError>;
  /** metadata-only pull の環境水準コミット(M1-A3 — 値床は捏造しない)。 */
  readonly commitMetadata: (
    projectId: string,
    commit: MetadataCommit,
  ) => Effect.Effect<EnvironmentFloor, CliError>;
  /** 受理確認済みマニフェストの床昇格(M1-A4)。 */
  readonly commitManifest: (
    projectId: string,
    commit: ManifestCommit,
  ) => Effect.Effect<EnvironmentFloor, CliError>;
  /**
   * security-critical mutation の送信前 intent(3-F)。追記の永続化(fsync
   * 相当)まで待ってから送信してよい — 失敗したら送信しない(fail-closed)。
   * 採番した intent id を返す。
   */
  readonly appendIntent: (
    projectId: string,
    intent: FloorIntentInput,
  ) => Effect.Effect<string, CliError>;
  /** 効果確認の結果で intent を閉じる resolution レコードの追記。 */
  readonly resolveIntent: (
    projectId: string,
    intentId: string,
    outcome: FloorIntentOutcome,
  ) => Effect.Effect<void, CliError>;
  /**
   * 前回提出したヘッド申告のヘッド(CRYPTO_SPEC §6.3 ヘッドゴシップの
   * 「前回申告より前進していれば提出」の判定材料 — 2026-08-28 PR-M4)。
   * 床の join 格子には入れない別クラス: 自分の送信記録であって検証済み観測では
   * なく、喪失の帰結は「同一 seq の再提出(サーバー側で冪等 204)」のみで
   * 安全性を担わない。missing / 破損は null(ベストエフォート)。
   */
  readonly loadAttestedHead: (projectId: string) => Effect.Effect<ChainHeadFloor | null, CliError>;
  /** 提出成功後の前回申告の更新(上書き可の非機密ローカル状態)。 */
  readonly saveAttestedHead: (
    projectId: string,
    head: ChainHeadFloor,
  ) => Effect.Effect<void, CliError>;
  /**
   * 矛盾ヘッド申告の証拠の追記(§6.6 照合 (a) — 追記専用 JSONL。フォーマットは
   * AttestationEvidenceRecord)。保存先パスを返す(警告文の導線)。
   */
  readonly appendAttestationEvidence: (
    projectId: string,
    evidence: AttestationEvidenceRecord,
  ) => Effect.Effect<string, CliError>;
}

export class FloorStore extends Context.Service<FloorStore, FloorStoreShape>()("cli/FloorStore") {}

/** 床ディレクトリ(設定と同系の置き場: <config.json の親>/floor)。 */
export function floorDirOf(configPath: string): string {
  return join(dirname(configPath), "floor");
}

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

/** 全座標が bottom の環境床(部分観測の join 台座)。 */
export function emptyEnvironmentFloor(): EnvironmentFloor {
  return { pullEpoch: 0, observedEpoch: 0, metaVersion: 0, metaSigHashHex: "", variables: {} };
}

/** join 中に検出した同座標 conflict の受け皿。 */
export type ConflictSink = (conflict: FloorConflict) => void;

interface VersionedEvidence {
  readonly version: number;
  readonly hashHex: string;
}

/**
 * 同一版・異ハッシュ = join 未定義。証拠を sink へ流し、代表値は**ハッシュの
 * 辞書順で大きい側**にする(可換・冪等 — fold の順序に依存しない決定的な代表。
 * conflict の存在自体が使用拒否の条件なので、代表の選び方は検出に影響しない)。
 */
function joinVersioned<T extends VersionedEvidence>(
  a: T,
  b: T,
  conflict: (first: VersionedEvidence, second: VersionedEvidence) => FloorConflict,
  sink: ConflictSink,
): T {
  if (a.version !== b.version) {
    return a.version > b.version ? a : b;
  }
  if (a.hashHex === b.hashHex) {
    return a;
  }
  sink(conflict(a, b));
  return a.hashHex > b.hashHex ? a : b;
}

/** チェーンヘッドの join(seq 前進のみ。同一 seq の異ハッシュ = 分岐の証拠)。 */
export function joinChainHead(
  existing: ChainHeadFloor | null,
  incoming: ChainHeadFloor,
  sink: ConflictSink,
): ChainHeadFloor {
  if (existing === null) {
    return incoming;
  }
  const joined = joinVersioned(
    { version: existing.seq, hashHex: existing.hashHex },
    { version: incoming.seq, hashHex: incoming.hashHex },
    (first, second) => ({
      kind: "chain-head",
      environmentId: null,
      variableId: null,
      firstVersion: first.version,
      firstHashHex: first.hashHex,
      secondVersion: second.version,
      secondHashHex: second.hashHex,
    }),
    sink,
  );
  return { seq: joined.version, hashHex: joined.hashHex };
}

function metaConflict(
  kind: "variable-meta" | "environment-meta",
  environmentId: string,
  variableId: string | null,
): (first: VersionedEvidence, second: VersionedEvidence) => FloorConflict {
  return (first, second) => ({
    kind,
    environmentId,
    variableId,
    firstVersion: first.version,
    firstHashHex: first.hashHex,
    secondVersion: second.version,
    secondHashHex: second.hashHex,
  });
}

interface MetaSide {
  readonly metaVersion: number;
  readonly metaSigHashHex: string;
}

function joinMetaSide(
  environmentId: string,
  variableId: string | null,
  a: MetaSide,
  b: MetaSide,
  sink: ConflictSink,
): MetaSide {
  const joined = joinVersioned(
    { version: a.metaVersion, hashHex: a.metaSigHashHex },
    { version: b.metaVersion, hashHex: b.metaSigHashHex },
    metaConflict(
      variableId === null ? "environment-meta" : "variable-meta",
      environmentId,
      variableId,
    ),
    sink,
  );
  return { metaVersion: joined.version, metaSigHashHex: joined.hashHex };
}

/** deleted(終端)と active の join: 削除後の active 観測 = undeletion の証拠。 */
function joinDeletedWithActive(
  environmentId: string,
  variableId: string,
  deleted: Extract<VariableFloor, { status: "deleted" }>,
  active: Extract<VariableFloor, { status: "active" }>,
  sink: ConflictSink,
): VariableFloor {
  if (active.metaVersion > deleted.metaVersion) {
    // deleted は終端状態(§4.2)— それより進んだ metaVersion の active 観測は
    // 正当な経路が存在しない(無断復活の証拠)。代表は deleted のまま
    sink({
      kind: "undeletion",
      environmentId,
      variableId,
      firstVersion: deleted.metaVersion,
      firstHashHex: deleted.metaSigHashHex,
      secondVersion: active.metaVersion,
      secondHashHex: active.metaSigHashHex,
    });
  } else if (active.metaVersion === deleted.metaVersion) {
    // 同一 metaVersion で status が違えば signed bytes も必ず違う = 規則 (b)
    sink({
      kind: "variable-meta",
      environmentId,
      variableId,
      firstVersion: deleted.metaVersion,
      firstHashHex: deleted.metaSigHashHex,
      secondVersion: active.metaVersion,
      secondHashHex: active.metaSigHashHex,
    });
  }
  return deleted;
}

/**
 * 変数床の join。deleted は終端状態(active で上書きしない)、active 同士は
 * 値側(version)とメタ側(metaVersion)を独立に join する。どちらの入力も
 * §6.3 検証を通過した観測なので、同座標の相違はすべて equivocation の証拠。
 */
function joinVariableFloor(
  environmentId: string,
  variableId: string,
  existing: VariableFloor | undefined,
  incoming: VariableFloor,
  sink: ConflictSink,
): VariableFloor {
  if (existing === undefined) {
    return incoming;
  }
  // 片側だけ deleted: metaVersion の大小に依らず deleted(終端)が代表。
  // active 側が deleted より進んでいれば undeletion、同一版なら規則 (b) の
  // 証拠として joinDeletedWithActive が sink へ流す
  if (existing.status === "deleted") {
    if (incoming.status === "deleted") {
      const meta = joinMetaSide(environmentId, variableId, existing, incoming, sink);
      return { status: "deleted", ...meta };
    }
    return joinDeletedWithActive(environmentId, variableId, existing, incoming, sink);
  }
  if (incoming.status === "deleted") {
    return joinDeletedWithActive(environmentId, variableId, incoming, existing, sink);
  }
  const value = joinVersioned(
    { version: existing.version, hashHex: existing.valueSigHashHex, epoch: existing.epoch },
    { version: incoming.version, hashHex: incoming.valueSigHashHex, epoch: incoming.epoch },
    (first, second) => ({
      kind: "value",
      environmentId,
      variableId,
      firstVersion: first.version,
      firstHashHex: first.hashHex,
      secondVersion: second.version,
      secondHashHex: second.hashHex,
    }),
    sink,
  );
  const meta = joinMetaSide(environmentId, variableId, existing, incoming, sink);
  return {
    status: "active",
    version: value.version,
    epoch: value.epoch,
    valueSigHashHex: value.hashHex,
    ...meta,
  };
}

/** マニフェスト床の join(manifestVersion 前進のみ。同一版の異ハッシュ = 分岐の証拠)。 */
function joinManifestFloor(
  environmentId: string,
  existing: ManifestFloor | undefined,
  incoming: ManifestFloor | undefined,
  sink: ConflictSink,
): ManifestFloor | undefined {
  if (existing === undefined || incoming === undefined) {
    return existing ?? incoming;
  }
  const joined = joinVersioned(
    {
      version: existing.manifestVersion,
      hashHex: existing.manifestSigHashHex,
      epoch: existing.epoch,
    },
    {
      version: incoming.manifestVersion,
      hashHex: incoming.manifestSigHashHex,
      epoch: incoming.epoch,
    },
    (first, second) => ({
      kind: "manifest",
      environmentId,
      variableId: null,
      firstVersion: first.version,
      firstHashHex: first.hashHex,
      secondVersion: second.version,
      secondHashHex: second.hashHex,
    }),
    sink,
  );
  return {
    manifestVersion: joined.version,
    epoch: joined.epoch,
    manifestSigHashHex: joined.hashHex,
  };
}

/**
 * 環境床の join(各座標を独立に): pullEpoch / observedEpoch は max、
 * メタ / マニフェストは版前進 + 同版相違の証拠化、変数は単調 union。
 */
export function joinEnvironmentFloor(
  environmentId: string,
  existing: EnvironmentFloor | undefined,
  incoming: EnvironmentFloor,
  sink: ConflictSink,
): EnvironmentFloor {
  if (existing === undefined) {
    return incoming;
  }
  const meta =
    existing.metaVersion === 0
      ? { metaVersion: incoming.metaVersion, metaSigHashHex: incoming.metaSigHashHex }
      : incoming.metaVersion === 0
        ? { metaVersion: existing.metaVersion, metaSigHashHex: existing.metaSigHashHex }
        : joinMetaSide(environmentId, null, existing, incoming, sink);
  const manifest = joinManifestFloor(environmentId, existing.manifest, incoming.manifest, sink);
  // union: 正当な床の変数キーは消えない(削除も tombstone レコードとして残る)
  // ため、片側にしかない変数は保持する
  const variables: Record<string, VariableFloor> = { ...existing.variables };
  for (const [variableId, variable] of Object.entries(incoming.variables)) {
    variables[variableId] = joinVariableFloor(
      environmentId,
      variableId,
      floorRecordGet(existing.variables, variableId),
      variable,
      sink,
    );
  }
  return {
    pullEpoch: Math.max(existing.pullEpoch, incoming.pullEpoch),
    observedEpoch: Math.max(existing.observedEpoch, incoming.observedEpoch),
    ...meta,
    ...(manifest === undefined ? {} : { manifest }),
    variables,
  };
}
