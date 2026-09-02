// 監査ログの追記ストア(AUDIT_SPEC §5.1)と読み取り面(§7 — C1)。
//
// - append-only: このサービスは追記と読み取りのみを公開する(更新・削除の口を
//   作らない — AUDIT_SPEC §1-4)
// - seq は単調・無欠番。次 seq は DO インスタンスメモリに保持し(初期化時に
//   MAX(seq) を 1 回だけ読む。DO 再起動で再読込)、同期 SQL なので await 境界を
//   またがない
// - アイデンティティ規則(§1-2): actor / target は内部 user_id と鍵 FP のみ。
//   プロバイダ ID・メールをこの層に持ち込まないこと
// - チェーンミラーの写像(§3.4)は @maruhi/core の chainMirrorEvent(CLI の
//   ミラー検証 — `maruhi audit verify` — と同一実装を共有する)

import type { AuditEventRecord } from "@maruhi/core";
import { CHAIN_MIRROR_EVENT_PREFIX } from "@maruhi/core";
import type { AuditHeadRow } from "@maruhi/crypto";
import { computeAuditHeadHash, computeAuditRowDigest, SUITE_ID } from "@maruhi/crypto";
import { Context, Effect, Layer } from "effect";

import { randomHex } from "./ids.ts";

/**
 * 監査イベント 1 行の入力(列は AUDIT_SPEC §5.1、未指定は NULL)。
 * 共有のレコード型(@maruhi/core — チェーンミラーの写像と同居)の別名。
 */
export type AuditEventInput = AuditEventRecord;

// ---------------------------------------------------------------------------
// 要ローテーション検出の読み取り面(AUDIT_SPEC §4.1 / §4.2 の Q1〜Q6)。
// 追記と読み取りのみを公開する(§1-4)— 更新・削除の口は引き続き作らない。
// すべて同期: 検出はチェーン受理の書き込みフェーズ(単一タスク)内で走り、
// ミラー追記と同一トランザクションで rotation.recommended を書く(§4.1)。
// ---------------------------------------------------------------------------

/** Q1: 対象 user_id の在籍区間イベント(chain.genesis / member_added / removed)。 */
export interface MembershipEventRow {
  readonly seq: number;
  readonly event: string;
}

/** Q6: サーバー鍵 FP の grant 区間イベント(chain.server_granted / revoked)。 */
export interface GrantEventRow {
  readonly seq: number;
  readonly event: string;
  /** chain.server_granted の payload から。revoked 行は空配列。 */
  readonly scopeEnvironmentIds: readonly string[];
}

/** Q2: 変数の存在区間イベント(var.created / var.deleted)。 */
export interface VariableLifecycleRow {
  readonly seq: number;
  readonly event: string;
  readonly environmentId: string;
  readonly variableId: string;
}

/** Q3: 対象 user_id の var.read。 */
export interface VariableReadRow {
  readonly seq: number;
  readonly environmentId: string;
  readonly variableId: string;
}

/** Q6: サーバー鍵 FP の開示行使(server.lease_issued / value_decrypted〔予約〕)。 */
export interface ServerAccessRow {
  readonly seq: number;
  readonly event: string;
  readonly environmentId: string;
  /** server.lease_issued は環境単位配布のため null(§3.5)。 */
  readonly variableId: string | null;
}

/** Q5: フラグ導出の入力行(rotation.recommended / dismissed / var.version_pushed)。 */
export interface RotationFlagSourceRow {
  readonly seq: number;
  readonly serverTs: number;
  readonly event: string;
  readonly environmentId: string;
  readonly variableId: string;
  readonly targetUserId: string | null;
  readonly targetKeyFingerprintHex: string | null;
  readonly payload: Readonly<Record<string, unknown>> | null;
}

/** 検出・フラグ導出が使う同期読み取り面(索引は §4.2 / do-schema.ts)。 */
export interface AuditRotationRead {
  readonly membershipEventsFor: (targetUserId: string) => readonly MembershipEventRow[];
  readonly serverGrantEventsFor: (fpHex: string) => readonly GrantEventRow[];
  readonly variableLifecycles: () => readonly VariableLifecycleRow[];
  readonly variableReadsBy: (actorUserId: string) => readonly VariableReadRow[];
  readonly serverAccessEventsBy: (actorFpHex: string) => readonly ServerAccessRow[];
  readonly rotationFlagEvents: () => readonly RotationFlagSourceRow[];
}

// ---------------------------------------------------------------------------
// 汎用読み取り面(AUDIT_SPEC §7 — C1)。seq カーソルページング + フィルタ。
// 可視性クラス(§6)は SQL の WHERE で強制する: クラス 2 の行は admin 未満の
// 結果・件数・ページングのどこにも現れない(「存在しないかのように振る舞う」)。
// ---------------------------------------------------------------------------

/**
 * クラス 1(チェーン role reader 以上 = 全メンバー)の**非 chain** イベント名
 * (§6)。`chain.` 名前空間と `chain_seq IS NOT NULL` の provenance claim は
 * 名前の列挙ではなく SQL の述語で覆う({@link visibilityCondition}) —
 * §6 は名前空間**全体**と chain provenance の検証材料をクラス 1 と定めており、
 * 写像済みの名前だけを許すと 2 方向で壊れる:
 *
 * 1. 将来の op 追加で列挙が漏れると、そのミラー行が admin 未満に不可視になり、
 *    全メンバー実行可能なはずの `maruhi audit verify` が健全なサーバーを
 *    「欠落 = 削除の隠蔽」と誤断定する(pullfrog 指摘)
 * 2. 写像に**無い** `chain.*` を名乗る偽造行がサーバー側で落とされ、admin 未満の
 *    verify には 1 行も届かない — R1 で閉じたはずの偽造方向の被覆漏れが、
 *    非 admin では残ったままになる(pullfrog / Cursor Security Reviewer 指摘)
 * 3. `chain.*` の外で `chain_seq` を名乗る偽造行がクラス 2 として落ちると、
 *    verify は名前空間の 1 歩外にある provenance claim を検査できない
 *    (deepsec S1)。正直な書き手でこの形は存在しないため、chain_seq の存在を
 *    クラス 1 に昇格するのは正常なクラス 2 行を開示せず、tamper evidence だけを
 *    全メンバーへ届ける
 *
 * **chain.* 以外は明示 allowlist の default-deny**: ここに無いイベント
 * (var.read / dek.registered / dek.deleted、および将来追加される非 chain
 * イベント)はクラス 2 扱いで admin 未満には見えない — イベントを増やした
 * ときに安全側へ倒す。
 */
const CLASS1_EVENTS: readonly string[] = [
  "env.created",
  "env.renamed",
  "env.deleted",
  "var.created",
  "var.renamed",
  "var.schema_reissued",
  "var.deleted",
  "var.version_pushed",
  "server.dek_unwrapped",
  "server.lease_issued",
  "server.lease_denied",
  "server.value_decrypted",
  "rotation.recommended",
  "rotation.dismissed",
  // 設定値自体が pull 応答で全メンバーへ advisory 配布されるためクラス 1
  // (AUDIT_SPEC §3.3 — AUTH_SPEC §12-11)
  "project.schema_policy_changed",
];

/**
 * クラス 1 か(§6): `chain.` 名前空間の全体 + {@link CLASS1_EVENTS}。
 * SQL 側の可視性述語({@link visibilityCondition})と同じ判定であり、
 * 片方だけ変えると応答とテストの主張が食い違う。
 */
export function isClass1Event(event: string): boolean {
  return event.startsWith(CHAIN_MIRROR_EVENT_PREFIX) || CLASS1_EVENTS.includes(event);
}

/**
 * 可視性の指定(§6)。admin = 全行(呼び出し側で「チェーン role admin 以上 ×
 * トークンスコープ admin」を確認済み)、class1-or-self = クラス 1 の行 +
 * 本人が actor の行(クラスに依らず本人閲覧可)。
 */
type AuditVisibility =
  | { readonly kind: "admin" }
  | { readonly kind: "class1-or-self"; readonly selfUserId: string };

/** 汎用読み取りのクエリ(§7 のフィルタ語彙のみ。null = フィルタなし)。 */
interface AuditEventsQuery {
  /**
   * ページングカーソル = 前ページ末尾行の row_id(§7 — 不透明)。解決は
   * 閲覧者の可視性述語つきで行い、不可視・不明な id は空ページとして振る舞う
   * (存在オラクルにしない)。
   */
  readonly beforeRowId: string | null;
  readonly limit: number;
  readonly event: string | null;
  /** event 名前空間の前置一致(§7 — deepsec R1)。LIKE ではなく substr 比較。 */
  readonly eventPrefix: string | null;
  /** chain_seq が NULL でない行だけを返す(§7 — deepsec S1)。 */
  readonly chainSeqPresent: boolean;
  readonly actorUserId: string | null;
  readonly targetUserId: string | null;
  readonly variableId: string | null;
  readonly environmentId: string | null;
  readonly visibility: AuditVisibility;
}

/**
 * 保存行の読み取り形(§5.1 の全列。NULL は null)。列集合は監査ヘッド計算の
 * 入力形(AuditHeadRow — §5.1 の固定 17 列)と同一で、row_id の非 NULL 制約と
 * payload の防御的 parse(TEXT そのままではなくオブジェクト)だけが異なる。
 */
export interface StoredAuditEventRow extends Omit<AuditHeadRow, "rowId" | "payloadText"> {
  /** ワイヤ行識別子(§5.1 row_id — 16 バイト乱数 hex)。 */
  readonly rowId: string;
  readonly payload: Readonly<Record<string, unknown>> | null;
}

/**
 * ensureHeadCurrent の結果: "current" = 列が MAX(seq) に到達(ヘッドを読んで
 * よい)、"more-remains" = 有界伸長の上限に達し未到達(読まずに retryable 拒否)。
 */
export type AuditHeadExtensionOutcome = "current" | "more-remains";

interface AuditStoreShape {
  /**
   * 同期追記。データ書き込みと同じ同期ブロック(= 同一イベントループタスク)で
   * 呼ぶことで、クラッシュ時に「データだけ書けてイベントが欠ける」不整合を
   * 構造的に防ぐ(DO SQLite の書き込みはタスク単位で原子コミットされる)。
   */
  readonly appendSync: (event: AuditEventInput) => void;
  /**
   * 複数イベントの一括同期追記(multi-row INSERT)。返却変数ごと・カスケード
   * 変数ごと・ラップごとのループ追記(1 リクエスト最大 1 万行)を行ごとの
   * INSERT 文にしないための経路。原子性は appendSync と同じ「同一同期ブロック
   * 内」で保たれる(文はチャンク分割されるが同一タスクでコミットされる)。
   */
  readonly appendManySync: (events: readonly AuditEventInput[]) => void;
  /**
   * 採番キャッシュの破棄。タスク失敗時はストレージがタスク単位でロールバック
   * されるのにメモリの採番だけが前進したまま残り、次の追記が欠番を作る
   * (AUDIT_SPEC §5.1 違反)ため、DO は失敗経路(chain-do.ts の defect フック)で
   * 必ずこれを呼び、次の追記を MAX(seq) の再読込から続ける。
   */
  readonly resetSeqCacheSync: () => void;
  /** 要ローテーション検出・フラグ導出の読み取り(§4.1。追記の口は増やさない)。 */
  readonly readRotationSync: AuditRotationRead;
  /**
   * 汎用読み取り(§7 — C1): seq 降順(新しい順)+ フィルタ + 可視性クラス。
   * 可視性は WHERE 句で強制するため、admin 未満のページはクラス 2 の行を
   * スキップした穴のない limit 件になる(件数・カーソルに漏れない — §7)。
   */
  readonly queryEventsSync: (query: AuditEventsQuery) => readonly StoredAuditEventRow[];
  /**
   * 監査ヘッド累積ハッシュ列(AUDIT_SPEC §5.1 — audit_head_hashes)を
   * MAX(seq) へ向けて伸ばす。ハッシュ列は append-only 行からの決定論的な導出値
   * で、materialize は読み取り経路(GET /audit-head・checkpoint 受理検証)の
   * 直前に行う — SHA-256 が非同期(WebCrypto)のため追記の同期ブロックには
   * 置けず、遅延拡張なら var.read の大量追記ホットパスにハッシュ計算が乗らない。
   * 初回呼び出しが既存全行からの再計算 = §5.1 の導入マイグレーションを兼ねる。
   * どの読み手も拡張後の完全な列しか観測しないため、行と列の食い違いは
   * 観測不能(設計の裁定は docs/notes/session-35.md)。DO permit 下で呼ぶこと。
   *
   * **有界契約(セッション 38 — PR #99 レビュー申し送りの解消)**: 1 呼び出しの
   * 伸長はチャンク数で有界({@link MAX_HEAD_EXTENSION_CHUNKS_PER_CALL})。
   * `"more-remains"` が返った呼び出しでは列は MAX(seq) に達していないので、
   * 呼び出し側は**ヘッドを読まず**(currentHeadHexSync / headPositionSync を
   * 呼ばず)retryable な拒否(AuditHeadNotReady — AUTH_SPEC §16-2)で応答する
   * こと。古い列で audit-head-unknown / stale を判定してはならない(fail-closed)。
   * 進捗はチャンク単位で保存済みなので、再試行は必ず前進して収束する。
   */
  readonly ensureHeadCurrent: Effect.Effect<AuditHeadExtensionOutcome>;
  /**
   * 累積ハッシュ列が MAX(seq) に未到達か(= 次の ensureHeadCurrent が実体化の
   * 書き込みを伴うか)。DO ストレージ総量ガード(AUTH_SPEC §12-8 — H2)の入力:
   * 実体化は監査行数に比例する書き込み(1 行あたりハッシュ 1 行 + 索引)で、
   * 拒否閾値以上の DO では未実体化の backlog を書かない(storage-guard.ts)。
   * 読み取りのみ(2 つの索引付き MAX / 存在検査)。
   */
  readonly headColumnBehindSync: () => boolean;
  /**
   * 現在の累積ハッシュ(監査行ゼロは空文字列)。ensureHeadCurrent が
   * "current" を返した後にのみ呼ぶ(有界契約 — 上記)。
   */
  readonly currentHeadHexSync: () => string;
  /**
   * 累積ハッシュ列内の出現位置(= 監査 seq。所属検査 — CRYPTO_SPEC §6.4)。
   * 列に存在しなければ null。ensureHeadCurrent が "current" を返した後にのみ
   * 呼ぶ(有界契約 — 上記)。
   */
  readonly headPositionSync: (headHashHex: string) => number | null;
  /**
   * 直前 checkpoint のミラー行(chain.checkpointed — 公証の有無を問わない)の
   * 監査 seq(位置下限検査の基準 — CRYPTO_SPEC §6.4)。存在しなければ null
   * (プロジェクト初の checkpoint — 位置下限を課さない)。
   */
  readonly latestCheckpointMirrorSeqSync: () => number | null;
}

export class AuditStore extends Context.Service<AuditStore, AuditStoreShape>()("AuditStore") {}

const INSERT_COLUMNS = `INSERT INTO audit_events (
    seq, row_id, server_ts, client_ts, event, actor_type, actor_user_id,
    actor_key_fingerprint, actor_api_token_id, target_user_id,
    target_key_fingerprint, environment_id, variable_id, epoch, version,
    chain_seq, payload
  ) VALUES `;

/** 1 行分のプレースホルダ(seq + row_id + eventBindings の 15 値 = 17 列)。 */
const VALUES_ROW = "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

/**
 * multi-row INSERT の 1 文あたり行数。17 列 × 5 行 = 85 バインドで、SQLite の
 * バインド変数上限(保守的に 100 と見る)を下回るように取る。
 */
const APPEND_CHUNK_ROWS = 5;

function orNull(value: string | number | undefined): string | number | null {
  return value === undefined ? null : value;
}

/**
 * chain_seq は chain.* ミラー専有(AUDIT_SPEC §5.1)。
 *
 * 読み取り側は chain_seq を持つ行を tamper evidence としてクラス 1 に昇格するため、
 * 正直な書き手の誤用をここで止めないと将来のクラス 2 行を全メンバーへ開示しうる。
 * 列だけ NULL にすると producer bug を隠して監査の突合材料を失うため defect にする。
 * 呼び出しは採番・SQL 実行より前に置き、違反で欠番や部分追記を作らない。
 */
function assertChainSeqInvariant(event: AuditEventInput): void {
  if (event.chainSeq !== undefined && !event.event.startsWith(CHAIN_MIRROR_EVENT_PREFIX)) {
    throw new Error("audit invariant violation: chain_seq is reserved for chain.* events");
  }
}

/** 挿入バインディング(INSERT_EVENT の SELECT 列と同順)。未指定は NULL。 */
function eventBindings(event: AuditEventInput): (string | number | null)[] {
  return [
    event.serverTs,
    orNull(event.clientTs),
    event.event,
    event.actorType,
    orNull(event.actorUserId),
    orNull(event.actorKeyFingerprintHex),
    orNull(event.actorApiTokenId),
    orNull(event.targetUserId),
    orNull(event.targetKeyFingerprintHex),
    orNull(event.environmentId),
    orNull(event.variableId),
    orNull(event.epoch),
    orNull(event.version),
    orNull(event.chainSeq),
    event.payload === undefined ? null : JSON.stringify(event.payload),
  ];
}

/**
 * AuditStore の実装(テストから直接構築できるよう Layer と分けて公開)。
 *
 * 次 seq(単調・無欠番 — AUDIT_SPEC §5.1)は DO インスタンスメモリに保持し、
 * 行ごとの `SELECT COALESCE(MAX(seq),0)+1` 集約を初期化時の 1 回に置き換える。
 * null はキャッシュ無効(DO 再起動直後・失敗後)で、次の追記時に MAX(seq) を
 * 再読込する。挿入の失敗時は採番キャッシュを即座に破棄する — チャンク成功 ≠
 * タスク成功であり、タスク失敗時のストレージロールバック(タスク単位)に対して
 * メモリの採番だけが前進したまま残ると次の追記が欠番を作るため(同じ理由で
 * DO の失敗経路も resetSeqCacheSync を呼ぶ — chain-do.ts)。全追記はこの実装
 * 経由 + DO の permit 下で直列化されている前提。
 */
/** makeAuditStore のオプション(テストが有界伸長の上限を縮めて固定するため)。 */
export interface AuditStoreOptions {
  /** ensureHeadCurrent の 1 呼び出しあたりチャンク上限(既定は本番値)。 */
  readonly maxHeadExtensionChunks?: number;
}

export const makeAuditStore = (sql: SqlStorage, options?: AuditStoreOptions): AuditStoreShape => {
  let nextSeqCache: number | null = null;
  const nextSeq = (): number => {
    if (nextSeqCache === null) {
      const row = sql
        .exec("SELECT COALESCE(MAX(seq), 0) + 1 AS next_seq FROM audit_events")
        .toArray()[0];
      nextSeqCache = Number(row?.["next_seq"] ?? 1);
    }
    return nextSeqCache;
  };
  return {
    appendSync: (event) => {
      assertChainSeqInvariant(event);
      const seq = nextSeq();
      try {
        // row_id = ワイヤ行識別子(16 バイト乱数 — AUDIT_SPEC §5.1 / §7)
        sql.exec(INSERT_COLUMNS + VALUES_ROW, seq, randomHex(16), ...eventBindings(event));
      } catch (error) {
        nextSeqCache = null;
        throw error;
      }
      nextSeqCache = seq + 1;
    },
    appendManySync: (events) => {
      // 全件を SQL より前に検査し、後半の違反で前半チャンクだけ書く形を作らない
      for (const event of events) {
        assertChainSeqInvariant(event);
      }
      try {
        for (let offset = 0; offset < events.length; offset += APPEND_CHUNK_ROWS) {
          const chunk = events.slice(offset, offset + APPEND_CHUNK_ROWS);
          const seq = nextSeq();
          sql.exec(
            INSERT_COLUMNS + chunk.map(() => VALUES_ROW).join(", "),
            ...chunk.flatMap((event, index) => [
              seq + index,
              randomHex(16),
              ...eventBindings(event),
            ]),
          );
          nextSeqCache = seq + chunk.length;
        }
      } catch (error) {
        nextSeqCache = null;
        throw error;
      }
    },
    resetSeqCacheSync: () => {
      nextSeqCache = null;
    },
    readRotationSync: makeRotationRead(sql),
    queryEventsSync: (query) => queryEvents(sql, query),
    ensureHeadCurrent: extendHeadHashes(
      sql,
      options?.maxHeadExtensionChunks ?? MAX_HEAD_EXTENSION_CHUNKS_PER_CALL,
    ),
    headColumnBehindSync: () => {
      const row = sql
        .exec(
          `SELECT 1 FROM audit_events
           WHERE seq > (SELECT COALESCE(MAX(seq), 0) FROM audit_head_hashes)
           LIMIT 1`,
        )
        .toArray()[0];
      return row !== undefined;
    },
    currentHeadHexSync: () => {
      const row = sql
        .exec("SELECT head_hash_hex FROM audit_head_hashes ORDER BY seq DESC LIMIT 1")
        .toArray()[0];
      return row === undefined ? "" : String(row["head_hash_hex"]);
    },
    headPositionSync: (headHashHex) => {
      const row = sql
        .exec("SELECT seq FROM audit_head_hashes WHERE head_hash_hex = ? LIMIT 1", headHashHex)
        .toArray()[0];
      return row === undefined ? null : Number(row["seq"]);
    },
    latestCheckpointMirrorSeqSync: () => {
      const row = sql
        .exec("SELECT MAX(seq) AS seq FROM audit_events WHERE event = 'chain.checkpointed'")
        .toArray()[0];
      return row === undefined || row["seq"] === null ? null : Number(row["seq"]);
    },
  };
};

// ---------------------------------------------------------------------------
// 監査ヘッド累積ハッシュの遅延拡張(AUDIT_SPEC §5.1 — 実装形の裁定は
// docs/notes/session-35.md)。正規形は @maruhi/crypto(audit-head.json が固定)。
// ---------------------------------------------------------------------------

/** 1 チャンクで読む・書く行数(2 列 × 50 行 = 100 バインドで SQLite 上限内)。 */
const HEAD_CHUNK_ROWS = 50;

/**
 * ensureHeadCurrent の 1 呼び出しあたりチャンク上限(セッション 38 の裁定 AF)。
 * 200 チャンク × 50 行 = 10,000 行 — §12-8 の 1 リクエスト最大監査行数
 * (appendManySync の上限)と同値に取る: 定常状態(読むたびに伸ばす)の
 * バックログは高々「直前の読み以降の追記」であり、最大の単発バーストでも
 * 1 呼び出しで解消する。上限に達しうるのは巨大な既存ログの初回実体化だけで、
 * その場合は "more-remains" → AuditHeadNotReady(503)→ クライアントの有界
 * 再試行(進捗はチャンク単位で保存済み — 各呼び出しが最大 1 万行前進する)。
 */
export const MAX_HEAD_EXTENSION_CHUNKS_PER_CALL = 200;

/** 拡張の読み取り列(row_digest の固定 17 列 — AUDIT_SPEC §5.1 の列順)。 */
const HEAD_ROW_COLUMNS = `seq, row_id, server_ts, client_ts, event, actor_type, actor_user_id,
  actor_key_fingerprint, actor_api_token_id, target_user_id, target_key_fingerprint,
  environment_id, variable_id, epoch, version, chain_seq, payload`;

function toAuditHeadRow(row: Record<string, unknown>): AuditHeadRow {
  return {
    seq: Number(row["seq"]),
    rowId: textOrNull(row["row_id"]),
    serverTs: Number(row["server_ts"]),
    clientTs: numberOrNull(row["client_ts"]),
    event: String(row["event"]),
    actorType: String(row["actor_type"]),
    actorUserId: textOrNull(row["actor_user_id"]),
    actorKeyFingerprintHex: textOrNull(row["actor_key_fingerprint"]),
    actorApiTokenId: textOrNull(row["actor_api_token_id"]),
    targetUserId: textOrNull(row["target_user_id"]),
    targetKeyFingerprintHex: textOrNull(row["target_key_fingerprint"]),
    environmentId: textOrNull(row["environment_id"]),
    variableId: textOrNull(row["variable_id"]),
    epoch: numberOrNull(row["epoch"]),
    version: numberOrNull(row["version"]),
    chainSeq: numberOrNull(row["chain_seq"]),
    // payload は保存 TEXT のバイト列そのまま(JSON 正規化をしない — §5.1)
    payloadText: textOrNull(row["payload"]),
  };
}

/**
 * audit_head_hashes を audit_events の MAX(seq) へ向けて伸ばす(1 呼び出し
 * maxChunks チャンクまで — 有界契約はサービス宣言の doc を参照)。
 *
 * 永続化の粒度はタスク単位(chain-do.ts 冒頭のとおり DO SQLite の書き込みは
 * タスクごとに原子コミットされ、失敗で巻き戻るのは**現在の**タスクの書き込み
 * のみ)。このループはチャンクごとに await(SHA-256)を挟んでタスクを跨いで
 * 進むため、完了済みチャンクの INSERT は先行タスクで確定済みで、途中失敗が
 * 失いうるのは高々進行中チャンクの単一 INSERT(そのチャンクの全ハッシュ計算が
 * 成功した後の 1 回の sql.exec)だけ。どの失敗・上限到達時点でも列は seq 1
 * からの連続接頭辞のまま残り、次回呼び出しが保存済みの末尾から再開して収束する
 * — 巨大な既存ログの初回パスは "more-remains"(→ AuditHeadNotReady)の有界
 * 再試行に分割され、各呼び出しが必ず前進する。seq の欠番は §5.1 の不変条件違反
 * (append-only ストレージの破損)なので defect にする。
 */
const extendHeadHashes = (
  sql: SqlStorage,
  maxChunks: number,
): Effect.Effect<AuditHeadExtensionOutcome> =>
  Effect.promise(async () => {
    const state = { hashedUpTo: 0, head: "" };
    const tail = sql
      .exec(`SELECT seq, head_hash_hex FROM audit_head_hashes ORDER BY seq DESC LIMIT 1`)
      .toArray()[0];
    if (tail !== undefined) {
      state.hashedUpTo = Number(tail["seq"]);
      state.head = String(tail["head_hash_hex"]);
    }
    for (let chunk = 0; chunk < maxChunks; chunk += 1) {
      if (await hashNextChunk(sql, state)) {
        return "current";
      }
    }
    // チャンク上限に到達。残行の有無を軽い存在検査で確定する(ちょうど上限で
    // 完了した呼び出しに余計な "more-remains" を返さない)
    const remains = sql
      .exec(`SELECT 1 FROM audit_events WHERE seq > ? LIMIT 1`, state.hashedUpTo)
      .toArray()[0];
    return remains === undefined ? "current" : "more-remains";
  });

/**
 * 次の 1 チャンク(最大 HEAD_CHUNK_ROWS 行)をハッシュして単一 INSERT で確定する。
 * 返り値 = このチャンクで列が MAX(seq) に到達したか(空チャンク・端数チャンク)。
 */
async function hashNextChunk(
  sql: SqlStorage,
  state: { hashedUpTo: number; head: string },
): Promise<boolean> {
  const rows = sql
    .exec(
      `SELECT ${HEAD_ROW_COLUMNS} FROM audit_events WHERE seq > ? ORDER BY seq LIMIT ?`,
      state.hashedUpTo,
      HEAD_CHUNK_ROWS,
    )
    .toArray()
    .map(toAuditHeadRow);
  if (rows.length === 0) {
    return true;
  }
  const inserts: (string | number)[] = [];
  for (const row of rows) {
    if (row.seq !== state.hashedUpTo + 1) {
      throw new Error(
        `audit log has a seq gap at ${state.hashedUpTo + 1} (append-only invariant violated)`,
      );
    }
    const digest = await computeAuditRowDigest(row);
    if (!digest.ok) {
      // 保存行由来の入力で構造不正は実装バグ(エラー値に秘密は含まれない)
      throw new Error(`audit row digest failed at seq ${row.seq}: ${digest.error.kind}`);
    }
    const next = await computeAuditHeadHash(SUITE_ID, state.head, row.seq, digest.value);
    if (!next.ok) {
      throw new Error(`audit head hash failed at seq ${row.seq}: ${next.error.kind}`);
    }
    state.head = next.value;
    state.hashedUpTo = row.seq;
    inserts.push(row.seq, state.head);
  }
  sql.exec(
    `INSERT INTO audit_head_hashes (seq, head_hash_hex) VALUES ${rows
      .map(() => "(?, ?)")
      .join(", ")}`,
    ...inserts,
  );
  // 端数チャンク = このチャンクで MAX(seq) に到達(追加の SELECT 不要)
  return rows.length < HEAD_CHUNK_ROWS;
}

/** queryEventsSync の SELECT 列(StoredAuditEventRow と同順)。 */
const EVENT_ROW_COLUMNS = `seq, row_id, server_ts, client_ts, event, actor_type, actor_user_id,
  actor_key_fingerprint, actor_api_token_id, target_user_id, target_key_fingerprint,
  environment_id, variable_id, epoch, version, chain_seq, payload`;

/** 可視性クラス(§6)の WHERE 条件(本クエリとカーソル解決で共用)。 */
function visibilityCondition(
  visibility: AuditVisibility,
): { readonly clause: string; readonly bindings: readonly (string | number)[] } | null {
  if (visibility.kind === "admin") {
    return null;
  }
  // §6 / §7: クラス 2 の行は admin 未満に対して存在しないかのように振る舞う。
  // 本人が actor の行はクラスに依らず本人が閲覧可。
  // chain.* は名前の列挙ではなく前置一致で覆う(isClass1Event と同じ判定 —
  // 理由は CLASS1_EVENTS の doc)。さらに chain_seq を持つ行はイベント名に
  // かかわらず provenance claim = 全メンバーが検証すべき tamper evidence として
  // クラス 1 にする(deepsec S1)。前置比較は LIKE ではなく substr で行い、
  // ワイルドカード意味論を持たせない
  return {
    clause: `(event IN (${CLASS1_EVENTS.map(() => "?").join(", ")}) OR substr(event, 1, ?) = ? OR chain_seq IS NOT NULL OR actor_user_id = ?)`,
    bindings: [
      ...CLASS1_EVENTS,
      CHAIN_MIRROR_EVENT_PREFIX.length,
      CHAIN_MIRROR_EVENT_PREFIX,
      visibility.selfUserId,
    ],
  };
}

/**
 * カーソル(row_id)→ 内部 seq の解決。**閲覧者の可視性述語つき**で引く:
 * 不可視な行の id をカーソルに差しても「不明な id」と同一(null)に振る舞い、
 * カーソル探索を存在オラクルにしない(§7。id は 128-bit 乱数で推測も不能)。
 */
function resolveCursorSeq(
  sql: SqlStorage,
  rowId: string,
  visibility: AuditVisibility,
): number | null {
  const condition = visibilityCondition(visibility);
  const where = condition === null ? "" : ` AND ${condition.clause}`;
  const row = sql
    .exec(
      `SELECT seq FROM audit_events WHERE row_id = ?${where}`,
      rowId,
      ...(condition?.bindings ?? []),
    )
    .toArray()[0];
  return row === undefined ? null : Number(row["seq"]);
}

function queryEvents(sql: SqlStorage, query: AuditEventsQuery): readonly StoredAuditEventRow[] {
  const conditions: string[] = [];
  const bindings: (string | number)[] = [];
  const filter = (clause: string, value: string | number | null): void => {
    if (value !== null) {
      conditions.push(clause);
      bindings.push(value);
    }
  };
  if (query.beforeRowId !== null) {
    const beforeSeq = resolveCursorSeq(sql, query.beforeRowId, query.visibility);
    if (beforeSeq === null) {
      // 不明・不可視なカーソルは空ページ(ページング終端と同じ形 — §7)
      return [];
    }
    filter("seq < ?", beforeSeq);
  }
  filter("event = ?", query.event);
  if (query.eventPrefix !== null) {
    // 前置一致は LIKE を使わない(deepsec R1): LIKE だと入力の % / _ が
    // ワイルドカードとして働き、フィルタが名前空間の指定でなくなる。
    // substr 比較は長さと値の 2 バインドだけで、特別扱いの文字を持たない
    conditions.push("substr(event, 1, ?) = ?");
    bindings.push(query.eventPrefix.length, query.eventPrefix);
  }
  if (query.chainSeqPresent) {
    conditions.push("chain_seq IS NOT NULL");
  }
  filter("actor_user_id = ?", query.actorUserId);
  filter("target_user_id = ?", query.targetUserId);
  filter("variable_id = ?", query.variableId);
  filter("environment_id = ?", query.environmentId);
  const visibility = visibilityCondition(query.visibility);
  if (visibility !== null) {
    conditions.push(visibility.clause);
    bindings.push(...visibility.bindings);
  }
  const where = conditions.length === 0 ? "" : ` WHERE ${conditions.join(" AND ")}`;
  return sql
    .exec(
      `SELECT ${EVENT_ROW_COLUMNS} FROM audit_events${where} ORDER BY seq DESC LIMIT ?`,
      ...bindings,
      query.limit,
    )
    .toArray()
    .map(toStoredRow);
}

const textOrNull = (value: unknown): string | null => (value === null ? null : String(value));
const numberOrNull = (value: unknown): number | null => (value === null ? null : Number(value));

function toStoredRow(row: Record<string, unknown>): StoredAuditEventRow {
  // 列の写像は監査ヘッド計算の入力形と共有する(列集合が同一 — §5.1 の 17 列)。
  // row_id の非 NULL 化と payload の防御的 parse だけがこの読み取り形の差分
  const { payloadText: _payloadText, ...shared } = toAuditHeadRow(row);
  return {
    ...shared,
    rowId: String(row["row_id"]),
    payload: parsePayload(row["payload"]),
  };
}

/** payload 列(JSON)の防御的 parse(壊れた行は null 扱い — 検出を defect にしない)。 */
function parsePayload(value: unknown): Readonly<Record<string, unknown>> | null {
  if (typeof value !== "string") {
    return null;
  }
  try {
    const parsed: unknown = JSON.parse(value);
    return typeof parsed === "object" && parsed !== null
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

/** chain.server_granted の payload から開示スコープを取り出す(それ以外は空)。 */
function scopeOf(payload: Readonly<Record<string, unknown>> | null): readonly string[] {
  const scope = payload?.["scopeEnvironmentIds"];
  return Array.isArray(scope) ? scope.filter((id): id is string => typeof id === "string") : [];
}

const makeRotationRead = (sql: SqlStorage): AuditRotationRead => ({
  // Q1: (target_user_id, seq) 索引(ae_target)
  membershipEventsFor: (targetUserId) =>
    sql
      .exec(
        `SELECT seq, event FROM audit_events
         WHERE target_user_id = ?
           AND event IN ('chain.genesis', 'chain.member_added', 'chain.member_removed')
         ORDER BY seq`,
        targetUserId,
      )
      .toArray()
      .map((row) => ({ seq: Number(row["seq"]), event: String(row["event"]) })),
  // Q6: (target_key_fingerprint, seq) 索引(ae_target_fp)
  serverGrantEventsFor: (fpHex) =>
    sql
      .exec(
        `SELECT seq, event, payload FROM audit_events
         WHERE target_key_fingerprint = ?
           AND event IN ('chain.server_granted', 'chain.server_revoked')
         ORDER BY seq`,
        fpHex,
      )
      .toArray()
      .map((row) => ({
        seq: Number(row["seq"]),
        event: String(row["event"]),
        scopeEnvironmentIds: scopeOf(parsePayload(row["payload"])),
      })),
  // Q2: (event, seq) 索引(ae_event)
  variableLifecycles: () =>
    sql
      .exec(
        `SELECT seq, event, environment_id, variable_id FROM audit_events
         WHERE event IN ('var.created', 'var.deleted') ORDER BY seq`,
      )
      .toArray()
      .map((row) => ({
        seq: Number(row["seq"]),
        event: String(row["event"]),
        environmentId: String(row["environment_id"]),
        variableId: String(row["variable_id"]),
      })),
  // Q3: (actor_user_id, seq) 索引(ae_actor)
  variableReadsBy: (actorUserId) =>
    sql
      .exec(
        `SELECT seq, environment_id, variable_id FROM audit_events
         WHERE actor_user_id = ? AND event = 'var.read' ORDER BY seq`,
        actorUserId,
      )
      .toArray()
      .map((row) => ({
        seq: Number(row["seq"]),
        environmentId: String(row["environment_id"]),
        variableId: String(row["variable_id"]),
      })),
  // Q6 の (a) 入力: (actor_key_fingerprint, seq) 索引(ae_actor_fp)
  serverAccessEventsBy: (actorFpHex) =>
    sql
      .exec(
        `SELECT seq, event, environment_id, variable_id FROM audit_events
         WHERE actor_key_fingerprint = ?
           AND event IN ('server.lease_issued', 'server.value_decrypted')
         ORDER BY seq`,
        actorFpHex,
      )
      .toArray()
      .map((row) => ({
        seq: Number(row["seq"]),
        event: String(row["event"]),
        environmentId: String(row["environment_id"]),
        variableId: row["variable_id"] === null ? null : String(row["variable_id"]),
      })),
  // Q5: (event, seq) 索引(ae_event)
  rotationFlagEvents: () =>
    sql
      .exec(
        `SELECT seq, server_ts, event, environment_id, variable_id,
                target_user_id, target_key_fingerprint, payload
         FROM audit_events
         WHERE event IN ('rotation.recommended', 'rotation.dismissed', 'var.version_pushed')
         ORDER BY seq`,
      )
      .toArray()
      .map((row) => ({
        seq: Number(row["seq"]),
        serverTs: Number(row["server_ts"]),
        event: String(row["event"]),
        environmentId: String(row["environment_id"]),
        variableId: String(row["variable_id"]),
        targetUserId: row["target_user_id"] === null ? null : String(row["target_user_id"]),
        targetKeyFingerprintHex:
          row["target_key_fingerprint"] === null ? null : String(row["target_key_fingerprint"]),
        payload: parsePayload(row["payload"]),
      })),
});

export const auditStoreLayer = (sql: SqlStorage): Layer.Layer<AuditStore> =>
  Layer.sync(AuditStore, () => makeAuditStore(sql));
