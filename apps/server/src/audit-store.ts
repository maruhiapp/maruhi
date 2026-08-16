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
import { Context, Layer } from "effect";

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
 * クラス 1(チェーン role reader 以上 = 全メンバー)のイベント名(§6)。
 * **明示 allowlist の default-deny**: ここに無いイベント(var.read /
 * dek.registered / dek.deleted、および将来追加されるイベント)はクラス 2 扱いで
 * admin 未満には見えない — イベントを増やしたときに安全側へ倒す。
 */
export const CLASS1_EVENTS: readonly string[] = [
  "chain.genesis",
  "chain.member_added",
  "chain.member_removed",
  "chain.role_changed",
  "chain.environment_created",
  "chain.epoch_rotated",
  "chain.server_granted",
  "chain.server_revoked",
  "env.created",
  "env.renamed",
  "env.deleted",
  "var.created",
  "var.renamed",
  "var.deleted",
  "var.version_pushed",
  "server.dek_unwrapped",
  "server.lease_issued",
  "server.lease_denied",
  "server.value_decrypted",
  "rotation.recommended",
  "rotation.dismissed",
];

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
  readonly actorUserId: string | null;
  readonly targetUserId: string | null;
  readonly variableId: string | null;
  readonly environmentId: string | null;
  readonly visibility: AuditVisibility;
}

/** 保存行の読み取り形(§5.1 の全列。NULL は null)。 */
export interface StoredAuditEventRow {
  readonly seq: number;
  /** ワイヤ行識別子(§5.1 row_id — 16 バイト乱数 hex)。 */
  readonly rowId: string;
  readonly serverTs: number;
  readonly clientTs: number | null;
  readonly event: string;
  readonly actorType: string;
  readonly actorUserId: string | null;
  readonly actorKeyFingerprintHex: string | null;
  readonly actorApiTokenId: string | null;
  readonly targetUserId: string | null;
  readonly targetKeyFingerprintHex: string | null;
  readonly environmentId: string | null;
  readonly variableId: string | null;
  readonly epoch: number | null;
  readonly version: number | null;
  readonly chainSeq: number | null;
  readonly payload: Readonly<Record<string, unknown>> | null;
}

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
export const makeAuditStore = (sql: SqlStorage): AuditStoreShape => {
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
  };
};

/** queryEventsSync の SELECT 列(StoredAuditEventRow と同順)。 */
const EVENT_ROW_COLUMNS = `seq, row_id, server_ts, client_ts, event, actor_type, actor_user_id,
  actor_key_fingerprint, actor_api_token_id, target_user_id, target_key_fingerprint,
  environment_id, variable_id, epoch, version, chain_seq, payload`;

/** 可視性クラス(§6)の WHERE 条件(本クエリとカーソル解決で共用)。 */
function visibilityCondition(
  visibility: AuditVisibility,
): { readonly clause: string; readonly bindings: readonly string[] } | null {
  if (visibility.kind === "admin") {
    return null;
  }
  // §6 / §7: クラス 2 の行は admin 未満に対して存在しないかのように振る舞う。
  // 本人が actor の行はクラスに依らず本人が閲覧可
  return {
    clause: `(event IN (${CLASS1_EVENTS.map(() => "?").join(", ")}) OR actor_user_id = ?)`,
    bindings: [...CLASS1_EVENTS, visibility.selfUserId],
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
  return {
    seq: Number(row["seq"]),
    rowId: String(row["row_id"]),
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
