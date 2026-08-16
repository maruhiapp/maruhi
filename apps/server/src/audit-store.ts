// 監査ログの追記ストア(AUDIT_SPEC §5.1)とチェーンミラーの写像(§3.4)。
//
// - append-only: このサービスは追記のみを公開する(更新・削除の口を作らない —
//   AUDIT_SPEC §1-4)。読み取りは Phase 2 の監査ログ UI と同時に設計する(§6)
// - seq は単調・無欠番。次 seq は DO インスタンスメモリに保持し(初期化時に
//   MAX(seq) を 1 回だけ読む。DO 再起動で再読込)、同期 SQL なので await 境界を
//   またがない
// - アイデンティティ規則(§1-2): actor / target は内部 user_id と鍵 FP のみ。
//   プロバイダ ID・メールをこの層に持ち込まないこと

import type { ChainEntry, ChainOp } from "@maruhi/crypto";
import { Context, Layer } from "effect";

/** 監査イベント 1 行の入力(列は AUDIT_SPEC §5.1、未指定は NULL)。 */
export interface AuditEventInput {
  readonly event: string;
  readonly serverTs: number;
  readonly clientTs?: number;
  readonly actorType: "user" | "server" | "system";
  readonly actorUserId?: string;
  readonly actorKeyFingerprintHex?: string;
  readonly actorApiTokenId?: string;
  readonly targetUserId?: string;
  readonly targetKeyFingerprintHex?: string;
  readonly environmentId?: string;
  readonly variableId?: string;
  readonly epoch?: number;
  readonly version?: number;
  readonly chainSeq?: number;
  readonly payload?: Readonly<Record<string, unknown>>;
}

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
}

export class AuditStore extends Context.Service<AuditStore, AuditStoreShape>()("AuditStore") {}

const INSERT_COLUMNS = `INSERT INTO audit_events (
    seq, server_ts, client_ts, event, actor_type, actor_user_id,
    actor_key_fingerprint, actor_api_token_id, target_user_id,
    target_key_fingerprint, environment_id, variable_id, epoch, version,
    chain_seq, payload
  ) VALUES `;

/** 1 行分のプレースホルダ(seq + eventBindings の 15 値 = 16 列)。 */
const VALUES_ROW = "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

/**
 * multi-row INSERT の 1 文あたり行数。16 列 × 6 行 = 96 バインドで、SQLite の
 * バインド変数上限(保守的に 100 と見る)を下回るように取る。
 */
const APPEND_CHUNK_ROWS = 6;

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
        sql.exec(INSERT_COLUMNS + VALUES_ROW, seq, ...eventBindings(event));
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
            ...chunk.flatMap((event, index) => [seq + index, ...eventBindings(event)]),
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
  };
};

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

// ---------------------------------------------------------------------------
// チェーンミラー(AUDIT_SPEC §3.4): 受理済みエントリ → 監査イベント。
// actor はチェーンエントリの actor(user_id + 鍵 FP)をそのまま写し、
// クライアント時刻(entry.timestampMs)とサーバー受理時刻の両方を持つ。
// バックフィルはしない(§3.4 の 2026-08-02 裁定 — 導入前のチェーンは存在しない)。
// ---------------------------------------------------------------------------

type MirrorTail = Pick<
  AuditEventInput,
  "event" | "targetUserId" | "targetKeyFingerprintHex" | "environmentId" | "epoch" | "payload"
>;

// op ごとの写像(§3.4 の表)。genesis の target は作成者 = actor(在籍区間の
// 開始点を Q1 の索引で引けるようにするため)
const mirrorTails: {
  readonly [K in ChainOp]: (entry: Extract<ChainEntry, { op: K }>) => MirrorTail;
} = {
  genesis: (entry) => ({ event: "chain.genesis", targetUserId: entry.actor.userId }),
  add_member: (entry) => ({
    event: "chain.member_added",
    targetUserId: entry.payload.targetUserId,
    payload: { role: entry.payload.role },
  }),
  remove_member: (entry) => ({
    event: "chain.member_removed",
    targetUserId: entry.payload.targetUserId,
  }),
  change_role: (entry) => ({
    event: "chain.role_changed",
    targetUserId: entry.payload.targetUserId,
    payload: { newRole: entry.payload.newRole },
  }),
  // dek_commitment は payload に写す(AUDIT_SPEC §3.4。2026-08-03 — 監査行と
  // チェーン掲載コミットメントの突合用)
  create_environment: (entry) => ({
    event: "chain.environment_created",
    environmentId: entry.payload.environmentId,
    epoch: 1,
    payload: { dekCommitmentHex: entry.payload.dekCommitmentHex },
  }),
  rotate_epoch: (entry) => ({
    event: "chain.epoch_rotated",
    environmentId: entry.payload.environmentId,
    epoch: entry.payload.newEpoch,
    payload: { reason: entry.payload.reason, dekCommitmentHex: entry.payload.dekCommitmentHex },
  }),
  grant_server: (entry) => ({
    event: "chain.server_granted",
    targetKeyFingerprintHex: entry.payload.serverKeyFingerprintHex,
    // lease_policy は意図的に写さない(AUDIT_SPEC §1-2 / AUTH_SPEC §14-4):
    // claim_value にはリポジトリ名等の外部識別子が現れるため、監査行には
    // 持ち込まない。ポリシーの真実源はチェーン(grant payload)で、chain_seq で
    // 突合できる。スコープ(内部 environment_id 集合)は §3.4 のとおり写す
    payload: { scopeEnvironmentIds: entry.payload.scopeEnvironmentIds },
  }),
  revoke_server: (entry) => ({
    event: "chain.server_revoked",
    targetKeyFingerprintHex: entry.payload.serverKeyFingerprintHex,
  }),
};

/** 受理済みチェーンエントリを §3.4 のミラーイベントへ写す。 */
export function chainMirrorEvent(entry: ChainEntry, serverTs: number): AuditEventInput {
  const tail = mirrorTails[entry.op](entry as never);
  return {
    ...tail,
    serverTs,
    clientTs: entry.timestampMs,
    chainSeq: entry.seq,
    actorType: "user",
    actorUserId: entry.actor.userId,
    actorKeyFingerprintHex: entry.actor.keyFingerprintHex,
  };
}
