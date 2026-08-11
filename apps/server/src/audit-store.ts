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

export const auditStoreLayer = (sql: SqlStorage): Layer.Layer<AuditStore> =>
  Layer.sync(AuditStore, () => {
    // 次 seq(単調・無欠番 — AUDIT_SPEC §5.1)の DO インスタンスメモリ保持。
    // 行ごとの `SELECT COALESCE(MAX(seq),0)+1` 集約を初期化時の 1 回に置き換える。
    // null はキャッシュ無効(DO 再起動直後)で、次の追記時に MAX(seq) を再読込
    // する。前進は挿入成功後のみ(挿入が失敗しても欠番を作らない)。全追記は
    // この Layer 経由 + DO の permit 下で直列化されている前提
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
        sql.exec(INSERT_COLUMNS + VALUES_ROW, seq, ...eventBindings(event));
        nextSeqCache = seq + 1;
      },
      appendManySync: (events) => {
        for (let offset = 0; offset < events.length; offset += APPEND_CHUNK_ROWS) {
          const chunk = events.slice(offset, offset + APPEND_CHUNK_ROWS);
          const seq = nextSeq();
          sql.exec(
            INSERT_COLUMNS + chunk.map(() => VALUES_ROW).join(", "),
            ...chunk.flatMap((event, index) => [seq + index, ...eventBindings(event)]),
          );
          nextSeqCache = seq + chunk.length;
        }
      },
    };
  });

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
