// 監査ログの追記ストア(AUDIT_SPEC §5.1)とチェーンミラーの写像(§3.4)。
//
// - append-only: このサービスは追記のみを公開する(更新・削除の口を作らない —
//   AUDIT_SPEC §1-4)。読み取りは Phase 2 の監査ログ UI と同時に設計する(§6)
// - seq は INSERT ... SELECT COALESCE(MAX(seq),0)+1 で単調・無欠番に採番する
//   (1 文の同期 SQL なので await 境界をまたがない)
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
}

export class AuditStore extends Context.Service<AuditStore, AuditStoreShape>()("AuditStore") {}

const INSERT_EVENT = `INSERT INTO audit_events (
    seq, server_ts, client_ts, event, actor_type, actor_user_id,
    actor_key_fingerprint, actor_api_token_id, target_user_id,
    target_key_fingerprint, environment_id, variable_id, epoch, version,
    chain_seq, payload
  )
  SELECT COALESCE(MAX(seq), 0) + 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
  FROM audit_events`;

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
  Layer.sync(AuditStore, () => ({
    appendSync: (event) => {
      sql.exec(INSERT_EVENT, ...eventBindings(event));
    },
  }));

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
