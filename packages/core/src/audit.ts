// 監査アクターの共有型と写像(AUDIT_SPEC §2)、およびチェーンミラーの写像
// (§3.4)。
//
// アイデンティティ規則(§1-2)の関門: 監査ログ(D1 側)とメンバーシップログの
// ミラー・データ系イベント(DO 側)のアクターは**内部 user_id と鍵フィンガー
// プリントのみ**で表す。認証主体 → アクターの写像はここ(auditActorOf)が唯一の
// 実装であり、GitHub ID・login・メール等のプロバイダ情報をこの型に足さないこと。
// DO 用(apps/server data-plane.ts の DataActor)/ D1 用(db.package/audit.ts の
// D1AuditActor)の入力型はこの型から派生する。
//
// チェーンミラーの写像(chainMirrorEvent)がここにあるのは、**サーバーの
// ミラー追記と CLI のミラー検証(`maruhi audit verify` — AUDIT_SPEC §1-5 /
// §6 の緩和策)が同一実装を共有する**ため。写像が二重管理になると、検証器の
// ドリフトが改竄の誤検出(または見逃し)になる。

import type { ChainEntry, ChainOp } from "@maruhi/crypto";

import type { AuthenticatedPrincipal } from "./auth.ts";

/**
 * A resolved audit actor (AUDIT_SPEC §2): the internal user id plus, depending
 * on how the request was authenticated, the maruhi-issued token id or the auth
 * method name. Never carries provider identifiers (GitHub id, login, email).
 */
export interface AuditActor {
  readonly userId: string;
  readonly apiTokenId?: string;
  readonly authMethod?: string;
}

/**
 * Maps an authenticated principal to its audit actor (AUDIT_SPEC §2). The only
 * principal-to-actor mapping — both the DO data plane and the D1 audit log go
 * through this.
 */
export function auditActorOf(principal: AuthenticatedPrincipal): AuditActor {
  return principal.kind === "token"
    ? { userId: principal.userId, apiTokenId: principal.tokenId }
    : { userId: principal.userId, authMethod: principal.authMethod };
}

/**
 * Merges the actor's auth method into the event payload (AUDIT_SPEC §5.1:
 * auth_method is a payload attribute, not a column). Shared by the DO event
 * builder and the D1 row builder so the merge cannot drift between the two.
 */
export function auditPayloadWith(
  actor: Pick<AuditActor, "authMethod">,
  payload: Readonly<Record<string, unknown>> | undefined,
): Readonly<Record<string, unknown>> {
  return {
    ...payload,
    ...(actor.authMethod === undefined ? {} : { authMethod: actor.authMethod }),
  };
}

// ---------------------------------------------------------------------------
// チェーンミラー(AUDIT_SPEC §3.4): 受理済みエントリ → 監査イベント。
// actor はチェーンエントリの actor(user_id + 鍵 FP)をそのまま写し、
// クライアント時刻(entry.timestampMs)とサーバー受理時刻の両方を持つ。
// ---------------------------------------------------------------------------

/**
 * One audit event (AUDIT_SPEC §5.1 columns; unspecified fields are absent /
 * NULL). Shared between the server-side append input (apps/server
 * audit-store.ts) and the client-side mirror verifier, so the mirror mapping
 * below produces the exact shape the server persists.
 */
export interface AuditEventRecord {
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

type MirrorTail = Pick<
  AuditEventRecord,
  "event" | "targetUserId" | "targetKeyFingerprintHex" | "environmentId" | "epoch" | "payload"
>;

/**
 * op → ミラーイベント名(§3.4)。ChainOp の全域マップ(型で網羅を強制)であり、
 * mirrorTails と CHAIN_MIRROR_EVENTS の両方がここから名前を取る — op が増えた
 * ときに片方だけ更新されて検証器がドリフトする形(誤検出・見逃し)を塞ぐ。
 */
const MIRROR_EVENT_NAME: { readonly [K in ChainOp]: string } = {
  genesis: "chain.genesis",
  add_member: "chain.member_added",
  remove_member: "chain.member_removed",
  change_role: "chain.role_changed",
  create_environment: "chain.environment_created",
  rotate_epoch: "chain.epoch_rotated",
  grant_server: "chain.server_granted",
  revoke_server: "chain.server_revoked",
};

/**
 * All chain-mirror audit event names (AUDIT_SPEC §3.4) — the image of
 * `chainMirrorEvent`. Derived from the exhaustive per-op map so the mirror
 * verifier (`maruhi audit verify`) cannot silently miss a future ChainOp.
 */
export const CHAIN_MIRROR_EVENTS: readonly string[] = Object.values(MIRROR_EVENT_NAME);

// op ごとの写像(§3.4 の表)。genesis の target は作成者 = actor(在籍区間の
// 開始点を Q1 の索引で引けるようにするため)
const mirrorTails: {
  readonly [K in ChainOp]: (entry: Extract<ChainEntry, { op: K }>) => MirrorTail;
} = {
  genesis: (entry) => ({
    event: MIRROR_EVENT_NAME.genesis,
    targetUserId: entry.actor.userId,
  }),
  add_member: (entry) => ({
    event: MIRROR_EVENT_NAME.add_member,
    targetUserId: entry.payload.targetUserId,
    payload: { role: entry.payload.role },
  }),
  remove_member: (entry) => ({
    event: MIRROR_EVENT_NAME.remove_member,
    targetUserId: entry.payload.targetUserId,
  }),
  change_role: (entry) => ({
    event: MIRROR_EVENT_NAME.change_role,
    targetUserId: entry.payload.targetUserId,
    payload: { newRole: entry.payload.newRole },
  }),
  // dek_commitment は payload に写す(AUDIT_SPEC §3.4。2026-08-03 — 監査行と
  // チェーン掲載コミットメントの突合用)
  create_environment: (entry) => ({
    event: MIRROR_EVENT_NAME.create_environment,
    environmentId: entry.payload.environmentId,
    epoch: 1,
    payload: { dekCommitmentHex: entry.payload.dekCommitmentHex },
  }),
  rotate_epoch: (entry) => ({
    event: MIRROR_EVENT_NAME.rotate_epoch,
    environmentId: entry.payload.environmentId,
    epoch: entry.payload.newEpoch,
    payload: { reason: entry.payload.reason, dekCommitmentHex: entry.payload.dekCommitmentHex },
  }),
  grant_server: (entry) => ({
    event: MIRROR_EVENT_NAME.grant_server,
    targetKeyFingerprintHex: entry.payload.serverKeyFingerprintHex,
    // lease_policy は意図的に写さない(AUDIT_SPEC §1-2 / AUTH_SPEC §14-4):
    // claim_value にはリポジトリ名等の外部識別子が現れるため、監査行には
    // 持ち込まない。ポリシーの真実源はチェーン(grant payload)で、chain_seq で
    // 突合できる。スコープ(内部 environment_id 集合)は §3.4 のとおり写す
    payload: { scopeEnvironmentIds: entry.payload.scopeEnvironmentIds },
  }),
  revoke_server: (entry) => ({
    event: MIRROR_EVENT_NAME.revoke_server,
    targetKeyFingerprintHex: entry.payload.serverKeyFingerprintHex,
  }),
};

/** 受理済みチェーンエントリを §3.4 のミラーイベントへ写す。 */
export function chainMirrorEvent(entry: ChainEntry, serverTs: number): AuditEventRecord {
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
