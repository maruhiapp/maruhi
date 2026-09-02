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
  checkpoint: "chain.checkpointed",
};

/**
 * All chain-mirror audit event names (AUDIT_SPEC §3.4) — the image of
 * `chainMirrorEvent`. Derived from the exhaustive per-op map so the mirror
 * verifier (`maruhi audit verify`) cannot silently miss a future ChainOp.
 */
export const CHAIN_MIRROR_EVENTS: readonly string[] = Object.values(MIRROR_EVENT_NAME);

/**
 * The `chain.` event namespace (AUDIT_SPEC §3.4). Mirror verification reads the
 * whole namespace by prefix rather than the known names one by one: a row that
 * claims a `chain.*` event outside `CHAIN_MIRROR_EVENTS` is evidence of forgery
 * and must not be able to hide from the verifier by using an unmapped name
 * (deepsec R1).
 */
export const CHAIN_MIRROR_EVENT_PREFIX = "chain.";

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
  // 公証対象のダイジェスト(環境ごとの epoch / manifest_version /
  // manifest_sig_hash / values_digest と audit_head_hash)を payload に写す
  // (AUDIT_SPEC §3.4 — 2026-08-18 起草。監査 seq・行数は payload にも写さない:
  // チェーン payload 自体が seq を含まない設計 — CRYPTO_SPEC §6.2)
  checkpoint: (entry) => ({
    event: MIRROR_EVENT_NAME.checkpoint,
    payload: {
      environments: entry.payload.environments.map((tuple) => ({
        environmentId: tuple.environmentId,
        epoch: tuple.epoch,
        manifestVersion: tuple.manifestVersion,
        manifestSigHashHex: tuple.manifestSigHashHex,
        valuesDigestHex: tuple.valuesDigestHex,
      })),
      auditHeadHashHex: entry.payload.auditHeadHashHex,
    },
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

// ---------------------------------------------------------------------------
// `var.read` の集約形(AUDIT_SPEC §3.3 — 2026-09-02): 値付き一括 pull ごとに
// 環境単位 1 行、返した変数の列挙を payload に持つ。payload の構築(サーバーの
// pull)と解釈(サーバーの要ローテーション検出・§7 フィルタ、CLI の表示)が
// 同一実装を共有する — 列挙の形(ソート・キー順)は row_digest(§5.1)の入力
// バイト列を決めるため、書き手と読み手を 1 箇所に置く。
// ---------------------------------------------------------------------------

/** The audit event name of a value read (AUDIT_SPEC §3.3). */
export const VAR_READ_EVENT = "var.read";

/** One variable listed by an aggregated `var.read` row (AUDIT_SPEC §3.3). */
export interface AuditReadVariable {
  readonly variableId: string;
  readonly epoch: number;
  readonly version: number;
}

/**
 * The payload of an aggregated `var.read` row (AUDIT_SPEC §3.3). A type alias
 * (not an interface) so it stays assignable to the generic payload record.
 */
export type AuditReadPayload = {
  readonly variables: readonly AuditReadVariable[];
};

/**
 * Builds the payload of an aggregated `var.read` row: the variables whose
 * ciphertext one value pull returned, sorted by `variableId` in code-unit
 * order with the key order fixed to variableId → epoch → version. A pull
 * returns each active variable at most once, so the list has no duplicates.
 * The stored JSON bytes feed the audit row digest (AUDIT_SPEC §5.1), which is
 * why the shape is fixed here rather than left to the caller.
 */
export function auditReadPayload(variables: readonly AuditReadVariable[]): AuditReadPayload {
  const sorted = variables.toSorted((a, b) =>
    a.variableId < b.variableId ? -1 : a.variableId > b.variableId ? 1 : 0,
  );
  return {
    variables: sorted.map(({ variableId, epoch, version }) => ({ variableId, epoch, version })),
  };
}

/**
 * Reads the variables listed by an aggregated `var.read` payload. Returns
 * `null` when the payload is not the aggregated form — a legacy per-variable
 * `var.read` row (variableId in the column, no `variables` list) or an
 * unrelated event. Entries that are not well-formed are skipped rather than
 * failing the caller (the audit log is server-managed data; a malformed entry
 * is corruption to surface, not a reason to abort rotation detection).
 */
export function auditReadVariablesOf(
  payload: Readonly<Record<string, unknown>> | null | undefined,
): readonly AuditReadVariable[] | null {
  const listed = payload?.["variables"];
  if (!Array.isArray(listed)) {
    return null;
  }
  return listed.flatMap((entry: unknown): AuditReadVariable[] => {
    if (typeof entry !== "object" || entry === null) {
      return [];
    }
    const { variableId, epoch, version } = entry as Record<string, unknown>;
    return typeof variableId === "string" && Number.isInteger(epoch) && Number.isInteger(version)
      ? [{ variableId, epoch: epoch as number, version: version as number }]
      : [];
  });
}
