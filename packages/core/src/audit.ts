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

import type { ChainActor, ChainEntry, ChainOp, ChainOperation } from "@maruhi/crypto";

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
// 四眼(PF1 — 2026-09-16 K5): approve / withdraw の行は参照先の提案エントリの
// seq を、完成した approve は加えて内側 op の適用行(同じ chain_seq・actor =
// 提案者・payload に viaProposalSeq)を持つ。どちらもエントリ単独からは写せず、
// 検証済みチェーンから導いた提案の索引(ProposalIndex)を入力に取る。
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
  // 四眼(AUDIT_SPEC §3.4 — 2026-09-14 PF1)
  set_approval_policy: "chain.approval_policy_changed",
  propose: "chain.proposed",
  approve: "chain.approved",
  withdraw: "chain.proposal_withdrawn",
};

/**
 * All chain-mirror audit event names (AUDIT_SPEC §3.4) — the image of
 * `chainMirrorEvents`. Derived from the exhaustive per-op map so the mirror
 * verifier (`maruhi audit verify`) cannot silently miss a future ChainOp.
 */
export const CHAIN_MIRROR_EVENTS: readonly string[] = Object.values(MIRROR_EVENT_NAME);

/**
 * The `chain.` event namespace (AUDIT_SPEC §3.4). Mirror verification reads the
 * whole namespace by prefix rather than the known names one by one: a row that
 * claims a `chain.*` event outside `CHAIN_MIRROR_EVENTS` is evidence of forgery
 * and must not be able to hide from the verifier by using an unmapped name.
 */
export const CHAIN_MIRROR_EVENT_PREFIX = "chain.";

/** A `propose` entry on a verified chain. */
export type ProposeEntry = ChainEntry & { readonly op: "propose" };

/**
 * One proposal on a verified chain (CRYPTO_SPEC §6.2 — identified by the
 * `propose` entry's hash): the entry itself and, when the proposal was applied,
 * the seq of the `approve` entry that reached the quorum (`null` while pending
 * or after a `withdraw`).
 */
export interface IndexedProposal {
  readonly entry: ProposeEntry;
  readonly completedAtSeq: number | null;
}

/**
 * Proposals of a verified chain keyed by the `propose` entry hash — the input
 * `chainMirrorEvents` needs for `approve` / `withdraw` rows (AUDIT_SPEC §3.4:
 * `proposalChainSeq` / `completed` / the applied inner-op row). Built once per
 * verified chain by {@link indexProposals}; the server (mirror writer) and the
 * CLI (`maruhi audit verify`) share that derivation so neither can drift.
 */
export type ProposalIndex = ReadonlyMap<string, IndexedProposal>;

/**
 * Derives the {@link ProposalIndex} of a verified chain. Completion is read
 * off the chain's consensus rules rather than re-evaluated: once a proposal
 * leaves the pending set (quorum reached or withdrawn) any later `approve` /
 * `withdraw` naming it is `unknown-proposal` and cannot be on a verified
 * chain. So a proposal that is absent from the final pending set and is not
 * named by a `withdraw` was completed by the **last** `approve` naming it.
 *
 * @param entries the verified chain (seq order)
 * @param entryHashAt entry hash by seq (CRYPTO_SPEC §4.1 history index)
 * @param pendingHashes hashes of the proposals still pending at the head
 */
export function indexProposals(
  entries: readonly ChainEntry[],
  entryHashAt: (seq: number) => string | undefined,
  pendingHashes: ReadonlySet<string>,
): ProposalIndex {
  const proposals = new Map<string, { entry: ProposeEntry; lastApproveSeq: number | null }>();
  const withdrawn = new Set<string>();
  for (const entry of entries) {
    if (entry.op === "propose") {
      const hash = entryHashAt(entry.seq);
      if (hash !== undefined) {
        proposals.set(hash, { entry, lastApproveSeq: null });
      }
    } else if (entry.op === "approve") {
      const proposal = proposals.get(entry.payload.proposalHashHex);
      if (proposal !== undefined) {
        proposal.lastApproveSeq = entry.seq;
      }
    } else if (entry.op === "withdraw") {
      withdrawn.add(entry.payload.proposalHashHex);
    }
  }
  const index = new Map<string, IndexedProposal>();
  for (const [hash, proposal] of proposals) {
    const closedByQuorum = !pendingHashes.has(hash) && !withdrawn.has(hash);
    index.set(hash, {
      entry: proposal.entry,
      completedAtSeq: closedByQuorum ? proposal.lastApproveSeq : null,
    });
  }
  return index;
}

/** The actor an operation is attributed to (the entry actor, or the proposer for an applied inner op). */
interface MirrorSubject {
  readonly actor: ChainActor;
}

// op ごとの写像(§3.4 の表)。入力は op + payload(+ actor — genesis の target だけが
// 使う)であり、署名済みエントリにも提案の内側 op にも適用できる。genesis の
// target は作成者 = actor(在籍区間の開始点を Q1 の索引で引けるようにするため)
const mirrorTails: {
  readonly [K in ChainOp]: (
    operation: Extract<ChainOperation, { op: K }> & MirrorSubject,
  ) => MirrorTail;
} = {
  genesis: (operation) => ({
    event: MIRROR_EVENT_NAME.genesis,
    targetUserId: operation.actor.userId,
  }),
  // scope も写す(AUDIT_SPEC §3.4 — 2026-09-14 ES: §4.1 の環境別アクセス窓の復元材料)
  add_member: (operation) => ({
    event: MIRROR_EVENT_NAME.add_member,
    targetUserId: operation.payload.targetUserId,
    payload: {
      role: operation.payload.role,
      scopeKind: operation.payload.scopeKind,
      scopeEnvironmentIds: operation.payload.scopeEnvironmentIds,
    },
  }),
  remove_member: (operation) => ({
    event: MIRROR_EVENT_NAME.remove_member,
    targetUserId: operation.payload.targetUserId,
  }),
  change_role: (operation) => ({
    event: MIRROR_EVENT_NAME.change_role,
    targetUserId: operation.payload.targetUserId,
    payload: {
      newRole: operation.payload.newRole,
      scopeKind: operation.payload.scopeKind,
      scopeEnvironmentIds: operation.payload.scopeEnvironmentIds,
    },
  }),
  // dek_commitment は payload に写す(AUDIT_SPEC §3.4 — 監査行と
  // チェーン掲載コミットメントの突合用)
  create_environment: (operation) => ({
    event: MIRROR_EVENT_NAME.create_environment,
    environmentId: operation.payload.environmentId,
    epoch: 1,
    payload: { dekCommitmentHex: operation.payload.dekCommitmentHex },
  }),
  rotate_epoch: (operation) => ({
    event: MIRROR_EVENT_NAME.rotate_epoch,
    environmentId: operation.payload.environmentId,
    epoch: operation.payload.newEpoch,
    payload: {
      reason: operation.payload.reason,
      dekCommitmentHex: operation.payload.dekCommitmentHex,
    },
  }),
  grant_server: (operation) => ({
    event: MIRROR_EVENT_NAME.grant_server,
    targetKeyFingerprintHex: operation.payload.serverKeyFingerprintHex,
    // lease_policy は意図的に写さない(AUDIT_SPEC §1-2 / AUTH_SPEC §14-4):
    // claim_value にはリポジトリ名等の外部識別子が現れるため、監査行には
    // 持ち込まない。ポリシーの真実源はチェーン(grant payload)で、chain_seq で
    // 突合できる。スコープ(内部 environment_id 集合)は §3.4 のとおり写す
    payload: { scopeEnvironmentIds: operation.payload.scopeEnvironmentIds },
  }),
  revoke_server: (operation) => ({
    event: MIRROR_EVENT_NAME.revoke_server,
    targetKeyFingerprintHex: operation.payload.serverKeyFingerprintHex,
  }),
  // 公証対象のダイジェスト(環境ごとの epoch / manifest_version /
  // manifest_sig_hash / values_digest と audit_head_hash)を payload に写す
  // (AUDIT_SPEC §3.4。監査 seq・行数は payload にも写さない:
  // チェーン payload 自体が seq を含まない設計 — CRYPTO_SPEC §6.2)
  checkpoint: (operation) => ({
    event: MIRROR_EVENT_NAME.checkpoint,
    payload: {
      environments: operation.payload.environments.map((tuple) => ({
        environmentId: tuple.environmentId,
        epoch: tuple.epoch,
        manifestVersion: tuple.manifestVersion,
        manifestSigHashHex: tuple.manifestSigHashHex,
        valuesDigestHex: tuple.valuesDigestHex,
      })),
      auditHeadHashHex: operation.payload.auditHeadHashHex,
    },
  }),
  // 四眼(AUDIT_SPEC §3.4 — 2026-09-14 PF1)。内側 payload は写さない(正は
  // チェーン)。approve / withdraw の参照先(proposalChainSeq)と completed は
  // 提案の索引を要するため chainMirrorEvents 側で足す(ここは名前だけ)
  set_approval_policy: (operation) => ({
    event: MIRROR_EVENT_NAME.set_approval_policy,
    payload: {
      ops: operation.payload.ops,
      requiredApprovals: operation.payload.requiredApprovals,
    },
  }),
  propose: (operation) => ({
    event: MIRROR_EVENT_NAME.propose,
    payload: { innerOp: operation.payload.inner.op, expiresAtMs: operation.payload.expiresAtMs },
  }),
  approve: () => ({ event: MIRROR_EVENT_NAME.approve }),
  withdraw: () => ({ event: MIRROR_EVENT_NAME.withdraw }),
};

function mirrorTailOf(operation: ChainOperation & MirrorSubject): MirrorTail {
  return mirrorTails[operation.op](operation as never);
}

/** The proposal an `approve` / `withdraw` entry names; a verified chain always has it. */
function referencedProposal(
  entry: ChainEntry & { readonly op: "approve" | "withdraw" },
  index: ProposalIndex,
): IndexedProposal {
  const proposal = index.get(entry.payload.proposalHashHex);
  if (proposal === undefined) {
    // 検証済みチェーンでは参照先の propose が必ず先行する(unknown-proposal は無効
    // エントリ)。欠けているのは索引の作り方の誤りであり、写像の入力の契約違反
    throw new Error(
      `chain mirror: entry seq=${entry.seq} (${entry.op}) names a proposal that is not in the proposal index`,
    );
  }
  return proposal;
}

/**
 * Maps one accepted chain entry to its §3.4 mirror row(s): exactly one row per
 * entry, plus — for an `approve` that reached the quorum — the applied
 * inner-op row (same `chainSeq`, actor = the proposer, `clientTs` = the
 * approve entry's timestamp, payload = the inner op's mirror payload +
 * `viaProposalSeq`). The order is mirror row first, applied row second (the
 * server writes them in this order in one transaction; rotation detection
 * reads the applied row as the latest membership event of its target).
 *
 * `index` comes from {@link indexProposals} over the verified chain the entry
 * belongs to (only `approve` / `withdraw` entries consult it).
 */
export function chainMirrorEvents(
  entry: ChainEntry,
  serverTs: number,
  index: ProposalIndex,
): readonly AuditEventRecord[] {
  const base = {
    serverTs,
    clientTs: entry.timestampMs,
    chainSeq: entry.seq,
    actorType: "user" as const,
  };
  const own = (tail: MirrorTail): AuditEventRecord => ({
    ...tail,
    ...base,
    actorUserId: entry.actor.userId,
    actorKeyFingerprintHex: entry.actor.keyFingerprintHex,
  });
  if (entry.op === "withdraw") {
    const proposal = referencedProposal(entry, index);
    return [
      own({
        ...mirrorTailOf(entry),
        payload: { proposalChainSeq: proposal.entry.seq },
      }),
    ];
  }
  if (entry.op !== "approve") {
    return [own(mirrorTailOf(entry))];
  }
  const proposal = referencedProposal(entry, index);
  const completed = proposal.completedAtSeq === entry.seq;
  const approved = own({
    ...mirrorTailOf(entry),
    payload: { proposalChainSeq: proposal.entry.seq, completed },
  });
  if (!completed) {
    return [approved];
  }
  // 適用行(AUDIT_SPEC §3.4): 内側 op のミラー写像に viaProposalSeq を足し、actor は
  // 提案者(内側 op の actor)。§4.1 の在籍区間(Q1)・grant 区間(Q6)の入力構造を
  // 変えないための規律 — 検出は直接追記と同じ行を同じ索引で引く
  const inner = proposal.entry.payload.inner;
  const tail = mirrorTailOf({ ...inner, actor: proposal.entry.actor });
  return [
    approved,
    {
      ...tail,
      ...base,
      actorUserId: proposal.entry.actor.userId,
      actorKeyFingerprintHex: proposal.entry.actor.keyFingerprintHex,
      payload: { ...tail.payload, viaProposalSeq: proposal.entry.seq },
    },
  ];
}

// ---------------------------------------------------------------------------
// `var.read` の集約形(AUDIT_SPEC §3.3): 値付き一括 pull ごとに
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
