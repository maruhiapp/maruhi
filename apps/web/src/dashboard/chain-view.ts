// チェーン取得応答からの表示用ビューの導出(S5 — 設計文書 §3)。
//
// これは**検証ではない**(ADR-0018 改訂 2・4 項 — Web バンドルにチェーン・署名
// 検証のコードを入れない): サーバーが返したエントリ列を、返された順で
// 機械的に畳み込むだけの表示変換であり、署名・ハッシュ連結・合意規則の検査を
// 一切行わない。結果はすべて「サーバー申告(as reported by the server)」で
// あり、UI もそう表示する。検証済みのメンバー集合が要る場面は
// `maruhi project verify`(CLI)の領分。
//
// 四眼(CRYPTO_SPEC §6.2 — PF1。設計録 es-design.md §12 K6-J): 方針と pending 提案も
// 同じ機械的な畳み込みで導く。approve / withdraw は提案を entry_hash で指すが、応答は
// エントリごとの hash を運ばないので、**次のエントリの prevHashHex**(末尾は headHashHex)
// から引く(hash を計算しない — 暗号を持ち込まない)。票数は記録をそのまま出さず、各
// approve の時点で「現 owner かつ鍵 FP が一致する投票者」を再集計する(K2 の実装メモ)。
// 鍵 FP は genesis の actor と、そのメンバーが署名した各エントリの actor から追跡し、
// add_member で前在籍と同じ鍵なら引き継ぐ(異なれば署名するまで「未知」= 数えない —
// 鍵が異なれば FP も異なるので合意規則も数えない)。定足数に達した approve は内側 op を
// 畳み込む(適用された remove を Members から消すために必要)。
import type { ChainEntry } from "./types.ts";

/** One member row derived from the reported entries (server-reported, unverified). */
export interface ReportedMember {
  userId: string;
  role: string;
  /** Environment scope as reported (CRYPTO_SPEC §6.2 — `all`, or the listed environment ids). */
  scopeKind: "all" | "listed";
  scopeEnvironmentIds: ReadonlyArray<string>;
  /** The reported chain seq that last set this member's role / scope. */
  sinceSeq: number;
}

/** One granted server key derived from the reported entries (server-reported). */
export interface ReportedServer {
  keyFingerprintHex: string;
  scopeEnvironmentIds: ReadonlyArray<string>;
  sinceSeq: number;
}

/** The four-eyes policy as reported (null = off). */
export interface ReportedPolicy {
  requiredApprovals: number;
  ops: ReadonlyArray<string>;
}

/** One pending proposal as reported (votes recounted under the policy current at the head). */
export interface ReportedProposal {
  proposalHashHex: string;
  proposalSeq: number;
  proposerUserId: string;
  /** `owner` puts the proposal signature into the signer set (one vote — §6.2). */
  proposerRoleAtProposal: string;
  innerOp: string;
  /** One-line summary of the inner operation (ids are shown raw — the UI neutralizes on render). */
  innerSummary: string;
  expiresAtMs: number;
  /** Distinct current owners whose signature counts (recounted — never the raw record). */
  votes: number;
  voterUserIds: ReadonlyArray<string>;
}

export interface ReportedChainView {
  members: ReportedMember[];
  servers: ReportedServer[];
  policy: ReportedPolicy | null;
  proposals: ReportedProposal[];
}

/** 投票の記録(user_id と署名時の鍵 FP — 原則 2 の S の要素)。 */
interface Vote {
  userId: string;
  keyFingerprintHex: string;
}

type EntryOf<Op extends ChainEntry["op"]> = Extract<ChainEntry, { op: Op }>;

/** 提案の内側 op(ワイヤ形 — approve の適用で畳み込む)。 */
type ProposableEntry = EntryOf<"propose">["payload"]["inner"];

interface PendingFold {
  seq: number;
  proposerUserId: string;
  proposerKeyFingerprintHex: string;
  proposerRoleAtProposal: string;
  inner: ProposableEntry;
  expiresAtMs: number;
  approvals: Vote[];
}

interface FoldState {
  members: Map<string, ReportedMember>;
  servers: Map<string, ReportedServer>;
  policy: ReportedPolicy | null;
  pending: Map<string, PendingFold>;
  /** メンバーの現在の鍵 FP(未知 = null — 署名するまで票を数えない)。 */
  fingerprints: Map<string, string | null>;
  /** メンバーの現在の鍵(add_member の payload — 再追加で同じ鍵なら FP を引き継ぐ)。 */
  keys: Map<string, { encPubHex: string; sigPubHex: string }>;
}

function setMember(
  state: FoldState,
  userId: string,
  role: string,
  scope: { scopeKind: "all" | "listed"; scopeEnvironmentIds: ReadonlyArray<string> },
  sinceSeq: number,
): void {
  state.members.set(userId, {
    userId,
    role,
    scopeKind: scope.scopeKind,
    scopeEnvironmentIds: scope.scopeEnvironmentIds,
    sinceSeq,
  });
}

/** genesis の作成者は構造的に scope = all(CRYPTO_SPEC §6.2)。 */
const ALL_SCOPE = { scopeKind: "all", scopeEnvironmentIds: [] } as const;

function applyChangeRole(
  state: FoldState,
  seq: number,
  payload: EntryOf<"change_role">["payload"],
): void {
  const existing = state.members.get(payload.targetUserId);
  if (existing !== undefined) {
    // 新 (role, scope) の全置換(§6.2 — 2026-09-15 ES K4 で scope も写す)
    setMember(state, existing.userId, payload.newRole, payload, seq);
  }
}

function applyGrantServer(
  state: FoldState,
  seq: number,
  payload: EntryOf<"grant_server">["payload"],
): void {
  state.servers.set(payload.serverKeyFingerprintHex, {
    keyFingerprintHex: payload.serverKeyFingerprintHex,
    scopeEnvironmentIds: payload.scopeEnvironmentIds,
    sinceSeq: seq,
  });
}

/** add_member: メンバー集合へ + 鍵 FP の追跡(前在籍と同じ鍵なら FP を引き継ぐ)。 */
function applyAddMember(
  state: FoldState,
  seq: number,
  payload: EntryOf<"add_member">["payload"],
): void {
  setMember(state, payload.targetUserId, payload.role, payload, seq);
  const previous = state.keys.get(payload.targetUserId);
  const sameKey =
    previous !== undefined &&
    previous.encPubHex === payload.encPubHex &&
    previous.sigPubHex === payload.sigPubHex;
  if (!sameKey) {
    state.fingerprints.set(payload.targetUserId, null);
  }
  state.keys.set(payload.targetUserId, {
    encPubHex: payload.encPubHex,
    sigPubHex: payload.sigPubHex,
  });
}

type OperationOf<Op extends ProposableEntry["op"]> = Extract<ProposableEntry, { op: Op }>;

// 適用済み op の畳み込み(直接追記と、定足数に達した approve の内側 op が共有する)。
// `seq` = 適用 seq(提案経由なら approve の seq — inclusive 規約)。create_environment /
// rotate_epoch / checkpoint / genesis はここに載せない(メンバー・サーバー集合に影響しない。
// genesis は deriveReportedView が鍵 FP の追跡込みで畳む)
const OPERATION_FOLDERS: {
  readonly [Op in ProposableEntry["op"]]?: (
    state: FoldState,
    seq: number,
    operation: OperationOf<Op>,
  ) => void;
} = {
  add_member: (state, seq, operation) => applyAddMember(state, seq, operation.payload),
  remove_member: (state, _seq, operation) =>
    void state.members.delete(operation.payload.targetUserId),
  change_role: (state, seq, operation) => applyChangeRole(state, seq, operation.payload),
  grant_server: (state, seq, operation) => applyGrantServer(state, seq, operation.payload),
  revoke_server: (state, _seq, operation) =>
    void state.servers.delete(operation.payload.serverKeyFingerprintHex),
  set_approval_policy: (state, _seq, operation) => {
    state.policy =
      operation.payload.requiredApprovals === 0
        ? null
        : {
            requiredApprovals: operation.payload.requiredApprovals,
            ops: [...new Set(operation.payload.ops)],
          };
  },
};

function applyOperation(state: FoldState, seq: number, operation: ProposableEntry): void {
  const fold = Object.hasOwn(OPERATION_FOLDERS, operation.op)
    ? (OPERATION_FOLDERS[operation.op] as
        | ((s: FoldState, q: number, o: ProposableEntry) => void)
        | undefined)
    : undefined;
  fold?.(state, seq, operation);
}

/** 原則 2 の S = {owner として提案した提案者} ∪ approvals。 */
function signersOf(pending: PendingFold): Vote[] {
  const proposer: Vote[] =
    pending.proposerRoleAtProposal === "owner"
      ? [{ userId: pending.proposerUserId, keyFingerprintHex: pending.proposerKeyFingerprintHex }]
      : [];
  return [...proposer, ...pending.approvals];
}

/** 1 票が数えられるか: 投票者が現 owner で、現在の鍵 FP(既知)が署名時と一致する。 */
function countsAsOwnerVote(state: FoldState, signer: Vote): boolean {
  return (
    state.members.get(signer.userId)?.role === "owner" &&
    state.fingerprints.get(signer.userId) === signer.keyFingerprintHex
  );
}

/** 票数 = S のうち「現 owner かつ鍵 FP が一致(既知)」の distinct user_id(再集計)。 */
function countedVoters(state: FoldState, signers: ReadonlyArray<Vote>): string[] {
  const counted = signers.filter((signer) => countsAsOwnerVote(state, signer));
  return [...new Set(counted.map((signer) => signer.userId))];
}

function applyPropose(state: FoldState, entry: EntryOf<"propose">, hash: string | undefined): void {
  if (hash === undefined) return;
  state.pending.set(hash, {
    seq: entry.seq,
    proposerUserId: entry.actor.userId,
    proposerKeyFingerprintHex: entry.actor.keyFingerprintHex,
    proposerRoleAtProposal: state.members.get(entry.actor.userId)?.role ?? "unknown",
    inner: entry.payload.inner,
    expiresAtMs: entry.payload.expiresAtMs,
    approvals: [],
  });
}

/**
 * approve: 票を記録し、再集計が現方針の required に達したら内側 op を適用して pending から
 * 外す(§6.2 — approve エントリの seq で適用)。チェーンに載っている approve は受理面で
 * 合意規則を通っている(無効なものは載らない)ので、ここでは票の算術だけを写す。
 */
function applyApprove(state: FoldState, entry: EntryOf<"approve">): void {
  const pending = state.pending.get(entry.payload.proposalHashHex);
  if (pending === undefined) return;
  const vote: Vote = {
    userId: entry.actor.userId,
    keyFingerprintHex: entry.actor.keyFingerprintHex,
  };
  if (!quorumReached(state, [...signersOf(pending), vote])) {
    pending.approvals.push(vote);
    return;
  }
  state.pending.delete(entry.payload.proposalHashHex);
  applyOperation(state, entry.seq, pending.inner);
}

/** 再集計した票数が現方針の required に達したか(方針オフなら達しない)。 */
function quorumReached(state: FoldState, signers: ReadonlyArray<Vote>): boolean {
  const required = state.policy?.requiredApprovals;
  return required !== undefined && countedVoters(state, signers).length >= required;
}

// 内側 op の 1 行要約(識別子は生のまま — 描画側が中和する)
const INNER_SUMMARIES: {
  readonly [Op in ProposableEntry["op"]]?: (operation: OperationOf<Op>) => string;
} = {
  add_member: (o) => `add ${o.payload.targetUserId} as ${o.payload.role}`,
  remove_member: (o) => `remove ${o.payload.targetUserId}`,
  change_role: (o) => `change ${o.payload.targetUserId} to ${o.payload.newRole}`,
  grant_server: (o) => `grant server key ${o.payload.serverKeyFingerprintHex}`,
  revoke_server: (o) => `revoke server key ${o.payload.serverKeyFingerprintHex}`,
  set_approval_policy: (o) =>
    o.payload.requiredApprovals === 0
      ? "turn the approval policy off"
      : `set the approval policy to ${o.payload.requiredApprovals} approvals`,
};

function summarizeInner(operation: ProposableEntry): string {
  const summarize = Object.hasOwn(INNER_SUMMARIES, operation.op)
    ? (INNER_SUMMARIES[operation.op] as ((o: ProposableEntry) => string) | undefined)
    : undefined;
  return summarize === undefined ? operation.op : summarize(operation);
}

function applyGenesis(state: FoldState, entry: EntryOf<"genesis">): void {
  setMember(state, entry.actor.userId, "owner", ALL_SCOPE, entry.seq);
  state.fingerprints.set(entry.actor.userId, entry.actor.keyFingerprintHex);
  state.keys.set(entry.actor.userId, {
    encPubHex: entry.payload.encPubHex,
    sigPubHex: entry.payload.sigPubHex,
  });
}

// エントリ自体の畳み込み(genesis と四眼の 4 op)。それ以外の状態を変える op は
// applyOperation(適用済み op の表 — 完成した approve の内側 op と共有)
const ENTRY_FOLDERS: {
  readonly [Op in ChainEntry["op"]]?: (
    state: FoldState,
    entry: EntryOf<Op>,
    hash: string | undefined,
  ) => void;
} = {
  genesis: applyGenesis,
  propose: applyPropose,
  approve: (state, entry) => applyApprove(state, entry),
  withdraw: (state, entry) => void state.pending.delete(entry.payload.proposalHashHex),
};

/** 1 エントリの畳み込み。 */
function foldEntry(state: FoldState, entry: ChainEntry, hash: string | undefined): void {
  // Object.hasOwn: 敵対的サーバーの op(例: "__proto__")がプロトタイプ鎖の
  // 値に当たって throw で描画を落とさないための自衛
  if (!Object.hasOwn(ENTRY_KINDS, entry.op)) return;
  const fold = Object.hasOwn(ENTRY_FOLDERS, entry.op)
    ? (ENTRY_FOLDERS[entry.op] as
        | ((s: FoldState, e: ChainEntry, h: string | undefined) => void)
        | undefined)
    : undefined;
  if (fold !== undefined) {
    fold(state, entry, hash);
    return;
  }
  applyOperation(state, entry.seq, entry as ProposableEntry);
}

// 畳み込みに載せる op の閉集合(own-property 判定用)。create_environment / rotate_epoch /
// checkpoint はメンバー・サーバー集合に影響しないため載せない。scope(add_member /
// change_role の末尾 2 フィールド)は K4(2026-09-15 ES — 設計録 K4-D)で、四眼の 4 op は
// K6(設計録 K6-J)で写す
const ENTRY_KINDS: { readonly [Op in ChainEntry["op"]]?: true } = {
  genesis: true,
  add_member: true,
  remove_member: true,
  change_role: true,
  grant_server: true,
  revoke_server: true,
  set_approval_policy: true,
  propose: true,
  approve: true,
  withdraw: true,
};

/**
 * 返された順のエントリ列を表示用のメンバー / サーバー集合・方針・pending 提案へ畳み込む。
 * `headHashHex` は末尾エントリの hash(応答の headHashHex — サーバー申告)。
 */
export function deriveReportedView(
  entries: ReadonlyArray<ChainEntry>,
  headHashHex?: string,
): ReportedChainView {
  const state: FoldState = {
    members: new Map(),
    servers: new Map(),
    policy: null,
    pending: new Map(),
    fingerprints: new Map(),
    keys: new Map(),
  };
  entries.forEach((entry, index) => {
    // 署名した本人の actor FP がそのメンバーの現在の鍵(受理面が検証済み — as reported)
    if (state.members.has(entry.actor.userId)) {
      state.fingerprints.set(entry.actor.userId, entry.actor.keyFingerprintHex);
    }
    // エントリ i の hash = エントリ i + 1 の prevHashHex、末尾は headHashHex
    foldEntry(state, entry, entries[index + 1]?.prevHashHex ?? headHashHex);
  });
  const proposals = [...state.pending]
    .map(([hash, pending]) => {
      const voters = countedVoters(state, signersOf(pending));
      return {
        proposalHashHex: hash,
        proposalSeq: pending.seq,
        proposerUserId: pending.proposerUserId,
        proposerRoleAtProposal: pending.proposerRoleAtProposal,
        innerOp: pending.inner.op,
        innerSummary: summarizeInner(pending.inner),
        expiresAtMs: pending.expiresAtMs,
        votes: voters.length,
        voterUserIds: voters,
      };
    })
    .toSorted((a, b) => a.proposalSeq - b.proposalSeq);
  return {
    members: [...state.members.values()],
    servers: [...state.servers.values()],
    policy: state.policy,
    proposals,
  };
}
