// チェーン取得応答からの表示用ビューの導出(S5 — 設計文書 §3)。
//
// これは**検証ではない**(ADR-0018 改訂 2・4 項 — Web バンドルにチェーン・署名
// 検証のコードを入れない): サーバーが返したエントリ列を、返された順で
// 機械的に畳み込むだけの表示変換であり、署名・ハッシュ連結・合意規則の検査を
// 一切行わない。結果はすべて「サーバー申告(as reported by the server)」で
// あり、UI もそう表示する。検証済みのメンバー集合が要る場面は
// `maruhi project verify`(CLI)の領分。
import type { ChainEntry } from "./types.ts";

/** One member row derived from the reported entries (server-reported, unverified). */
export interface ReportedMember {
  userId: string;
  role: string;
  /** The reported chain seq that last set this member's role. */
  sinceSeq: number;
}

/** One granted server key derived from the reported entries (server-reported). */
export interface ReportedServer {
  keyFingerprintHex: string;
  scopeEnvironmentIds: ReadonlyArray<string>;
  sinceSeq: number;
}

export interface ReportedChainView {
  members: ReportedMember[];
  servers: ReportedServer[];
}

interface FoldState {
  members: Map<string, ReportedMember>;
  servers: Map<string, ReportedServer>;
}

type EntryOf<Op extends ChainEntry["op"]> = Extract<ChainEntry, { op: Op }>;

function setMember(state: FoldState, userId: string, role: string, sinceSeq: number): void {
  state.members.set(userId, { userId, role, sinceSeq });
}

function applyChangeRole(state: FoldState, entry: EntryOf<"change_role">): void {
  const existing = state.members.get(entry.payload.targetUserId);
  if (existing !== undefined) {
    setMember(state, existing.userId, entry.payload.newRole, entry.seq);
  }
}

function applyGrantServer(state: FoldState, entry: EntryOf<"grant_server">): void {
  state.servers.set(entry.payload.serverKeyFingerprintHex, {
    keyFingerprintHex: entry.payload.serverKeyFingerprintHex,
    scopeEnvironmentIds: entry.payload.scopeEnvironmentIds,
    sinceSeq: entry.seq,
  });
}

// op ごとの畳み込み(表示変換のみ)。create_environment / rotate_epoch /
// checkpoint はメンバー・サーバー集合に影響しないため写像に載せない
const ENTRY_FOLDERS: { [Op in ChainEntry["op"]]?: (state: FoldState, entry: EntryOf<Op>) => void } =
  {
    genesis: (state, entry) => setMember(state, entry.actor.userId, "owner", entry.seq),
    add_member: (state, entry) =>
      setMember(state, entry.payload.targetUserId, entry.payload.role, entry.seq),
    remove_member: (state, entry) => state.members.delete(entry.payload.targetUserId),
    change_role: applyChangeRole,
    grant_server: applyGrantServer,
    revoke_server: (state, entry) => state.servers.delete(entry.payload.serverKeyFingerprintHex),
  };

/** 返された順のエントリ列を表示用のメンバー / サーバー集合へ畳み込む。 */
export function deriveReportedView(entries: ReadonlyArray<ChainEntry>): ReportedChainView {
  const state: FoldState = { members: new Map(), servers: new Map() };
  for (const entry of entries) {
    const fold = ENTRY_FOLDERS[entry.op] as ((s: FoldState, e: ChainEntry) => void) | undefined;
    fold?.(state, entry);
  }
  return { members: [...state.members.values()], servers: [...state.servers.values()] };
}
