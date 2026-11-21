import {
  hasStrings,
  isStringArray,
  ownProp,
  reportedScope,
  startTenure,
  type EntryOf,
  type FoldState,
  type MutableMember,
  type OperationFolder,
  type ProposableEntry,
} from "./chain-view-state.ts";
import { isRecord } from "./json-record.ts";

function holdsRoleAndScope(
  member: MutableMember,
  role: string,
  scope: Pick<MutableMember, "scopeKind" | "scopeEnvironmentIds">,
): boolean {
  const ids = new Set(member.scopeEnvironmentIds);
  return (
    member.role === role &&
    member.scopeKind === scope.scopeKind &&
    ids.size === new Set(scope.scopeEnvironmentIds).size &&
    scope.scopeEnvironmentIds.every((id) => ids.has(id))
  );
}

function applyChangeRole(
  state: FoldState,
  seq: number,
  payload: EntryOf<"change_role">["payload"],
): void {
  if (!hasStrings(payload, ["targetUserId", "newRole"])) {
    state.unreadableEntries += 1;
    return;
  }
  const existing = state.members.get(payload.targetUserId);
  if (existing === undefined) return;
  const scope = reportedScope(payload);
  if (!holdsRoleAndScope(existing, payload.newRole, scope)) existing.sinceSeq = seq;
  existing.role = payload.newRole;
  existing.scopeKind = scope.scopeKind;
  existing.scopeEnvironmentIds = scope.scopeEnvironmentIds;
}

function applyGrantServer(
  state: FoldState,
  seq: number,
  payload: EntryOf<"grant_server">["payload"],
): void {
  if (typeof payload.serverKeyFingerprintHex !== "string") {
    state.unreadableEntries += 1;
    return;
  }
  state.servers.set(payload.serverKeyFingerprintHex, {
    keyFingerprintHex: payload.serverKeyFingerprintHex,
    scopeEnvironmentIds: isStringArray(payload.scopeEnvironmentIds)
      ? payload.scopeEnvironmentIds
      : [],
    sinceSeq: seq,
  });
}

function applyAddMember(
  state: FoldState,
  seq: number,
  payload: EntryOf<"add_member">["payload"],
): void {
  if (!hasStrings(payload, ["targetUserId", "role", "encPubHex", "sigPubHex"])) {
    state.unreadableEntries += 1;
    return;
  }
  startTenure(state, payload.targetUserId, payload.role, reportedScope(payload), payload, seq);
}

export type OperationOf<Op extends ProposableEntry["op"]> = Extract<ProposableEntry, { op: Op }>;

const OPERATION_FOLDERS: {
  readonly [Op in ProposableEntry["op"]]?: (
    state: FoldState,
    seq: number,
    operation: OperationOf<Op>,
  ) => void;
} = {
  add_member: (state, seq, operation) => applyAddMember(state, seq, operation.payload),
  remove_member: (state, _seq, operation) => {
    if (typeof operation.payload.targetUserId === "string") {
      state.members.delete(operation.payload.targetUserId);
    } else {
      state.unreadableEntries += 1;
    }
  },
  change_role: (state, seq, operation) => applyChangeRole(state, seq, operation.payload),
  grant_server: (state, seq, operation) => applyGrantServer(state, seq, operation.payload),
  revoke_server: (state, _seq, operation) => {
    if (typeof operation.payload.serverKeyFingerprintHex === "string") {
      state.servers.delete(operation.payload.serverKeyFingerprintHex);
    } else {
      state.unreadableEntries += 1;
    }
  },
  set_approval_policy: (state, _seq, operation) => {
    const { requiredApprovals, ops } = operation.payload;
    if (typeof requiredApprovals !== "number" || !isStringArray(ops)) {
      state.unreadableEntries += 1;
      return;
    }
    state.policy = requiredApprovals === 0 ? null : { requiredApprovals, ops: [...new Set(ops)] };
  },
};

export function applyOperation(state: FoldState, seq: number, operation: ProposableEntry): void {
  const fold = ownProp(OPERATION_FOLDERS, operation.op) as OperationFolder | undefined;
  if (fold === undefined) return;
  if (!isRecord(operation.payload)) {
    state.unreadableEntries += 1;
    return;
  }
  fold(state, seq, operation);
}
