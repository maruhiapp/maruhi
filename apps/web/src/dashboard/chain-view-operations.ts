// See chain-view.ts for the display-only contract.

import {
  hasStrings,
  isStringArray,
  ownProp,
  reportedScope,
  startTenure,
  type EntryOf,
  type FoldState,
  type OperationFolder,
  type ProposableEntry,
} from "./chain-view-state.ts";
import { isRecord } from "./json-record.ts";

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
  if (existing !== undefined) {
    // Full replacement by the new (role, scope) (§6.2 — scope is also
    // copied per 2026-09-15 ES K4). The device set is unchanged
    const scope = reportedScope(payload);
    existing.role = payload.newRole;
    existing.scopeKind = scope.scopeKind;
    existing.scopeEnvironmentIds = scope.scopeEnvironmentIds;
    existing.sinceSeq = seq;
  }
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

/** add_member: starts a membership interval (the first device = the payload's key. Same key as the previous interval inherits the FP). */
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

// The fold of applied ops (shared between a direct append and an
// approve's inner op that reached quorum).
// `seq` = the application seq (the approve's seq when it came via a
// proposal — the inclusive convention). create_environment /
// rotate_epoch / checkpoint / genesis are not here (they do not affect
// the member/server sets; genesis is folded by deriveReportedView with
// key-FP tracking). delete_environment and the 2 device ops are not
// here either: they are never four-eyes targets, so they fold only as
// direct entries (chain-view.ts ENTRY_FOLDERS — K5-4)
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
  // An unmodeled inner op is ignored (K5-4). Because the folders read
  // the payload's fields, a non-record payload is counted here as an
  // unreadable row (same discipline as K5-17)
  if (fold === undefined) return;
  if (!isRecord(operation.payload)) {
    state.unreadableEntries += 1;
    return;
  }
  fold(state, seq, operation);
}
