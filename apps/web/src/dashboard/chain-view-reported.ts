export interface ReportedDevice {
  keyFingerprintHex: string | null;
  encPubHex: string;
  sigPubHex: string;
  roleCap: string;
  scopeKind: "all" | "listed";
  scopeEnvironmentIds: ReadonlyArray<string>;
  addedSeq: number;
}

export interface ReportedMember {
  userId: string;
  role: string;
  scopeKind: "all" | "listed";
  scopeEnvironmentIds: ReadonlyArray<string>;
  sinceSeq: number;
  devices: ReadonlyArray<ReportedDevice>;
  unresolvedRevocations: number;
}

export function reportedDeviceCount(
  member: Pick<ReportedMember, "devices" | "unresolvedRevocations">,
): number {
  return member.devices.length - member.unresolvedRevocations;
}

export interface ReportedServer {
  keyFingerprintHex: string;
  scopeEnvironmentIds: ReadonlyArray<string>;
  sinceSeq: number;
}

export interface ReportedPolicy {
  requiredApprovals: number;
  ops: ReadonlyArray<string>;
}

export interface ReportedProposal {
  proposalHashHex: string;
  proposalSeq: number;
  proposerUserId: string;
  innerOp: string;
  innerSummary: string;
  expiresAtMs: number;
  votes: number;
  voterUserIds: ReadonlyArray<string>;
}

export interface ReportedChainView {
  members: ReportedMember[];
  servers: ReportedServer[];
  policy: ReportedPolicy | null;
  proposals: ReportedProposal[];
  unreadableEntries: number;
}
