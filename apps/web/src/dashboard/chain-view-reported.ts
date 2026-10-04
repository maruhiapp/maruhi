// See chain-view.ts for the display-only contract.

/**
 * One device key of a member, derived from the reported entries (server-reported,
 * unverified). `keyFingerprintHex` is null while the fingerprint could not be
 * bound from the reported bytes (the `add_device` wire carries public keys, not
 * the fingerprint — K5-1); the cap and the adding seq are always reported.
 */
export interface ReportedDevice {
  keyFingerprintHex: string | null;
  encPubHex: string;
  sigPubHex: string;
  /** Role cap as reported (`owner` = no bound — CRYPTO_SPEC §6.2). */
  roleCap: string;
  scopeKind: "all" | "listed";
  scopeEnvironmentIds: ReadonlyArray<string>;
  /** The reported chain seq that put this key on the chain (genesis / add_member / add_device). */
  addedSeq: number;
}

/** One member row derived from the reported entries (server-reported, unverified). */
export interface ReportedMember {
  userId: string;
  role: string;
  /** Environment scope as reported (CRYPTO_SPEC §6.2 — `all`, or the listed environment ids). */
  scopeKind: "all" | "listed";
  scopeEnvironmentIds: ReadonlyArray<string>;
  /** The reported chain seq that last set this member's role / scope. */
  sinceSeq: number;
  /** The member's device keys as reported (may include revoked-but-unresolved ones — see below). */
  devices: ReadonlyArray<ReportedDevice>;
  /**
   * Devices revoked among the fingerprint-less ones whose identity the reported
   * bytes cannot resolve (K5-1). The active device count is
   * `devices.length - unresolvedRevocations` (`reportedDeviceCount`).
   */
  unresolvedRevocations: number;
}

/** Active device count as reported (row count minus the unresolved revocations). */
export function reportedDeviceCount(
  member: Pick<ReportedMember, "devices" | "unresolvedRevocations">,
): number {
  return member.devices.length - member.unresolvedRevocations;
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
  /**
   * Entries the fold could not read and left out (the K5-17 generalization): unknown actor / target,
   * a key already held, a fingerprint that is not the target's, a revocation that would
   * leave no device, a malformed payload, or a malformed envelope (non-record entry,
   * actor without a string id/fingerprint, non-record payload). A dropped `add_device`
   * leaves a device out; a dropped `revoke_device` leaves one in — so the displayed sets
   * may be smaller or larger than what those rows would have produced. Shown, never
   * silently absorbed. Ops the fold does not model at all are not counted.
   */
  unreadableEntries: number;
}
