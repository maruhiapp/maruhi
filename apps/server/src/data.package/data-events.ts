// The audit events a data operation writes (AUDIT_SPEC §3.3): the event
// names and payloads open to a user actor, and the builders of the event row
// and of a DEK wrap row's audit target.

import type {
  AuditEventColumns,
  ChainMirrorEventName,
  ProjectAuditEventName,
  ProjectAuditEventPayload,
} from "@maruhi/core";

import type { AuditEventInput } from "../audit-store.ts";
import type { DataActor, DekRecipientPosition } from "./data-plane.ts";

/**
 * The events a data operation's actor writes (AUDIT_SPEC §3.3) — never a
 * chain mirror row (§3.4), a server access row (§3.5) or a row whose actor
 * is the system (detection, a workload's proposal, an expiry sweep).
 */
type DataEventName = Exclude<
  ProjectAuditEventName,
  | ChainMirrorEventName
  | `server.${string}`
  | "rotation.recommended"
  | "rotation.proposed"
  | "rotation.proposal_expired"
>;

/**
 * The payload a user actor writes for a data event: the event's own
 * (audit-payloads.ts), except `dek.deleted`, whose cause-naming payload is
 * the system actor's cleanup on a member's re-add (chain-accept.ts) — a
 * user's deletion (the §12-6 repair path) writes none.
 */
type UserActorPayload<E extends DataEventName> = E extends "dek.deleted"
  ? { readonly event: E; readonly payload?: never }
  : Extract<ProjectAuditEventPayload, { readonly event: E }>;

/** A data event's name, payload and columns — a discriminated union on the name. */
export type DataEventFields = {
  readonly [E in DataEventName]: Pick<
    AuditEventColumns,
    | "environmentId"
    | "variableId"
    | "epoch"
    | "version"
    | "targetUserId"
    | "targetKeyFingerprintHex"
    | "actorKeyFingerprintHex"
  > &
    UserActorPayload<E>;
}[DataEventName];

/**
 * Build the audit event of a data operation (AUDIT_SPEC §3.3). The
 * actor's auth_method rides the actor (`actorAuthMethod`) and the store
 * merges it into the stored payload (§5.1: only frequent attributes are
 * promoted to columns).
 * The actor's key FP is in principle absent (the chain mirror's
 * exclusive remit), but operations accompanied by a client signature
 * (dek.registered, the value writes, the meta statements, the
 * environment deletion) record the signer FP into actorKeyFingerprintHex
 * (AUDIT_SPEC §3.3 — for cross-checking the audit row against the
 * chain-external signature).
 */
export function dataEvent(
  actor: DataActor,
  serverTs: number,
  fields: DataEventFields,
): AuditEventInput {
  return {
    ...fields,
    serverTs,
    actorType: "user",
    actorUserId: actor.userId,
    ...(actor.apiTokenId === undefined ? {} : { actorApiTokenId: actor.apiTokenId }),
    ...(actor.authMethod === undefined ? {} : { actorAuthMethod: actor.authMethod }),
  };
}

/**
 * The audit target of a DEK wrap row (AUDIT_SPEC §3.3): the recipient
 * position holds a member's user id, or the server key FP for recipient
 * class server (CRYPTO_SPEC §9). A server recipient has no user_id (the
 * §2 actor model), so its FP goes on target_key_fingerprint, never into
 * the user-id column. The class already decided the id's brand at the
 * wire (DekRecipientPosition), so this only routes it to its column.
 */
export function dekRecipientTarget(
  recipient: DekRecipientPosition,
): Pick<AuditEventInput, "targetUserId" | "targetKeyFingerprintHex"> {
  return recipient.recipientClass === "server"
    ? { targetKeyFingerprintHex: recipient.recipientUserId }
    : { targetUserId: recipient.recipientUserId };
}
