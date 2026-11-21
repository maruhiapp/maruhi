import type {
  AuditEventColumns,
  ChainMirrorEventName,
  ProjectAuditEventName,
  ProjectAuditEventPayload,
} from "@maruhi/core";

import type { AuditEventInput } from "../audit-store.ts";
import type { DataActor, DekRecipientPosition } from "./data-plane.ts";

type DataEventName = Exclude<
  ProjectAuditEventName,
  | ChainMirrorEventName
  | `server.${string}`
  | "rotation.recommended"
  | "rotation.proposed"
  | "rotation.proposal_expired"
>;

type UserActorPayload<E extends DataEventName> = E extends "dek.deleted"
  ? { readonly event: E; readonly payload?: never }
  : Extract<ProjectAuditEventPayload, { readonly event: E }>;

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

export function dekRecipientTarget(
  recipient: DekRecipientPosition,
): Pick<AuditEventInput, "targetUserId" | "targetKeyFingerprintHex"> {
  return recipient.recipientClass === "server"
    ? { targetKeyFingerprintHex: recipient.recipientUserId }
    : { targetUserId: recipient.recipientUserId };
}
