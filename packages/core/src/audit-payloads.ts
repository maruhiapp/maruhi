// The per-event audit payloads (AUDIT_SPEC §3), one Effect Schema per event
// — the app-layer enforcement of the per-event attributes that §5.1
// prescribes. The audit records' types are derived from these schemas (a
// discriminated union keyed by the event name), and each store checks a
// payload against its schema at its single serialization point, rejecting
// any key the spec does not list.
//
// Gate of the identity rule (§1-2, CLAUDE.md): an append-only row never
// carries a provider identity. A payload can hold only the attributes of
// §3's tables for its event — none of which is a provider identifier — and
// its free-text fields are `AuditText`, which refuses a value typed
// `ProviderUserId` at compile time (a guard, not a sound exclusion — see its
// doc). The only provider-derived values §1-2 allows are the authentication
// means' kind name (`authMethod`) and the provider's kind name
// (`auth.identity_linked`'s `provider`).
//
// Two maps, one per store: the project events (§3.3–§3.5 — the project DO's
// log) and the user / org events (§3.1–§3.2 — D1). An event absent from a
// map cannot be written to that store. Events the spec reserves or the code
// does not write yet (`server.value_decrypted`, `org.renamed`, …) are not
// listed; writing one starts by adding its row here from the spec.
//
// The session actor's `authMethod` (§2) is not part of these payloads: it
// rides the actor (`actorAuthMethod` / `D1AuditActor.authMethod`) and each
// store merges it into the stored payload (`auditPayloadWith`).

import { APPROVAL_TARGET_OPS } from "@maruhi/crypto";
import { Exit, Schema } from "effect";

import { OrgRoleSchema, TokenScopeSchema } from "./auth.ts";
import { KeyFingerprintHexSchema, type ProviderUserId } from "./identity.ts";

/** What a {@link ProviderUserId} carries beyond a string: its brand marker (derived, so it follows the brand's definition). */
type ProviderSubjectMarker = Omit<ProviderUserId, keyof string>;

/**
 * Free text in an audit payload: any string except a provider subject. A
 * type-level exclusion only — a provider subject is a string at runtime. It
 * refuses a value typed `ProviderUserId`, but not soundly: a union of one
 * with a plain string widens to `string`, which is audit text. So it is a
 * guard against the direct mistake; what closes a payload is the per-event
 * key set below and the stores' runtime check. The display login is a plain
 * string (identity.ts), so no type tells it from other text: the key set
 * keeps out every attribute that would carry it (a login, a personal org's
 * name), and a free-text attribute's value is the writer's (review's) charge.
 */
export type AuditText = string & {
  readonly [K in keyof ProviderSubjectMarker]?: {
    readonly [B in keyof ProviderSubjectMarker[K]]?: never;
  };
};

function isAuditText(_value: string): _value is AuditText {
  return true;
}

const Text = Schema.String.pipe(
  Schema.refine(isAuditText, { expected: "audit text (never a provider subject)" }),
);
const Seq = Schema.Int;
const Role = Schema.Literals(["owner", "admin", "member", "reader"]);
const ScopeKind = Schema.Literals(["all", "listed"]);
const GuardianMode = Schema.Literals(["any", "all"]);
const Imported = Schema.Literal(true);

/** A name snapshot (§3.3 — environment and variable names are plaintext metadata in v1). */
const NameSnapshot = Schema.Struct({ name: Text });

/** The scope copied from a membership entry (§3.4 — the input of §4.1's access windows). */
const scopeFields = { scopeKind: ScopeKind, scopeEnvironmentIds: Schema.Array(Text) };

/**
 * A chain mirror payload (§3.4). An inner operation applied by a completed
 * `approve` is written at the approve's seq with `viaProposalSeq` added (PF1).
 */
function chainPayload<const Fields extends Schema.Struct.Fields>(fields: Fields) {
  return Schema.Struct({ ...fields, viaProposalSeq: Schema.optionalKey(Seq) });
}

/** A chain mirror row whose op carries nothing into the audit row (§3.4) — except an applied row's `viaProposalSeq`. */
const chainNoPayload = Schema.UndefinedOr(Schema.Struct({ viaProposalSeq: Seq }));

/** The rotation-needed basis (§4.1 step 3). */
export const ROTATION_BASES = ["read", "readable"] as const;

/** The operation that triggered a rotation-needed detection (§3.3 / §4.1). */
export const ROTATION_TRIGGERS = [
  "remove_member",
  "change_role",
  "revoke_server",
  "revoke_device",
] as const;

/** The project events (AUDIT_SPEC §3.3–§3.5) — the project DO's log. */
const PROJECT_AUDIT_PAYLOADS = {
  // §3.3 project data events
  "env.created": NameSnapshot,
  "env.renamed": NameSnapshot,
  "env.deleted": NameSnapshot,
  "var.created": NameSnapshot,
  "var.renamed": NameSnapshot,
  "var.schema_reissued": NameSnapshot,
  "var.deleted": Schema.Undefined,
  "var.version_pushed": Schema.UndefinedOr(Schema.Struct({ sameValueAs: Schema.Int })),
  "var.read": Schema.Struct({
    variables: Schema.Array(Schema.Struct({ variableId: Text, epoch: Seq, version: Seq })),
  }),
  "dek.registered": Schema.Undefined,
  // The admin repair path has no payload; the cleanup on re-add (actor system) names its cause
  "dek.deleted": Schema.UndefinedOr(
    Schema.Struct({ cause: Schema.Literal("member-readded"), triggerChainSeq: Seq }),
  ),
  "rotation.recommended": Schema.Struct({
    basis: Schema.Literals(ROTATION_BASES),
    triggerChainSeq: Seq,
    trigger: Schema.Literals(ROTATION_TRIGGERS),
    revokedDeviceKeyFingerprints: Schema.optionalKey(Schema.Array(KeyFingerprintHexSchema)),
  }),
  "rotation.dismissed": Schema.Undefined,
  "rotation.proposed": Schema.Struct({
    proposalId: Text,
    variableIds: Schema.Array(Text),
    claimsDigest: Text,
    grantChainSeq: Seq,
    connector: Text,
  }),
  "rotation.proposal_accepted": Schema.Struct({
    proposalId: Text,
    versions: Schema.Array(Schema.Struct({ variableId: Text, version: Seq })),
  }),
  "rotation.proposal_rejected": Schema.Struct({ proposalId: Text }),
  "rotation.proposal_expired": Schema.Struct({ proposalId: Text, expiresAtMs: Schema.Number }),
  "project.schema_policy_changed": Schema.Struct({
    previous: Schema.Literals(["enabled", "locked"]),
    next: Schema.Literals(["enabled", "locked"]),
  }),
  "project.exported": Schema.Struct({ chainHeadSeq: Seq, chainHeadHashHex: Text }),
  // §3.4 chain mirror
  "chain.genesis": chainNoPayload,
  "chain.member_added": chainPayload({ role: Role, ...scopeFields }),
  "chain.member_removed": chainNoPayload,
  "chain.role_changed": chainPayload({ newRole: Role, ...scopeFields }),
  "chain.environment_created": chainPayload({ dekCommitmentHex: Text }),
  "chain.environment_deleted": chainNoPayload,
  "chain.epoch_rotated": chainPayload({ reason: Text, dekCommitmentHex: Text }),
  "chain.server_granted": chainPayload({ scopeEnvironmentIds: Schema.Array(Text) }),
  "chain.server_revoked": chainNoPayload,
  "chain.checkpointed": chainPayload({
    environments: Schema.Array(
      Schema.Struct({
        environmentId: Text,
        epoch: Seq,
        manifestVersion: Seq,
        manifestSigHashHex: Text,
        valuesDigestHex: Text,
      }),
    ),
    auditHeadHashHex: Text,
  }),
  "chain.approval_policy_changed": chainPayload({
    ops: Schema.Array(Schema.Literals(APPROVAL_TARGET_OPS)),
    requiredApprovals: Seq,
  }),
  "chain.proposed": Schema.Struct({ innerOp: Text, expiresAtMs: Schema.Number }),
  "chain.approved": Schema.Struct({ proposalChainSeq: Seq, completed: Schema.Boolean }),
  "chain.proposal_withdrawn": Schema.Struct({ proposalChainSeq: Seq }),
  "chain.device_added": chainPayload({
    deviceKeyFingerprint: KeyFingerprintHexSchema,
    roleCap: Role,
    ...scopeFields,
  }),
  "chain.device_revoked": chainPayload({
    deviceKeyFingerprints: Schema.Array(KeyFingerprintHexSchema),
  }),
  // §3.5 server access via grant_server
  "server.dek_unwrapped": Schema.Undefined,
  "server.lease_issued": Schema.Struct({
    grantChainSeq: Seq,
    claimsDigest: Text,
    epochs: Schema.Array(Seq),
  }),
  "server.lease_denied": Schema.Struct({
    reason: Text,
    claimsDigest: Schema.optionalKey(Text),
  }),
};

/** The ledger kinds of the reserve-key wrap ledger (§3.1 — AUTH_SPEC §13-7). */
const passkeyWrap = Schema.Struct({ kind: Schema.Literal("passkey-prf"), wrapId: Text });

/** The fixed-window suppression marker (§3.1): only the classification, the window, the cap and the count. */
const SuppressionMarker = Schema.Struct({
  authMethod: Text,
  reason: Text,
  windowMs: Schema.Int,
  limit: Schema.Int,
  suppressedCount: Schema.Int,
});

/** The user / org events (AUDIT_SPEC §3.1–§3.2) — D1. */
const USER_ORG_AUDIT_PAYLOADS = {
  // §3.1 auth events. A Web login copies the session id hash; a CLI login the flow id
  "auth.login_succeeded": Schema.Union([
    Schema.Struct({ sessionId: Text }),
    Schema.Struct({ flowId: Text }),
  ]),
  // Unauthenticated (no actor user id): the kind name and the reason only — never the presented external id
  "auth.login_failed": Schema.Struct({ authMethod: Text, reason: Text }),
  "auth.login_failed_suppressed": SuppressionMarker,
  "auth.signup_denied": Schema.Struct({
    authMethod: Text,
    reason: Schema.Literals(["policy-closed", "invite-required", "invite-invalid"]),
  }),
  "auth.signup_denied_suppressed": SuppressionMarker,
  "auth.session_revoked": Schema.Struct({ sessionId: Text }),
  // replacedTokenId is added by the SQL of a same-name rotation (the row that actually vanished)
  "auth.token_created": Schema.Struct({
    tokenId: Text,
    name: Text,
    scopes: Schema.Array(TokenScopeSchema),
    replacedTokenId: Schema.optionalKey(Text),
  }),
  "auth.token_revoked": Schema.Struct({ tokenId: Text }),
  // The provider's kind name only (§3.1) — provider_user_id and the login are never recorded
  "auth.identity_linked": Schema.Struct({ provider: Schema.Literal("github") }),
  "auth.recovery_blob_fetched": Schema.Undefined,
  "auth.recovery_code_reissued": Schema.Undefined,
  "auth.key_wrap_registered": Schema.Union([
    passkeyWrap,
    Schema.Struct({
      kind: Schema.Literal("guardian"),
      groupId: Text,
      mode: GuardianMode,
      recipientCount: Schema.Int,
    }),
  ]),
  "auth.key_wrap_removed": Schema.Union([
    passkeyWrap,
    Schema.Struct({ kind: Schema.Literal("guardian"), groupId: Text }),
  ]),
  "auth.key_wrap_fetched": Schema.Union([
    passkeyWrap,
    Schema.Struct({ kind: Schema.Literal("guardian"), groupId: Text }),
  ]),
  "auth.guardian_designated": Schema.Struct({
    groupId: Text,
    mode: GuardianMode,
    shareIndex: Schema.Int,
  }),
  "auth.guardian_released": Schema.Struct({
    groupId: Text,
    mode: GuardianMode,
    shareIndex: Schema.Int,
  }),
  "auth.guardian_share_fetched": Schema.Struct({ groupId: Text, shareIndex: Schema.Int }),
  "auth.key_handoff_requested": Schema.Struct({ requestId: Text }),
  // D1 rows have no actor key column, so the approving device's fingerprint rides the payload
  "auth.key_handoff_approved": Schema.Struct({
    requestId: Text,
    source: Text,
    shareIndex: Schema.Int,
    approverKeyFingerprintHex: KeyFingerprintHexSchema,
  }),
  "auth.key_handoff_collected": Schema.Struct({ requestId: Text, approvalCount: Schema.Int }),
  // A signup consuming an invite names the invite row (an internal ULID); a restore marks the import
  "auth.user_created": Schema.UndefinedOr(
    Schema.Union([Schema.Struct({ signupInviteId: Text }), Schema.Struct({ imported: Imported })]),
  ),
  // §3.2 org events. A personal org's name derives from the login, so it is never copied
  "org.created": Schema.Struct({
    personal: Schema.Literal(true),
    imported: Schema.optionalKey(Imported),
  }),
  "org.member_added": Schema.Struct({ role: OrgRoleSchema }),
  "org.project_created": Schema.UndefinedOr(Schema.Struct({ imported: Imported })),
  "invite.created": Schema.Struct({ inviteId: Text, role: Role }),
  // The accepting key's fingerprint only — not the backing source's login, the link key or a signature (§3.2 — IV)
  "invite.accepted": Schema.Struct({
    inviteId: Text,
    inviteeKeyFingerprintHex: KeyFingerprintHexSchema,
  }),
  "invite.revoked": Schema.Struct({ inviteId: Text, role: Role }),
};

type ProjectPayloadSchemas = typeof PROJECT_AUDIT_PAYLOADS;
type UserOrgPayloadSchemas = typeof USER_ORG_AUDIT_PAYLOADS;

/** A project event name (§3.3–§3.5). */
export type ProjectAuditEventName = keyof ProjectPayloadSchemas;

/** A user / org event name (§3.1–§3.2). */
type UserOrgAuditEventName = keyof UserOrgPayloadSchemas;

/** The `chain.` mirror event names (§3.4). */
export type ChainMirrorEventName = Extract<ProjectAuditEventName, `chain.${string}`>;

/** The payload of a project event (`undefined` = the event writes no payload). */
export type ProjectAuditPayload<E extends ProjectAuditEventName> = ProjectPayloadSchemas[E]["Type"];

/** The payload of a user / org event (`undefined` = the event writes no payload). */
type UserOrgAuditPayload<E extends UserOrgAuditEventName> = UserOrgPayloadSchemas[E]["Type"];

/**
 * The payload field of a record: required when the event always writes one,
 * optional when it may write none, absent when it never writes one.
 */
type PayloadField<P> = [P] extends [undefined]
  ? { readonly payload?: never }
  : undefined extends P
    ? { readonly payload?: Exclude<P, undefined> }
    : { readonly payload: P };

/** An event name with its payload field, as a discriminated union over the project events. */
export type ProjectAuditEventPayload = {
  readonly [E in ProjectAuditEventName]: { readonly event: E } & PayloadField<
    ProjectAuditPayload<E>
  >;
}[ProjectAuditEventName];

/** An event name with its payload field, as a discriminated union over the user / org events. */
export type UserOrgAuditEventPayload = {
  readonly [E in UserOrgAuditEventName]: { readonly event: E } & PayloadField<
    UserOrgAuditPayload<E>
  >;
}[UserOrgAuditEventName];

/**
 * Checks a payload against its event's schema, rejecting a key the spec does
 * not list. The types already hold this at every write; the check holds it
 * against a value that escaped them (a widened object, an assertion). A
 * violation is a producer bug and throws (a defect — the append and the
 * write it belongs to roll back together), naming the event, never a value.
 */
function assertPayload(
  schemas: Readonly<Record<string, Schema.ConstraintDecoder<unknown>>>,
  store: string,
  event: string,
  payload: unknown,
): void {
  const schema = Object.hasOwn(schemas, event) ? schemas[event] : undefined;
  if (schema === undefined) {
    throw new Error(`audit invariant violation: ${event} is not a ${store} event (AUDIT_SPEC §3)`);
  }
  const checked = Schema.decodeUnknownExit(schema, { onExcessProperty: "error" })(payload);
  if (Exit.isFailure(checked)) {
    throw new Error(
      `audit invariant violation: the ${event} payload is not the AUDIT_SPEC §3 shape`,
    );
  }
}

/** Checks a project event's payload (the project DO's append — AUDIT_SPEC §5.1). */
export function assertProjectAuditPayload(record: {
  readonly event: string;
  readonly payload?: unknown;
}): void {
  assertPayload(PROJECT_AUDIT_PAYLOADS, "project", record.event, record.payload);
}

/** Checks a user / org event's payload (the D1 append — AUDIT_SPEC §5.2). */
export function assertUserOrgAuditPayload(record: {
  readonly event: string;
  readonly payload?: unknown;
}): void {
  assertPayload(USER_ORG_AUDIT_PAYLOADS, "user / org", record.event, record.payload);
}
