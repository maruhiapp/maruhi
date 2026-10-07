// The per-event audit payloads (AUDIT_SPEC §3), one Effect Schema per event
// — the app-layer enforcement of the per-event attributes that §5.1
// prescribes. The audit records' types are derived from these schemas (a
// discriminated union keyed by the event name), and each store checks a
// payload against its schema at its single serialization point, rejecting
// any key the spec does not list.
//
// Gate of the identity rule (§1-2, CLAUDE.md): an append-only row never
// carries a provider identity. A payload can hold only the attributes §3
// lists for its event — none of which is a provider identifier. Every
// attribute that carries server vocabulary (a reason code, a kind name, an
// op name, a connector) is a closed literal set derived from its single
// definition, so the remaining free text is user-authored content (name
// snapshots, a token's name, a rotation's reason) and identifiers or
// digests. Those are `AuditText`, which refuses a value typed
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

import { APPROVAL_TARGET_OPS, type ProposableOperation } from "@maruhi/crypto";
import { Exit, Schema } from "effect";

import {
  AUTH_FLOW_FAILURE_REASONS,
  AUTH_METHODS,
  OrgRoleSchema,
  SIGNUP_DENIAL_REASONS,
  TokenScopeSchema,
} from "./auth.ts";
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

/**
 * The connector that minted a sealed value proposal (AUTH_SPEC §14-5 — the
 * rotation config's vocabulary, docs/rotation). The single definition: the
 * api-schema wire literal and the server's stored-row check derive from it.
 */
export const ROTATION_CONNECTORS = [
  "aws-iam-access-key",
  "cloudflare-api-token",
  "postgres",
  "mysql",
  "exec",
] as const;

/**
 * Why a workload lease was refused after its OIDC signature verified
 * (`server.lease_denied` — §3.5; AUTH_SPEC §14). The `reseal-*` reasons are
 * the server key's reseal failures (apps/server server-key.ts
 * `ResealFailure`); the server builds them as `reseal-${failure}`, which
 * must type-check against this set, so neither side can drift.
 */
export const LEASE_DENIAL_REASONS = [
  "no-grant",
  "policy-mismatch",
  "scope-out-of-range",
  "environment-not-found",
  "rate-limited",
  "token-replayed",
  "server-wraps-missing",
  "reseal-not-configured",
  "reseal-unwrap-failed",
  "reseal-wrap-failed",
] as const;

/** A `server.lease_denied` reason. */
export type LeaseDenialReason = (typeof LEASE_DENIAL_REASONS)[number];

/** The operations a `propose` entry may carry (CRYPTO_SPEC §6.2 — every op but the approval ops). */
type ProposableOp = ProposableOperation["op"];

/**
 * Every member of `All`, as a runtime list: a list missing a member makes the
 * argument `never` (a compile error), and an extra member fails the element
 * constraint — so the list cannot drift from the type it enumerates.
 */
function everyOf<All extends string>() {
  return <const List extends readonly All[]>(
    list: List & ([Exclude<All, List[number]>] extends [never] ? unknown : never),
  ): List => list;
}

/** {@link ProposableOp} as a runtime list, complete against crypto's ChainOperation. */
const PROPOSABLE_OPS = everyOf<ProposableOp>()([
  "genesis",
  "add_member",
  "remove_member",
  "change_role",
  "create_environment",
  "delete_environment",
  "rotate_epoch",
  "grant_server",
  "revoke_server",
  "checkpoint",
  "set_approval_policy",
  "add_device",
  "revoke_device",
]);

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
    connector: Schema.Literals(ROTATION_CONNECTORS),
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
  "chain.proposed": Schema.Struct({
    innerOp: Schema.Literals(PROPOSABLE_OPS),
    expiresAtMs: Schema.Number,
  }),
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
    reason: Schema.Literals(LEASE_DENIAL_REASONS),
    claimsDigest: Schema.optionalKey(Text),
  }),
};

/** The ledger kinds of the reserve-key wrap ledger (§3.1 — AUTH_SPEC §13-7). */
const passkeyWrap = Schema.Struct({ kind: Schema.Literal("passkey-prf"), wrapId: Text });

const AuthMethod = Schema.Literals(AUTH_METHODS);
const AuthFlowFailureReason = Schema.Literals(AUTH_FLOW_FAILURE_REASONS);
const SignupDenialReason = Schema.Literals(SIGNUP_DENIAL_REASONS);

/** The fixed-window suppression marker (§3.1): only the classification, the window, the cap and the count. */
function suppressionMarker<const Reason extends Schema.Constraint>(reason: Reason) {
  return Schema.Struct({
    authMethod: AuthMethod,
    reason,
    windowMs: Schema.Int,
    limit: Schema.Int,
    suppressedCount: Schema.Int,
  });
}

/** The user / org events (AUDIT_SPEC §3.1–§3.2) — D1. */
const USER_ORG_AUDIT_PAYLOADS = {
  // §3.1 auth events. A Web login copies the session id hash; a CLI login the flow id
  "auth.login_succeeded": Schema.Union([
    Schema.Struct({ sessionId: Text }),
    Schema.Struct({ flowId: Text }),
  ]),
  // Unauthenticated (no actor user id): the kind name and the reason only — never the presented external id
  "auth.login_failed": Schema.Struct({ authMethod: AuthMethod, reason: AuthFlowFailureReason }),
  "auth.login_failed_suppressed": suppressionMarker(AuthFlowFailureReason),
  // Only the Web OAuth signup can be denied (the CLI handoff never creates an account — AUTH_SPEC §4)
  "auth.signup_denied": Schema.Struct({
    authMethod: Schema.Literal("github_oauth"),
    reason: SignupDenialReason,
  }),
  "auth.signup_denied_suppressed": suppressionMarker(SignupDenialReason),
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
