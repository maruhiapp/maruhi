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

type ProviderSubjectMarker = Omit<ProviderUserId, keyof string>;

export type AuditText = string & {
  readonly [K in keyof ProviderSubjectMarker]?: {
    readonly [B in keyof ProviderSubjectMarker[K]]?: never;
  };
};

function isAuditText(_value: string): _value is AuditText {
  return true;
}

function isAscendingUniqueEnumeration<T extends { readonly variableId: string }>(
  variables: readonly T[],
): variables is readonly T[] {
  return (
    variables.length >= 1 &&
    variables.every(
      (variable, index) =>
        index === 0 || (variables[index - 1]?.variableId ?? "") < variable.variableId,
    )
  );
}

const Text = Schema.String.pipe(
  Schema.refine(isAuditText, { expected: "audit text (never a provider subject)" }),
);
const Seq = Schema.Int;
const Role = Schema.Literals(["owner", "admin", "member", "reader"]);
const ScopeKind = Schema.Literals(["all", "listed"]);
const GuardianMode = Schema.Literals(["any", "all"]);
const Imported = Schema.Literal(true);

const NameSnapshot = Schema.Struct({ name: Text });

const scopeFields = { scopeKind: ScopeKind, scopeEnvironmentIds: Schema.Array(Text) };

function chainPayload<const Fields extends Schema.Struct.Fields>(fields: Fields) {
  return Schema.Struct({ ...fields, viaProposalSeq: Schema.optionalKey(Seq) });
}

const chainNoPayload = Schema.UndefinedOr(Schema.Struct({ viaProposalSeq: Seq }));

export const ROTATION_BASES = ["read", "readable"] as const;

export const ROTATION_TRIGGERS = [
  "remove_member",
  "change_role",
  "revoke_server",
  "revoke_device",
] as const;

export const ROTATION_CONNECTORS = [
  "aws-iam-access-key",
  "cloudflare-api-token",
  "postgres",
  "mysql",
  "exec",
] as const;

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

export type LeaseDenialReason = (typeof LEASE_DENIAL_REASONS)[number];

type ProposableOp = ProposableOperation["op"];

function everyOf<All extends string>() {
  return <const List extends readonly All[]>(
    list: List & ([Exclude<All, List[number]>] extends [never] ? unknown : never),
  ): List => list;
}

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

const PROJECT_AUDIT_PAYLOADS = {
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
  "dek.deleted": Schema.UndefinedOr(
    Schema.Struct({ cause: Schema.Literal("member-readded"), triggerChainSeq: Seq }),
  ),
  "rotation.recommended": Schema.Struct({
    triggerChainSeq: Seq,
    trigger: Schema.Literals(ROTATION_TRIGGERS),
    variables: Schema.Array(
      Schema.Struct({ variableId: Text, basis: Schema.Literals(ROTATION_BASES) }),
    ).pipe(
      Schema.refine(isAscendingUniqueEnumeration, {
        expected: "a non-empty enumeration, ascending and unique by variableId (AUDIT_SPEC §3.3)",
      }),
    ),
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
  "rotation.proposal_cancelled": Schema.Struct({ proposalId: Text }),
  "project.schema_policy_changed": Schema.Struct({
    previous: Schema.Literals(["enabled", "locked"]),
    next: Schema.Literals(["enabled", "locked"]),
  }),
  "project.exported": Schema.Struct({ chainHeadSeq: Seq, chainHeadHashHex: Text }),
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

const passkeyWrap = Schema.Struct({ kind: Schema.Literal("passkey-prf"), wrapId: Text });

const AuthMethod = Schema.Literals(AUTH_METHODS);
const AuthFlowFailureReason = Schema.Literals(AUTH_FLOW_FAILURE_REASONS);
const SignupDenialReason = Schema.Literals(SIGNUP_DENIAL_REASONS);

function suppressionMarker<const Reason extends Schema.Constraint>(reason: Reason) {
  return Schema.Struct({
    authMethod: AuthMethod,
    reason,
    windowMs: Schema.Int,
    limit: Schema.Int,
    suppressedCount: Schema.Int,
  });
}

const USER_ORG_AUDIT_PAYLOADS = {
  "auth.login_succeeded": Schema.Union([
    Schema.Struct({ sessionId: Text }),
    Schema.Struct({ flowId: Text }),
  ]),
  "auth.login_failed": Schema.Struct({ authMethod: AuthMethod, reason: AuthFlowFailureReason }),
  "auth.login_failed_suppressed": suppressionMarker(AuthFlowFailureReason),
  "auth.signup_denied": Schema.Struct({
    authMethod: Schema.Literal("github_oauth"),
    reason: SignupDenialReason,
  }),
  "auth.signup_denied_suppressed": suppressionMarker(SignupDenialReason),
  "auth.session_revoked": Schema.Struct({ sessionId: Text }),
  "auth.token_created": Schema.Struct({
    tokenId: Text,
    name: Text,
    scopes: Schema.Array(TokenScopeSchema),
    replacedTokenId: Schema.optionalKey(Text),
  }),
  "auth.token_revoked": Schema.Struct({ tokenId: Text }),
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
  "auth.key_handoff_approved": Schema.Struct({
    requestId: Text,
    source: Text,
    shareIndex: Schema.Int,
    approverKeyFingerprintHex: KeyFingerprintHexSchema,
  }),
  "auth.key_handoff_collected": Schema.Struct({ requestId: Text, approvalCount: Schema.Int }),
  "auth.user_created": Schema.UndefinedOr(
    Schema.Union([Schema.Struct({ signupInviteId: Text }), Schema.Struct({ imported: Imported })]),
  ),
  "org.created": Schema.Struct({
    personal: Schema.Literal(true),
    imported: Schema.optionalKey(Imported),
  }),
  "org.member_added": Schema.Struct({ role: OrgRoleSchema }),
  "org.project_created": Schema.UndefinedOr(Schema.Struct({ imported: Imported })),
  "invite.created": Schema.Struct({ inviteId: Text, role: Role }),
  "invite.accepted": Schema.Struct({
    inviteId: Text,
    inviteeKeyFingerprintHex: KeyFingerprintHexSchema,
  }),
  "invite.revoked": Schema.Struct({ inviteId: Text, role: Role }),
};

type ProjectPayloadSchemas = typeof PROJECT_AUDIT_PAYLOADS;
type UserOrgPayloadSchemas = typeof USER_ORG_AUDIT_PAYLOADS;

export type ProjectAuditEventName = keyof ProjectPayloadSchemas;

type UserOrgAuditEventName = keyof UserOrgPayloadSchemas;

export type ChainMirrorEventName = Extract<ProjectAuditEventName, `chain.${string}`>;

export type ProjectAuditPayload<E extends ProjectAuditEventName> = ProjectPayloadSchemas[E]["Type"];

type UserOrgAuditPayload<E extends UserOrgAuditEventName> = UserOrgPayloadSchemas[E]["Type"];

type PayloadField<P> = [P] extends [undefined]
  ? { readonly payload?: never }
  : undefined extends P
    ? { readonly payload?: Exclude<P, undefined> }
    : { readonly payload: P };

export type ProjectAuditEventPayload = {
  readonly [E in ProjectAuditEventName]: { readonly event: E } & PayloadField<
    ProjectAuditPayload<E>
  >;
}[ProjectAuditEventName];

export type UserOrgAuditEventPayload = {
  readonly [E in UserOrgAuditEventName]: { readonly event: E } & PayloadField<
    UserOrgAuditPayload<E>
  >;
}[UserOrgAuditEventName];

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

export function assertProjectAuditPayload(record: {
  readonly event: string;
  readonly payload?: unknown;
}): void {
  assertPayload(PROJECT_AUDIT_PAYLOADS, "project", record.event, record.payload);
}

export function assertUserOrgAuditPayload(record: {
  readonly event: string;
  readonly payload?: unknown;
}): void {
  assertPayload(USER_ORG_AUDIT_PAYLOADS, "user / org", record.event, record.payload);
}
