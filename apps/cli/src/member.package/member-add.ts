import { type EnvironmentId, type UserId } from "@maruhi/core";
import {
  type ChainDevice,
  type ChainEntry,
  type ChainMember,
  deviceReceivesEnvironment,
  isApprovalTarget,
  memberScopeOf,
  type ProposableOperation,
  type Role,
  scopeIncludesEnvironment,
  type ScopePayloadFields,
  type SigningKeyPair,
} from "@maruhi/crypto";
import { Effect, Stdio } from "effect";
import type { HttpClient } from "effect/http";

import type { MaruhiClient } from "../api.ts";
import { describeKeyReuse, keyReuseOf } from "../approval-rules.ts";
import { type ProposalInput, proposeOperation, proposeRecheck } from "../approval.package/index.ts";
import { backfillEachEnvironment, backfillEnvironmentFor, registerWraps } from "../backfill.ts";
import { signEntryAtHead } from "../chain-append.ts";
import { resyncExtended, type VerifiedProject } from "../chain-sync.ts";
import type { IdentityBacking } from "../config.ts";
import { ROLE_RANK } from "../dek-wrap.ts";
import type { DekRecipient } from "../deks.ts";
import { chainDeletedEnvironments, chainEnvironmentIds } from "../deks.ts";
import { devicesOf, memberHasKeys, registeredKeyHolderOf } from "../device-key.ts";
import { displayText } from "../display.ts";
import { cliError, type CliError } from "../errors.ts";
import { toCliError } from "../failure.ts";
import {
  acceptanceFailureText,
  type InviteAcceptance,
  issuanceFailureText,
  listInvitations,
  pinMismatchOf,
  verifyAcceptanceBlock,
  verifyIssuance,
} from "../invite.package/index.ts";
import { CliIo } from "../io.ts";
import type { FingerprintBook } from "../known-fingerprints.ts";
import { logNote, logWarning } from "../notice.ts";
import { type InvitePins, issuedPinOf } from "../pins.ts";
import { compareCodePoints, describeScope, scopeContains } from "../scope.ts";
import {
  type AddableRow,
  confirmInviteeFingerprint,
  confirmInviteeViaBacking,
  selectInvitation,
} from "./member-add-ceremony.ts";
import {
  type ActorAuthority,
  actorAuthority,
  appendWithCas,
  type MemberOpOutcome,
} from "./member.ts";

export interface MemberAddSummary {
  readonly appended: boolean;
  readonly targetUserId: UserId;
  readonly role: Role;
  readonly registered: number;
  readonly alreadyRegistered: number;
  readonly repaired: number;
  readonly failed: readonly { readonly environmentId: EnvironmentId; readonly message: string }[];
}

function warnKeyReuse(
  verified: VerifiedProject,
  acceptance: InviteAcceptance,
): Effect.Effect<void, never, CliIo> {
  return Effect.forEach(
    keyReuseOf(verified, {
      targetUserId: acceptance.inviteeUserId,
      encPubHex: acceptance.inviteeEncPubHex,
      sigPubHex: acceptance.inviteeSigPubHex,
    }),
    (reuse) => logWarning(describeKeyReuse("the acceptance key", reuse)),
    { discard: true },
  );
}

function addActorRejection(actor: ActorAuthority | undefined, role: Role): string | null {
  if (actor === undefined || ROLE_RANK[actor.role] < ROLE_RANK.admin) {
    return "Only admins and above can run add_member (CRYPTO_SPEC §6.2)";
  }
  if (ROLE_RANK[role] >= ROLE_RANK.admin && actor.role !== "owner") {
    return "Only an owner can run a role=admin add_member (CRYPTO_SPEC §6.2)";
  }
  return null;
}

function duplicateMemberKeyRejection(
  verified: VerifiedProject,
  acceptance: InviteAcceptance,
): string | null {
  const holder = registeredKeyHolderOf(verified.state, {
    encPubHex: acceptance.inviteeEncPubHex,
    sigPubHex: acceptance.inviteeSigPubHex,
  });
  if (holder === null) {
    return null;
  }
  const held =
    holder.kind === "device"
      ? `equals current member ${displayText(holder.userId)}'s key`
      : `is server key ${holder.serverKeyFingerprintHex}, which a grant has named, so no device may hold it`;
  return `The acceptance key ${held} (consensus rule duplicate-member-key — CRYPTO_SPEC §6.2). add_member cannot proceed with this acceptance`;
}

const ensureAddable = Effect.fn("member-add.ensureAddable")(function* (input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: UserId;
  readonly acceptance: InviteAcceptance;
  readonly role: Role;
  readonly scope: ScopePayloadFields;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.fn.Return<{ readonly alreadyAdded: boolean }, CliError> {
  const actor = input.verified.state.members.get(input.signerUserId);
  if (actor === undefined) {
    return yield* Effect.fail(
      cliError("Only admins and above can run add_member (CRYPTO_SPEC §6.2)"),
    );
  }
  const permission = yield* actorAuthority(input.verified, actor, input.signingKeyPair);
  const actorRejection = addActorRejection(permission, input.role);
  if (actorRejection !== null) {
    return yield* Effect.fail(cliError(actorRejection));
  }
  const existing = input.verified.state.members.get(input.acceptance.inviteeUserId);
  if (existing !== undefined) {
    if (
      memberHasKeys(existing, input.acceptance.inviteeEncPubHex, input.acceptance.inviteeSigPubHex)
    ) {
      return { alreadyAdded: true };
    }
    return yield* Effect.fail(
      cliError(
        "The target user ID is already a member with a different key (the acceptance block contradicts the chain). Another acceptance may already have been added, or the acceptances were mixed up — check the state with `maruhi invite list` and `maruhi project verify`",
      ),
    );
  }
  const keyRejection = duplicateMemberKeyRejection(input.verified, input.acceptance);
  if (keyRejection !== null) {
    return yield* Effect.fail(cliError(keyRejection));
  }
  const invited = memberScopeOf(input.scope);
  if (!scopeContains(permission.scope, invited)) {
    return yield* Effect.fail(
      cliError(
        `Your environment scope (${describeScope(permission.scope)}) does not contain the invite's scope (${describeScope(invited)}), so add_member would be rejected (CRYPTO_SPEC §6.2 scope-not-contained). Ask an owner or an admin whose scope covers it to run member add`,
      ),
    );
  }
  return { alreadyAdded: false };
});

function signAddMemberEntry(input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: UserId;
  readonly acceptance: InviteAcceptance;
  readonly role: Role;
  readonly scope: ScopePayloadFields;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<ChainEntry, CliError> {
  return signEntryAtHead({
    verified: input.verified,
    signerUserId: input.signerUserId,
    operation: {
      op: "add_member",
      payload: {
        targetUserId: input.acceptance.inviteeUserId,
        encPubHex: input.acceptance.inviteeEncPubHex,
        sigPubHex: input.acceptance.inviteeSigPubHex,
        role: input.role,
        scopeKind: input.scope.scopeKind,
        scopeEnvironmentIds: input.scope.scopeEnvironmentIds,
      },
    },
    signingKeyPair: input.signingKeyPair,
  });
}

interface MemberBackfillResult {
  readonly registered: number;
  readonly alreadyRegistered: number;
  readonly repaired: number;
}

const backfillMemberEnvironment = Effect.fn("member-add.backfillMemberEnvironment")(
  function* (input: {
    readonly client: MaruhiClient;
    readonly verified: VerifiedProject;
    readonly environmentId: EnvironmentId;
    readonly recipient: DekRecipient;
    readonly target: ChainMember;
    readonly signerUserId: UserId;
    readonly signingKeyPair: SigningKeyPair;
  }): Effect.fn.Return<MemberBackfillResult, CliError> {
    const devices = devicesOf(input.target).filter((device) =>
      deviceReceivesEnvironment(input.target, device, input.environmentId),
    );
    let registered = 0;
    let alreadyRegistered = 0;
    let repaired = 0;
    for (const device of devices) {
      const result = yield* backfillMemberDevice({ ...input, targetDevice: device });
      registered += result.registered;
      alreadyRegistered += result.alreadyRegistered;
      repaired += result.repaired;
    }
    return { registered, alreadyRegistered, repaired };
  },
);

function backfillMemberDevice(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly recipient: DekRecipient;
  readonly target: ChainMember;
  readonly targetDevice: ChainDevice;
  readonly signerUserId: UserId;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<MemberBackfillResult, CliError> {
  const register = registerWraps(input.client, input.verified.projectId, input.environmentId);
  const { targetDevice } = input;
  return backfillEnvironmentFor({
    client: input.client,
    verified: input.verified,
    environmentId: input.environmentId,
    recipient: input.recipient,
    wrapRecipient: { kind: "member", member: input.target, device: targetDevice },
    recipientLabel: "new-member-addressed",
    signerUserId: input.signerUserId,
    signingKeyPair: input.signingKeyPair,
    onSlotConflict: (wrap, storedRecipientEncPubHex) =>
      Effect.gen(function* () {
        if (storedRecipientEncPubHex === targetDevice.encPubHex) {
          return "already-registered" as const;
        }
        yield* input.client.deks
          .remove({
            params: { projectId: input.verified.projectId, environmentId: input.environmentId },
            payload: {
              wraps: [
                {
                  epoch: wrap.epoch,
                  recipientClass: "member",
                  recipientUserId: input.target.userId,
                  recipientEncPubHex: storedRecipientEncPubHex,
                },
              ],
            },
          })
          .pipe(
            Effect.asVoid,
            Effect.catchTag(
              "DekWrapNotFound",
              () => Effect.void,
              (error) => Effect.fail(toCliError(error)),
            ),
          );
        const retried = yield* register([wrap]).pipe(
          Effect.mapError((error) =>
            cliError(
              `After the repair path deleted the old wrap, re-registering the new-key wrap failed — the epoch ${wrap.epoch} slot remains empty (the target cannot decrypt this epoch; a re-run recovers it as a direct registration into the empty slot): ${error.message}`,
            ),
          ),
        );
        return retried.kind === "ok" ? ("repaired" as const) : ("already-registered" as const);
      }),
  });
}

const prepareMemberAdd = Effect.fn("member-add.prepareMemberAdd")(function* (input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly inviteId: string | null;
  readonly expectFingerprintHex: string | null;
  readonly githubLogin: string | null;
  readonly identityBacking: IdentityBacking;
  readonly pins: InvitePins | null;
  readonly signerUserId: UserId;
  readonly signingKeyPair: SigningKeyPair;
  readonly origin: string;
}): Effect.fn.Return<
  {
    readonly row: AddableRow;
    readonly alreadyAdded: boolean;
  },
  CliError,
  CliIo | FingerprintBook | Stdio.Stdio | HttpClient.HttpClient
> {
  const listed = yield* listInvitations(input.client, input.verified.projectId);
  const row = yield* selectInvitation(listed, input.inviteId);

  const issuance = yield* verifyIssuance({ verified: input.verified, row });
  if (!issuance.ok) {
    return yield* Effect.fail(
      cliError(`This invite ${issuanceFailureText(issuance.reason)}. add_member was aborted`),
    );
  }

  const pin = pinMismatchOf(input.pins, row);
  if (pin === "mismatch") {
    return yield* Effect.fail(
      cliError(
        "The server's claim for the invite row (link key / role) does not match the local record from issuance. The row may have been swapped or the role tampered with — add_member was aborted",
      ),
    );
  }
  if (pin === "missing") {
    yield* logNote(
      "this machine has no issuance pin for this invite (it may have been issued on another device). The issue signature still fixes the row; only the addressee login recorded at issuance is unavailable here",
    );
  }

  const acceptanceVerified = yield* verifyAcceptanceBlock({
    projectId: input.verified.projectId,
    issuance: row.issuance,
    acceptance: row.acceptance,
  });
  if (!acceptanceVerified.ok) {
    return yield* Effect.fail(
      cliError(
        `For this invite, ${acceptanceFailureText(acceptanceVerified.which)}. This acceptance block cannot be trusted — add_member was aborted (revoke the invite)`,
      ),
    );
  }

  const first = yield* ensureAddable({
    verified: input.verified,
    signerUserId: input.signerUserId,
    acceptance: row.acceptance,
    role: row.role,
    scope: { scopeKind: row.scopeKind, scopeEnvironmentIds: row.scopeEnvironmentIds },
    signingKeyPair: input.signingKeyPair,
  });
  if (!first.alreadyAdded) {
    yield* warnKeyReuse(input.verified, row.acceptance);
  }

  const backed = yield* confirmInviteeViaBacking({
    identityBacking: input.identityBacking,
    flagLogin: input.githubLogin,
    pinLogin: issuedPinOf(input.pins, row.id)?.expectedGithubLogin ?? null,
    sigPubHex: row.acceptance.inviteeSigPubHex,
    fingerprintHex: acceptanceVerified.fingerprintHex,
    expectFingerprintHex: input.expectFingerprintHex,
  });
  if (!backed) {
    yield* confirmInviteeFingerprint({
      origin: input.origin,
      targetUserId: row.acceptance.inviteeUserId,
      role: row.role,
      fingerprintHex: acceptanceVerified.fingerprintHex,
      expectFingerprintHex: input.expectFingerprintHex,
    });
  }
  return { row, alreadyAdded: first.alreadyAdded };
});

export const backfillAllEnvironments = Effect.fn("member-add.backfillAllEnvironments")(
  function* (input: {
    readonly client: MaruhiClient;
    readonly verified: VerifiedProject;
    readonly recipient: DekRecipient;
    readonly target: ChainMember;
    readonly environments?: readonly EnvironmentId[];
    readonly signerUserId: UserId;
    readonly signingKeyPair: SigningKeyPair;
  }): Effect.fn.Return<
    Pick<MemberAddSummary, "registered" | "alreadyRegistered" | "repaired" | "failed">,
    CliError
  > {
    const deletedVerified = chainDeletedEnvironments(input.verified);
    const environments = (input.environments ?? chainEnvironmentIds(input.verified))
      .filter(
        (environmentId) =>
          !deletedVerified.has(environmentId) &&
          scopeIncludesEnvironment(input.target.scope, environmentId),
      )
      .toSorted(compareCodePoints);
    return yield* backfillEachEnvironment(environments, (environmentId) =>
      backfillMemberEnvironment({ ...input, environmentId }),
    );
  },
);

function addMemberOperation(
  row: AddableRow,
): Extract<ProposableOperation, { readonly op: "add_member" }> {
  return {
    op: "add_member",
    payload: {
      targetUserId: row.acceptance.inviteeUserId,
      encPubHex: row.acceptance.inviteeEncPubHex,
      sigPubHex: row.acceptance.inviteeSigPubHex,
      role: row.role,
      scopeKind: row.scopeKind,
      scopeEnvironmentIds: row.scopeEnvironmentIds,
    },
  };
}

export const backfillNewMember = Effect.fn("member-add.backfillNewMember")(function* (input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly target: ChainMember;
  readonly recipient: DekRecipient;
  readonly signerUserId: UserId;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.fn.Return<
  Pick<MemberAddSummary, "registered" | "alreadyRegistered" | "repaired" | "failed">,
  CliError,
  CliIo
> {
  const io = yield* CliIo;
  const readdedWithNewKey = (input.verified.keyHistory.get(input.target.userId) ?? []).some(
    (binding) => !memberHasKeys(input.target, binding.encPubHex, binding.sigPubHex),
  );
  if (readdedWithNewKey) {
    yield* io.log(
      "The target user ID was previously a member with a different key. If leftover wraps addressed to the old key are found, the repair path (delete → re-register) replaces them with the new key (CRYPTO_SPEC §7 / AUTH_SPEC §12-6)",
    );
  }
  return yield* backfillAllEnvironments({
    client: input.client,
    verified: input.verified,
    recipient: input.recipient,
    target: input.target,
    signerUserId: input.signerUserId,
    signingKeyPair: input.signingKeyPair,
  });
});

export const memberAddOp = Effect.fn("member-add.memberAddOp")(function* (input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly inviteId: string | null;
  readonly expectFingerprintHex: string | null;
  readonly githubLogin: string | null;
  readonly identityBacking: IdentityBacking;
  readonly pins: InvitePins | null;
  readonly signerUserId: UserId;
  readonly origin: string;
  readonly signingKeyPair: SigningKeyPair;
  readonly recipient: DekRecipient;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly proposal: ProposalInput;
}): Effect.fn.Return<
  MemberOpOutcome<MemberAddSummary>,
  CliError,
  CliIo | FingerprintBook | Stdio.Stdio | HttpClient.HttpClient
> {
  const io = yield* CliIo;
  const { row, alreadyAdded } = yield* prepareMemberAdd(input);
  const inner = addMemberOperation(row);
  const scope = { scopeKind: row.scopeKind, scopeEnvironmentIds: row.scopeEnvironmentIds };
  const recheck = (view: VerifiedProject) =>
    ensureAddable({
      verified: view,
      signerUserId: input.signerUserId,
      acceptance: row.acceptance,
      role: row.role,
      scope,
      signingKeyPair: input.signingKeyPair,
    });

  if (!alreadyAdded && isApprovalTarget(inner, input.verified.state.approvalPolicy)) {
    const proposal = yield* proposeOperation(
      input,
      inner,
      proposeRecheck(
        recheck,
        (rechecked) => rechecked.alreadyAdded,
        "The target was added by a concurrent run while this proposal was being appended — nothing to propose. Re-run `maruhi member add` to resume the backfill",
      ),
    );
    return { kind: "proposed", proposal };
  }

  let verified = input.verified;
  let appended = false;
  if (alreadyAdded) {
    yield* io.log(
      "The target is already a member with the same key — skipping add_member and running only the backfill (crash recovery)",
    );
  } else {
    const outcome = yield* appendWithCas({
      client: input.client,
      verified,
      resync: input.resync,
      inner,
      signEntry: (view) =>
        signAddMemberEntry({
          verified: view,
          signerUserId: input.signerUserId,
          acceptance: row.acceptance,
          role: row.role,
          scope,
          signingKeyPair: input.signingKeyPair,
        }),
      recheck: (view) =>
        Effect.map(recheck(view), (rechecked) => ({ already: rechecked.alreadyAdded })),
    });
    appended = outcome.appended;
    verified = outcome.verified;
  }

  verified = yield* resyncExtended(input.resync, verified);
  const target = verified.state.members.get(row.acceptance.inviteeUserId);
  if (
    target === undefined ||
    !memberHasKeys(target, row.acceptance.inviteeEncPubHex, row.acceptance.inviteeSigPubHex)
  ) {
    return yield* Effect.fail(
      cliError(
        "The resync after add_member was accepted does not show the member (with the acceptance key) on the chain (the server's response contradicts the chain). Investigate the served chain",
      ),
    );
  }
  if (appended) {
    yield* io.log(
      `Appended add_member to the chain (target=${displayText(target.userId)}, role=${row.role}, seq=${verified.state.headSeq})`,
    );
  }

  const backfilled = yield* backfillNewMember({
    client: input.client,
    verified,
    target,
    recipient: input.recipient,
    signerUserId: input.signerUserId,
    signingKeyPair: input.signingKeyPair,
  });
  return {
    kind: "applied",
    summary: { appended, targetUserId: target.userId, role: row.role, ...backfilled },
  };
});
