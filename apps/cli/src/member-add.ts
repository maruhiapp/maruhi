// `maruhi member add`: the §6.5 independent verification of the list's
// acceptance block + issuance-pin cross-check -> the invitee confirmation
// (member-add-ceremony.ts) -> add_member append (CAS retry) -> backfill of
// every environment × every epoch (the group's overview lives in member.ts).

import {
  type ChainDevice,
  type ChainEntry,
  type ChainMember,
  memberScopeOf,
  type ProposableOperation,
  type Role,
  scopeIncludesEnvironment,
  type ScopePayloadFields,
  type SigningKeyPair,
} from "@maruhi/crypto";
import { Effect, Stdio } from "effect";
import type { HttpClient } from "effect/http";

import type { MaruhiClient } from "./api.ts";
import { describeKeyReuse, isApprovalTarget, keyReuseOf } from "./approval-rules.ts";
import {
  ensureStillTarget,
  type ProposalInput,
  proposeOperation,
  proposeRecheck,
} from "./approval.ts";
import { backfillEachEnvironment, backfillEnvironmentFor, registerWraps } from "./backfill.ts";
import { signEntryAtHead } from "./chain-append.ts";
import { resyncExtended, type VerifiedProject } from "./chain-sync.ts";
import type { IdentityBacking } from "./config.ts";
import { deviceReceivesEnvironment, ROLE_RANK } from "./dek-wrap.ts";
import type { DekRecipient } from "./deks.ts";
import { chainDeletedEnvironments } from "./deks.ts";
import { devicesOf, memberHasKeys } from "./device-key.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import {
  acceptanceFailureText,
  type InviteAcceptance,
  issuanceFailureText,
  listInvitations,
  pinMismatchOf,
  verifyAcceptanceBlock,
  verifyIssuance,
} from "./invite.ts";
import { CliIo } from "./io.ts";
import type { FingerprintBook } from "./known-fingerprints.ts";
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
import { logNote, logWarning } from "./notice.ts";
import { type InvitePins, issuedPinOf } from "./pins.ts";
import { compareCodePoints, describeScope, scopeContains } from "./scope.ts";

// ---------------------------------------------------------------------------
// member add
// ---------------------------------------------------------------------------

export interface MemberAddSummary {
  /** Whether it was appended to the chain (false = already a member under the same key — a backfill-only resume). */
  readonly appended: boolean;
  readonly targetUserId: string;
  readonly role: Role;
  /** The number of wraps newly registered by the backfill. */
  readonly registered: number;
  /** The number of wraps already registered (a re-run's convergence). */
  readonly alreadyRegistered: number;
  /** The number deleted → re-registered on stale-key-wrap suspicion (the re-addition auto-repair — §12-6). */
  readonly repaired: number;
  /** The environments whose backfill failed (§7 — never skipped silently). */
  readonly failed: readonly { readonly environmentId: string; readonly message: string }[];
}

/**
 * The key-FP re-registration warning (design record K5-K / K6-I): warns
 * when the acceptance key appears on a different membership interval of
 * the verified chain's history (not a refusal — §6.2 permits a return
 * under the same key). Distinguishes the same user_id's past membership
 * from a different user_id's membership. The judgment material is
 * `keyHistory` (covers additions via proposals too — K6-C). Shown before
 * signing on both the direct-append and proposal paths.
 */
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

/** Early check of the add_member actor-role rule (§6.2) (a reason string when unmet). */
function addActorRejection(actor: ActorAuthority | undefined, role: Role): string | null {
  if (actor === undefined || ROLE_RANK[actor.role] < ROLE_RANK.admin) {
    return "Only admins and above can run add_member (CRYPTO_SPEC §6.2)";
  }
  if (ROLE_RANK[role] >= ROLE_RANK.admin && actor.role !== "owner") {
    return "Only an owner can run a role=admin add_member (CRYPTO_SPEC §6.2)";
  }
  return null;
}

/** Early check of member-key uniqueness (§6.2 duplicate-member-key) (a reason when unmet). */
function duplicateMemberKeyRejection(
  verified: VerifiedProject,
  acceptance: InviteAcceptance,
): string | null {
  // The comparison target is every device key of the current member set (§6.2 — 2026-09-19 DK)
  for (const member of verified.state.members.values()) {
    for (const device of member.devices.values()) {
      if (
        device.encPubHex === acceptance.inviteeEncPubHex ||
        device.sigPubHex === acceptance.inviteeSigPubHex
      ) {
        return `The acceptance key equals current member ${displayText(member.userId)}'s key (consensus rule duplicate-member-key — CRYPTO_SPEC §6.2). add_member cannot proceed with this acceptance`;
      }
    }
  }
  return null;
}

/** The pre-append check of add_member (re-run after a CAS retry's resync as well). */
const ensureAddable = Effect.fn("member-add.ensureAddable")(function* (input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: string;
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
      // Already appended (a previous run's interruption / a concurrent
      // run) — resume as backfill-only
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
  // Principle 1 (§6.2 scope-not-contained — check order is also §6.2's:
  // after the duplicate family): add's permission-change environment set
  // = the new scope (the invite row). The issuance-time check (K4-G) is
  // the issuer's; the add's actor may be a different person at a
  // different time (independent review S1). Dropped before the ceremony.
  // An already-appended resume (above), like remove / change-role, asks
  // no containment (what remains is only the backfill)
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

/**
 * Signs an add_member entry right after the current head (the shared core
 * = chain-append.ts). scope is the invite row's to-be-granted scope
 * (AUTH_SPEC §15-2 — an inviter cannot grant a different scope after
 * acceptance: the consent's range is fixed by the issuance signature at
 * issuance)
 */
function signAddMemberEntry(input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: string;
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
    failureText: "Failed to sign the add_member entry",
  });
}

/** The result of one environment's backfill. */
interface MemberBackfillResult {
  readonly registered: number;
  readonly alreadyRegistered: number;
  readonly repaired: number;
}

/**
 * The backfill of one environment's every epoch addressed to the new
 * member (CRYPTO_SPEC §7 — a new member can read history too. Shared core
 * = backfill.ts).
 *
 * **The re-addition auto-repair (ruling B1b + §12-6 supplement)**: a
 * per-epoch 409 may mean "a stale-key wrap from the previous membership is
 * occupying the slot". Left alone the re-added member cannot decrypt that
 * epoch (treating the 409 as already-registered makes it invisible), so
 * when judged a stale-key wrap, the §12-6 repair path (delete →
 * re-register) replaces it with a new-key wrap. The judgment is made by the
 * **exact comparison** of the 409 response's stored recipient enc public
 * key (`storedRecipientEncPubHex` — AUTH_SPEC §12-6) with the acceptance
 * key (decryptability = enc-key equality itself).
 */
const backfillMemberEnvironment = Effect.fn("member-add.backfillMemberEnvironment")(
  function* (input: {
    readonly client: MaruhiClient;
    readonly verified: VerifiedProject;
    readonly environmentId: string;
    readonly recipient: DekRecipient;
    readonly target: ChainMember;
    readonly signerUserId: string;
    readonly signingKeyPair: SigningKeyPair;
  }): Effect.fn.Return<MemberBackfillResult, CliError> {
    // Of the target's **all devices**, those whose effective scope
    // includes E (the device expansion of R(E) — CRYPTO_SPEC §6.2, DK K4).
    // Each device has its own slot, so register per device
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

/** The backfill of one environment × one device of the target (slot = (epoch, user_id, enc key)). */
function backfillMemberDevice(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly recipient: DekRecipient;
  readonly target: ChainMember;
  readonly targetDevice: ChainDevice;
  readonly signerUserId: string;
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
        // Whether the occupied slot is a stale-key wrap: the exact
        // comparison against the response's stored enc public key (a match
        // = registered under the current key = idempotent)
        if (storedRecipientEncPubHex === targetDevice.encPubHex) {
          return "already-registered" as const;
        }
        // The repair path (§12-6): delete the occupied slot and
        // re-register the new-key wrap. The reference names down to the
        // device's enc key
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
              // When a concurrent repair made the slot disappear, only the re-registration is needed
              () => Effect.void,
              (error) => Effect.fail(toCliError(error)),
            ),
          );
        // delete → re-register is not atomic: if the re-register fails
        // here the slot stays empty. The state is made explicit instead of
        // blending into a generic failure wording (a re-run becomes a
        // direct registration into an empty slot, so it is itself the
        // recovery path)
        const retried = yield* register([wrap]).pipe(
          Effect.mapError((error) =>
            cliError(
              `After the repair path deleted the old wrap, re-registering the new-key wrap failed — the epoch ${wrap.epoch} slot remains empty (the target cannot decrypt this epoch; a re-run recovers it as a direct registration into the empty slot): ${error.message}`,
            ),
          ),
        );
        // When a concurrent run registered between the delete and the
        // re-register, the acceptance check (§12-6's recipient match)
        // passed on the current chain's key, so it converged as a new-key
        // wrap
        return retried.kind === "ok" ? ("repaired" as const) : ("already-registered" as const);
      }),
  });
}

/**
 * The prologue of member add: choose the invite → issuance-pin cross-check
 * → §6.5 independent verification → pre-append checks → the
 * FP-confirmation ceremony. The ceremony runs regardless of whether an
 * append happens (even on a backfill-only re-run, never skip verifying the
 * key wraps are about to be dealt to — same discipline as server grant).
 */
const prepareMemberAdd = Effect.fn("member-add.prepareMemberAdd")(function* (input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly inviteId: string | null;
  readonly expectFingerprintHex: string | null;
  /** `--github <login>` (the backing source's match target. Beats the issuance pin's destination). */
  readonly githubLogin: string | null;
  readonly identityBacking: IdentityBacking;
  readonly pins: InvitePins | null;
  readonly signerUserId: string;
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

  // Verifying the issuance text (CRYPTO_SPEC §6.5 — IV): the row's
  // issuance signature is verified with the chain-derived inviter key.
  // For a row I issued, my own key settles "is it my issuance" (independent
  // of the issuance pin). Failure = the row was substituted / tampered →
  // refuse
  const issuance = yield* verifyIssuance({ verified: input.verified, row });
  if (!issuance.ok) {
    return yield* Effect.fail(
      cliError(`This invite ${issuanceFailureText(issuance.reason)}. add_member was aborted`),
    );
  }

  // The issuance-pin cross-check (SHOULD — agreement of the
  // issuance-time link_pub / role with the server's claims). Without a
  // pin (issued on another device, beyond the retention window) only the
  // issuance signature's verification pins the row (the IV revision moved
  // the source of truth to the issuance signature)
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

  // §6.5's independent verification (never trusting the server's claimed verification result): the link signature → the acceptance signature
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

  // Adequacy form 4 (backing source) → if unmet, adequacy forms 1-3 (ceremony / flag / book)
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

/** The all-environment sweep of the backfill (one environment's failure doesn't stop the rest — §7). */
export const backfillAllEnvironments = Effect.fn("member-add.backfillAllEnvironments")(
  function* (input: {
    readonly client: MaruhiClient;
    readonly verified: VerifiedProject;
    readonly recipient: DekRecipient;
    readonly target: ChainMember;
    /** The environments to backfill (default = all environments of the target's scope). An explicit list is re-narrowed by the scope. */
    readonly environments?: readonly string[];
    readonly signerUserId: string;
    readonly signingKeyPair: SigningKeyPair;
  }): Effect.fn.Return<
    Pick<MemberAddSummary, "registered" | "alreadyRegistered" | "repaired" | "failed">,
    CliError
  > {
    // The target scope's environments (chain-derived, chain-deleted ones
    // excluded) × every epoch (CRYPTO_SPEC §7 "every epoch DEK of every
    // environment in the target's scope" — 2026-09-15 ES K4. The
    // `environments` explicit list is used for change-role's widening
    // backfill)
    const deletedVerified = chainDeletedEnvironments(input.verified);
    const environments = (input.environments ?? [...input.verified.state.environments.keys()])
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

/** add_member's inner op (the same payload for a direct append and a proposal — the invite row's scope). */
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

/**
 * The backfill addressed to the new member (the aftermath of add_member's
 * append — CRYPTO_SPEC §7 / AUTH_SPEC §12-6). Shared between a direct
 * append's add and the fulfillment of the approver who completes the
 * application under four-eyes (§12-6's fifth path — approval-approve.ts).
 * The target is the current member after resync (`target`).
 */
export const backfillNewMember = Effect.fn("member-add.backfillNewMember")(function* (input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly target: ChainMember;
  readonly recipient: DekRecipient;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.fn.Return<
  Pick<MemberAddSummary, "registered" | "alreadyRegistered" | "repaired" | "failed">,
  CliError,
  CliIo
> {
  const io = yield* CliIo;
  // Guidance on a re-addition (a past membership under a different key):
  // does the key history carry a binding different from the current key.
  // The 409 judgment is the exact comparison against the response's
  // stored enc public key (AUTH_SPEC §12-6 supplement); this is guidance
  // only. The server auto-cleans stale-key wraps on add_member acceptance
  // (same supplement), so normally a 409 only ever means "registered under
  // the current key". "A different key" = a history binding that matches
  // none of the target's current device set (with multiple devices, a
  // current device's key is not a stale key — DK K4)
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
  readonly signerUserId: string;
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

  // Four-eyes (K6-A / K6-D): if the policy targets add_member, propose
  // and finish. The ceremony (prepareMemberAdd) was done by the proposer,
  // and the backfill is done by the approver who completes the
  // application
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
      opLabel: "add_member",
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
        ensureStillTarget(view, inner, false).pipe(
          Effect.flatMap(() => recheck(view)),
          Effect.map((rechecked) => ({ already: rechecked.alreadyAdded })),
        ),
    });
    appended = outcome.appended;
    verified = outcome.verified;
  }

  // The post-acceptance resync confirms the listing (the server's claim is never the source of truth)
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
