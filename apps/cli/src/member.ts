// `maruhi member add|remove|change-role` (CRYPTO_SPEC §6.2 / §6.5 / §7,
// AUTH_SPEC §12-6 / §15).
//
// - add: §6.5 independent verification of the list's acceptance block +
//   issuance-pin cross-check + the FP-confirmation ceremony → add_member
//   append (CAS retry) → backfill of every environment × every epoch
//   (409 = an idempotent resume of already-registered. **A 409 from a
//   re-addition (a past membership under a different key) suggests a
//   stale-key wrap**, so it auto-repairs via delete → re-register behind a
//   key-history gate — §12-6's repair path. Left alone, a re-added member
//   cannot decrypt historical epochs)
// - remove / change-role (demotion below member): append the entry →
//   **forced rotation of every environment** (§7). Interruption recovery
//   uses the same chain-derived scheme as server revoke
//   (rotation-sweep.ts — baseline = the seq of the last rotation-duty
//   entry)
//
// Removing yourself or demoting yourself below member is refused: after
// the operation the actor loses rotate_epoch authority and cannot fulfill
// the §7 duty themselves (the consensus rules don't forbid it, but the CLI
// never creates a shape where the duty is structurally orphaned).

import { ChainHeadConflictError, DekWrapNotFoundError } from "@maruhi/api-schema";
import {
  ALL_SCOPE,
  type ChainDevice,
  type ChainEntry,
  type ChainMember,
  effectivePermissionOf,
  type EffectivePermission,
  type MemberScope,
  memberScopeOf,
  type ProposableOperation,
  type Role,
  type ScopePayloadFields,
  scopeIncludesEnvironment,
  scopePayloadFieldsOf,
  type SigningKeyPair,
} from "@maruhi/crypto";
import { Effect, Stdio } from "effect";
import type { HttpClient } from "effect/unstable/http";

import type { MaruhiClient } from "./api.ts";
import { describeKeyReuse, isApprovalTarget, keyReuseOf } from "./approval-rules.ts";
import {
  ensureStillTarget,
  type ProposalInput,
  type ProposeContext,
  proposeOperation,
  proposeRecheck,
  type ProposedSummary,
} from "./approval.ts";
import { backfillEachEnvironment, backfillEnvironmentFor, registerWraps } from "./backfill.ts";
import { appendEntry, signEntryAtHead } from "./chain-append.ts";
import type { IdentityBacking } from "./config.ts";
import { deviceReceivesEnvironment, ROLE_RANK } from "./dek-wrap.ts";
import type { DekRecipient } from "./deks.ts";
import { describeDevice, devicesOf, memberHasKeys, ownDeviceBySigningKey } from "./device-key.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError, usageError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { confirmByLastWord, fingerprintWords, formatWordList } from "./fp-words.ts";
import { checkSigningKeyBacking, describeBackingFallback } from "./github-signing-keys.ts";
import {
  acceptanceFailureText,
  type InvitationRow,
  type InviteAcceptance,
  issuanceFailureText,
  listInvitations,
  pinMismatchOf,
  verifyAcceptanceBlock,
  verifyIssuance,
} from "./invite.ts";
import { CliIo } from "./io.ts";
import {
  confirmKnownFingerprint,
  consultFingerprintBook,
  type FingerprintBook,
  usableBookHit,
} from "./known-fingerprints.ts";
import { logNote, logWarning } from "./notice.ts";
import { type InvitePins, issuedPinOf } from "./pins.ts";
import { retryOnConflict } from "./retry.ts";
import {
  baselinesOf,
  partitionSweepBaselines,
  type RotationMandate,
  rotationMandates,
  type SweepOutcome,
  type SweepRotate,
  sweepRotations,
  verifiedDeletedEnvironmentSet,
} from "./rotation-sweep.ts";
import {
  compareCodePoints,
  describeScope,
  environmentsOfScopeAt,
  requireScopeEnvironmentsExist,
  sameScope,
  scopeChangeAt,
  scopeContains,
} from "./scope.ts";
import { resyncExtended, type VerifiedProject } from "./sync.ts";

const MAX_ATTEMPTS = 5;

/**
 * Each op's result under four-eyes (K6): if the policy targets the inner
 * op, append a `propose` and finish (`proposed` — nothing is applied).
 * Otherwise the usual application result (`applied`).
 */
export type MemberOpOutcome<S> =
  | { readonly kind: "proposed"; readonly proposal: ProposedSummary }
  | { readonly kind: "applied"; readonly summary: S };

/** The rotation reason after a remove / demotion / narrowing (the fixed string of the §6.2 payload). */
const MEMBER_REMOVED_ROTATION_REASON = "member-removed";
const ROLE_DEMOTED_ROTATION_REASON = "role-demoted";
const SCOPE_NARROWED_ROTATION_REASON = "scope-narrowed";

// ---------------------------------------------------------------------------
// Shared: the rotation-duty environment set and the baseline seq (the interruption-recovery baseline — chain-derived only)
// ---------------------------------------------------------------------------

/**
 * **The target user_id's** rotation-duty entries (`remove_member` /
 * demotion / narrowing — §7). The derivation's core is rotation-sweep.ts's
 * rotationMandates (the same single derivation as the always-on
 * unconverged warning — prevents judgment drift structurally). The duty's
 * environment set is concretized per entry (remove = the current scope,
 * demotion = the new scope, narrowing = old \ new — design record K4-J).
 *
 * Target-scoping exists to limit the duty each command converges to **its
 * own operation's share**: keyed on the global duty, a no-op re-run
 * against a born-reader would pick up **someone else's** unconverged duty
 * and start a rotation. Rotations after the target's duty entry close the
 * target's forgeable coordinates (§7), so a target scope never
 * under-fulfills its own duty (others' unconverged duties are the
 * always-on warning — rotation-sweep.ts — and that operation's re-run's
 * responsibility).
 */
function memberMandatesFor(
  verified: VerifiedProject,
  targetUserId: string,
): readonly RotationMandate[] {
  // The device-revocation duty (`device-revoked`) is fulfilled by `device
  // revoke`'s own sweep (device-ops.ts) — member commands' re-runs never
  // pick up another operation's duty (same line)
  return rotationMandates(verified).filter(
    (mandate) =>
      mandate.kind !== "server-revoked" &&
      mandate.kind !== "device-revoked" &&
      mandate.target === targetUserId,
  );
}

/** The §7 duty-environment sweep (the shared aftermath of remove / demotion / narrowing. Baseline = environment → the max duty seq). */
function sweepAfterMandate<R>(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly mandates: readonly RotationMandate[];
  /** The actor. A duty environment outside scope cannot be rotated (§7), so it is dropped from the targets and noted. */
  readonly actorUserId: string;
  /** The key of the device the actor signs with (the fulfillable range = the device's effective scope — DK K4-17). */
  readonly signingKeyPair: SigningKeyPair;
  /** The per-duty-kind rotation injection (the rotate entry's reason matches the duty). */
  readonly rotateWith: (reason: string) => SweepRotate<R>;
}): Effect.Effect<MemberSweepOutcome, CliError, R> {
  return Effect.gen(function* () {
    const actorScope = yield* actorEffectiveScope(
      input.verified,
      input.actorUserId,
      input.signingKeyPair,
    );
    // Duty environments outside my (the device's effective) scope (when a
    // duty from a narrowing / remove someone made in the past remains on
    // the target's history, when run on a capped device) are excluded from
    // the rotate targets (CRYPTO_SPEC §7 — even the actor cannot rotate
    // outside scope. Independent review S2). The always-on warning keeps
    // displaying them
    const deletedVerified = yield* verifiedDeletedEnvironmentSet(input.client, input.verified);
    const { baselines, outOfScope, skippedDeleted } = partitionSweepBaselines({
      verified: input.verified,
      all: baselinesOf(input.mandates),
      actorScope,
      deletedVerified,
    });
    // Each environment's reason = the kind of the duty that became that environment's baseline (max seq) (independent review N3)
    const reasons = reasonsByEnvironment(input.mandates);
    const sweep = yield* sweepRotations({
      rotate: (environmentId, mode) =>
        input.rotateWith(reasons.get(environmentId) ?? MEMBER_REMOVED_ROTATION_REASON)(
          environmentId,
          mode,
        ),
      verified: input.verified,
      baselines,
      deletedVerified,
    });
    return { ...sweep, skippedDeleted, outOfScope };
  });
}

/**
 * The range of environments where the actor can fulfill rotate = the
 * signing device's effective scope (person ∩ device — DK K4-17). An
 * effective role below member (reader, or a member-cap device) is empty
 * (rotate needs member or above — §6.2). Non-members and unregistered
 * devices are empty too (fail-closed — they stay on the always-on
 * warning).
 */
function actorEffectiveScope(
  verified: VerifiedProject,
  actorUserId: string,
  signingKeyPair: SigningKeyPair,
): Effect.Effect<MemberScope, CliError> {
  return Effect.gen(function* () {
    const actor = verified.state.members.get(actorUserId);
    if (actor === undefined) {
      return { kind: "listed", environmentIds: [] };
    }
    const device = yield* ownDeviceBySigningKey(verified, actor, signingKeyPair).pipe(
      Effect.catch(() => Effect.succeed<ChainDevice | null>(null)),
    );
    if (device === null) {
      return { kind: "listed", environmentIds: [] };
    }
    const permission = effectivePermissionOf(actor, device);
    return ROLE_RANK[permission.role] >= ROLE_RANK.member
      ? permission.scope
      : { kind: "listed", environmentIds: [] };
  });
}

/**
 * The sweep of the target's duties (remove / demotion / narrowing —
 * including application via a proposal). Shared between the direct
 * append's aftermath and the approver's fulfillment that completes the
 * application under four-eyes (approval-approve.ts — approval item 22).
 */
export function sweepMemberMandates<R>(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly targetUserId: string;
  readonly actorUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  readonly rotateWith: (reason: string) => SweepRotate<R>;
}): Effect.Effect<MemberSweepOutcome | null, CliError, R> {
  const mandates = memberMandatesFor(input.verified, input.targetUserId);
  return mandates.length === 0 ? Effect.succeed(null) : sweepAfterMandate({ ...input, mandates });
}

/** The member-family sweep result (includes deleted environments and ones that could not be rotated because they are outside the actor's scope). */
export type MemberSweepOutcome = SweepOutcome & {
  readonly skippedDeleted: readonly string[];
  /** Duty environments outside the actor's scope that cannot be rotated (§7 — left to another member's fulfillment). */
  readonly outOfScope: readonly string[];
};

const MANDATE_REASONS = {
  "member-removed": MEMBER_REMOVED_ROTATION_REASON,
  "role-demoted": ROLE_DEMOTED_ROTATION_REASON,
  "scope-narrowed": SCOPE_NARROWED_ROTATION_REASON,
  "server-revoked": "server-revoked",
  "device-revoked": "device-revoked",
} satisfies Record<RotationMandate["kind"], string>;

/** Environment → the reason of the baseline (max seq) duty (on a seq tie, demotion wins). */
function reasonsByEnvironment(mandates: readonly RotationMandate[]): ReadonlyMap<string, string> {
  const chosen = new Map<string, RotationMandate>();
  for (const mandate of mandates) {
    for (const environmentId of mandate.environmentIds) {
      const current = chosen.get(environmentId);
      if (
        current === undefined ||
        current.seq < mandate.seq ||
        (current.seq === mandate.seq && mandate.kind === "role-demoted")
      ) {
        chosen.set(environmentId, mandate);
      }
    }
  }
  return new Map(
    [...chosen].map(([environmentId, mandate]) => [environmentId, MANDATE_REASONS[mandate.kind]]),
  );
}

/**
 * The CAS append of a membership op (the shared scaffolding of
 * retryOnConflict — same shape across add / remove / change_role). On each
 * head conflict: resync with the extension check → redo the pre-check via
 * `recheck`; if a concurrent run already committed the same change
 * (already), continue without appending.
 */
function appendWithCas(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  /** The op name used in the exhausted wording (e.g. "remove_member"). */
  readonly opLabel: string;
  readonly signEntry: (verified: VerifiedProject) => Effect.Effect<ChainEntry, CliError>;
  readonly recheck: (
    verified: VerifiedProject,
  ) => Effect.Effect<{ readonly already: boolean }, CliError>;
}): Effect.Effect<{ readonly verified: VerifiedProject; readonly appended: boolean }, CliError> {
  return retryOnConflict<
    { readonly verified: VerifiedProject; readonly already: boolean },
    { readonly verified: VerifiedProject; readonly appended: boolean },
    "head-conflict"
  >(
    { verified: input.verified, already: false },
    {
      maxAttempts: MAX_ATTEMPTS,
      attempt: (state) =>
        state.already
          ? Effect.succeed({ verified: state.verified, appended: false })
          : Effect.gen(function* () {
              const entry = yield* input.signEntry(state.verified);
              yield* appendEntry(input.client, state.verified, entry);
              return { verified: state.verified, appended: true };
            }),
      classify: (error) => (error instanceof ChainHeadConflictError ? "head-conflict" : null),
      recover: (state) =>
        Effect.gen(function* () {
          const resynced = yield* resyncExtended(input.resync, state.verified);
          const rechecked = yield* input.recheck(resynced);
          return { verified: resynced, already: rechecked.already };
        }),
      exhaustedMessage: `${input.opLabel}'s chain-head conflict did not resolve (${MAX_ATTEMPTS} attempts). Wait a moment and re-run`,
    },
  );
}

/** Resolving the actor and the target (the shared prologue of remove / change_role). */
function resolveActorAndTarget(
  verified: VerifiedProject,
  signerUserId: string,
  targetUserId: string,
): Effect.Effect<
  { readonly actor: ChainMember; readonly target: ChainMember | undefined },
  CliError
> {
  const actor = verified.state.members.get(signerUserId);
  if (actor === undefined) {
    return Effect.fail(cliError("You are not a chain-derived member of this project"));
  }
  return Effect.succeed({ actor, target: verified.state.members.get(targetUserId) });
}

/**
 * The actor's authority material the pre-flight sees. Since the consensus
 * judges by effective authority (person ∩ device cap — §6.2
 * `effectivePermissionOf`), the early judgment follows it (if the signing
 * device's cap is narrower than the person's, skipping the effective-side
 * check means advancing to the append-time refusal).
 */
type ActorAuthority = { readonly role: Role; readonly scope: MemberScope };

/**
 * Pulls the signing device and returns its effective authority. For a key
 * absent from the chain (unregistered / revoked), a typed failure precedes
 * the person's-authority wording (same order as device-ops.ts).
 */
function actorAuthority(
  verified: VerifiedProject,
  actor: ChainMember,
  signingKeyPair: SigningKeyPair,
): Effect.Effect<EffectivePermission, CliError> {
  return Effect.map(ownDeviceBySigningKey(verified, actor, signingKeyPair), (device) =>
    effectivePermissionOf(actor, device),
  );
}

/** The CLI's early check of the target rules (§6.2) for remove / change_role (a pre-judgment for the wording). */
function targetedOpRejection(input: {
  readonly actor: ActorAuthority;
  readonly target: ChainMember;
  readonly operation: string;
}): string | null {
  if (ROLE_RANK[input.actor.role] < ROLE_RANK.admin) {
    return `Only admins and above can run ${input.operation} (CRYPTO_SPEC §6.2)`;
  }
  if (ROLE_RANK[input.target.role] >= ROLE_RANK.admin && input.actor.role !== "owner") {
    return `Only an owner can run ${input.operation} against an admin / owner (CRYPTO_SPEC §6.2)`;
  }
  return null;
}

function ownersCount(verified: VerifiedProject): number {
  let count = 0;
  for (const member of verified.state.members.values()) {
    if (member.role === "owner") {
      count += 1;
    }
  }
  return count;
}

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

/** An accepted row (every row carries the issuance text). */
type AddableRow = InvitationRow & { readonly acceptance: InviteAcceptance };

const withAcceptance = (
  row: InvitationRow,
): row is InvitationRow & { readonly acceptance: InviteAcceptance } => row.acceptance !== null;

/**
 * Choosing the accepted invite: a given id picks that row; without one,
 * auto-select only when exactly one accepted row exists (multiple or zero
 * requires an explicit choice).
 */
function selectInvitation(
  rows: readonly InvitationRow[],
  inviteId: string | null,
): Effect.Effect<AddableRow, CliError> {
  if (inviteId !== null) {
    const row = rows.find((candidate) => candidate.id === inviteId);
    if (row === undefined) {
      return Effect.fail(
        cliError("The specified invite was not found (check the id with `maruhi invite list`)"),
      );
    }
    if (row.status === "revoked") {
      return Effect.fail(
        cliError(
          "The specified invite has been revoked (its acceptance block, if any, will not be used)",
        ),
      );
    }
    if (!withAcceptance(row)) {
      return Effect.fail(
        cliError(
          "The specified invite has not been accepted yet (check with `maruhi invite list` after acceptance)",
        ),
      );
    }
    return Effect.succeed(row);
  }
  const accepted = rows.filter(withAcceptance).filter((row) => row.status === "accepted");
  const first = accepted[0];
  if (first === undefined) {
    // completed rows are never auto-selected (ambiguous: every past
    // member's row stays completed forever). The resume of a backfill for
    // an already add_member'd invite takes the explicit-id path — that
    // route is shown here
    return Effect.fail(
      cliError(
        "There is no accepted invite. To resume the backfill of an invite that completed through add_member, look up the id with `maruhi invite list` and pass it explicitly: `maruhi member add <invite-id>`",
      ),
    );
  }
  if (accepted.length > 1) {
    return Effect.fail(
      cliError(
        `Multiple invites have been accepted (${accepted.map((row) => displayText(row.id)).join(", ")}). Specify which invite id to add`,
      ),
    );
  }
  return Effect.succeed(first);
}

/**
 * The inviter's mutual confirmation (§6.5 — mandatory UX): displays the
 * acceptance key's FP word list and the granted role, and requires an
 * explicit confirmation of the out-of-band match. The ceremony is not
 * skipped even on a re-run (a backfill-only interruption recovery) — same
 * discipline as server-grant (never skip verifying the key wraps are about
 * to be dealt to).
 *
 * The verified fingerprint book (KF — known-fingerprints.ts): when it
 * matches the fingerprint of a previously out-of-band-verified
 * counterpart (origin × user_id), the 12-word out-of-band recital is
 * waived. **The explicit confirmation (yes input) of the grant itself is
 * still required on a hit**, and in agent environments the book is never
 * used as an auto-pass (a flag stays required — the book records a past
 * verification and does not substitute a human's consent to this grant).
 * Furthermore **the book is usable only when stdin / stdout are an
 * interactive terminal** (the same allow-list as ADR-0016 decision 7's
 * primary boundary): the 12-word ceremony requires re-typing the last word
 * on each run so a blind pipe can't pass it, but a yes confirmation is not
 * like that, so on a pipe / CI / undetected agent the book is disabled and
 * the full ceremony returns (fail-closed). An explicit flag beats the
 * book; a mismatch warns and returns to the normal ceremony (not an
 * automatic failure — a legitimate key update is possible). A successful
 * ceremony / flag match is recorded into the book.
 * automatic failure — a legitimate key update is possible). A successful ceremony / flag match is recorded into the book.
 */
function confirmInviteeFingerprint(input: {
  readonly origin: string;
  readonly targetUserId: string;
  readonly role: Role;
  readonly fingerprintHex: string;
  readonly expectFingerprintHex: string | null;
}): Effect.Effect<void, CliError, CliIo | FingerprintBook | Stdio.Stdio> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const words = yield* fingerprintWords(
      input.fingerprintHex,
      "The acceptance key's fingerprint is malformed",
    );
    const book = yield* consultFingerprintBook({
      origin: input.origin,
      userId: input.targetUserId,
      fingerprintHex: input.fingerprintHex,
    });
    // A book hit is usable only on the interactive-terminal + no-flag +
    // non-agent path (judged by usableBookHit). In that case the 2 lines
    // instructing the recital comparison are dropped (never say "not
    // needed" right after instructing the call)
    const hit = yield* usableBookHit({
      book,
      flagProvided: input.expectFingerprintHex !== null,
      isAgent: io.agentProfile().isAgent,
    });
    const lines = [
      "Acceptor's key fingerprint (mutual confirmation — CRYPTO_SPEC §6.5):",
      `  invitee: ${displayText(input.targetUserId)}`,
      `  role:    ${input.role} (will be granted to this member)`,
      `  hex:  ${input.fingerprintHex}`,
      "  word: " + formatWordList(words),
      ...(hit !== null
        ? []
        : [
            "Check that this word list matches the 12 words the acceptor reads to you out of band (e.g. over a call).",
            "If they do not match, the acceptance has been hijacked (an attacker's key was injected) — abort add_member and revoke the invite.",
          ]),
    ];
    for (const line of lines) {
      yield* io.log(line);
    }
    if (input.expectFingerprintHex !== null) {
      if (input.expectFingerprintHex !== input.fingerprintHex) {
        return yield* Effect.fail(
          cliError(
            "--expect-fingerprint does not match the acceptance key's fingerprint. The acceptance may have been hijacked — add_member was aborted (revoke the invite and reissue)",
          ),
        );
      }
      yield* io.log(
        "--expect-fingerprint matches (continuing; the out-of-band record counts as checked)",
      );
      yield* book.record;
      return;
    }
    yield* book.warnIfChanged;
    if (io.agentProfile().isAgent) {
      return yield* Effect.fail(
        cliError(
          "Refused to run the acceptance-key confirmation ceremony: an AI agent environment was detected. Run this yourself in a terminal, or pass the acceptance key fingerprint noted out of band via --expect-fingerprint",
        ),
      );
    }
    if (hit !== null) {
      return yield* confirmKnownFingerprint({
        entry: hit,
        filePath: book.filePath,
        prompt: `Type yes to add ${displayText(input.targetUserId)} as ${input.role} with this previously verified key`,
        cancelText: "add_member was cancelled.",
      });
    }
    yield* confirmByLastWord({
      words,
      promptText:
        "Once you have checked against the acceptor's out-of-band read-out (e.g. a call), type the last of the 12 words shown above",
      mismatchText: "That does not match. Type the last word of the list shown above",
      exhaustedText:
        "Acceptance key fingerprint confirmation failed (the re-typed word does not match). add_member was not performed — re-run once you can check with the acceptor",
    });
    yield* book.record;
  });
}

/**
 * Resolving the destination login (adequacy form 4's (iii)): `--github` →
 * the issuance pin's destination. Absent = null = go to the ceremony. No
 * interactive input is provided (it would mix with the ceremony's re-input
 * prompt, and a typo becomes a query for "someone else's GitHub" — naming
 * is limited to issuance time or an explicit flag).
 */
function resolveAddresseeLogin(input: {
  readonly flagLogin: string | null;
  readonly pinLogin: string | null;
}): Effect.Effect<string | null, never, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    if (input.flagLogin !== null) {
      return input.flagLogin;
    }
    if (input.pinLogin !== null) {
      yield* io.log(
        `The invite was issued for github.com/${input.pinLogin} (recorded at issuance on this machine)`,
      );
      return input.pinLogin;
    }
    return null;
  });
}

/**
 * The two choices when unregistered (supplement 21 ruling D ④): when the
 * counterpart's GitHub carries no key, ask before entering the ceremony —
 * "ask them and re-run" or "ceremony right now". Only on an interactive
 * terminal + non-agent + no flag (non-interactive stays flag-only, as
 * before). yes = proceed to the ceremony.
 */
function askCeremonyOrWait(input: {
  readonly login: string;
  readonly flagProvided: boolean;
}): Effect.Effect<void, CliError, CliIo | Stdio.Stdio> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const stdio = yield* Stdio.Stdio;
    const interactive =
      !io.agentProfile().isAgent &&
      (yield* stdio.stdinIsTerminal) &&
      (yield* stdio.stdoutIsTerminal);
    if (!interactive || input.flagProvided) {
      return;
    }
    yield* io.log(
      `github.com/${input.login} has not registered this key as a signing key. Ask them to run \`maruhi key publish\` and re-run \`maruhi member add\` to add them without a call, or confirm the 12 words with them now`,
    );
    const answer = yield* io.promptLine({
      prompt:
        "Type yes to confirm the 12 words now; anything else to stop and wait for their registration: ",
    });
    if (answer.trim().toLowerCase() !== "yes") {
      return yield* Effect.fail(
        cliError(
          `add_member was not performed. Ask github.com/${input.login} to register their key with \`maruhi key publish\`, then re-run \`maruhi member add\``,
        ),
      );
    }
  });
}

/**
 * The inviter's adequacy form 4 (CRYPTO_SPEC §6.5 — IV2): in addition to
 * verifying the issuance text and both signatures (done by the caller),
 * when the backing source can confirm "the acceptance's sig key is the
 * named counterpart's key", it may proceed to add_member **without a
 * confirmation input** (the naming was the explicit act at issuance). If
 * `--expect-fingerprint` is also given, it is required on top of the
 * match, and a mismatch refuses. An impossible match (backing `none`, no
 * destination, unregistered, unfetchable) = false = falls back to adequacy
 * forms 1-3 (confirmInviteeFingerprint).
 */
function confirmInviteeViaBacking(input: {
  readonly identityBacking: IdentityBacking;
  readonly flagLogin: string | null;
  readonly pinLogin: string | null;
  readonly sigPubHex: string;
  readonly fingerprintHex: string;
  readonly expectFingerprintHex: string | null;
}): Effect.Effect<boolean, CliError, CliIo | Stdio.Stdio | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    if (input.identityBacking === "none") {
      if (input.flagLogin !== null) {
        yield* logNote(
          "identityBacking is none, so --github cannot be checked against github.com — falling back to the fingerprint confirmation",
        );
      }
      return false;
    }
    const login = yield* resolveAddresseeLogin({
      flagLogin: input.flagLogin,
      pinLogin: input.pinLogin,
    });
    if (login === null) {
      yield* logNote(
        "no GitHub login to check the acceptance key against (pass --github <login>, or name the invitee with `maruhi invite create --github`) — falling back to the fingerprint confirmation",
      );
      return false;
    }
    const verdict = yield* checkSigningKeyBacking({ login, sigPubHex: input.sigPubHex });
    if (verdict.kind === "not-registered") {
      yield* askCeremonyOrWait({ login, flagProvided: input.expectFingerprintHex !== null });
      yield* logNote(
        `${describeBackingFallback(login, verdict)} — falling back to the fingerprint confirmation`,
      );
      return false;
    }
    if (verdict.kind !== "match") {
      yield* logNote(
        `${describeBackingFallback(login, verdict)} — falling back to the fingerprint confirmation`,
      );
      return false;
    }
    if (
      input.expectFingerprintHex !== null &&
      input.expectFingerprintHex !== input.fingerprintHex
    ) {
      return yield* Effect.fail(
        cliError(
          "--expect-fingerprint does not match the acceptance key's fingerprint. The acceptance may have been hijacked — add_member was aborted (revoke the invite and reissue)",
        ),
      );
    }
    yield* io.log(
      `Acceptance key verified: it is registered as a signing key on github.com/${login}, and the acceptance is bound to the link you issued (CRYPTO_SPEC §6.5) — no 12-word call is needed`,
    );
    yield* io.log(`  fp:   ${input.fingerprintHex}`);
    return true;
  });
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
function ensureAddable(input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: string;
  readonly acceptance: InviteAcceptance;
  readonly role: Role;
  readonly scope: ScopePayloadFields;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<{ readonly alreadyAdded: boolean }, CliError> {
  return Effect.gen(function* () {
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
        memberHasKeys(
          existing,
          input.acceptance.inviteeEncPubHex,
          input.acceptance.inviteeSigPubHex,
        )
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
    // Like remove / change-role, no containment is asked (what remains is only the backfill)
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
}

/**
 * Signs an add_member entry right after the current head (the shared core
 * = chain-append.ts). scope is the invite row's to-be-granted scope
 * (AUTH_SPEC §15-2 — an inviter cannot grant a different scope after
 * acceptance: the consent's range is fixed by the issuance signature at
 * issuance)
 * grant a different scope after acceptance: the consent's range is fixed by the issuance signature at issuance)
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
 * re-register) replaces it with a new-key wrap. The judgment prefers the
 * **exact comparison** of the 409 response's stored recipient enc public
 * key (`storedRecipientEncPubHex` — AUTH_SPEC §12-6) with the acceptance
 * key (decryptability = enc-key equality itself), falling back to the
 * conventional key-history heuristic (`staleWrapSuspected`) only when the
 * response lacks it (a pre-supplement self-hosted server). Even if the
 * occupying wrap under the heuristic path were actually the current key,
 * delete → re-register converges to the same content and is safe.
 * the occupying wrap under the heuristic path were actually the current key, delete → re-register converges to the same content and is safe.
 */
function backfillMemberEnvironment(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly recipient: DekRecipient;
  readonly target: ChainMember;
  readonly staleWrapSuspected: boolean;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<MemberBackfillResult, CliError> {
  return Effect.gen(function* () {
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
  });
}

/** The backfill of one environment × one device of the target (slot = (epoch, user_id, enc key)). */
function backfillMemberDevice(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly recipient: DekRecipient;
  readonly target: ChainMember;
  readonly targetDevice: ChainDevice;
  readonly staleWrapSuspected: boolean;
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
        // comparison against the response's stored enc public key is
        // preferred (a match = registered under the current key =
        // idempotent). Degrades to estimation only when absent
        const staleWrap =
          storedRecipientEncPubHex === null
            ? input.staleWrapSuspected
            : storedRecipientEncPubHex !== targetDevice.encPubHex;
        if (!staleWrap) {
          return "already-registered" as const;
        }
        // The repair path (§12-6): delete the occupied slot and
        // re-register the new-key wrap. The reference names down to the
        // device's enc key (with multiple devices, omitting it is a 422
        // duplicate-recipient)
        yield* input.client.deks
          .remove({
            params: { projectId: input.verified.projectId, environmentId: input.environmentId },
            payload: {
              wraps: [
                {
                  epoch: wrap.epoch,
                  recipientUserId: input.target.userId,
                  recipientEncPubHex: storedRecipientEncPubHex ?? targetDevice.encPubHex,
                },
              ],
            },
          })
          .pipe(
            Effect.asVoid,
            Effect.catch((error) =>
              // When a concurrent repair made the slot disappear, only the re-registration is needed
              error instanceof DekWrapNotFoundError ? Effect.void : Effect.fail(toCliError(error)),
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
function prepareMemberAdd(input: {
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
}): Effect.Effect<
  {
    readonly row: AddableRow;
    readonly alreadyAdded: boolean;
  },
  CliError,
  CliIo | FingerprintBook | Stdio.Stdio | HttpClient.HttpClient
> {
  return Effect.gen(function* () {
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
    // issuance signature's verification pins the row (the IV revision moved the source of truth to the issuance signature)
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
}

/** The all-environment sweep of the backfill (one environment's failure doesn't stop the rest — §7). */
function backfillAllEnvironments(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly recipient: DekRecipient;
  readonly target: ChainMember;
  /** The environments to backfill (default = all environments of the target's scope). An explicit list is re-narrowed by the scope. */
  readonly environments?: readonly string[];
  readonly staleWrapSuspected: boolean;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<
  Pick<MemberAddSummary, "registered" | "alreadyRegistered" | "repaired" | "failed">,
  CliError
> {
  return Effect.gen(function* () {
    // The target scope's environments (chain-derived, verified-deletions
    // excluded) × every epoch (CRYPTO_SPEC §7 "every epoch DEK of every
    // environment in the target's scope" — 2026-09-15 ES K4. The
    // `environments` explicit list is used for change-role's widening
    // backfill)
    const deletedVerified = yield* verifiedDeletedEnvironmentSet(input.client, input.verified);
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
  });
}

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
export function backfillNewMember(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly target: ChainMember;
  readonly recipient: DekRecipient;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<
  Pick<MemberAddSummary, "registered" | "alreadyRegistered" | "repaired" | "failed">,
  CliError,
  CliIo
> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    // Detecting a re-addition (a past membership under a different key):
    // does the key history carry a binding different from the current key.
    // The 409 judgment prefers the exact comparison against the response's
    // stored enc public key (AUTH_SPEC §12-6 supplement); this heuristic is
    // a fallback used only for 409s from old servers whose response lacks
    // the field. Note a supplemented server auto-cleans stale-key wraps on
    // add_member acceptance (same supplement), so normally a 409 only ever
    // means "registered under the current key". "A different key" = a
    // history binding that matches none of the target's current device set
    // (with multiple devices, a current device's key is not a stale key —
    // DK K4)
    const staleWrapSuspected = (input.verified.keyHistory.get(input.target.userId) ?? []).some(
      (binding) => !memberHasKeys(input.target, binding.encPubHex, binding.sigPubHex),
    );
    if (staleWrapSuspected) {
      yield* io.log(
        "The target user ID was previously a member with a different key. If leftover wraps addressed to the old key are found, the repair path (delete → re-register) replaces them with the new key (CRYPTO_SPEC §7 / AUTH_SPEC §12-6)",
      );
    }
    return yield* backfillAllEnvironments({
      client: input.client,
      verified: input.verified,
      recipient: input.recipient,
      target: input.target,
      staleWrapSuspected,
      signerUserId: input.signerUserId,
      signingKeyPair: input.signingKeyPair,
    });
  });
}

export function memberAddOp(input: {
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
}): Effect.Effect<
  MemberOpOutcome<MemberAddSummary>,
  CliError,
  CliIo | FingerprintBook | Stdio.Stdio | HttpClient.HttpClient
> {
  return Effect.gen(function* () {
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
}

// ---------------------------------------------------------------------------
// member remove
// ---------------------------------------------------------------------------

export interface MemberRemoveSummary extends MemberSweepOutcome {
  /** Whether it was appended to the chain (false = already deleted — resumes from mid-rotation). */
  readonly appended: boolean;
  readonly targetUserId: string;
}

/**
 * remove's pre-append checks (re-run after a CAS retry's resync as well).
 * `proposing` = the proposal path (the self-remove refusal is dropped
 * because the fulfiller moves to the approver — design record K6-N).
 */
function ensureRemovable(input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: string;
  readonly targetUserId: string;
  readonly proposing: boolean;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<{ readonly alreadyRemoved: boolean }, CliError> {
  return Effect.gen(function* () {
    if (input.targetUserId === input.signerUserId && !input.proposing) {
      return yield* Effect.fail(
        cliError(
          "You cannot remove yourself. You would be unable to run the post-removal rotation of every environment (CRYPTO_SPEC §7) — ask another admin / owner to remove you",
        ),
      );
    }
    const { actor, target } = yield* resolveActorAndTarget(
      input.verified,
      input.signerUserId,
      input.targetUserId,
    );
    const permission = yield* actorAuthority(input.verified, actor, input.signingKeyPair);
    if (target === undefined) {
      const resumable = removalResumeRejection(input.verified, permission, input.targetUserId);
      return resumable === null
        ? { alreadyRemoved: true }
        : yield* Effect.fail(cliError(resumable));
    }
    const rejection = removeRuleRejection(input.verified, permission, target);
    return rejection === null ? { alreadyRemoved: false } : yield* Effect.fail(cliError(rejection));
  });
}

/**
 * The conditions for resuming from deleted (interruption recovery): a
 * remove of that user_id exists on the chain (never create a shape where
 * the sweep runs on a mistyped user_id. A remove applied via a proposal —
 * four-eyes K6 — also lands on the same list: design record K6-C), and the
 * resuming actor is member or above.
 */
function removalResumeRejection(
  verified: VerifiedProject,
  actor: ActorAuthority,
  targetUserId: string,
): string | null {
  const removedBefore = verified.applied.some(
    ({ operation }) =>
      operation.op === "remove_member" && operation.payload.targetUserId === targetUserId,
  );
  if (!removedBefore) {
    return "The target is not a member and the chain has no removal record for it (check the user ID)";
  }
  return ROLE_RANK[actor.role] < ROLE_RANK.member
    ? "Resuming the rotation requires the member role or above (CRYPTO_SPEC §6.2)"
    : null;
}

/** The pre-judgment of remove_member's §6.2 rules (role → scope-not-contained → last-owner). */
function removeRuleRejection(
  verified: VerifiedProject,
  actor: ActorAuthority,
  target: ChainMember,
): string | null {
  const rejection = targetedOpRejection({ actor, target, operation: "remove_member" });
  if (rejection !== null) {
    return rejection;
  }
  // Principle 1 (§6.2 scope-not-contained): remove's permission-change
  // environment set = the target's current scope ("can remove = can
  // fulfill rotate" — ruling D). The same pre-judgment as change-role
  if (!scopeContains(actor.scope, target.scope)) {
    return `Your environment scope (${describeScope(actor.scope)}) does not contain the target's scope (${describeScope(target.scope)}), so you could not run the post-removal rotation — CRYPTO_SPEC §6.2 scope-not-contained. Ask an owner or an admin whose scope covers them`;
  }
  return target.role === "owner" && ownersCount(verified) === 1
    ? "The last owner cannot be removed (CRYPTO_SPEC §6.2 last-owner-protected)"
    : null;
}

/** Signs a remove_member entry right after the current head (the shared core = chain-append.ts). */
function signRemoveEntry(input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: string;
  readonly targetUserId: string;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<ChainEntry, CliError> {
  return signEntryAtHead({
    verified: input.verified,
    signerUserId: input.signerUserId,
    operation: { op: "remove_member", payload: { targetUserId: input.targetUserId } },
    signingKeyPair: input.signingKeyPair,
    failureText: "Failed to sign the remove_member entry",
  });
}

export function memberRemoveOp<R>(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly targetUserId: string;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly rotateWith: (reason: string) => SweepRotate<R>;
  readonly proposal: ProposalInput;
}): Effect.Effect<MemberOpOutcome<MemberRemoveSummary>, CliError, R> {
  return Effect.gen(function* () {
    const inner: ProposableOperation = {
      op: "remove_member",
      payload: { targetUserId: input.targetUserId },
    };
    const proposing = isApprovalTarget(inner, input.verified.state.approvalPolicy);
    const recheck = (view: VerifiedProject) =>
      ensureRemovable({
        verified: view,
        signerUserId: input.signerUserId,
        targetUserId: input.targetUserId,
        proposing,
        signingKeyPair: input.signingKeyPair,
      });
    const first = yield* recheck(input.verified);

    // Four-eyes (K6-A): if the policy targets remove_member, propose and
    // finish (the rotate duty is fulfilled by the approver's sweep after
    // the application — rulings P7 / P8). A resume (already deleted) is
    // never proposed
    if (!first.alreadyRemoved && proposing) {
      const proposal = yield* proposeOperation(
        input,
        inner,
        proposeRecheck(
          recheck,
          (rechecked) => rechecked.alreadyRemoved,
          "The target was removed by a concurrent run while this proposal was being appended — nothing to propose. Re-run `maruhi member remove` to resume the rotation",
        ),
      );
      return { kind: "proposed", proposal };
    }

    let verified = input.verified;
    let appended = false;
    if (!first.alreadyRemoved) {
      const outcome = yield* appendWithCas({
        client: input.client,
        verified,
        resync: input.resync,
        opLabel: "remove_member",
        signEntry: (view) =>
          signRemoveEntry({
            verified: view,
            signerUserId: input.signerUserId,
            targetUserId: input.targetUserId,
            signingKeyPair: input.signingKeyPair,
          }),
        recheck: (view) =>
          ensureStillTarget(view, inner, false).pipe(
            Effect.flatMap(() => recheck(view)),
            Effect.map((rechecked) => ({ already: rechecked.alreadyRemoved })),
          ),
      });
      verified = outcome.verified;
      appended = outcome.appended;
    }

    // The post-acceptance resync confirms the deletion's listing (the server's claim is never the source of truth)
    verified = yield* resyncExtended(input.resync, verified);
    if (verified.state.members.has(input.targetUserId)) {
      return yield* Effect.fail(
        cliError(
          "The resync after remove_member was accepted still shows the target as a member (the server's response contradicts the chain). Investigate the served chain",
        ),
      );
    }

    // The target's duty entry (this remove's append or a historical one —
    // past narrowings / demotions included) becomes the baseline. No remove
    // at all means "a deletion was confirmed yet no duty entry exists" = an
    // internal contradiction of the derivation. The duty's environment set
    // is the target's current scope (§7 — listed{} means empty)
    const mandates = memberMandatesFor(verified, input.targetUserId);
    if (!mandates.some((mandate) => mandate.kind === "member-removed")) {
      return yield* Effect.fail(
        cliError(
          "Cannot find the rotation-mandate entry on the chain (internal contradiction in the derivation)",
        ),
      );
    }
    const sweep = yield* sweepAfterMandate({
      client: input.client,
      verified,
      mandates,
      actorUserId: input.signerUserId,
      signingKeyPair: input.signingKeyPair,
      rotateWith: input.rotateWith,
    });
    return { kind: "applied", summary: { appended, targetUserId: input.targetUserId, ...sweep } };
  });
}

// ---------------------------------------------------------------------------
// member change-role
// ---------------------------------------------------------------------------

export interface MemberChangeRoleSummary {
  /** Whether it was appended to the chain (false = already at the target (role, scope) — only the duty resumes). */
  readonly appended: boolean;
  readonly targetUserId: string;
  readonly newRole: Role;
  readonly newScope: MemberScope;
  /** Of the widened environments (new \ old — the actor's backfill duty. §12-6), those inside the actor's scope. */
  readonly widenedEnvironmentIds: readonly string[];
  /** Of the historical widenings, those outside the actor's scope (not my duty — left to a member whose scope has that environment). */
  readonly widenedOutOfScopeEnvironmentIds: readonly string[];
  /** The narrowed environments (old \ new — the rotate duty. §7). */
  readonly narrowedEnvironmentIds: readonly string[];
  /** The widened part's backfill result (no widening = null). */
  readonly backfill: Pick<
    MemberAddSummary,
    "registered" | "alreadyRegistered" | "repaired" | "failed"
  > | null;
  /** Whether the target has a demotion duty (role-demoted) (report-wording material — not re-derived from the new role). */
  readonly demoted: boolean;
  /** The result of rotating the duty environments for the demotion / narrowing (no duty = null). */
  readonly sweep: MemberSweepOutcome | null;
}

/** The change_role input (omitting role or scope means kept as-is — design record K4-A). */
export interface ChangeRoleRequest {
  readonly newRole: Role | null;
  readonly newScope: MemberScope | null;
}

/** From the target's current (role, scope) and the request, decides the new (role, scope) to append (a full replacement — §6.2). */
function resolveRoleChange(
  target: ChainMember,
  request: ChangeRoleRequest,
): Effect.Effect<{ readonly role: Role; readonly scope: MemberScope }, CliError> {
  const role = request.newRole ?? target.role;
  if (role === "owner") {
    // An owner's scope is always all (§6.2 scope-role-mismatch) — combining `--env` is a contradiction
    if (request.newScope !== null && request.newScope.kind !== "all") {
      return Effect.fail(
        usageError(
          "An owner's scope is always all environments (CRYPTO_SPEC §6.2 scope-role-mismatch) — drop --env / --no-envs, or use --all-envs",
        ),
      );
    }
    return Effect.succeed({ role, scope: ALL_SCOPE });
  }
  return Effect.succeed({ role, scope: request.newScope ?? target.scope });
}

/** Early check of change_role's role rules (§6.2) (a reason string when unmet). */
function changeRoleRuleRejection(input: {
  readonly verified: VerifiedProject;
  readonly actor: ActorAuthority;
  readonly target: ChainMember;
  readonly newRole: Role;
}): string | null {
  const base = targetedOpRejection({
    actor: input.actor,
    target: input.target,
    operation: "change_role",
  });
  if (base !== null) {
    return base;
  }
  if (ROLE_RANK[input.newRole] >= ROLE_RANK.admin && input.actor.role !== "owner") {
    return "Only an owner can change a role to admin / owner (CRYPTO_SPEC §6.2)";
  }
  if (
    input.target.role === "owner" &&
    input.newRole !== "owner" &&
    ownersCount(input.verified) === 1
  ) {
    return "The last owner cannot be demoted (CRYPTO_SPEC §6.2 last-owner-protected)";
  }
  return null;
}

/**
 * The pre-judgment of principle 1 (§6.2 scope-not-contained): when the
 * role changes, old ∪ new; when only the scope changes, the symmetric
 * difference must be contained in the actor's scope. If old or new is all,
 * the difference becomes U \ X, so only an all-scoped actor can do it
 * (set algebra — the derivation of design record K4-I).
 */
function scopeContainmentRejection(input: {
  readonly actor: ActorAuthority;
  readonly target: ChainMember;
  readonly newRole: Role;
  readonly newScope: MemberScope;
}): string | null {
  const contained =
    input.newRole !== input.target.role
      ? scopeContains(input.actor.scope, input.target.scope) &&
        scopeContains(input.actor.scope, input.newScope)
      : actorMayReplaceScope(input);
  if (contained) {
    return null;
  }
  return `Your environment scope (${describeScope(input.actor.scope)}) does not contain the environments whose permissions this change affects (target: ${describeScope(input.target.scope)} → ${describeScope(input.newScope)}) — CRYPTO_SPEC §6.2 scope-not-contained. Ask an owner or an admin whose scope covers them`;
}

/** For a scope-only replacement, whether the actor contains the symmetric difference (old △ new). */
function actorMayReplaceScope(input: {
  readonly actor: ActorAuthority;
  readonly target: ChainMember;
  readonly newScope: MemberScope;
}): boolean {
  if (input.actor.scope.kind === "all") {
    return true;
  }
  const before = input.target.scope;
  const after = input.newScope;
  if (before.kind === "all" || after.kind === "all") {
    // all △ all = ∅ (no change), all △ listed = U \ X (a listed actor cannot contain it)
    return before.kind === after.kind;
  }
  const beforeIds = new Set(before.environmentIds);
  const afterIds = new Set(after.environmentIds);
  const changed = [
    ...before.environmentIds.filter((id) => !afterIds.has(id)),
    ...after.environmentIds.filter((id) => !beforeIds.has(id)),
  ];
  return scopeContains(input.actor.scope, { kind: "listed", environmentIds: changed });
}

/**
 * Refusing a demotion / narrowing onto oneself: the person would become
 * unable to fulfill the §7 duty (rotate) (below member after a demotion,
 * the environment outside scope after a narrowing).
 */
function rejectSelfObligation(
  verified: VerifiedProject,
  target: ChainMember,
  next: { readonly role: Role; readonly scope: MemberScope },
): Effect.Effect<void, CliError> {
  switch (selfObligationReason(verified, target, next)) {
    case "demotion":
      return Effect.fail(
        cliError(
          "You cannot demote yourself below member. You would be unable to run the post-demotion rotation of every environment (CRYPTO_SPEC §7) — ask another admin / owner to demote you",
        ),
      );
    case "scope-narrowing":
      return Effect.fail(
        cliError(
          "You cannot narrow your own scope. You would be unable to run the rotation of the environments you leave (CRYPTO_SPEC §7) — ask another admin / owner to narrow it",
        ),
      );
    case null:
      return Effect.void;
  }
}

/**
 * Whether the change makes the target itself unable to fulfill its §7
 * duty: a demotion below member, or a scope narrowing (a direct append
 * where the fulfiller = the target itself, and an approve where the
 * approver = the target — design record K6-N / Cursor Bugbot's catch).
 */
export function selfObligationReason(
  verified: VerifiedProject,
  target: ChainMember,
  next: { readonly role: Role; readonly scope: MemberScope },
): "demotion" | "scope-narrowing" | null {
  if (ROLE_RANK[target.role] >= ROLE_RANK.member && ROLE_RANK[next.role] < ROLE_RANK.member) {
    return "demotion";
  }
  return scopeChangeAt(verified, target.scope, next.scope, verified.state.headSeq).narrowed.length >
    0
    ? "scope-narrowing"
    : null;
}

/**
 * change_role's pre-append checks (re-run after a CAS retry's resync as
 * well). `proposing` = the proposal path (the self-demotion /
 * self-narrowing refusal is dropped because the fulfiller moves to the
 * approver — design record K6-N).
 */
function ensureRoleChangeable(input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: string;
  readonly targetUserId: string;
  readonly request: ChangeRoleRequest;
  readonly proposing: boolean;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<
  { readonly alreadyChanged: boolean; readonly role: Role; readonly scope: MemberScope },
  CliError
> {
  return Effect.gen(function* () {
    const { actor, target } = yield* resolveActorAndTarget(
      input.verified,
      input.signerUserId,
      input.targetUserId,
    );
    const permission = yield* actorAuthority(input.verified, actor, input.signingKeyPair);
    if (target === undefined) {
      return yield* Effect.fail(cliError("The target is not a member (check the user ID)"));
    }
    const next = yield* resolveRoleChange(target, input.request);
    if (input.targetUserId === input.signerUserId && !input.proposing) {
      yield* rejectSelfObligation(input.verified, target, next);
    }
    if (target.role === next.role && sameScope(target.scope, next.scope)) {
      // Already appended (a previous run's interruption / a concurrent
      // run) or a no-op. Shapes so an interrupted demotion / narrowing
      // recovery (the entry landed but the duty is unfinished) can resume
      // from here. The resume (rotate / backfill) requires member or above
      // (same guard as a remove resume — independent review N11)
      if (ROLE_RANK[permission.role] < ROLE_RANK.member) {
        return yield* Effect.fail(
          cliError(
            "Resuming the rotation / backfill requires the member role or above (CRYPTO_SPEC §6.2)",
          ),
        );
      }
      return { alreadyChanged: true, ...next };
    }
    // The check order follows §6.2's consensus rules: role rules →
    // last-owner → unknown-environment → scope-not-contained (independent
    // review N2)
    const rejection = changeRoleRuleRejection({
      verified: input.verified,
      actor: permission,
      target,
      newRole: next.role,
    });
    if (rejection !== null) {
      return yield* Effect.fail(cliError(rejection));
    }
    yield* requireScopeEnvironmentsExist(input.verified, next.scope);
    const containment = scopeContainmentRejection({
      actor: permission,
      target,
      newRole: next.role,
      newScope: next.scope,
    });
    if (containment !== null) {
      return yield* Effect.fail(cliError(containment));
    }
    return { alreadyChanged: false, ...next };
  });
}

/**
 * Signs a change_role entry right after the current head (the shared core
 * = chain-append.ts). The payload is the full replacement of (role,
 * scope) (CRYPTO_SPEC §6.2) — 2026-09-15 ES K4: omitting `--role` /
 * `--env` / `--all-envs` keeps each as-is (design record K4-A), and an
 * owner is pinned to all.
 */
function signChangeRoleEntry(input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: string;
  readonly targetUserId: string;
  readonly newRole: Role;
  readonly newScope: MemberScope;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<ChainEntry, CliError> {
  const scope = scopePayloadFieldsOf(input.newScope);
  return signEntryAtHead({
    verified: input.verified,
    signerUserId: input.signerUserId,
    operation: {
      op: "change_role",
      payload: {
        targetUserId: input.targetUserId,
        newRole: input.newRole,
        scopeKind: scope.scopeKind,
        scopeEnvironmentIds: scope.scopeEnvironmentIds,
      },
    },
    signingKeyPair: input.signingKeyPair,
    failureText: "Failed to sign the change_role entry",
  });
}

/**
 * Resolves the new (role, scope) from the target's current state **on the
 * signing view** and signs (the kept-as-is side comes from that view's
 * state). Even when a concurrent change_role changed the kept-as-is side
 * across a CAS retry, it is not overwritten (design record K4-A's
 * "omitted = unchanged" — Cursor Bugbot's catch).
 */
function signChangeRoleAtView(input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: string;
  readonly targetUserId: string;
  readonly request: ChangeRoleRequest;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<ChainEntry, CliError> {
  return Effect.gen(function* () {
    const current = input.verified.state.members.get(input.targetUserId);
    if (current === undefined) {
      return yield* Effect.fail(cliError("The target is not a member (check the user ID)"));
    }
    const next = yield* resolveRoleChange(current, input.request);
    return yield* signChangeRoleEntry({
      verified: input.verified,
      signerUserId: input.signerUserId,
      targetUserId: input.targetUserId,
      newRole: next.role,
      newScope: next.scope,
      signingKeyPair: input.signingKeyPair,
    });
  });
}

/**
 * The widened part = of the union of the widened parts of **all**
 * `change_role` entries in the target's history (each entry's diff against
 * its immediately preceding state), the environments still in the current
 * scope (pullfrog's catch: looking at only the last entry, a third party's
 * change_role committed mid-interruption of a widening backfill would make
 * the widened part empty and never resumed. Like the sweep side folding
 * every duty of the target, it is derived from the whole history. A 409 is
 * idempotent, so excess converges to "already registered"). The narrowed
 * part is for reporting — the last entry's diff.
 */
export function scopeChangesOf(
  verified: VerifiedProject,
  target: ChainMember,
): { readonly widened: readonly string[]; readonly narrowed: readonly string[] } {
  const current = new Set(environmentsOfScopeAt(verified, target.scope, verified.state.headSeq));
  const widened = new Set<string>();
  let narrowed: readonly string[] = [];
  // A change_role applied via a proposal lands on the same list (design record K6-C)
  for (const { seq, operation } of verified.applied) {
    if (operation.op !== "change_role" || operation.payload.targetUserId !== target.userId) {
      continue;
    }
    const before = verified.history.memberStateAt(target.userId, seq - 1);
    if (before === undefined) {
      continue;
    }
    const change = scopeChangeAt(verified, before.scope, memberScopeOf(operation.payload), seq);
    for (const environmentId of change.widened) {
      if (current.has(environmentId)) {
        widened.add(environmentId);
      }
    }
    narrowed = change.narrowed;
  }
  return { widened: [...widened].toSorted(compareCodePoints), narrowed };
}

/**
 * Of the historical widenings, environments outside the actor's scope are
 * not my duty (a §6.2 corollary — duty environment set ⊆ permission-change
 * environment set ⊆ actor scope. Independent review S6). Like the sweep,
 * they go to the note and are left to a re-run by a member whose scope
 * carries that environment.
 */
function splitWidenedByActorScope(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly actorUserId: string;
  readonly widened: readonly string[];
}): Effect.Effect<
  { readonly widened: readonly string[]; readonly widenedOutOfScope: readonly string[] },
  CliError
> {
  return Effect.gen(function* () {
    // A verified-deleted environment is dropped from the widened part even
    // if still in scope (never keep emitting an out-of-scope note for "an
    // environment nobody can fill" — pullfrog's catch. Same set as
    // backfillAllEnvironments). No widening means no query (don't dirty the
    // exit with a pointless post-append request)
    const deletedVerified =
      input.widened.length === 0
        ? new Set<string>()
        : yield* verifiedDeletedEnvironmentSet(input.client, input.verified);
    const live = input.widened.filter((environmentId) => !deletedVerified.has(environmentId));
    const actor = input.verified.state.members.get(input.actorUserId);
    const actorScope: MemberScope = actor?.scope ?? { kind: "listed", environmentIds: [] };
    return {
      widened: live.filter((environmentId) => scopeIncludesEnvironment(actorScope, environmentId)),
      widenedOutOfScope: live.filter(
        (environmentId) => !scopeIncludesEnvironment(actorScope, environmentId),
      ),
    };
  });
}

/**
 * `maruhi member change-role`: appends the full replacement of (role,
 * scope), the actor backfills the widened part (§12-6's append path), then
 * rotates the duty environments of the demotion / narrowing (§7) (the
 * order is design record K4-B: the 3 environment sets are pairwise
 * disjoint, and each can resume idempotently).
 */
/** change_role's inner op (proposal-ization — the omitted side is already resolved against the target's state on the proposal-time view). */
function changeRoleOperation(input: {
  readonly targetUserId: string;
  readonly newRole: Role;
  readonly newScope: MemberScope;
}): Extract<ProposableOperation, { readonly op: "change_role" }> {
  const scope = scopePayloadFieldsOf(input.newScope);
  return {
    op: "change_role",
    payload: {
      targetUserId: input.targetUserId,
      newRole: input.newRole,
      scopeKind: scope.scopeKind,
      scopeEnvironmentIds: scope.scopeEnvironmentIds,
    },
  };
}

/** change_role's proposal (K6-A): after the resync it also confirms that the omitted side's re-resolution matches the proposal-time one. */
function proposeRoleChange(
  input: ProposeContext,
  inner: ProposableOperation,
  resolved: { readonly role: Role; readonly scope: MemberScope },
  recheck: (
    view: VerifiedProject,
  ) => Effect.Effect<
    { readonly alreadyChanged: boolean; readonly role: Role; readonly scope: MemberScope },
    CliError
  >,
): Effect.Effect<ProposedSummary, CliError> {
  const notApplied = proposeRecheck(
    recheck,
    (rechecked) => rechecked.alreadyChanged,
    "The target already has the requested role / scope (a concurrent run applied it) — nothing to propose. Re-run `maruhi member change-role` to resume any pending backfill / rotation",
  );
  return proposeOperation(input, inner, (view) =>
    notApplied(view).pipe(
      Effect.flatMap((rechecked) =>
        rechecked.role === resolved.role && sameScope(rechecked.scope, resolved.scope)
          ? Effect.void
          : Effect.fail(
              cliError(
                "The target's role / scope changed concurrently, so the omitted side of this request no longer resolves to the same (role, scope) — re-run to propose against the current state",
              ),
            ),
      ),
    ),
  );
}

/**
 * change_role's direct append (CAS) and the listing confirmation on the
 * post-acceptance resync (the server's claim is never the source of
 * truth). Must match the request's fixpoint (the omitted side stays
 * as-is) — even if a concurrent change_role changed the kept side, it
 * holds when the requested side is on the chain.
 */
function appendRoleChange(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly targetUserId: string;
  readonly request: ChangeRoleRequest;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly inner: ProposableOperation;
  readonly alreadyChanged: boolean;
  readonly recheck: (
    view: VerifiedProject,
  ) => Effect.Effect<{ readonly alreadyChanged: boolean }, CliError>;
}): Effect.Effect<
  { readonly verified: VerifiedProject; readonly appended: boolean; readonly target: ChainMember },
  CliError
> {
  return Effect.gen(function* () {
    let verified = input.verified;
    let appended = false;
    if (!input.alreadyChanged) {
      const outcome = yield* appendWithCas({
        client: input.client,
        verified,
        resync: input.resync,
        opLabel: "change_role",
        // The omitted side (role / scope) is resolved from the target's
        // state on **the signing view** (signChangeRoleAtView — Cursor
        // Bugbot's catch)
        signEntry: (view) =>
          signChangeRoleAtView({
            verified: view,
            signerUserId: input.signerUserId,
            targetUserId: input.targetUserId,
            request: input.request,
            signingKeyPair: input.signingKeyPair,
          }),
        recheck: (view) =>
          ensureStillTarget(view, input.inner, false).pipe(
            Effect.flatMap(() => input.recheck(view)),
            Effect.map((rechecked) => ({ already: rechecked.alreadyChanged })),
          ),
      });
      verified = outcome.verified;
      appended = outcome.appended;
    }
    verified = yield* resyncExtended(input.resync, verified);
    const target = verified.state.members.get(input.targetUserId);
    const expected =
      target === undefined ? undefined : yield* resolveRoleChange(target, input.request);
    if (
      target === undefined ||
      expected === undefined ||
      target.role !== expected.role ||
      !sameScope(target.scope, expected.scope)
    ) {
      return yield* Effect.fail(
        cliError(
          "The resync after change_role was accepted does not show the target's new role / scope (the server's response contradicts the chain). Investigate the served chain",
        ),
      );
    }
    return { verified, appended, target };
  });
}

/** The result of change_role's post-application fulfillment (widening backfill + demotion / narrowing sweep). */
export type RoleChangeFulfilment = Pick<
  MemberChangeRoleSummary,
  | "widenedEnvironmentIds"
  | "widenedOutOfScopeEnvironmentIds"
  | "narrowedEnvironmentIds"
  | "backfill"
  | "demoted"
  | "sweep"
>;

/**
 * change_role's post-application stage (design record K4-B's order:
 * widening backfill → rotate of the demotion / narrowing part). Shared
 * between a direct-append change-role and the fulfillment of the approver
 * who completes the application under four-eyes (approval-approve.ts —
 * approval item 22). The target is the current member after resync.
 */
export function fulfilRoleChange<R>(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly target: ChainMember;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  readonly recipient: DekRecipient;
  readonly rotateWith: (reason: string) => SweepRotate<R>;
}): Effect.Effect<RoleChangeFulfilment, CliError, R> {
  return Effect.gen(function* () {
    const change = scopeChangesOf(input.verified, input.target);
    const { widened, widenedOutOfScope } = yield* splitWidenedByActorScope({
      client: input.client,
      verified: input.verified,
      actorUserId: input.signerUserId,
      widened: change.widened,
    });

    // (1) The widening backfill — the actor holds the DEK by the containment rule (§12-6). Idempotent via 409
    const backfill =
      widened.length === 0
        ? null
        : yield* backfillAllEnvironments({
            client: input.client,
            verified: input.verified,
            recipient: input.recipient,
            target: input.target,
            environments: widened,
            staleWrapSuspected: false,
            signerUserId: input.signerUserId,
            signingKeyPair: input.signingKeyPair,
          });

    // (2) Rotate the demotion / narrowing duty environments (§7). With no
    // duty entry on the target, no duty ever arose (promotion, widening, a
    // born-reader no-op) — others' unconverged duties are not picked up
    const mandates = memberMandatesFor(input.verified, input.target.userId);
    const demoted = mandates.some((mandate) => mandate.kind === "role-demoted");
    const sweep =
      mandates.length === 0
        ? null
        : yield* sweepAfterMandate({
            client: input.client,
            verified: input.verified,
            mandates,
            actorUserId: input.signerUserId,
            signingKeyPair: input.signingKeyPair,
            rotateWith: input.rotateWith,
          });
    return {
      widenedEnvironmentIds: widened,
      widenedOutOfScopeEnvironmentIds: widenedOutOfScope,
      narrowedEnvironmentIds: change.narrowed,
      backfill,
      demoted,
      sweep,
    };
  });
}

export function memberChangeRoleOp<R>(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly targetUserId: string;
  readonly request: ChangeRoleRequest;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  readonly recipient: DekRecipient;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  /** The per-duty-reason rotation injection (demotion = role-demoted / narrowing only = scope-narrowed). */
  readonly rotateWith: (reason: string) => SweepRotate<R>;
  readonly proposal: ProposalInput;
}): Effect.Effect<MemberOpOutcome<MemberChangeRoleSummary>, CliError, R> {
  return Effect.gen(function* () {
    // The proposal-ization judgment runs on the new (role, scope) resolved
    // from the request on the current view (establishing an owner is always
    // targeted). The check order (the order of §6.2's consensus rules — own
    // duty → role rules → …) belongs to ensureRoleChangeable
    const { target: current } = yield* resolveActorAndTarget(
      input.verified,
      input.signerUserId,
      input.targetUserId,
    );
    if (current === undefined) {
      return yield* Effect.fail(cliError("The target is not a member (check the user ID)"));
    }
    const resolved = yield* resolveRoleChange(current, input.request);
    const inner = changeRoleOperation({
      targetUserId: input.targetUserId,
      newRole: resolved.role,
      newScope: resolved.scope,
    });
    const proposing = isApprovalTarget(inner, input.verified.state.approvalPolicy);
    const recheck = (view: VerifiedProject) =>
      ensureRoleChangeable({
        verified: view,
        signerUserId: input.signerUserId,
        targetUserId: input.targetUserId,
        request: input.request,
        proposing,
        signingKeyPair: input.signingKeyPair,
      });
    const first = yield* recheck(input.verified);

    // Four-eyes (K6-A): if the policy targets it, propose and finish (the
    // widening backfill and the narrowing sweep are fulfilled by the
    // approver after the application — approval item 22). The omitted side
    // is fixed to the proposal-time view's state
    if (!first.alreadyChanged && proposing) {
      const proposal = yield* proposeRoleChange(input, inner, resolved, recheck);
      return { kind: "proposed", proposal };
    }

    const { verified, appended, target } = yield* appendRoleChange({
      ...input,
      inner,
      alreadyChanged: first.alreadyChanged,
      recheck,
    });
    const fulfilment = yield* fulfilRoleChange({
      client: input.client,
      verified,
      target,
      signerUserId: input.signerUserId,
      signingKeyPair: input.signingKeyPair,
      recipient: input.recipient,
      rotateWith: input.rotateWith,
    });
    return {
      kind: "applied",
      summary: {
        appended,
        targetUserId: input.targetUserId,
        newRole: target.role,
        newScope: target.scope,
        ...fulfilment,
      },
    };
  });
}

// ---------------------------------------------------------------------------
// member list
// ---------------------------------------------------------------------------

/** One member row (verified-chain-derived — zero values. Design record ruling M / K4-E; the devices column is DK K4-20). */
export interface MemberListRow {
  readonly userId: string;
  readonly role: Role;
  readonly scope: MemberScope;
  /** The member's device keys (fingerprint ascending — 2026-09-19 DK: a member can have multiple devices). */
  readonly devices: readonly ChainDevice[];
}

/** The verified chain's member list (user_id ascending). */
export function memberListRows(verified: VerifiedProject): readonly MemberListRow[] {
  return [...verified.state.members.values()]
    .map((member) => ({
      userId: member.userId,
      role: member.role,
      scope: member.scope,
      devices: devicesOf(member),
    }))
    .toSorted((a, b) => (a.userId < b.userId ? -1 : a.userId > b.userId ? 1 : 0));
}

/** One `--json` document (machine-readable — for agents / scripts. Zero values). */
export function memberListJson(rows: readonly MemberListRow[]): string {
  return JSON.stringify(
    {
      members: rows.map((row) => ({
        userId: row.userId,
        role: row.role,
        scope: jsonScope(row.scope),
        // The devices list (K4-20): FP and cap emitted structured. The
        // concatenated `keyFingerprintHex` was removed in K4 (never make
        // consumers decompose it — the finished form of design record §7
        // K2-10 extra round j-4)
        devices: row.devices.map((device) => ({
          keyFingerprintHex: device.keyFingerprintHex,
          roleCap: device.roleCap,
          scope: jsonScope(device.scope),
        })),
        deviceKeyFingerprintsHex: row.devices.map((device) => device.keyFingerprintHex),
      })),
    },
    null,
    2,
  );
}

function jsonScope(scope: MemberScope) {
  return scope.kind === "all"
    ? { kind: "all" as const }
    : { kind: "listed" as const, environmentIds: [...scope.environmentIds] };
}

/** The human-readable row (user id, role, scope, device count, device FPs (cap). The id is neutralized). */
export function formatMemberListRow(row: MemberListRow): string {
  return `${displayText(row.userId)}\t${row.role}\tscope=${describeScope(row.scope)}\tdevices=${row.devices.length}\tfp=${row.devices.map(describeDevice).join(",")}`;
}
