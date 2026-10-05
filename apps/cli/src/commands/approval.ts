// `maruhi approval` (discipline: see commands/index.ts).

import { Clock, Effect } from "effect";
import { Argument, Command } from "effect/cli";

import { type Fulfilment, approveProposalOp } from "../approval-approve.ts";
import {
  type ProposalView,
  describeInnerOperation,
  describeInnerOperationLines,
  describeKeyReuse,
  describePolicy,
  describeUnresolvedRef,
  keyReuseOf,
  proposalViewOf,
  proposalViews,
  resolveProposalRef,
  voteEligibility,
} from "../approval-rules.ts";
import { withdrawProposalOp } from "../approval.ts";
import {
  type CliServices,
  type CommonFlags,
  openMetadataProject,
  openProject,
} from "../context.ts";
import { displayText, formatUtcMinutes } from "../display.ts";
import { CliError, cliError } from "../errors.ts";
import { CliIo, type CliIoShape } from "../io.ts";
import { logNote, logWarning } from "../notice.ts";
import { type SweepOutcome } from "../rotation-sweep.ts";
import { loadMasterKeys } from "../session.ts";
import { sweepRotateFor } from "../sweep-rotate.ts";
import { NonBlank, projectFlags, singleFlag } from "./flags.ts";
import { reportMemberAdd, reportRoleChangeFulfilment } from "./member.ts";
import { describeNeeded, reportSweepOutcome } from "./shared.ts";

/** The proposal id positional (`maruhi approval show / approve / withdraw` — approval item 23). */
const proposalIdArgument = () =>
  Argument.String("proposal-id").pipe(
    Argument.withDescription(
      "Proposal id (the propose entry's hash; a unique prefix of at least 8 hex digits, or #<seq> of the propose entry — see `maruhi approval list`)",
    ),
    Argument.withSchema(NonBlank),
  );

export const approvalListConfig = {
  ...projectFlags(),
  json: singleFlag(
    "json",
    "Print the policy and the pending proposals as JSON (votes recounted under the current policy)",
  ),
};

export const approvalShowConfig = { ...projectFlags(), "proposal-id": proposalIdArgument() };

export const approvalApproveConfig = { ...projectFlags(), "proposal-id": proposalIdArgument() };

export const approvalWithdrawConfig = { ...projectFlags(), "proposal-id": proposalIdArgument() };

/* -------------------------------------------------------------------------- */
/* Four-eyes (CRYPTO_SPEC §6.2 — PF1 K6): approval list / show / approve / withdraw, */
/* project policy approvals. Zero values, so the agent-gate is not applied (design record K6-E) */
/* -------------------------------------------------------------------------- */

/** The summary line of one proposal (`approval list`). */
function formatProposalRow(view: ProposalView): string {
  const p = view.proposal;
  const votes = view.required === null ? "policy off" : `${view.votes}/${view.required} approvals`;
  const flags = [
    ...(view.expired ? ["EXPIRED"] : []),
    ...(!view.target ? ["NOT-A-TARGET"] : []),
    ...(view.target && !view.expired && view.needed === 0 ? ["READY"] : []),
  ];
  return `${p.proposalHashHex.slice(0, 12)}…\tseq=${p.proposalSeq}\tby ${displayText(p.proposerUserId)}\t${describeInnerOperation(p.inner)}\t${votes}\texpires ${formatUtcMinutes(p.expiresAtMs)}${flags.length === 0 ? "" : `\t[${flags.join(", ")}]`}`;
}

/** One `--json` document (machine-readable — K6-O. Zero values). */
function approvalListJson(
  policy: Parameters<typeof describePolicy>[0],
  views: readonly ProposalView[],
): string {
  return JSON.stringify(
    {
      policy:
        policy === null
          ? null
          : { requiredApprovals: policy.requiredApprovals, ops: [...policy.ops].toSorted() },
      proposals: views.map((view) => ({
        id: view.proposal.proposalHashHex,
        seq: view.proposal.proposalSeq,
        proposerUserId: view.proposal.proposerUserId,
        proposerRoleAtProposal: view.proposal.proposerRoleAtProposal,
        inner: view.proposal.inner,
        expiresAtMs: view.proposal.expiresAtMs,
        expired: view.expired,
        target: view.target,
        required: view.required,
        votes: view.votes,
        voters: view.voters,
        needed: view.needed,
        eligibleApprovers: view.eligibleApprovers,
      })),
    },
    null,
    2,
  );
}

/**
 * The guidance for an already-satisfied pending proposal (K5-L / K6 —
 * after the `required_approvals` reduction): the next approve completes
 * it — only a not-yet-voted owner can complete it.
 */
function readyNote(view: ProposalView): string | null {
  if (!view.target || view.expired || view.needed !== 0) {
    return null;
  }
  const eligible =
    view.eligibleApprovers.length === 0
      ? "no current owner is left who has not voted — the proposal cannot be completed as is (add an owner, or withdraw it)"
      : `an owner who has not voted yet completes it: ${view.eligibleApprovers.map(displayText).join(", ")} (owners who already voted get duplicate-approval)`;
  return `${view.proposal.proposalHashHex.slice(0, 12)}… already has enough recounted approvals under the current policy — the next approve applies it; ${eligible}`;
}

/** `maruhi approval list [--json]` (the verified chain's pending — K5-M. Vote counts are re-tallied). */
function approvalListCommand(
  flags: CommonFlags & { readonly json: boolean },
): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const context = yield* openMetadataProject(flags);
    const views = proposalViews(context.verified, yield* Clock.currentTimeMillis);
    if (flags.json) {
      yield* io.log(approvalListJson(context.verified.state.approvalPolicy, views));
      return;
    }
    yield* io.log(`Four-eyes policy: ${describePolicy(context.verified.state.approvalPolicy)}`);
    yield* io.log(
      `Pending proposals (${views.length}) — verified chain head seq=${context.verified.state.headSeq}:`,
    );
    for (const view of views) {
      yield* io.log(`  ${formatProposalRow(view)}`);
    }
    for (const view of views) {
      const note = readyNote(view);
      if (note !== null) {
        yield* logNote(note);
      }
    }
  });
}

/** `maruhi approval show <id>` (the proposer, the inner op, the expiry, the voters, whether I can approve). */
function approvalShowCommand(
  flags: CommonFlags & { readonly ref: string },
): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const context = yield* openMetadataProject(flags);
    const resolution = resolveProposalRef(context.verified, flags.ref);
    if (resolution.kind !== "pending") {
      return yield* Effect.fail(cliError(describeUnresolvedRef(resolution)));
    }
    const view = proposalViewOf(
      context.verified,
      resolution.proposal,
      yield* Clock.currentTimeMillis,
    );
    for (const line of proposalDetailLines(view)) {
      yield* io.log(line);
    }
    // The approver-side key-FP re-registration warning (K6-I′ — same predicate and wording as the proposer-side K6-I)
    if (view.proposal.inner.op === "add_member") {
      for (const reuse of keyReuseOf(context.verified, view.proposal.inner.payload)) {
        yield* logWarning(describeKeyReuse("the proposed member's key", reuse));
      }
    }
    // A vote's eligibility is the signing device's effective role (DK
    // K4). On a keyless run (MARUHI_TOKEN) no device is determined, so
    // only that is stated (show stays a key-free command)
    const localKeys = yield* loadMasterKeys(context.session).pipe(
      Effect.catch(() => Effect.succeed(null)),
    );
    yield* io.log(
      eligibilityLine(
        context.verified,
        context.session.userId,
        localKeys === null ? null : localKeys.fingerprintHex,
        view,
      ),
    );
    const note = readyNote(view);
    if (note !== null) {
      yield* logNote(note);
    }
  });
}

/** `approval show`'s detail lines (the proposer, the inner op, the expiry, the votes — a pure function). */
function proposalDetailLines(view: ProposalView): readonly string[] {
  const p = view.proposal;
  const lapsed = p.approvals.filter((vote) => !view.voters.includes(vote.userId));
  const proposerNote =
    p.proposerRoleAtProposal === "owner"
      ? " — counts as one approval"
      : " — does not count as an approval";
  return [
    `Proposal ${p.proposalHashHex}`,
    `  proposed at seq: ${p.proposalSeq}`,
    `  proposer:        ${displayText(p.proposerUserId)} (as ${p.proposerRoleAtProposal}${proposerNote})`,
    `  operation:       ${p.inner.op}`,
    ...describeInnerOperationLines(p.inner).map((line) => `    ${line}`),
    `  expires:         ${formatUtcMinutes(p.expiresAtMs)}${view.expired ? " (EXPIRED by this machine's clock)" : ""}`,
    `  approvals:       ${view.required === null ? "policy off" : `${view.votes} of ${view.required} required`} (recounted — signers: ${view.voters.length === 0 ? "none" : view.voters.map(displayText).join(", ")})`,
    ...(lapsed.length === 0
      ? []
      : [
          `  lapsed votes:    ${lapsed.map((vote) => displayText(vote.userId)).join(", ")} (no longer an owner with the same key — not counted; they may approve again after being re-added with a new key)`,
        ]),
    ...(view.target
      ? []
      : [
          "  status:          not a target of the current policy (approval-not-required) — withdraw it; the operation can be run directly",
        ]),
  ];
}

/** The "can you approve" line (including K5-L's guidance). */
function eligibilityLine(
  verified: Parameters<typeof voteEligibility>[0],
  userId: string,
  deviceFingerprintHex: string | null,
  view: ProposalView,
): string {
  if (deviceFingerprintHex === null) {
    return "  you:             cannot tell — no device key is loaded on this machine (approving needs the key of one of your registered devices)";
  }
  const eligibility = voteEligibility(verified, userId, deviceFingerprintHex, view);
  if (!eligibility.ok) {
    return `  you:             cannot approve — ${eligibility.message}`;
  }
  const command = `\`maruhi approval approve ${view.proposal.proposalHashHex.slice(0, 12)}\``;
  if (eligibility.completes) {
    return `  you:             can approve — your approval completes it and applies the operation (you become the fulfiller of its rotation / key distribution — CRYPTO_SPEC §7): ${command}`;
  }
  const afterMine = {
    ...view,
    votes: view.votes + 1,
    needed: view.needed === null ? null : Math.max(0, view.needed - 1),
  };
  return `  you:             can approve — after yours it still ${describeNeeded(afterMine)}: ${command}`;
}

/** Reporting the sweep part of the approver's fulfillment (remove / revoke) (preamble → sweep → the completion line). */
function reportFulfilledSweep(
  io: CliIoShape,
  input: {
    readonly intro: string;
    readonly sweep: SweepOutcome & { readonly skippedDeleted: readonly string[] };
    readonly rerunCommand: string;
    readonly alreadyRotatedBasis: string;
    readonly done: string;
  },
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    yield* io.log(input.intro);
    const code = yield* reportSweepOutcome(input.sweep, {
      rerunCommand: input.rerunCommand,
      alreadyRotatedBasis: input.alreadyRotatedBasis,
    });
    if (code === 0) {
      yield* io.log(input.done);
    }
    return code;
  });
}

/** Reporting the approver's fulfillment (approval item 22) and the exit code (per inner op kind). */
const FULFILMENT_REPORTERS: {
  readonly [K in Fulfilment["kind"]]: (
    io: CliIoShape,
    fulfilment: Extract<Fulfilment, { readonly kind: K }>,
  ) => Effect.Effect<number, CliError, CliServices>;
} = {
  none: (io) =>
    io.log("Done: the policy change was applied (no follow-up obligation)").pipe(Effect.as(0)),
  "member-rotation": (io, fulfilment) =>
    fulfilment.sweep === null
      ? io.log("Done: applied (no rotation mandate for the target)").pipe(Effect.as(0))
      : reportFulfilledSweep(io, {
          intro:
            "Forcing a rotation of every environment in the removed member's scope (CRYPTO_SPEC §7 — you completed the removal, so you fulfil its mandate)",
          sweep: fulfilment.sweep,
          rerunCommand: `\`maruhi member remove ${displayText(fulfilment.targetUserId)}\``,
          alreadyRotatedBasis: "the mandate entry",
          done: "Done: the removal and the rotation of the affected environments completed",
        }),
  "member-backfill": (io, fulfilment) =>
    reportMemberAdd(io, {
      targetUserId: fulfilment.targetUserId,
      role: null,
      ...fulfilment.backfill,
    }),
  "role-change": (io, fulfilment) =>
    reportRoleChangeFulfilment(
      io,
      fulfilment.change,
      `\`maruhi member change-role ${displayText(fulfilment.targetUserId)}\` with the member's current role and scope`,
    ),
  "server-backfill": (io, fulfilment) =>
    Effect.gen(function* () {
      yield* io.log(
        `Done: disclosure to server key ${fulfilment.serverKeyFingerprintHex} is active (scope=${fulfilment.scopeEnvironmentIds.join(", ")}). Backfill: ${fulfilment.registered} newly registered, ${fulfilment.alreadyRegistered} already registered`,
      );
      yield* logNote(
        "the epoch DEKs of environments in the disclosure scope are disclosed to the server (CRYPTO_SPEC §9). To withdraw, run `maruhi server revoke` (it forces a rotation of every environment — §7)",
      );
      return 0;
    }),
  "server-rotation": (io, fulfilment) =>
    reportFulfilledSweep(io, {
      intro: `Revoked server key ${fulfilment.serverKeyFingerprintHex}. Forcing a rotation of every environment (§7 — you completed the revocation, so you fulfil its mandate)`,
      sweep: fulfilment.sweep,
      rerunCommand: "`maruhi server revoke`",
      alreadyRotatedBasis: "the revocation",
      done: "Done: the revocation and the rotation of every environment completed",
    }),
};

function reportFulfilment(
  io: CliIoShape,
  fulfilment: Fulfilment,
): Effect.Effect<number, CliError, CliServices> {
  // An exhaustive Record narrows the argument type per kind (Extract), but the shared call site calls it with the wide type
  const report = FULFILMENT_REPORTERS[fulfilment.kind] as (
    io: CliIoShape,
    fulfilment: Fulfilment,
  ) => Effect.Effect<number, CliError, CliServices>;
  return report(io, fulfilment);
}

/** `maruhi approval approve <id>` (sign → fulfill if complete — K6-B / approval item 22). */
function approvalApproveCommand(
  flags: CommonFlags & { readonly ref: string },
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    // The completion-time sweep report carries the unconverged duties, so the always-on warning is suppressed (same as a convergent command)
    const context = yield* openProject(flags, { quietMandateWarning: true });
    const outcome = yield* approveProposalOp({
      client: context.client,
      verified: context.verified,
      ref: flags.ref,
      signerUserId: context.session.userId,
      signerFingerprintHex: context.masterKeys.fingerprintHex,
      signingKeyPair: context.masterKeys.sigKeyPair,
      recipient: context.recipient,
      resync: context.resync,
      rotateWith: (reason) => sweepRotateFor(context, reason),
      nowMs: yield* Clock.currentTimeMillis,
    });
    switch (outcome.kind) {
      case "recorded":
        yield* io.log(
          `Recorded your approval of ${describeInnerOperation(outcome.view.proposal.inner)} (proposal ${outcome.view.proposal.proposalHashHex.slice(0, 12)}…). It still ${describeNeeded(outcome.view)} — nothing has been applied yet`,
        );
        return 0;
      case "completed-by-other":
        yield* io.log(
          `This proposal was already completed by another owner's approval at seq=${outcome.completedAtSeq} — your approval was not needed. That owner's CLI fulfils the follow-up rotation / key distribution (CRYPTO_SPEC §7); any unconverged mandate stays visible in \`maruhi project verify\``,
        );
        return 0;
      case "withdrawn-concurrently":
        return yield* Effect.fail(
          cliError("The proposal was withdrawn concurrently — nothing to approve"),
        );
      case "applied":
        return yield* reportFulfilment(io, outcome.fulfilment);
    }
  });
}

/** `maruhi approval withdraw <id>` (the proposer or an owner — K6-L). */
function approvalWithdrawCommand(
  flags: CommonFlags & { readonly ref: string },
): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const context = yield* openProject(flags);
    const summary = yield* withdrawProposalOp({
      client: context.client,
      verified: context.verified,
      ref: flags.ref,
      signerUserId: context.session.userId,
      signingKeyPair: context.masterKeys.sigKeyPair,
      resync: context.resync,
    });
    if (summary.closedByOtherOwner) {
      yield* logNote(
        `withdrawing a proposal made by ${displayText(summary.proposerUserId)} (owners may close any proposal)`,
      );
    }
    yield* io.log(
      `Withdrew proposal ${summary.proposalHashHex.slice(0, 12)}… (seq=${summary.proposalSeq}) — nothing was applied`,
    );
  });
}

export function makeApprovalCommands(onExitCode: (code: number) => void) {
  const approvalList = Command.make("list", approvalListConfig, (values) =>
    approvalListCommand({ server: values.server, project: values.project, json: values.json }),
  ).pipe(
    Command.withDescription(
      "List the pending four-eyes proposals (votes recounted under the current policy)",
    ),
  );

  const approvalShow = Command.make("show", approvalShowConfig, (values) =>
    approvalShowCommand({
      server: values.server,
      project: values.project,
      ref: values["proposal-id"],
    }),
  ).pipe(
    Command.withDescription(
      "Show a pending proposal (proposer, operation, expiry, voters, whether you can approve it)",
    ),
  );

  const approvalApprove = Command.make("approve", approvalApproveConfig, (values) =>
    Effect.gen(function* () {
      onExitCode(
        yield* approvalApproveCommand({
          server: values.server,
          project: values.project,
          ref: values["proposal-id"],
        }),
      );
    }),
  ).pipe(
    Command.withDescription(
      "Approve a pending proposal as an owner; the approval that reaches the quorum applies it and runs the follow-up rotation / key distribution",
    ),
  );

  const approvalWithdraw = Command.make("withdraw", approvalWithdrawConfig, (values) =>
    approvalWithdrawCommand({
      server: values.server,
      project: values.project,
      ref: values["proposal-id"],
    }),
  ).pipe(Command.withDescription("Withdraw a pending proposal (as its proposer or an owner)"));

  const approval = Command.make("approval").pipe(
    Command.withDescription("Four-eyes proposals (list / show / approve / withdraw)"),
    Command.withSubcommands([approvalList, approvalShow, approvalApprove, approvalWithdraw]),
  );

  return approval;
}
