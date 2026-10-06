// `maruhi rotation` (discipline: see commands/index.ts).

import { isEnvironmentId, isVariableId } from "@maruhi/core";
import { Effect } from "effect";
import { Argument, Command, Flag } from "effect/cli";

import { type CliServices, openEnvironment, openMetadataProject } from "../context.ts";
import { CliError, usageError } from "../errors.ts";
import { CliIo } from "../io.ts";
import {
  describeAcceptance,
  findProposal,
  rotationAcceptOp,
  rotationProposalsOp,
  rotationRejectOp,
} from "../rotation-proposals.ts";
import {
  fetchRotationProposals,
  parseDismissRequest,
  resolveDismissTargets,
  rotationDismissOp,
  rotationListOp,
} from "../rotation.ts";
import { logRotationWarnings } from "../var-rotate.ts";
import { NonBlank, projectFlags, singleFlag, singleValued } from "./flags.ts";
import { ENV_FLAG_SHAPE_MESSAGE, proposeCheckpointRefresh } from "./shared.ts";

export const rotationListConfig = {
  ...projectFlags(),
  "fail-on-due": singleFlag(
    "fail-on-due",
    "Exit with code 3 when a value is past the max age its schema declares (a CI cron turns it into a failed build or an issue; see also --due-within)",
  ),
  "due-within": Flag.Int("due-within").pipe(
    Flag.withDescription(
      "With --fail-on-due: also fail when a value comes due within this many days (default 0 = only values already past their max age)",
    ),
    Flag.atMost(1),
    Flag.map((values) => values[0]),
  ),
  "fail-on-flags": singleFlag(
    "fail-on-flags",
    "Exit with code 3 while any rotation flag is active (a credential a departed party could read has not been rotated or dismissed)",
  ),
  "fail-on-pending": singleFlag(
    "fail-on-pending",
    "Exit with code 3 while a sealed proposal minted by a CI job awaits a member (with --due-within, the ones expiring inside the window are counted in the message); needs a member's token",
  ),
};

export const rotationDismissConfig = {
  ...projectFlags(),
  env: singleValued(
    "env",
    "Environment ID of the flag to dismiss (with --all, narrows the dismissal to that environment)",
  ),
  all: singleFlag("all", "Dismiss every currently-active flag (an explicit acceptance of risk)"),
  // Not taken on a --all run. atMost(1) expresses "omitted under --all" in the declaration
  variable: Argument.String("variable").pipe(
    Argument.withDescription("Variable ID to dismiss (omit with --all)"),
    Argument.withSchema(NonBlank),
    Argument.atMost(1),
    Argument.map((values) => values[0]),
  ),
};

export const rotationProposalsConfig = {
  ...projectFlags(),
  env: singleValued("env", "Only the proposals of this environment"),
};

export const rotationAcceptConfig = {
  ...projectFlags(),
  yes: singleFlag(
    "yes",
    "Skip the confirmation (the only non-interactive path; the pushes are signed by you)",
  ),
  id: Argument.String("id").pipe(
    Argument.withDescription(
      "Proposal id from `maruhi rotation proposals` (a unique prefix of 8+ characters works)",
    ),
    Argument.withSchema(NonBlank),
  ),
};

export const rotationRejectConfig = {
  ...projectFlags(),
  id: Argument.String("id").pipe(
    Argument.withDescription(
      "Proposal id from `maruhi rotation proposals` (a unique prefix of 8+ characters works)",
    ),
    Argument.withSchema(NonBlank),
  ),
};

export function makeRotationCommands(onExitCode: (code: number) => void) {
  const rotationList = Command.make(
    "list",
    rotationListConfig,
    Effect.fn("commands-rotation.rotationList")(function* (values) {
      const dueWithin = values["due-within"];
      if (
        dueWithin !== undefined &&
        (dueWithin < 0 || (!values["fail-on-due"] && !values["fail-on-pending"]))
      ) {
        return yield* Effect.fail(
          usageError(
            dueWithin < 0
              ? "--due-within must be a number of days (0 or more)"
              : "--due-within applies to --fail-on-due / --fail-on-pending only",
          ),
        );
      }
      const context = yield* openMetadataProject(values);
      onExitCode(
        yield* rotationListOp(context, {
          failOnDue: values["fail-on-due"],
          dueWithinDays: dueWithin,
          failOnFlags: values["fail-on-flags"],
          failOnPending: values["fail-on-pending"],
        }),
      );
    }),
  ).pipe(
    Command.withDescription(
      "List the currently active rotation flags and the values past their max age (--fail-on-due / --fail-on-flags make a CI cron out of it)",
    ),
  );

  const rotationDismiss = Command.make(
    "dismiss",
    rotationDismissConfig,
    Effect.fn("commands-rotation.rotationDismiss")(function* (values) {
      // The targets' format is checked before any network
      const environmentId = values.env;
      if (environmentId !== undefined && !isEnvironmentId(environmentId)) {
        return yield* Effect.fail(usageError(ENV_FLAG_SHAPE_MESSAGE));
      }
      const variableId = values.variable;
      if (variableId !== undefined && !isVariableId(variableId)) {
        return yield* Effect.fail(
          usageError("Invalid variableId (see `maruhi rotation list` for the current targets)"),
        );
      }
      // The request's shape (an --all / variable-id contradiction, a missing target) is settled before communication too
      const request = yield* parseDismissRequest({
        all: values.all,
        environmentId: environmentId ?? null,
        variableId: variableId ?? null,
      });
      const context = yield* openMetadataProject({
        server: values.server,
        project: values.project,
      });
      const resolved = yield* resolveDismissTargets({
        client: context.client,
        projectId: context.projectId,
        request,
      });
      onExitCode(
        yield* rotationDismissOp({
          client: context.client,
          projectId: context.projectId,
          targets: resolved.targets,
        }),
      );
    }),
  ).pipe(
    Command.withDescription(
      "Dismiss rotation flags without rotating (an explicit acceptance of risk; admin only)",
    ),
  );

  // Neither list nor dismiss requires the master key (the flags are
  // non-secret metadata, and the name resolution is only reading verified
  // statements — the same keyless class as project verify). dismiss's
  // authority (admin or above × admin scope) is enforced server-side
  const rotationProposals = Command.make(
    "proposals",
    rotationProposalsConfig,
    Effect.fn("commands-rotation.rotationProposals")(function* (values): Effect.fn.Return<
      void,
      CliError,
      CliServices
    > {
      const environmentId = values.env;
      if (environmentId !== undefined && !isEnvironmentId(environmentId)) {
        return yield* Effect.fail(usageError(ENV_FLAG_SHAPE_MESSAGE));
      }
      const context = yield* openMetadataProject(values);
      yield* rotationProposalsOp(context, { environmentId });
    }),
  ).pipe(
    Command.withDescription(
      "List the sealed proposals CI jobs minted and nobody has accepted or rejected yet (no value is opened)",
    ),
  );

  const rotationAccept = Command.make(
    "accept",
    rotationAcceptConfig,
    Effect.fn("commands-rotation.rotationAccept")(function* (values): Effect.fn.Return<
      void,
      CliError,
      CliServices
    > {
      const io = yield* CliIo;
      // The proposal decides the environment: it is looked up through a
      // keyless project context first, then the environment context (the
      // device key) is opened for its environment
      const lookup = yield* openMetadataProject(values);
      const proposal = yield* findProposal(
        yield* fetchRotationProposals(lookup.client, lookup.projectId),
        values.id,
      );
      const context = yield* openEnvironment({ ...values, env: proposal.environmentId });
      const result = yield* rotationAcceptOp({ context, proposal, yes: values.yes });
      yield* logRotationWarnings(result.warnings);
      for (const line of describeAcceptance(result, context.environmentId)) {
        yield* io.log(line);
      }
      yield* proposeCheckpointRefresh(context, { includeAnchor: true });
    }),
  ).pipe(
    Command.withDescription(
      "Open the sealed values a CI job proposed to this device and push them as new versions signed by you (the previous credential stays valid until --finalize). Never displays a value",
    ),
  );

  const rotationReject = Command.make(
    "reject",
    rotationRejectConfig,
    Effect.fn("commands-rotation.rotationReject")(function* (values): Effect.fn.Return<
      void,
      CliError,
      CliServices
    > {
      const context = yield* openMetadataProject(values);
      const proposal = yield* findProposal(
        yield* fetchRotationProposals(context.client, context.projectId),
        values.id,
      );
      yield* rotationRejectOp({ context, proposal });
    }),
  ).pipe(
    Command.withDescription(
      "Drop a sealed proposal without pushing it (the credential the job created at the issuer is named so you can retire it)",
    ),
  );

  const rotation = Command.make("rotation").pipe(
    Command.withDescription(
      "Manage rotation flags and sealed proposals (list / dismiss / proposals / accept / reject)",
    ),
    Command.withSubcommands([
      rotationList,
      rotationDismiss,
      rotationProposals,
      rotationAccept,
      rotationReject,
    ]),
  );

  return rotation;
}
