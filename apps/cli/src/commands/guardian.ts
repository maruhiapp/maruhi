// `maruhi guardian` (discipline: see commands/index.ts).

import { type GuardianMode } from "@maruhi/crypto";
import { Effect } from "effect";
import { Argument, Command } from "effect/cli";

import { openSession } from "../context.ts";
import { usageError } from "../errors.ts";
import {
  guardianAddOp,
  guardianApproveOp,
  guardianListOp,
  guardianRemoveOp,
  guardianWardsOp,
} from "../guardian.ts";
import { openLedgerReserveForChange } from "../ledger-open.ts";
import { NonBlank, projectFlags, serverOnlyFlags, singleValued } from "./flags.ts";

export const guardianApproveConfig = {
  ...serverOnlyFlags(),
  code: Argument.String("code").pipe(
    Argument.withDescription(
      "Handoff code shown by `maruhi key recover --handoff` on the requesting device",
    ),
    Argument.withSchema(NonBlank),
  ),
};

/** The guardian group's approval scheme (CRYPTO_SPEC §8.3). */
const GUARDIAN_MODES = ["any", "all"] as const;

function isGuardianMode(value: string | undefined): value is GuardianMode {
  return GUARDIAN_MODES.some((known) => known === value);
}

export const guardianAddConfig = {
  ...projectFlags(),
  mode: singleValued(
    "mode",
    "Approval mode: any (one guardian is enough) or all (every guardian must approve)",
  ),
  "user-id": Argument.String("user-id").pipe(
    Argument.withDescription("User ID of a guardian (a member of the project; repeatable)"),
    Argument.withSchema(NonBlank),
    Argument.atLeast(1),
  ),
};
export const guardianListConfig = { ...projectFlags() };
export const guardianRemoveConfig = {
  ...serverOnlyFlags(),
  "group-id": Argument.String("group-id").pipe(
    Argument.withDescription("Guardian group ID (see `maruhi guardian list`)"),
    Argument.withSchema(NonBlank),
  ),
};
export const guardianWardsConfig = serverOnlyFlags();

export function makeGuardianCommands() {
  const guardianAdd = Command.make(
    "add",
    guardianAddConfig,
    Effect.fn("commands-guardian.guardianAdd")(function* (values) {
      if (!isGuardianMode(values.mode)) {
        return yield* Effect.fail(usageError(`Specify --mode (${GUARDIAN_MODES.join(" | ")})`));
      }
      yield* guardianAddOp({
        flags: values,
        mode: values.mode,
        userIds: values["user-id"],
        openReserve: (session, client) =>
          openLedgerReserveForChange({
            session,
            client,
            via: "code",
            command: "maruhi guardian add …",
          }),
      });
    }),
  ).pipe(
    Command.withDescription(
      "Designate project members as guardians who can approve restoring your reserve key (opens the ledger with the recovery code first)",
    ),
  );

  const guardianApprove = Command.make(
    "approve",
    guardianApproveConfig,
    Effect.fn("commands-guardian.guardianApprove")(function* (values) {
      const context = yield* openSession(values.server);
      yield* guardianApproveOp({
        session: context.session,
        client: context.client,
        code: values.code,
      });
    }),
  ).pipe(
    Command.withDescription(
      "Approve a reserve-key handoff request as one of the requester's guardians (the code comes from `maruhi key recover --handoff` on the requesting device)",
    ),
  );

  const guardianList = Command.make("list", guardianListConfig, (values) =>
    guardianListOp({ flags: values }),
  ).pipe(
    Command.withDescription(
      "List your guardian groups (with --project, flag guardians whose key changed)",
    ),
  );

  const guardianRemove = Command.make(
    "remove",
    guardianRemoveConfig,
    Effect.fn("commands-guardian.guardianRemove")(function* (values) {
      const context = yield* openSession(values.server);
      yield* guardianRemoveOp({
        session: context.session,
        client: context.client,
        groupId: values["group-id"],
      });
    }),
  ).pipe(Command.withDescription("Remove a guardian group"));

  const guardianWards = Command.make(
    "wards",
    guardianWardsConfig,
    Effect.fn("commands-guardian.guardianWards")(function* (values) {
      const context = yield* openSession(values.server);
      yield* guardianWardsOp({ session: context.session, client: context.client });
    }),
  ).pipe(Command.withDescription("List the people who made you one of their guardians"));

  const guardian = Command.make("guardian").pipe(
    Command.withDescription(
      "Manage guardians for reserve-key recovery (add / approve / list / remove / wards)",
    ),
    Command.withSubcommands([
      guardianAdd,
      guardianApprove,
      guardianList,
      guardianRemove,
      guardianWards,
    ]),
  );

  return guardian;
}
