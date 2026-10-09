// `maruhi device` (discipline: see commands/index.ts).

import { hostname } from "node:os";

import { ProjectIdSchema } from "@maruhi/core";
import { ALL_SCOPE } from "@maruhi/crypto";
import { Effect } from "effect";
import { Argument, Command } from "effect/cli";

import type { CliServices } from "../context.ts";
import type { DeviceRevokeSummary, ProjectRevokeOutcome } from "../device-revoke.ts";
import { displayText } from "../display.ts";
import { CliError } from "../errors.ts";
import { CliIo } from "../io.ts";
import { logNote, logWarning } from "../notice.ts";
import { scopeFromFlags } from "../scope.ts";
import {
  NonBlank,
  scopeEnvFlag,
  serverOnlyFlags,
  singleFlag,
  singleValued,
  singleValuedAs,
} from "./flags.ts";
import { reportSweepOutcome } from "./shared.ts";

export const deviceAddConfig = {
  ...serverOnlyFlags(),
  label: singleValued(
    "label",
    "Display name for this device in the device registry (default: the hostname)",
  ),
  replace: singleFlag(
    "replace",
    "Generate a new key even though this machine already has one, replacing the old key in this keychain once the new key's request is created (for a device that was revoked, or a copy of another device's key)",
  ),
};
export const deviceApproveConfig = {
  ...serverOnlyFlags(),
  project: singleValuedAs(
    "project",
    "Register the device on this project only (default: every project you belong to)",
    ProjectIdSchema,
  ),
  cap: singleValued(
    "cap",
    "Role cap for the new device: owner (default, no bound), admin, member or reader",
  ),
  env: scopeEnvFlag(
    "Environment the device may hold keys for (repeatable; default: all environments)",
  ),
  "all-envs": singleFlag("all-envs", "Let the device hold keys for every environment (default)"),
  "no-envs": singleFlag("no-envs", "Let the device hold no environment keys (a vote-only device)"),
  ref: Argument.String("fp-or-words").pipe(
    Argument.withDescription(
      "The new device's full 32-character fingerprint, or its 12 words, as shown by `maruhi device add`",
    ),
    Argument.withSchema(NonBlank),
  ),
};
export const deviceListConfig = {
  ...serverOnlyFlags(),
  project: singleValuedAs(
    "project",
    "Show only this project's chain (default: every project you belong to)",
    ProjectIdSchema,
  ),
};
export const deviceRevokeConfig = {
  ...serverOnlyFlags(),
  project: singleValuedAs(
    "project",
    "Revoke on this project only (default: every project you belong to)",
    ProjectIdSchema,
  ),
  user: singleValued(
    "user",
    "Revoke another member's device (admin/owner; devices are named by fingerprint)",
  ),
  yes: singleFlag("yes", "Skip the confirmation prompt"),
  "revoke-token": singleFlag(
    "revoke-token",
    "Also revoke the API tokens the registry associates with the revoked devices",
  ),
  ref: Argument.String("ref").pipe(
    Argument.withDescription(
      "Fingerprint prefix (at least 8 hex characters) or, for your own devices, the registry label (repeatable)",
    ),
    Argument.withSchema(NonBlank),
    Argument.atLeast(1),
  ),
};
/** `maruhi device revoke`'s report (the per-project revoked FPs and the sweep — K4-7 / K4-8). */
const reportDeviceRevoke = Effect.fn("commands-device.reportDeviceRevoke")(function* (
  summary: DeviceRevokeSummary,
): Effect.fn.Return<number, CliError, CliServices> {
  let exitCode = 0;
  for (const project of summary.projects) {
    if (project.skipped === null && (yield* reportRevokedProject(project)) !== 0) {
      exitCode = 1;
    }
  }
  return exitCode;
});

/** Reporting one project's revocation result (exit code: an append failure, a sweep failure, a rotate failure = 1). */
function reportRevokedProject(
  project: ProjectRevokeOutcome,
): Effect.Effect<number, CliError, CliServices> {
  const label = displayText(project.projectId);
  return Effect.gen(function* () {
    const io = yield* CliIo;
    if (project.failed !== null) {
      yield* logWarning(`${label}: revocation failed — ${project.failed}`);
      return 1;
    }
    yield* io.log(
      `${label}: revoked ${project.revoked.length === 0 ? "nothing (already revoked)" : project.revoked.join(", ")}`,
    );
    if (project.sweepFailed !== null) {
      // The revocation is on the chain. What remains is only fulfilling the duty (the always-on warning keeps displaying it)
      yield* logWarning(
        `${label}: the rotation sweep after the revocation failed — ${project.sweepFailed}. The revocation itself is on the chain; the mandate stays listed as unconverged until \`maruhi env rotate <environment> --new-epoch --reason <text>\` is run for the affected environments`,
      );
      return 1;
    }
    if (project.sweep === null) {
      if (project.revoked.length > 0) {
        yield* logNote(
          `${label}: the rotation mandated by the revocation was not run from this device (it cannot sign here any more, or nothing is mandated). It stays listed as an unconverged mandate until another device rotates`,
        );
      }
      return 0;
    }
    return yield* reportSweepOutcome(project.sweep, {
      rerunCommand: "`maruhi env rotate <environment> --new-epoch --reason <text>`",
      alreadyRotatedBasis: "the revocation",
    });
  });
}

export function makeDeviceCommands(onExitCode: (code: number) => void) {
  const deviceAdd = Command.make(
    "add",
    deviceAddConfig,
    Effect.fn("commands-device.deviceAdd")(function* (values) {
      const { openSession } = yield* Effect.promise(() =>
        import("../context.ts").then(({ openSession }) => ({ openSession })),
      );
      const { deviceAddOp } = yield* Effect.promise(() =>
        import("../device-add.ts").then(({ deviceAddOp }) => ({ deviceAddOp })),
      );

      const context = yield* openSession(values.server);
      yield* deviceAddOp({
        session: context.session,
        client: context.client,
        label: values.label ?? hostname(),
        replace: values.replace,
      });
    }),
  ).pipe(
    Command.withDescription(
      "Register this machine as a new device: generate its key, print the fingerprint to approve from a registered device, and wait for the approval",
    ),
  );

  const deviceApprove = Command.make(
    "approve",
    deviceApproveConfig,
    Effect.fn("commands-device.deviceApprove")(function* (values) {
      const { openSession } = yield* Effect.promise(() =>
        import("../context.ts").then(({ openSession }) => ({ openSession })),
      );
      const { deviceApproveOp, parseApproveRef, reportApproveOutcomes } = yield* Effect.promise(
        () =>
          import("../device-approve.ts").then(
            ({ deviceApproveOp, parseApproveRef, reportApproveOutcomes }) => ({
              deviceApproveOp,
              parseApproveRef,
              reportApproveOutcomes,
            }),
          ),
      );
      const { parseCapRole } = yield* Effect.promise(() =>
        import("../device-revoke.ts").then(({ parseCapRole }) => ({ parseCapRole })),
      );

      const ref = yield* parseApproveRef(values.ref);
      const roleCap = yield* parseCapRole(values.cap);
      const scope =
        (yield* scopeFromFlags({
          env: values.env,
          allEnvs: values["all-envs"],
          noEnvs: values["no-envs"],
        })) ?? ALL_SCOPE;
      const context = yield* openSession(values.server);
      const outcomes = yield* deviceApproveOp({
        session: context.session,
        client: context.client,
        ref,
        cap: { roleCap, scope },
        project: values.project,
      });
      onExitCode(yield* reportApproveOutcomes(outcomes));
    }),
  ).pipe(
    Command.withDescription(
      "Approve a device-add request from this (registered) device: adds the device key to your projects' chains and backfills its DEK wraps",
    ),
  );

  const deviceList = Command.make(
    "list",
    deviceListConfig,
    Effect.fn("commands-device.deviceList")(function* (values) {
      const { openSession } = yield* Effect.promise(() =>
        import("../context.ts").then(({ openSession }) => ({ openSession })),
      );
      const { deviceListOp } = yield* Effect.promise(() =>
        import("../device-list.ts").then(({ deviceListOp }) => ({ deviceListOp })),
      );

      const context = yield* openSession(values.server);
      yield* deviceListOp({
        session: context.session,
        client: context.client,
        project: values.project,
      });
    }),
  ).pipe(
    Command.withDescription(
      "List your device keys: what each project's chain holds, with registry labels (server-reported) and this machine's records",
    ),
  );

  const deviceRevoke = Command.make(
    "revoke",
    deviceRevokeConfig,
    Effect.fn("commands-device.deviceRevoke")(function* (values) {
      const { openSession } = yield* Effect.promise(() =>
        import("../context.ts").then(({ openSession }) => ({ openSession })),
      );
      const { deviceRevokeOp } = yield* Effect.promise(() =>
        import("../device-revoke.ts").then(({ deviceRevokeOp }) => ({ deviceRevokeOp })),
      );

      const context = yield* openSession(values.server);
      const summary = yield* deviceRevokeOp({
        session: context.session,
        client: context.client,
        refs: values.ref,
        user: values.user,
        project: values.project,
        yes: values.yes,
        revokeToken: values["revoke-token"],
      });
      onExitCode(yield* reportDeviceRevoke(summary));
    }),
  ).pipe(
    Command.withDescription(
      "Revoke device keys (a lost or retired device) on every project and rotate the environments they could open",
    ),
  );

  const device = Command.make("device").pipe(
    Command.withDescription("Manage your device keys (add / approve / list / revoke)"),
    Command.withSubcommands([deviceAdd, deviceApprove, deviceList, deviceRevoke]),
  );

  return device;
}
