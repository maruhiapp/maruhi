// `maruhi push` (discipline: see commands/index.ts).

import { Effect, Redacted } from "effect";
import { Argument, Command } from "effect/cli";

import {
  NonBlank,
  commonFlags,
  rejectNoSyncWithConfig,
  singleFlag,
  singleValued,
} from "../commands/flags.ts";
import { finishWrite, openWriteEnvironment } from "../commands/shared.ts";
import { displayText, logWarnings } from "../display.ts";
import { CliIo } from "../io.ts";
import { DEFAULT_SYNC_CONFIG_PATH } from "../sync.package/index.ts";

/** @public */
export const pushConfig = {
  ...commonFlags(),
  config: singleValued(
    "config",
    `Path to the sync config whose "onPush" targets are synced after the push (default: ${DEFAULT_SYNC_CONFIG_PATH} in the working directory, when it exists and names this project)`,
  ),
  "no-sync": singleFlag(
    "no-sync",
    "Skip the sync after the push (the default sync config is not read; run `maruhi sync apply` once after several pushes)",
  ),
  name: Argument.String("name").pipe(
    Argument.withDescription(
      "Variable name (the display name; becomes the environment variable name)",
    ),
    Argument.withSchema(NonBlank),
  ),
};

/** @public */
export function makePushCommand() {
  const push = Command.make(
    "push",
    pushConfig,
    Effect.fn("push-command.push")(function* (values) {
      const { normalizeStdinValue, pushVariable } = yield* Effect.promise(() =>
        import("./push.ts").then((m) => ({
          normalizeStdinValue: m.normalizeStdinValue,
          pushVariable: m.pushVariable,
        })),
      );

      const io = yield* CliIo;
      const { context, sync } = yield* openWriteEnvironment(values);
      // stdin is the origin where plaintext enters as raw bytes. Wrapped
      // here and flows only as a Redacted from now on (unwrapped only at
      // push.ts's encryption boundary)
      const value = Redacted.make(normalizeStdinValue(yield* io.readStdin), {
        label: "variable-value",
      });
      const pushed = yield* pushVariable({
        client: context.client,
        environmentId: context.environmentId,
        recipient: context.recipient,
        name: values.name,
        value,
        verified: context.verified,
        resync: context.resync,
        // The value signature (§4.1) / the creation-time statement author
        // signature (§4.2): writer / author = my internal user_id, key =
        // the master sig key
        writerUserId: context.session.userId,
        signingKey: context.masterKeys.sigKeyPair.privateKey,
        floor: context.floorHandle,
      });
      yield* logWarnings(pushed.warnings);
      yield* io.log(
        `Pushed ${displayText(values.name)} (version=${pushed.version}, epoch=${pushed.epoch})`,
      );
      yield* finishWrite(context, sync);
    }),
  ).pipe(
    Command.withDescription(
      "Encrypt a value read from stdin and push it to the environment (one trailing newline is stripped), then sync the deploy targets whose config asks for it",
    ),
    Command.validate((values) => rejectNoSyncWithConfig(values)),
  );

  return push;
}
