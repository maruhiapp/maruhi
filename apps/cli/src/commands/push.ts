// `maruhi push` (discipline: see commands/index.ts).

import { Effect, Redacted } from "effect";
import { Argument, Command } from "effect/cli";

import { displayText, logWarnings } from "../display.ts";
import { CliIo } from "../io.ts";
import {
  DEFAULT_SYNC_CONFIG_PATH,
  decidePushSync,
  loadPushSyncConfig,
  syncAfterPush,
} from "../sync.package/index.ts";
import { NonBlank, commonFlags, singleFlag, singleValued } from "./flags.ts";
import { proposeCheckpointRefresh } from "./shared.ts";

/**
 * `maruhi push`'s specific fix, attached to its extra positional
 * arguments. `maruhi push API_KEY "$SECRET"` is the most likely
 * misspelling. The refused argument's content is never shown (it may be
 * plaintext), so "the value comes via stdin" is always attached instead —
 * otherwise there is no way to fix it (cli-formatter.ts's strayHint).
 */
export const PUSH_STDIN_HINT =
  '. Values are read from stdin (example: `printf %s "$SECRET" | maruhi push API_KEY`)';

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

export function makePushCommand() {
  const push = Command.make(
    "push",
    pushConfig,
    Effect.fn("commands-push.push")(function* (values) {
      const { openEnvironment } = yield* Effect.promise(() => import("../context.ts"));
      const { normalizeStdinValue, pushVariable } = yield* Effect.promise(
        () => import("../push.ts"),
      );

      const io = yield* CliIo;
      // The sync config is read **before any network**: detecting a broken
      // file or an explicitly-given other project's config is never placed
      // behind the push (same as SY2 stage 2 2b's ruling B)
      const syncSetup = yield* loadPushSyncConfig({
        config: values.config,
        noSync: values["no-sync"],
      });
      const context = yield* openEnvironment(values);
      // The cleanup's contents are decided **before** the push (a
      // disagreement with the explicitly-given config's `project` is a
      // misspelling = 2, and the push is not sent)
      const syncDecision =
        syncSetup === null
          ? null
          : yield* decidePushSync(syncSetup, {
              projectId: context.projectId,
              environmentId: context.environmentId,
              name: values.name,
            });
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
      // Issuance trigger (iii) (CRYPTO_SPEC §6.3): detecting the baseline
      // checkpoint's staleness on a successful push. The anchor-update
      // proposal rides the same route (the ruling is
      // docs/notes/session-35.md)
      yield* proposeCheckpointRefresh(context, { includeAnchor: true });
      if (syncSetup !== null && syncDecision !== null) {
        // Cleanup: apply directly to targets carrying `onPush`, or launch
        // CI. A failure stays a warning and the exit code stays push's
        // (only the evidence fails — sync-push.ts)
        yield* syncAfterPush({ context, setup: syncSetup, decision: syncDecision });
      }
    }),
  ).pipe(
    Command.withDescription(
      "Encrypt a value read from stdin and push it to the environment (one trailing newline is stripped), then sync the deploy targets whose config asks for it",
    ),
  );

  return push;
}
