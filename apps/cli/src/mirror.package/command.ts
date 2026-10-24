// `maruhi mirror` (discipline: see commands/index.ts).

import { Effect } from "effect";
import { Command } from "effect/cli";

import { projectFlags, singleFlag, singleValued } from "../commands/flags.ts";

/** `maruhi mirror sync` / `status`: the server (session + export) and the mirror (its own session + the pages).
 * @public
 */
export const mirrorStatusConfig = {
  ...projectFlags(),
  mirror: singleValued("mirror", "Mirror URL (default: the `mirror` setting)"),
};

/** @public */
export const mirrorSyncConfig = {
  ...mirrorStatusConfig,
  force: singleFlag(
    "force",
    "Replicate even though the mirror is marked as a mirror of another server",
  ),
};

/** `maruhi mirror mark`: --server is the mirror deployment, --source the deployment it mirrors.
 * @public
 */
export const mirrorMarkConfig = {
  ...projectFlags(),
  source: singleValued("source", "URL of the deployment this project mirrors (required)"),
  force: singleFlag(
    "force",
    "Mark even though this project's chain is not part of the source's (a mirror that can never be synced)",
  ),
};

/** @public */
export const mirrorPromoteConfig = {
  ...projectFlags(),
  force: singleFlag(
    "force",
    "Promote even though the source still answers (two writable copies of the project — a split you accept)",
  ),
};

/** @public */
export function makeMirrorCommands() {
  const mirrorSync = Command.make("sync", mirrorSyncConfig, (values) =>
    Effect.flatMap(
      Effect.promise(() =>
        import("./mirror-sync.ts").then((m) => ({ mirrorSyncOp: m.mirrorSyncOp })),
      ),
      ({ mirrorSyncOp }) => mirrorSyncOp(values),
    ),
  ).pipe(
    Command.withDescription(
      "Replicate the project from the server to the mirror (the export's pages uploaded in order; the mirror accepts only a replica that extends what it holds). From a cron: MARUHI_TOKEN / MARUHI_TOKEN_ORIGIN for the server, MARUHI_MIRROR_TOKEN for the mirror",
    ),
  );

  const mirrorStatus = Command.make("status", mirrorStatusConfig, (values) =>
    Effect.flatMap(
      Effect.promise(() =>
        import("./mirror-status.ts").then((m) => ({ mirrorStatusOp: m.mirrorStatusOp })),
      ),
      ({ mirrorStatusOp }) => mirrorStatusOp(values),
    ),
  ).pipe(
    Command.withDescription(
      "Show the server's verified chain head and the mirror's side by side, with the last replication",
    ),
  );

  const mirrorMark = Command.make("mark", mirrorMarkConfig, (values) =>
    Effect.flatMap(
      Effect.promise(() =>
        import("./mirror-mark.ts").then((m) => ({ mirrorMarkOp: m.mirrorMarkOp })),
      ),
      ({ mirrorMarkOp }) => mirrorMarkOp(values),
    ),
  ).pipe(
    Command.withDescription(
      "Mark the project on this server (--server names the mirror deployment) as a read-only mirror of --source; writes are refused there from then on (owner only)",
    ),
  );

  const mirrorPromote = Command.make("promote", mirrorPromoteConfig, (values) =>
    Effect.flatMap(
      Effect.promise(() =>
        import("./mirror-promote.ts").then((m) => ({ mirrorPromoteOp: m.mirrorPromoteOp })),
      ),
      ({ mirrorPromoteOp }) => mirrorPromoteOp(values),
    ),
  ).pipe(
    Command.withDescription(
      "Remove the mirror mark on this server (--server names the mirror deployment): the project accepts writes again and becomes the primary (owner only)",
    ),
  );

  const mirror = Command.make("mirror").pipe(
    Command.withDescription(
      "Manage a read replica of the project in another deployment (sync / status / mark / promote)",
    ),
    Command.withSubcommands([mirrorSync, mirrorStatus, mirrorMark, mirrorPromote]),
  );

  return mirror;
}
