import type { MirrorStatus } from "@maruhi/api-schema";
import type { ProjectId } from "@maruhi/core";
import { Effect } from "effect";

import type { MaruhiClient } from "../api.ts";
import { syncProject } from "../chain-sync.ts";
import { loadCliConfig } from "../config.ts";
import {
  checkInviteAnchor,
  loadCheckedFloor,
  openSession,
  reconcileGossip,
  resolveMirrorOrigin,
  resolveProjectId,
  type SessionContext,
} from "../context.ts";
import { formatUtcMinutes } from "../display.ts";
import { type CliError, cliError, usageError } from "../errors.ts";
import { toCliError } from "../failure.ts";
import { noteServerDisclosure } from "../server-disclosure.ts";
import { resolveServerOrigin } from "../session.ts";

export const openMirrorTarget = Effect.fn("mirror-target.openMirrorTarget")(function* (flags: {
  readonly server?: string | undefined;
  readonly project?: string | undefined;
  readonly mirror?: string | undefined;
}) {
  const config = yield* loadCliConfig;
  const projectId = yield* resolveProjectId(flags.project, config);
  const serverOrigin = yield* resolveServerOrigin(flags.server, config);
  const mirrorOrigin = yield* resolveMirrorOrigin(flags.mirror, config);
  if (mirrorOrigin === null) {
    return yield* Effect.fail(
      cliError(
        "No mirror URL. Pass --mirror <url> or set it with `maruhi config set mirror <url>`",
      ),
    );
  }
  if (mirrorOrigin === serverOrigin) {
    return yield* Effect.fail(
      usageError("The mirror URL is the server URL itself (pass the mirror deployment's URL)"),
    );
  }
  const mirror = yield* openSession(mirrorOrigin, "mirror");
  return { mirror, mirrorOrigin, serverOrigin, projectId };
});

export const verifiedViewOf = Effect.fn("mirror-target.verifiedViewOf")(function* (
  source: SessionContext,
  projectId: ProjectId,
) {
  const synced = yield* syncProject(source.client, projectId);
  const checked = yield* loadCheckedFloor(projectId, synced, syncProject(source.client, projectId));
  yield* checkInviteAnchor(projectId, checked.verified);
  const verified = yield* reconcileGossip(
    projectId,
    checked.verified,
    syncProject(source.client, projectId),
  );
  yield* noteServerDisclosure(verified);
  return verified;
});

export function readMirrorStatus(input: {
  readonly client: MaruhiClient;
  readonly projectId: ProjectId;
}): Effect.Effect<MirrorStatus, CliError> {
  return input.client.mirror
    .status({ params: { projectId: input.projectId } })
    .pipe(Effect.mapError(toCliError));
}

export function describeLastSync(status: MirrorStatus): string {
  return status.lastSync === undefined
    ? "No replication recorded since the mark (the replication history is shown to admins and owners)"
    : `Last replication: chain head seq=${status.lastSync.chainHeadSeq}, audit seq=${status.lastSync.auditMaxSeq}, at ${formatUtcMinutes(status.lastSync.atMs)}`;
}
