// The command layer's lazy entry points into context.ts and session.ts
// (P-6 — commands/shared.ts's note), and into two rotation helpers several
// commands share (rotation.ts's reportRotationChecklist and sweep-rotate.ts's
// sweepRotateFor, which import context.ts): one wrapper for each context.ts
// and session.ts function a command calls, and one for each of the two
// helpers (commands/rotation.ts loads the rest of rotation.ts itself). A
// wrapper takes the arguments of the function it names and returns that
// function's effect, which loads the module when it runs (sweepRotateFor's
// returns its rotation function, which loads the module when a rotation
// runs). So a command imports these statically, and parsing, help and
// version still load none of the modules (test/startup-loads.test.ts runs
// them and checks). A leaf: nothing here imports another commands/ file.
//
// The wrappers are exported under the names of the functions they wrap (the
// list at the end), so a command's call reads as the direct call. Their
// local names differ so that a load's binding, which must carry the wrapped
// function's name, shadows nothing.

import { Effect } from "effect";

import type * as Context from "../context.ts";
import type { CliError } from "../errors.ts";
import type * as Rotation from "../rotation.ts";
import type * as Session from "../session.ts";
import type * as SweepRotate from "../sweep-rotate.ts";

/* -------------------------------------------------------------------------- */
/* context.ts                                                                 */
/* -------------------------------------------------------------------------- */

const lazyCheckInviteAnchor = (
  ...args: Parameters<typeof Context.checkInviteAnchor>
): ReturnType<typeof Context.checkInviteAnchor> =>
  Effect.flatMap(
    Effect.promise(() =>
      import("../context.ts").then((m) => ({ checkInviteAnchor: m.checkInviteAnchor })),
    ),
    ({ checkInviteAnchor }) => checkInviteAnchor(...args),
  );

const lazyCommitVerifiedHead = (
  ...args: Parameters<typeof Context.commitVerifiedHead>
): ReturnType<typeof Context.commitVerifiedHead> =>
  Effect.flatMap(
    Effect.promise(() =>
      import("../context.ts").then((m) => ({ commitVerifiedHead: m.commitVerifiedHead })),
    ),
    ({ commitVerifiedHead }) => commitVerifiedHead(...args),
  );

const lazyFloorHandleFor = (
  ...args: Parameters<typeof Context.floorHandleFor>
): ReturnType<typeof Context.floorHandleFor> =>
  Effect.flatMap(
    Effect.promise(() =>
      import("../context.ts").then((m) => ({ floorHandleFor: m.floorHandleFor })),
    ),
    ({ floorHandleFor }) => floorHandleFor(...args),
  );

const lazyLoadCheckedFloor = (
  ...args: Parameters<typeof Context.loadCheckedFloor>
): ReturnType<typeof Context.loadCheckedFloor> =>
  Effect.flatMap(
    Effect.promise(() =>
      import("../context.ts").then((m) => ({ loadCheckedFloor: m.loadCheckedFloor })),
    ),
    ({ loadCheckedFloor }) => loadCheckedFloor(...args),
  );

const lazyOpenEnvironment = (
  ...args: Parameters<typeof Context.openEnvironment>
): ReturnType<typeof Context.openEnvironment> =>
  Effect.flatMap(
    Effect.promise(() =>
      import("../context.ts").then((m) => ({ openEnvironment: m.openEnvironment })),
    ),
    ({ openEnvironment }) => openEnvironment(...args),
  );

const lazyOpenMetadataEnvironment = (
  ...args: Parameters<typeof Context.openMetadataEnvironment>
): ReturnType<typeof Context.openMetadataEnvironment> =>
  Effect.flatMap(
    Effect.promise(() =>
      import("../context.ts").then((m) => ({
        openMetadataEnvironment: m.openMetadataEnvironment,
      })),
    ),
    ({ openMetadataEnvironment }) => openMetadataEnvironment(...args),
  );

const lazyOpenMetadataEnvironmentPair = (
  ...args: Parameters<typeof Context.openMetadataEnvironmentPair>
): ReturnType<typeof Context.openMetadataEnvironmentPair> =>
  Effect.flatMap(
    Effect.promise(() =>
      import("../context.ts").then((m) => ({
        openMetadataEnvironmentPair: m.openMetadataEnvironmentPair,
      })),
    ),
    ({ openMetadataEnvironmentPair }) => openMetadataEnvironmentPair(...args),
  );

const lazyOpenMetadataProject = (
  ...args: Parameters<typeof Context.openMetadataProject>
): ReturnType<typeof Context.openMetadataProject> =>
  Effect.flatMap(
    Effect.promise(() =>
      import("../context.ts").then((m) => ({ openMetadataProject: m.openMetadataProject })),
    ),
    ({ openMetadataProject }) => openMetadataProject(...args),
  );

const lazyOpenProject = (
  ...args: Parameters<typeof Context.openProject>
): ReturnType<typeof Context.openProject> =>
  Effect.flatMap(
    Effect.promise(() => import("../context.ts").then((m) => ({ openProject: m.openProject }))),
    ({ openProject }) => openProject(...args),
  );

const lazyOpenSession = (
  ...args: Parameters<typeof Context.openSession>
): ReturnType<typeof Context.openSession> =>
  Effect.flatMap(
    Effect.promise(() => import("../context.ts").then((m) => ({ openSession: m.openSession }))),
    ({ openSession }) => openSession(...args),
  );

const lazyReconcileGossip = (
  ...args: Parameters<typeof Context.reconcileGossip>
): ReturnType<typeof Context.reconcileGossip> =>
  Effect.flatMap(
    Effect.promise(() =>
      import("../context.ts").then((m) => ({ reconcileGossip: m.reconcileGossip })),
    ),
    ({ reconcileGossip }) => reconcileGossip(...args),
  );

const lazyResolveProjectId = (
  ...args: Parameters<typeof Context.resolveProjectId>
): ReturnType<typeof Context.resolveProjectId> =>
  Effect.flatMap(
    Effect.promise(() =>
      import("../context.ts").then((m) => ({ resolveProjectId: m.resolveProjectId })),
    ),
    ({ resolveProjectId }) => resolveProjectId(...args),
  );

/** Generic in the read's value, so it is declared rather than derived from context.ts's type. */
const lazyWithMirrorFallback = <A>(
  flags: Context.CommonFlags,
  read: (flags: Context.CommonFlags) => Effect.Effect<A, CliError, Context.CliServices>,
): Effect.Effect<A, CliError, Context.CliServices> =>
  Effect.flatMap(
    Effect.promise(() =>
      import("../context.ts").then((m) => ({ withMirrorFallback: m.withMirrorFallback })),
    ),
    ({ withMirrorFallback }) => withMirrorFallback(flags, read),
  );

/* -------------------------------------------------------------------------- */
/* session.ts                                                                 */
/* -------------------------------------------------------------------------- */

const lazyLoadMasterKeys = (
  ...args: Parameters<typeof Session.loadMasterKeys>
): ReturnType<typeof Session.loadMasterKeys> =>
  Effect.flatMap(
    Effect.promise(() =>
      import("../session.ts").then((m) => ({ loadMasterKeys: m.loadMasterKeys })),
    ),
    ({ loadMasterKeys }) => loadMasterKeys(...args),
  );

const lazyNormalizeHttpOrigin = (
  ...args: Parameters<typeof Session.normalizeHttpOrigin>
): ReturnType<typeof Session.normalizeHttpOrigin> =>
  Effect.flatMap(
    Effect.promise(() =>
      import("../session.ts").then((m) => ({ normalizeHttpOrigin: m.normalizeHttpOrigin })),
    ),
    ({ normalizeHttpOrigin }) => normalizeHttpOrigin(...args),
  );

const lazyResolveServerOrigin = (
  ...args: Parameters<typeof Session.resolveServerOrigin>
): ReturnType<typeof Session.resolveServerOrigin> =>
  Effect.flatMap(
    Effect.promise(() =>
      import("../session.ts").then((m) => ({ resolveServerOrigin: m.resolveServerOrigin })),
    ),
    ({ resolveServerOrigin }) => resolveServerOrigin(...args),
  );

/* -------------------------------------------------------------------------- */
/* rotation.ts and sweep-rotate.ts                                            */
/* -------------------------------------------------------------------------- */

const lazyReportRotationChecklist = (
  ...args: Parameters<typeof Rotation.reportRotationChecklist>
): ReturnType<typeof Rotation.reportRotationChecklist> =>
  Effect.flatMap(
    Effect.promise(() =>
      import("../rotation.ts").then((m) => ({
        reportRotationChecklist: m.reportRotationChecklist,
      })),
    ),
    ({ reportRotationChecklist }) => reportRotationChecklist(...args),
  );

/** sweepRotateFor returns the rotation function, so the load waits for a rotation. */
const lazySweepRotateFor =
  (
    ...args: Parameters<typeof SweepRotate.sweepRotateFor>
  ): ReturnType<typeof SweepRotate.sweepRotateFor> =>
  (...rotation) =>
    Effect.flatMap(
      Effect.promise(() =>
        import("../sweep-rotate.ts").then((m) => ({ sweepRotateFor: m.sweepRotateFor })),
      ),
      ({ sweepRotateFor }) => sweepRotateFor(...args)(...rotation),
    );

export {
  lazyCheckInviteAnchor as checkInviteAnchor,
  lazyCommitVerifiedHead as commitVerifiedHead,
  lazyFloorHandleFor as floorHandleFor,
  lazyLoadCheckedFloor as loadCheckedFloor,
  lazyOpenEnvironment as openEnvironment,
  lazyOpenMetadataEnvironment as openMetadataEnvironment,
  lazyOpenMetadataEnvironmentPair as openMetadataEnvironmentPair,
  lazyOpenMetadataProject as openMetadataProject,
  lazyOpenProject as openProject,
  lazyOpenSession as openSession,
  lazyReconcileGossip as reconcileGossip,
  lazyResolveProjectId as resolveProjectId,
  lazyWithMirrorFallback as withMirrorFallback,
  lazyLoadMasterKeys as loadMasterKeys,
  lazyNormalizeHttpOrigin as normalizeHttpOrigin,
  lazyResolveServerOrigin as resolveServerOrigin,
  lazyReportRotationChecklist as reportRotationChecklist,
  lazySweepRotateFor as sweepRotateFor,
};
