// `maruhi device approve <fp|words>` (a registered device): the ceremony gate ->
// FP recomputation and match -> add_device per project -> backfill -> the
// registry signal -> request cancel (the group's overview lives in device.ts).

import { DeviceRegistryLimitError, MAX_DEVICE_REGISTRY_ROWS_PER_USER } from "@maruhi/api-schema";
import type { DeviceCap } from "@maruhi/crypto";
import { Clock, Effect, Result } from "effect";

import { ensureDeviceApproveAllowed } from "./agent-gate.ts";
import type { MaruhiClient } from "./api.ts";
import { type CliServices, openProject, type ProjectContext } from "./context.ts";
import { describeGapFillRoute } from "./device-gaps.ts";
import { capWithinSignerCap, describeCap, findOwnDevice, reAddDeviceRoute } from "./device-key.ts";
import { appendAddDevice, backfillToDevice, type DeviceBackfillOutcome } from "./device-ops.ts";
import { FULL_FINGERPRINT, recomputeFingerprint, resolveProjectIds, WORD_COUNT } from "./device.ts";
import { countNoun, displayText, formatUtcMinutes } from "./display.ts";
import { cliError, type CliError, usageError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { fingerprintWords, formatWordList } from "./fp-words.ts";
import { CliIo } from "./io.ts";
import { logNote, logWarning } from "./notice.ts";
import { type OwnDeviceEntry, OwnDeviceStore } from "./own-devices.ts";
import { requireScopeEnvironmentsExist, sameScope } from "./scope.ts";
import { type CliSession, loadMasterKeys, type MasterKeys } from "./session.ts";

// ---------------------------------------------------------------------------
// device approve
// ---------------------------------------------------------------------------

/** Interpreting `<fp-or-words>` (K4-6: the full 32 hex chars, or 12 words. Prefixes are not accepted). */
export type ApproveRef =
  | { readonly kind: "hex"; readonly fingerprintHex: string }
  | { readonly kind: "words"; readonly words: readonly string[] };

export function parseApproveRef(raw: string): Effect.Effect<ApproveRef, CliError> {
  const trimmed = raw.trim().toLowerCase();
  if (FULL_FINGERPRINT.test(trimmed)) {
    return Effect.succeed({ kind: "hex", fingerprintHex: trimmed });
  }
  const words = trimmed.split(/[\s,]+/).filter((word) => word.length > 0);
  if (words.length === WORD_COUNT && words.every((word) => /^[a-z]+$/.test(word))) {
    return Effect.succeed({ kind: "words", words });
  }
  return Effect.fail(
    usageError(
      "The device reference must be the full 32-character fingerprint or its 12 words (separated by spaces or commas) as shown by `maruhi device add` — fingerprints are never truncated for approval",
    ),
  );
}

/** One request row (an approval candidate — the FP is recomputed). */
interface ApprovableRequest {
  readonly fingerprintHex: string;
  readonly encPubHex: string;
  readonly sigPubHex: string;
  readonly label: string;
  readonly expiresAtMs: number;
}

/** Picks the request-list row matching the reference the human carried (the response's FP is not used — recomputed). */
function matchRequest(
  client: MaruhiClient,
  ref: ApproveRef,
): Effect.Effect<ApprovableRequest, CliError, CliIo> {
  return Effect.gen(function* () {
    const { requests } = yield* client.devices.requestList({}).pipe(Effect.mapError(toCliError));
    const matches: ApprovableRequest[] = [];
    for (const row of requests) {
      const fingerprintHex = yield* recomputeFingerprint(row.encPubHex, row.sigPubHex);
      if (fingerprintHex === null) {
        continue;
      }
      if (fingerprintHex !== row.keyFingerprintHex) {
        yield* logWarning(
          `a device-add request claims fingerprint ${row.keyFingerprintHex} but its public keys compute to ${fingerprintHex} — ignored (the server's row does not match its own keys)`,
        );
        continue;
      }
      const hit =
        ref.kind === "hex"
          ? fingerprintHex === ref.fingerprintHex
          : (yield* fingerprintWords(fingerprintHex, "The key fingerprint is malformed")).join(
              " ",
            ) === ref.words.join(" ");
      if (hit) {
        matches.push({
          fingerprintHex,
          encPubHex: row.encPubHex,
          sigPubHex: row.sigPubHex,
          label: row.label,
          expiresAtMs: row.expiresAtMs,
        });
      }
    }
    const match = matches[0];
    if (match === undefined) {
      return yield* Effect.fail(
        cliError(
          "No pending device-add request matches that fingerprint. Requests expire 15 minutes after `maruhi device add`; re-run it on the new device and compare the fingerprint it prints (full hex or the 12 words) with what you typed",
        ),
      );
    }
    if (matches.length > 1) {
      // Multiple requests for the same key (the server is supposed to
      // dedupe by FP). Rather than silently picking one and granting chain
      // authority, stop and show them
      return yield* Effect.fail(
        cliError(
          `${countNoun(matches.length, "pending device-add request")} carry the same key fingerprint ${match.fingerprintHex} (labels: ${matches.map((item) => displayText(item.label)).join(", ")}). The server should hold at most one request per fingerprint, so refusing to pick one. Wait for them to expire (15 minutes), re-run \`maruhi device add\` on the new device and approve the single new request`,
        ),
      );
    }
    return match;
  });
}

/** The approval result on one project. */
export interface ProjectApproveOutcome {
  readonly projectId: string;
  readonly state: "registered" | "already" | "skipped" | "failed";
  readonly backfill: DeviceBackfillOutcome | null;
  readonly message: string | null;
}

/** `maruhi device approve <fp|words> [--cap <role>] [--env …|--all-envs|--no-envs] [--project]`. */
export function deviceApproveOp(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly ref: ApproveRef;
  readonly cap: DeviceCap;
  readonly project: string | undefined;
}): Effect.Effect<readonly ProjectApproveOutcome[], CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    // The ceremony gate precedes fetching the request list (K4-6 counterexample 3)
    yield* ensureDeviceApproveAllowed;
    const request = yield* matchRequest(input.client, input.ref);
    const masterKeys = yield* loadMasterKeys(input.session);
    if (request.fingerprintHex === masterKeys.fingerprintHex) {
      return yield* Effect.fail(
        cliError("That request carries this machine's own key; approve it from another device"),
      );
    }
    const words = yield* fingerprintWords(
      request.fingerprintHex,
      "The key fingerprint is malformed",
    );
    yield* io.log(
      `Approving device ${request.fingerprintHex} (label "${displayText(request.label)}", cap ${describeCap(input.cap)})`,
    );
    yield* io.log(`fp words: ${formatWordList(words)}`);
    // The FP-provenance discipline (K7-7 — the same claim as docs
    // `devices.mdx`): only `ensureKeyMaterialAccess` (a `*` × admin token)
    // can place a request, so the path of placing a request with a stolen
    // token and getting a conveyed FP approved is stopped not by the yes
    // but by "read it from the screen of the machine being added"
    yield* io.log(
      "Compare them with the screen of the machine you are adding, never with a fingerprint sent to you: a request can be placed by anyone holding an account-wide admin API token of yours, and approving it adds their key to your projects",
    );
    const projectIds = yield* resolveProjectIds(input.client, input.project);
    // 2-phase (DK K10-4): open every project first to collect the
    // outcomes and the "caps already registered"; if a cap disagrees, stop
    // without appending anywhere (judging while appending means noticing
    // only after this run's cap was added to an unregistered project). The
    // opened contexts are used in phase 2
    const plans: ProjectApprovePlan[] = [];
    for (const projectId of projectIds) {
      plans.push(
        yield* planApproveOnProject({
          session: input.session,
          projectId,
          request,
          cap: input.cap,
          masterKeys,
        }),
      );
    }
    yield* refuseCapMismatch({ plans, request, cap: input.cap, project: input.project });
    const outcomes: ProjectApproveOutcome[] = [];
    for (const plan of plans) {
      outcomes.push(
        plan.kind === "settled"
          ? plan.outcome
          : yield* appendOnProject({
              session: input.session,
              plan,
              request,
              cap: input.cap,
              masterKeys,
            }),
      );
    }
    // If it landed on no project (all failed / skipped), the later stages
    // (record, registry, request cancellation) do not run: recording makes
    // the first sync repeat the same failure, the registry row sends the
    // requester a false signal, and cancelling the request erases the
    // re-run's material (Bugbot's catch)
    if (!outcomes.some((item) => item.state === "registered" || item.state === "already")) {
      yield* logWarning(
        "the device was not registered on any project, so nothing was recorded and the request was left in place. Fix the cause reported above and re-run `maruhi device approve` with the same fingerprint (the request stays valid until it expires)",
      );
      return outcomes;
    }
    // The local record (approved — writer (2) of K4-3). The approver's device FP is kept as provenance
    const store = yield* OwnDeviceStore;
    const entry: OwnDeviceEntry = {
      keyFingerprintHex: request.fingerprintHex,
      encPubHex: request.encPubHex,
      sigPubHex: request.sigPubHex,
      roleCap: input.cap.roleCap,
      scope: input.cap.scope,
      source: "approved",
      label: request.label,
      addedByFingerprintHex: masterKeys.fingerprintHex,
      observedProjectId: null,
      recordedAtMs: yield* Clock.currentTimeMillis,
      revokedAtMs: null,
    };
    yield* store.record(input.session.origin, input.session.userId, entry);
    // The registry PUT (the signal — done last). The result is taken as a
    // value and becomes the cancellation condition (DK K9-1): deleting a
    // request after failing to send the signal leaves the approver's
    // re-run unable to find the request, with no way to resend the signal.
    // The failure kind doesn't matter (K9-2 — only the wording sees the
    // kind)
    const listed = yield* Effect.result(
      input.client.devices.register({
        params: { fp: request.fingerprintHex },
        payload: {
          encPubHex: request.encPubHex,
          sigPubHex: request.sigPubHex,
          label: request.label,
        },
      }),
    );
    if (Result.isFailure(listed)) {
      // The request is left (until its expiry). A re-run converges via
      // all-projects already (the previously failed ones retry) → PUT →
      // cancellation. Past the expiry there is no path that writes the
      // registry row (K9-3's T3)
      const retry = `The request is left in place until ${formatUtcMinutes(request.expiresAtMs)}:`;
      // The re-run uses the same cap (K10-1 — a different cap is refused.
      // A flagless re-run becomes the default owner / all, so the command
      // is issued as-is)
      const rerun = approveCommandOf(request.fingerprintHex, input.cap, input.project);
      const afterwards =
        "After that the device stays registered on the chains above but unlisted in your device registry";
      yield* logNote(
        listed.failure instanceof DeviceRegistryLimitError
          ? `the device registry is full (${MAX_DEVICE_REGISTRY_ROWS_PER_USER} rows), so the new device was not listed there and \`maruhi device add\` on it will not see the completion signal. ${retry} remove old rows (\`maruhi device list\`, then \`maruhi device revoke\`) and re-run \`${rerun}\` before then to list it. ${afterwards}`
          : `could not update the device registry (${toCliError(listed.failure).message}); the device is registered on the chains above regardless, but \`maruhi device add\` on it will not see the completion signal. ${retry} re-run \`${rerun}\` before then to list it. ${afterwards}`,
      );
      return outcomes;
    }
    yield* input.client.devices.requestCancel({ params: { fp: request.fingerprintHex } }).pipe(
      Effect.asVoid,
      Effect.catch(() => Effect.void),
    );
    return outcomes;
  });
}

/**
 * The phase-1 result (DK K10-4): settled (skipped / already / failed), or
 * the context of a project to append to in phase 2. `chainCap` is this
 * key's cap if it is already on this chain (a chain fact regardless of
 * whether a signing device exists — K10-2 round 3).
 */
type ProjectApprovePlan =
  | {
      readonly kind: "settled";
      readonly outcome: ProjectApproveOutcome;
      readonly chainCap: DeviceCap | null;
    }
  | {
      readonly kind: "append";
      readonly projectId: string;
      readonly context: ProjectContext;
      readonly chainCap: null;
    };

/** Opens one project and judges its outcome (a failure is folded into the result — one failure doesn't stop the rest). */
function planApproveOnProject(input: {
  readonly session: CliSession;
  readonly projectId: string;
  readonly request: ApprovableRequest;
  readonly cap: DeviceCap;
  readonly masterKeys: MasterKeys;
}): Effect.Effect<ProjectApprovePlan, never, CliServices> {
  const settled = (
    state: ProjectApproveOutcome["state"],
    message: string | null,
    chainCap: DeviceCap | null = null,
  ): ProjectApprovePlan => ({
    kind: "settled",
    outcome: { projectId: input.projectId, state, backfill: null, message },
    chainCap,
  });
  return Effect.gen(function* () {
    const context = yield* openProject({ server: input.session.origin, project: input.projectId });
    const self = context.verified.state.members.get(input.session.userId);
    if (self === undefined) {
      return settled("skipped", "you are not a member of this project");
    }
    const present = self.devices.get(input.request.fingerprintHex);
    const chainCap: DeviceCap | null =
      present === undefined ? null : { roleCap: present.roleCap, scope: present.scope };
    const signer = findOwnDevice(self, { keyFingerprintHex: input.masterKeys.fingerprintHex });
    if (signer === undefined) {
      // There is no path to re-approve without a request (a registered
      // key cannot recreate one — DK K10-5). What registers it is this
      // project's own-device sync (`device-sync.ts`'s observe → register),
      // whose prologue opens only via a keyed command targeting this
      // project
      return settled(
        "skipped",
        `this machine's key is not one of your registered devices here, so it cannot register devices here. A device of yours that is registered here adds the new device (and this machine) when it runs a keyed command on this project at a terminal (\`maruhi pull --project ${displayText(input.projectId)}\`, for instance), if its cap covers them and it has synced a project that has them`,
        chainCap,
      );
    }
    if (present !== undefined) {
      return settled("already", null, chainCap);
    }
    // Pre-communication judgment (K4-3 counterexamples 3 / 4): monotonicity and the existence of `listed` environments
    if (!capWithinSignerCap(input.cap, signer)) {
      return settled(
        "skipped",
        `the requested cap ${describeCap(input.cap)} exceeds this device's own cap ${describeCap(signer)} (a device may only register devices bounded by its own cap — CRYPTO_SPEC §6.2); approve from a device with a wider cap`,
      );
    }
    yield* requireScopeEnvironmentsExist(context.verified, input.cap.scope);
    return { kind: "append", projectId: input.projectId, context, chainCap: null } as const;
  }).pipe(Effect.catch((error) => Effect.succeed(settled("failed", error.message))));
}

/** Cap equality (role and scope — scope is compared as a set). */
function sameCap(a: DeviceCap, b: DeviceCap): boolean {
  return a.roleCap === b.roleCap && sameScope(a.scope, b.scope);
}

/**
 * The command to re-run `device approve` with the same cap (DK K10-1).
 * The flag spellings are transcribed from the help golden (`--cap` /
 * `--env` / `--all-envs` / `--no-envs` / `--project`).
 */
function approveCommandOf(
  fingerprintHex: string,
  cap: DeviceCap,
  project: string | undefined,
): string {
  const scope =
    cap.scope.kind === "all"
      ? ["--all-envs"]
      : cap.scope.environmentIds.length === 0
        ? ["--no-envs"]
        : cap.scope.environmentIds.map((id) => `--env ${displayText(id)}`);
  const target = project === undefined ? [] : [`--project ${displayText(project)}`];
  return ["maruhi device approve", fingerprintHex, "--cap", cap.roleCap, ...scope, ...target].join(
    " ",
  );
}

/**
 * The re-run cap discipline (DK K10-1 / K10-2): if this key is already on
 * the chain of any visited project and its cap differs from this run's,
 * stop without appending or recording anything, leaving the request. A
 * device's cap is fixed at its first approval and cannot change, so a
 * re-run (after a PUT failure, after an interruption) is only ever a
 * continuation of the first approval. The comparison is against the chain
 * (the truth) only — the local records are never read (K4-5).
 */
function refuseCapMismatch(input: {
  readonly plans: readonly ProjectApprovePlan[];
  readonly request: ApprovableRequest;
  readonly cap: DeviceCap;
  readonly project: string | undefined;
}): Effect.Effect<void, CliError> {
  const present = input.plans.flatMap((plan) =>
    plan.chainCap === null ? [] : [{ projectId: plan.outcome.projectId, cap: plan.chainCap }],
  );
  if (present.every((item) => sameCap(item.cap, input.cap))) {
    return Effect.void;
  }
  const listed = present
    .map((item) => `${describeCap(item.cap)} on ${displayText(item.projectId)}`)
    .join(", ");
  const distinct = present.filter(
    (item, index) => present.findIndex((other) => sameCap(other.cap, item.cap)) === index,
  );
  const only = distinct.length === 1 ? distinct[0] : undefined;
  const rerun =
    only === undefined
      ? "Its cap differs between those projects, so re-run it once per project with `--project <id>` and the cap shown for that project."
      : `Re-run it with that cap: \`${approveCommandOf(input.request.fingerprintHex, only.cap, input.project)}\`.`;
  return Effect.fail(
    cliError(
      `Device ${input.request.fingerprintHex} is already registered with cap ${listed}, and this approval asks for ${describeCap(input.cap)}: a device's cap is set when it is first approved and cannot be changed later, so this approval appended nothing, recorded nothing and left the request in place. ${rerun} To give the device another cap, revoke it, then ${reAddDeviceRoute("that machine")} with the cap you want`,
    ),
  );
}

/** Phase 2: `add_device` + backfill in the contexts opened in phase 1 (failures fold into the result). */
function appendOnProject(input: {
  readonly session: CliSession;
  readonly plan: Extract<ProjectApprovePlan, { readonly kind: "append" }>;
  readonly request: ApprovableRequest;
  readonly cap: DeviceCap;
  readonly masterKeys: MasterKeys;
}): Effect.Effect<ProjectApproveOutcome, never, CliServices> {
  const { context, projectId } = input.plan;
  const outcome = (
    state: ProjectApproveOutcome["state"],
    message: string | null,
    backfill: DeviceBackfillOutcome | null = null,
  ): ProjectApproveOutcome => ({ projectId, state, backfill, message });
  return Effect.gen(function* () {
    const appended = yield* appendAddDevice({
      client: context.client,
      verified: context.verified,
      resync: context.resync,
      signer: { userId: input.session.userId, signingKeyPair: input.masterKeys.sigKeyPair },
      candidate: {
        encPubHex: input.request.encPubHex,
        sigPubHex: input.request.sigPubHex,
        cap: input.cap,
      },
    });
    const verified = yield* context.resync;
    const current = verified.state.members.get(input.session.userId);
    const targetDevice = current?.devices.get(input.request.fingerprintHex);
    if (current === undefined || targetDevice === undefined) {
      return yield* Effect.fail(
        cliError(
          "The resync after add_device was accepted does not show the device on the chain (the server's response contradicts the chain). Investigate the served chain",
        ),
      );
    }
    const backfill = yield* backfillToDevice({
      client: context.client,
      verified,
      recipient: context.recipient,
      targetMember: current,
      targetDevice,
      signerUserId: input.session.userId,
      signingKeyPair: input.masterKeys.sigKeyPair,
    });
    return outcome(appended.appended ? "registered" : "already", null, backfill);
  }).pipe(Effect.catch((error) => Effect.succeed(outcome("failed", error.message))));
}

/** Reporting the approval result (called by commands/device.ts). */
export function reportApproveOutcomes(
  outcomes: readonly ProjectApproveOutcome[],
): Effect.Effect<number, never, CliIo> {
  return Effect.gen(function* () {
    // It landed nowhere (all skipped / failed — no record or request
    // cancellation happened). The approval ends as a failure (not 0 even
    // when everything was only skipped)
    let exitCode = outcomes.some((item) => item.state === "registered" || item.state === "already")
      ? 0
      : 1;
    for (const item of outcomes) {
      if ((yield* reportApproveOutcome(item)) !== 0) {
        exitCode = 1;
      }
    }
    return exitCode;
  });
}

/** The backfill summary (in parentheses. null = no backfill). */
export function describeBackfill(backfill: DeviceBackfillOutcome | null): string {
  return backfill === null
    ? ""
    : ` (backfilled ${countNoun(backfill.registered, "DEK wrap")}, ${backfill.alreadyRegistered} already present, ${countNoun(backfill.environments, "environment")})`;
}

/** One project's approval result (exit code: a backfill failure or a failure is 1). */
function reportApproveOutcome(item: ProjectApproveOutcome): Effect.Effect<number, never, CliIo> {
  const label = displayText(item.projectId);
  switch (item.state) {
    case "registered":
    case "already":
      return reportRegisteredDevice({
        label,
        action:
          item.state === "registered"
            ? "registered the device"
            : "the device was already registered",
        backfill: item.backfill,
        // `already` does not backfill, so re-running the approval fills no
        // gap (DK K11 — the sibling devices' pull fills it. Also avoids
        // K10-12's cap refusal)
        rerun: (environmentId) => describeGapFillRoute(item.projectId, environmentId),
      });
    case "skipped":
      return logNote(`${label}: skipped — ${item.message ?? ""}`).pipe(Effect.as(0));
    case "failed":
      return logWarning(`${label}: failed — ${item.message ?? ""}`).pipe(Effect.as(1));
  }
}

/** The registered(-already) row + a backfill-failure warning (shared by approve and restore — 1 when there is a failure). */
export function reportRegisteredDevice(input: {
  readonly label: string;
  readonly action: string;
  readonly backfill: DeviceBackfillOutcome | null;
  /** Guidance for the path that fills the failed environments (DK K11-5 — the wording is built by device-gaps.ts). */
  readonly rerun: (environmentId: string) => string;
}): Effect.Effect<number, never, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* io.log(`${input.label}: ${input.action}${describeBackfill(input.backfill)}`);
    const failed = input.backfill?.failed ?? [];
    for (const failure of failed) {
      yield* logWarning(
        `${input.label}: backfill of environment ${displayText(failure.environmentId)} failed (${failure.message}). ${input.rerun(failure.environmentId)}`,
      );
    }
    return failed.length > 0 ? 1 : 0;
  });
}
