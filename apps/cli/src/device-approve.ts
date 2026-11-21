import { DeviceRegistryLimitError, MAX_DEVICE_REGISTRY_ROWS_PER_USER } from "@maruhi/api-schema";
import { type EnvironmentId, type KeyFingerprintHex, type ProjectId } from "@maruhi/core";
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

interface ApprovableRequest {
  readonly fingerprintHex: KeyFingerprintHex;
  readonly encPubHex: string;
  readonly sigPubHex: string;
  readonly label: string;
  readonly expiresAtMs: number;
}

const matchRequest = Effect.fn("device-approve.matchRequest")(function* (
  client: MaruhiClient,
  ref: ApproveRef,
): Effect.fn.Return<ApprovableRequest, CliError, CliIo> {
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
    return yield* Effect.fail(
      cliError(
        `${countNoun(matches.length, "pending device-add request")} carry the same key fingerprint ${match.fingerprintHex} (labels: ${matches.map((item) => displayText(item.label)).join(", ")}). The server should hold at most one request per fingerprint, so refusing to pick one. Wait for them to expire (15 minutes), re-run \`maruhi device add\` on the new device and approve the single new request`,
      ),
    );
  }
  return match;
});

interface ProjectApproveOutcome {
  readonly projectId: ProjectId;
  readonly state: "registered" | "already" | "skipped" | "failed";
  readonly backfill: DeviceBackfillOutcome | null;
  readonly message: string | null;
}

export const deviceApproveOp = Effect.fn("device-approve.deviceApproveOp")(function* (input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly ref: ApproveRef;
  readonly cap: DeviceCap;
  readonly project: ProjectId | undefined;
}): Effect.fn.Return<readonly ProjectApproveOutcome[], CliError, CliServices> {
  const io = yield* CliIo;
  yield* ensureDeviceApproveAllowed;
  const request = yield* matchRequest(input.client, input.ref);
  const masterKeys = yield* loadMasterKeys(input.session);
  if (request.fingerprintHex === masterKeys.fingerprintHex) {
    return yield* Effect.fail(
      cliError("That request carries this machine's own key; approve it from another device"),
    );
  }
  const words = yield* fingerprintWords(request.fingerprintHex, "The key fingerprint is malformed");
  yield* io.log(
    `Approving device ${request.fingerprintHex} (label "${displayText(request.label)}", cap ${describeCap(input.cap)})`,
  );
  yield* io.log(`fp words: ${formatWordList(words)}`);
  yield* io.log(
    "Compare them with the screen of the machine you are adding, never with a fingerprint sent to you: a request can be placed by anyone holding an account-wide admin API token of yours, and approving it adds their key to your projects",
  );
  const projectIds = yield* resolveProjectIds(input.client, input.project);
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
  if (!outcomes.some((item) => item.state === "registered" || item.state === "already")) {
    yield* logWarning(
      "the device was not registered on any project, so nothing was recorded and the request was left in place. Fix the cause reported above and re-run `maruhi device approve` with the same fingerprint (the request stays valid until it expires)",
    );
    return outcomes;
  }
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
    const retry = `The request is left in place until ${formatUtcMinutes(request.expiresAtMs)}:`;
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
  yield* input.client.devices
    .requestCancel({ params: { fp: request.fingerprintHex } })
    .pipe(Effect.asVoid, Effect.ignore);
  return outcomes;
});

type ProjectApprovePlan =
  | {
      readonly kind: "settled";
      readonly outcome: ProjectApproveOutcome;
      readonly chainCap: DeviceCap | null;
    }
  | {
      readonly kind: "append";
      readonly projectId: ProjectId;
      readonly context: ProjectContext;
      readonly chainCap: null;
    };

function planApproveOnProject(input: {
  readonly session: CliSession;
  readonly projectId: ProjectId;
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
      return settled(
        "skipped",
        `this machine's key is not one of your registered devices here, so it cannot register devices here. A device of yours that is registered here adds the new device (and this machine) when it runs a keyed command on this project at a terminal (\`maruhi pull --project ${displayText(input.projectId)}\`, for instance), if its cap covers them and it has synced a project that has them`,
        chainCap,
      );
    }
    if (present !== undefined) {
      return settled("already", null, chainCap);
    }
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

function sameCap(a: DeviceCap, b: DeviceCap): boolean {
  return a.roleCap === b.roleCap && sameScope(a.scope, b.scope);
}

function approveCommandOf(
  fingerprintHex: string,
  cap: DeviceCap,
  project: ProjectId | undefined,
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

function refuseCapMismatch(input: {
  readonly plans: readonly ProjectApprovePlan[];
  readonly request: ApprovableRequest;
  readonly cap: DeviceCap;
  readonly project: ProjectId | undefined;
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

export const reportApproveOutcomes = Effect.fn("device-approve.reportApproveOutcomes")(function* (
  outcomes: readonly ProjectApproveOutcome[],
): Effect.fn.Return<number, never, CliIo> {
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

export function describeBackfill(backfill: DeviceBackfillOutcome | null): string {
  return backfill === null
    ? ""
    : ` (backfilled ${countNoun(backfill.registered, "DEK wrap")}, ${backfill.alreadyRegistered} already present, ${countNoun(backfill.environments, "environment")})`;
}

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
        rerun: (environmentId) => describeGapFillRoute(item.projectId, environmentId),
      });
    case "skipped":
      return logNote(`${label}: skipped — ${item.message ?? ""}`).pipe(Effect.as(0));
    case "failed":
      return logWarning(`${label}: failed — ${item.message ?? ""}`).pipe(Effect.as(1));
  }
}

export const reportRegisteredDevice = Effect.fn("device-approve.reportRegisteredDevice")(
  function* (input: {
    readonly label: string;
    readonly action: string;
    readonly backfill: DeviceBackfillOutcome | null;
    readonly rerun: (environmentId: EnvironmentId) => string;
  }): Effect.fn.Return<number, never, CliIo> {
    const io = yield* CliIo;
    yield* io.log(`${input.label}: ${input.action}${describeBackfill(input.backfill)}`);
    const failed = input.backfill?.failed ?? [];
    for (const failure of failed) {
      yield* logWarning(
        `${input.label}: backfill of environment ${displayText(failure.environmentId)} failed (${failure.message}). ${input.rerun(failure.environmentId)}`,
      );
    }
    return failed.length > 0 ? 1 : 0;
  },
);
