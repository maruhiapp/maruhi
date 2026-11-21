import { DEVICE_ADD_REQUEST_TTL_MS } from "@maruhi/api-schema";
import { type EnvironmentId, type KeyFingerprintHex, type ProjectId } from "@maruhi/core";
import type { ChainDevice, ChainMember } from "@maruhi/crypto";
import { Clock, Duration, Effect, Result, Schedule } from "effect";

import type { MaruhiClient } from "./api.ts";
import { type CliServices, type ProjectContextBase } from "./context.ts";
import { type DekRecipient, environmentKeysFor, missingEpochsOf } from "./deks.ts";
import { describeMissingOwnEpochs, gapFillCommandOf } from "./device-gaps.ts";
import { reAddDeviceRoute } from "./device-key.ts";
import { deviceEnvironmentsOf } from "./device-ops.ts";
import {
  groupStandings,
  type KeyStandings,
  keyStandingsOf,
  type StandingGroups,
} from "./device-standing.ts";
import { fetchRegistry } from "./device.ts";
import { countNoun, describeListed, displayText, formatUtcMinutes } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { FloorStore } from "./floor.ts";
import { fingerprintWords, formatWordList } from "./fp-words.ts";
import { CliIo } from "./io.ts";
import { generateKeyRecord } from "./key-record.ts";
import { Keychain, masterKeyEntryName, serializeStoredMasterKey } from "./keychain.ts";
import { logNote, logWarning } from "./notice.ts";
import {
  type CliSession,
  importMasterKeys,
  loadMasterKeys,
  type MasterKeys,
  storeMasterKeyAndReport,
} from "./session.ts";

const DEVICE_ADD_POLL_INTERVAL_MS = 3_000;

export const DEVICE_ADD_WAIT_HINT_AFTER_MS = DEVICE_ADD_REQUEST_TTL_MS / 3;

export const deviceAddOp = Effect.fn("device-add.deviceAddOp")(function* (input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly label: string;
  readonly replace: boolean;
}): Effect.fn.Return<void, CliError, CliServices> {
  const keychain = yield* Keychain;
  const entryName = masterKeyEntryName(input.session.origin, input.session.userId);
  const existing = yield* keychain.get(entryName);
  if (existing !== null && !input.replace) {
    const keys = yield* loadMasterKeys(input.session);
    const pending = yield* pendingRequestOf(input.client, keys.fingerprintHex);
    if (pending !== null) {
      yield* logNote(
        `this machine already has device key ${keys.fingerprintHex} with a device-add request — resuming the wait for its approval`,
      );
      return yield* awaitApproval(input, keys, pending.expiresAtMs);
    }
    return yield* settleExistingKey(input, keys);
  }
  const started = yield* startWithNewKey(input, entryName, existing);
  if (started.request.kind === "already-registered") {
    return yield* settleExistingKey(input, started.keys);
  }
  return yield* awaitApproval(input, started.keys, started.request.expiresAtMs);
});

function pendingRequestOf(
  client: MaruhiClient,
  fingerprintHex: KeyFingerprintHex,
): Effect.Effect<{ readonly expiresAtMs: number } | null, CliError> {
  return client.devices.requestGet({ params: { fp: fingerprintHex } }).pipe(
    Effect.map((request) => ({ expiresAtMs: request.expiresAtMs })),
    Effect.catchTag("DeviceNotFound", () => Effect.succeed(null)),
    Effect.mapError(toCliError),
  );
}

const announceFingerprint = Effect.fn("device-add.announceFingerprint")(function* (
  keys: MasterKeys,
): Effect.fn.Return<void, CliError, CliIo> {
  const io = yield* CliIo;
  const words = yield* fingerprintWords(keys.fingerprintHex, "The key fingerprint is malformed");
  yield* io.log(`This device's key fingerprint: ${keys.fingerprintHex}`);
  yield* io.log(`fp words: ${formatWordList(words)}`);
});

const awaitApproval = Effect.fn("device-add.awaitApproval")(function* (
  input: {
    readonly session: CliSession;
    readonly client: MaruhiClient;
  },
  keys: MasterKeys,
  expiresAtMs: number,
): Effect.fn.Return<void, CliError, CliServices> {
  const io = yield* CliIo;
  yield* announceFingerprint(keys);
  yield* io.log(
    `On a device that is already registered, run \`maruhi device approve ${keys.fingerprintHex}\` (or pass the 12 words). The request expires at ${formatUtcMinutes(expiresAtMs)} (15 minutes); re-running \`maruhi device add\` with this key resumes waiting while the request is valid`,
  );
  yield* io.log("Waiting for approval (Ctrl+C to stop waiting; the request stays valid)…");
  const signalled = yield* waitForRegistryRow({
    client: input.client,
    fingerprintHex: keys.fingerprintHex,
    expiresAtMs,
    hintAfterMs: DEVICE_ADD_WAIT_HINT_AFTER_MS,
  });
  const standings = yield* keyStandingsOf({
    session: input.session,
    client: input.client,
    fingerprintHex: keys.fingerprintHex,
  });
  if (!signalled) {
    return yield* Effect.fail(
      cliError(
        `The device-add request expired before this machine saw the completion signal (requests live 15 minutes). Check the output on the approving device: if it registered nothing, run \`maruhi device add --replace\` on this machine — this key (${keys.fingerprintHex}) is registered nowhere, so discarding it loses nothing — and approve the new fingerprint it prints from a registered device with \`maruhi device approve\`. If it registered this device but could not list it in your device registry, keep this key: it is already registered on the projects that output lists (\`maruhi device list\` on this machine shows where), and only its row in your device registry is missing. ${describeChainsNow(standings)}`,
      ),
    );
  }
  if (standings.listFailure !== null) {
    yield* io.log(
      "Approved: the approving device gave the completion signal (this device is listed in your device registry)",
    );
    yield* logNote(
      `your projects could not be listed (${standings.listFailure}), so no project chain was checked; \`maruhi device list\` checks where this key is registered`,
    );
    return;
  }
  const groups = groupStandings(standings);
  yield* io.log(
    `Approved: this device is registered on ${countNoun(groups.active.length, "project")} (verified on each project's chain)${describeUnchecked(groups)}`,
  );
  yield* reportStandings(groups, keys, { approved: true });
});

function describeChainsNow(standings: KeyStandings): string {
  if (standings.listFailure !== null) {
    return `maruhi could not check the project chains just now (your projects could not be listed: ${standings.listFailure}); re-running \`maruhi device add\` on this machine checks them again without a new request`;
  }
  const groups = groupStandings(standings);
  if (groups.active.length > 0) {
    return `On the project chains right now, this key is registered on ${groups.active.map((project) => displayText(project.projectId)).join(", ")} — keep it; re-running \`maruhi device add\` on this machine confirms that without a new request`;
  }
  const unchecked =
    groups.unsynced.length === 0
      ? ""
      : ` (${groups.unsynced.map((project) => displayText(project.projectId)).join(", ")} could not be checked)`;
  const revoked =
    groups.revoked.length === 0
      ? ""
      : `; it is revoked on ${groups.revoked.map(displayText).join(", ")}`;
  return `On the project chains right now, this key is on ${describeListed(standings.projects.length)}${unchecked}${revoked}. If the approving device is still working, re-running \`maruhi device add\` on this machine later shows whether it registered this key, without a new request`;
}

function describeUnchecked(groups: StandingGroups): string {
  return groups.unsynced.length === 0
    ? ""
    : `, and ${countNoun(groups.unsynced.length, "project")} could not be checked`;
}

function projectList(projectIds: readonly ProjectId[]): string {
  return projectIds.map(displayText).join(", ");
}

const settleExistingKey = Effect.fn("device-add.settleExistingKey")(function* (
  input: { readonly session: CliSession; readonly client: MaruhiClient },
  keys: MasterKeys,
): Effect.fn.Return<void, CliError, CliServices> {
  const standings = yield* keyStandingsOf({ ...input, fingerprintHex: keys.fingerprintHex });
  const groups = groupStandings(standings);
  if (groups.active.length > 0) {
    return yield* reportActiveKey(input.client, keys, groups);
  }
  return yield* Effect.fail(cliError(yield* refusalWithoutActiveKey(keys, standings, groups)));
});

const reportActiveKey = Effect.fn("device-add.reportActiveKey")(function* (
  client: MaruhiClient,
  keys: MasterKeys,
  groups: StandingGroups,
): Effect.fn.Return<void, CliError, CliServices> {
  const io = yield* CliIo;
  const fingerprintHex = keys.fingerprintHex;
  yield* io.log(`This device's key fingerprint: ${fingerprintHex}`);
  yield* io.log(
    `This key is registered on ${countNoun(groups.active.length, "project")} (verified on each project's chain)${describeUnchecked(groups)}`,
  );
  const registry = yield* fetchRegistry(client);
  if (registry !== null && !registry.some((row) => row.keyFingerprintHex === fingerprintHex)) {
    yield* logNote(
      "this key has no row in your device registry (an approval whose registry write failed leaves it so). The registry only labels devices, so nothing else is needed; `maruhi device list` shows this key without a label",
    );
  }
  yield* reportStandings(groups, keys, { approved: false });
});

const refusalWithoutActiveKey = Effect.fn("device-add.refusalWithoutActiveKey")(function* (
  keys: MasterKeys,
  standings: KeyStandings,
  groups: StandingGroups,
): Effect.fn.Return<string, never, CliServices> {
  const fingerprintHex = keys.fingerprintHex;
  if (standings.listFailure !== null || groups.unsynced.length > 0) {
    yield* warnEvidence(groups.unsynced);
    const causes =
      standings.listFailure === null
        ? groups.unsynced
            .map(
              (project) =>
                `${displayText(project.projectId)} could not be synced (${project.message})`,
            )
            .join("; ")
        : `your projects could not be listed (${standings.listFailure})`;
    const facts = [
      groups.revoked.length > 0 ? `It is revoked on ${projectList(groups.revoked)}. ` : "",
      groups.absent.length > 0 ? `It is not on ${projectList(groups.absent)}. ` : "",
    ].join("");
    return `This machine's device key (${fingerprintHex}) has no pending device-add request, and maruhi could not check every project it may be registered on: ${causes}. ${facts}Nothing is decided from a project that was not checked, so this does not say the key is unused. Re-run \`maruhi device add\` once those projects sync. If you know this key is revoked, a copy of another device's key, or registered nowhere, re-run with --replace instead (not on your only device)`;
  }
  if (groups.revoked.length > 0) {
    return `This machine's device key (${fingerprintHex}) is revoked on ${projectList(groups.revoked)} and registered on ${describeListed(standings.projects.length)}, and it has no pending device-add request. To add this machine back, ${reAddDeviceRoute("this machine")} — you choose its cap again when approving`;
  }
  const unlisted = yield* unlistedFloorProjects(standings);
  return `This machine's device key (${fingerprintHex}) has no pending device-add request and is on ${describeListed(standings.projects.length)}, each chain synced and verified, so replacing it loses nothing there: re-run with --replace — it discards this key, generates a new one and prints its fingerprint to approve from a registered device${unlisted}`;
});

const unlistedFloorProjects = Effect.fn("device-add.unlistedFloorProjects")(function* (
  standings: KeyStandings,
): Effect.fn.Return<string, never, CliServices> {
  const floor = yield* FloorStore;
  const ids = yield* floor
    .listProjectIds()
    .pipe(Effect.orElseSucceed((): readonly ProjectId[] => []));
  const listed = new Set(standings.projects.map((project) => project.projectId));
  const unlisted = ids.filter((id) => !listed.has(id));
  if (unlisted.length === 0) {
    return "";
  }
  return `. This machine also has local records of ${countNoun(unlisted.length, "project")} that list does not include (${unlisted.map(displayText).join(", ")}); those records are not separated by server or account, so they may not be yours here — if one is, check it with \`maruhi project verify --project <id>\` before replacing`;
});

function warnEvidence(unsynced: StandingGroups["unsynced"]): Effect.Effect<void, never, CliIo> {
  return Effect.forEach(
    unsynced.filter((project) => project.evidence),
    (project) =>
      logWarning(
        `${displayText(project.projectId)}: ${project.message} — a sign of tampering rather than a network error, so nothing about this key is decided from that project`,
      ),
    { discard: true },
  );
}

const reportStandings = Effect.fn("device-add.reportStandings")(function* (
  groups: StandingGroups,
  keys: MasterKeys,
  options: { readonly approved: boolean },
): Effect.fn.Return<void, never, CliIo> {
  for (const project of groups.active) {
    const issues = yield* checkKeyReach({ ...project.standing, keys });
    for (const issue of issues) {
      yield* reportKeyReachIssue(project.projectId, issue);
    }
  }
  if (groups.revoked.length > 0) {
    yield* logNote(
      `this key was revoked on ${groups.revoked.map(displayText).join(", ")}, so it is not registered there again. To put this machine back there, ${reAddDeviceRoute("this machine")}${groups.active.length > 0 ? `. This keychain then no longer holds this key, so revoke it on ${groups.active.map((project) => displayText(project.projectId)).join(", ")}, where it is still registered (\`maruhi device revoke ${keys.fingerprintHex}\` from a registered device)` : ""}`,
    );
  }
  yield* warnEvidence(groups.unsynced);
  const unsyncedNotes = groups.unsynced.filter((project) => !project.evidence);
  for (const project of unsyncedNotes) {
    yield* logNote(
      `${displayText(project.projectId)}: could not sync this project (${project.message}), so whether this key is registered there is unknown; \`maruhi device list\` checks again`,
    );
  }
  if (groups.absent.length === 0) {
    return;
  }
  const absent = groups.absent.map(displayText).join(", ");
  if (options.approved) {
    yield* logNote(
      `not registered yet on ${absent} — the approving device skipped or failed on them (its output says which, and why: its cap does not cover them, you are not a member there, or the append failed there), or you approved with --project. The request is used up. A device of yours whose cap covers them registers this key on each of them when it runs a keyed command on that project at a terminal (\`maruhi pull --project <id>\`, for instance) — the approving device itself if its cap was not the cause, another device otherwise, once it has synced a project that did register this key. \`maruhi device list\` shows where this key is registered`,
    );
    return;
  }
  yield* logNote(
    `this key is not registered on ${absent}. A device of yours whose cap covers them registers it on each of them when it runs a keyed command on that project at a terminal (\`maruhi pull --project <id>\`, for instance), once it has synced a project that has this key. \`maruhi device list\` shows where this key is registered`,
  );
});

const startWithNewKey = Effect.fn("device-add.startWithNewKey")(function* (
  input: {
    readonly session: CliSession;
    readonly client: MaruhiClient;
    readonly label: string;
  },
  entryName: string,
  previous: string | null,
): Effect.fn.Return<
  { readonly keys: MasterKeys; readonly request: RequestState },
  CliError,
  CliServices
> {
  if (previous !== null) {
    yield* describeReplacedKey(input);
  }
  const record = yield* generateKeyRecord();
  const validated = yield* importMasterKeys(record).pipe(
    Effect.mapError(() =>
      cliError(
        "Could not load the generated device key back (nothing was stored in the keychain). Report this as a maruhi bug",
      ),
    ),
  );
  const request = yield* createOrResumeRequest(input, validated).pipe(
    Effect.tapError(() =>
      previous === null
        ? Effect.void
        : logNote(
            "nothing was replaced: the previous key is still in this machine's keychain (--replace replaces it only once the new key's request exists)",
          ),
    ),
  );
  yield* storeMasterKeyAndReport({
    entryName,
    serialized: serializeStoredMasterKey(record),
    action: previous === null ? "Generated this device's key" : "Generated this device's new key",
    fingerprintHex: validated.fingerprintHex,
    deviceAdd: { previous },
  });
  if (previous !== null) {
    yield* logNote("replaced the previous key in this machine's keychain (--replace)");
  }
  return { keys: validated, request };
});

const describeReplacedKey = Effect.fn("device-add.describeReplacedKey")(function* (input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
}): Effect.fn.Return<void, never, CliServices> {
  const loaded = yield* Effect.result(loadMasterKeys(input.session));
  if (Result.isFailure(loaded)) {
    yield* logNote(
      `could not read the key being replaced (${loaded.failure.message}); its standing on your projects is not shown`,
    );
    return;
  }
  const fingerprintHex = loaded.success.fingerprintHex;
  const standings = yield* keyStandingsOf({ ...input, fingerprintHex });
  const groups = groupStandings(standings);
  const parts = [
    groups.active.length > 0
      ? `registered on ${projectList(groups.active.map((project) => project.projectId))}`
      : null,
    groups.revoked.length > 0 ? `revoked on ${groups.revoked.map(displayText).join(", ")}` : null,
    groups.unsynced.length > 0
      ? `not checked on ${projectList(groups.unsynced.map((project) => project.projectId))} (could not sync)`
      : null,
    standings.listFailure === null
      ? null
      : `not checked anywhere (your projects could not be listed: ${standings.listFailure})`,
  ].filter((part): part is string => part !== null);
  yield* logNote(
    `replacing this machine's key ${fingerprintHex}, which is ${parts.length === 0 ? `on ${describeListed(standings.projects.length)}` : parts.join("; ")}${groups.active.length > 0 ? `. Once the new key is approved, revoke the previous key where it is still registered unless another machine holds it (\`maruhi device revoke ${fingerprintHex}\` from a registered device)` : ""}`,
  );
});

type KeyReachIssue =
  | {
      readonly kind: "missing";
      readonly environmentId: EnvironmentId;
      readonly epochs: readonly number[];
    }
  | {
      readonly kind: "unchecked";
      readonly environmentId: EnvironmentId;
      readonly message: string;
    };

const checkKeyReach = Effect.fn("device-add.checkKeyReach")(function* (input: {
  readonly context: ProjectContextBase;
  readonly member: ChainMember;
  readonly device: ChainDevice;
  readonly keys: MasterKeys;
}): Effect.fn.Return<readonly KeyReachIssue[]> {
  const { client, verified } = input.context;
  const environments = deviceEnvironmentsOf({
    verified,
    targetMember: input.member,
    targetDevice: input.device,
  });
  const recipient: DekRecipient = {
    userId: input.context.session.userId,
    encPubHex: input.keys.record.encPubHex,
    encKeyPair: input.keys.encKeyPair,
  };
  const issues: KeyReachIssue[] = [];
  for (const environmentId of environments) {
    const opened = yield* Effect.result(
      environmentKeysFor({ client, verified, environmentId, recipient }),
    );
    if (Result.isFailure(opened)) {
      issues.push({ kind: "unchecked", environmentId, message: opened.failure.message });
      continue;
    }
    const epochs = missingEpochsOf(opened.success);
    if (epochs.length > 0) {
      issues.push({ kind: "missing", environmentId, epochs });
    }
  }
  return issues;
});

function reportKeyReachIssue(
  projectId: ProjectId,
  issue: KeyReachIssue,
): Effect.Effect<void, never, CliIo> {
  const project = displayText(projectId);
  if (issue.kind === "missing") {
    return logWarning(
      `${project}: environment ${displayText(issue.environmentId)}: ${describeMissingOwnEpochs(projectId, issue.environmentId, issue.epochs)}`,
    );
  }
  return logNote(
    `${project}: could not check that the keys of environment ${displayText(issue.environmentId)} reached this device (${issue.message}); \`${gapFillCommandOf(projectId, issue.environmentId)}\` on this machine reports any missing epochs`,
  );
}

type RequestState =
  | { readonly kind: "pending"; readonly expiresAtMs: number }
  | { readonly kind: "already-registered" };

function createOrResumeRequest(
  input: { readonly client: MaruhiClient; readonly label: string },
  keys: MasterKeys,
): Effect.Effect<RequestState, CliError> {
  return input.client.devices
    .requestCreate({
      payload: {
        encPubHex: keys.record.encPubHex,
        sigPubHex: keys.record.sigPubHex,
        label: input.label,
      },
    })
    .pipe(
      Effect.map((response): RequestState => ({
        kind: "pending",
        expiresAtMs: response.expiresAtMs,
      })),
      Effect.catchTags(
        {
          DeviceRegistryConflict: (conflict) =>
            Effect.gen(function* () {
              if (conflict.reason === "device-registered") {
                return { kind: "already-registered" } satisfies RequestState;
              }
              const request = yield* input.client.devices
                .requestGet({ params: { fp: keys.fingerprintHex } })
                .pipe(Effect.mapError(toCliError));
              return { kind: "pending", expiresAtMs: request.expiresAtMs } satisfies RequestState;
            }),
          DeviceRegistryLimit: (limit) =>
            Effect.fail(
              cliError(
                limit.reason === "add-requests"
                  ? `Too many device-add requests in the last hour (limit ${limit.limit}). Wait${limit.retryAfterSeconds === undefined ? "" : ` about ${Math.ceil(limit.retryAfterSeconds / 60)} minutes`} and re-run`
                  : `Your device registry is full (${limit.limit} rows). On a registered device, remove old rows with \`maruhi device list\` / \`maruhi device revoke\`, then re-run`,
              ),
            ),
        },
        (error) => Effect.fail(toCliError(error)),
      ),
    );
}

const waitForRegistryRow = Effect.fn("device-add.waitForRegistryRow")(function* (input: {
  readonly client: MaruhiClient;
  readonly fingerprintHex: string;
  readonly expiresAtMs: number;
  readonly hintAfterMs: number | null;
}): Effect.fn.Return<boolean, never, CliIo> {
  let hinted = false;
  const result = yield* Effect.repeat(
    Effect.gen(function* () {
      const rows = yield* fetchRegistry(input.client);
      if (rows?.some((row) => row.keyFingerprintHex === input.fingerprintHex) === true) {
        return "found" as const;
      }
      const nowMs = yield* Clock.currentTimeMillis;
      if (nowMs >= input.expiresAtMs) {
        return "expired" as const;
      }
      const requestedAtMs = input.expiresAtMs - DEVICE_ADD_REQUEST_TTL_MS;
      const elapsedMs = nowMs - requestedAtMs;
      if (!hinted && input.hintAfterMs !== null && elapsedMs >= input.hintAfterMs) {
        hinted = true;
        yield* logNote(
          `still waiting (${Math.round(elapsedMs / 60_000)} minutes since the request): this key is not in your device registry yet. If \`maruhi device approve\` already ran on the approving device and failed on every project, or could not list this device in your device registry, the cause is in its output and this request stays valid until ${formatUtcMinutes(input.expiresAtMs)} — fix it there and re-run it. Otherwise nothing is needed here`,
        );
      }
      return "waiting" as const;
    }),
    {
      schedule: Schedule.spaced(Duration.millis(DEVICE_ADD_POLL_INTERVAL_MS)),
      until: (round) => round !== "waiting",
    },
  );
  return result === "found";
});
