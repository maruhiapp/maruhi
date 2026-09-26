// The `maruhi device` group (CRYPTO_SPEC §3 / §6.2 "device keys",
// AUTH_SPEC §13-11 — 2026-09-19 DK. Design record dk-design.md §9 K4-5 /
// K4-6 / K4-7 / K4-13 / K4-18).
//
// - `device add [--label] [--replace]` (the new device): generates a device
//   key, issues a request, saves, then prints the FP (hex + 12 words) and
//   waits (`--replace` is also "generate → request → guarded replacement" —
//   DK K13-8). The wait signal is the registry (advisory); the completion
//   check is each project's verified chain (K4-5). In the same view it
//   verifies and reports the keys' arrival on the registered projects
//   (whether a DEK addressed to this device exists on every epoch — DK K12)
//   and revoked keys. If the key already exists, a live request resumes the
//   wait, and without one it branches on the chain standing
//   (`device-standing.ts`) without creating a request (DK K13-2 — the
//   revision of K4-21 (c)). No gate (DK-D — the requesting side adds
//   nothing)
// - `device approve <fp|words> [--cap] [--env…]` (an already-registered
//   device): the ceremony gate (TTY + non-agent — agent-gate.ts) → FP is
//   **recomputed** from the public key of a request-list row and matched
//   (K4-6) → each project is opened and judged (if the cap of an
//   already-registered key differs from this run's cap, stop without
//   writing anything — K10-1) → `add_device` to each project → backfill →
//   local record (approved) → PUT to the registry (the signal) → cancel
//   the request (only when the PUT succeeded — on failure the request is
//   left: K9-1)
// - `device list [--project]`: cross-checks the chain (the truth), the
//   registry (server-reported), and the local records (provenance) to
//   display. No values, no keys needed, no gate
// - `device revoke <ref…> [--user] [--project] [--yes] [--revoke-token]`:
//   the reference is an FP prefix (8+ chars, unique) or the registry's
//   display name (only your own — confirm with the FP shown alongside).
//   Confirmation table → yes → `revoke_device` to each project → sweep
//   kind 5 (K4-8) → local record revoked → delete the registry row →
//   propose token revocation (K4-13 — automatic only with an explicit
//   `--revoke-token`)
//
// The registry is only ever used for display and the signal: a key is
// approved only when the FP recomputed from the request row's public key
// matches the FP the human carried; a device is revoked only when it is on
// the chain; the local records are written only by the 3 paths — sealing,
// approval, observation (K4-3).

import {
  DEVICE_ADD_REQUEST_TTL_MS,
  DeviceRegistryConflictError,
  DeviceRegistryLimitError,
  ForbiddenError,
  MAX_DEVICE_REGISTRY_ROWS_PER_USER,
  TokenNotFoundError,
} from "@maruhi/api-schema";
import type { ChainDevice, ChainMember, DeviceCap, MemberScope, Role } from "@maruhi/crypto";
import {
  computeUserKeyFingerprint,
  decodeHex,
  effectivePermissionOf,
  encodeHex,
  scopeIncludesEnvironment,
} from "@maruhi/crypto";
import { Duration, Effect, Result } from "effect";

import { ensureDeviceApproveAllowed } from "./agent-gate.ts";
import type { MaruhiClient } from "./api.ts";
import {
  type CliServices,
  openMetadataProject,
  openProject,
  type ProjectContext,
  type ProjectContextBase,
} from "./context.ts";
import { ROLE_RANK } from "./dek-wrap.ts";
import { type DekRecipient, environmentKeysFor, missingEpochsOf } from "./deks.ts";
import { describeGapFillRoute, describeMissingOwnEpochs, gapFillCommandOf } from "./device-gaps.ts";
import {
  capWithinSignerCap,
  describeCap,
  describeDevice,
  deviceProvenanceOf,
  devicesOf,
  findOwnDevice,
  reAddDeviceRoute,
} from "./device-key.ts";
import {
  appendAddDevice,
  appendRevokeDevice,
  backfillToDevice,
  DEVICE_REVOKED_ROTATION_REASON,
  type DeviceBackfillOutcome,
  deviceEnvironmentsOf,
  type DeviceSweepOutcome,
  sweepAfterDeviceRevoke,
} from "./device-ops.ts";
import {
  groupStandings,
  keyStandingIn,
  type KeyStandings,
  keyStandingsOf,
  type StandingGroups,
} from "./device-standing.ts";
import { countNoun, describeListed, displayText, formatUtcMinutes } from "./display.ts";
import { cliError, type CliError, usageError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { FloorStore } from "./floor.ts";
import { fingerprintWords, formatWordList } from "./fp-words.ts";
import { CliIo } from "./io.ts";
import { generateKeyRecord } from "./key-record.ts";
import { Keychain, masterKeyEntryName, serializeStoredMasterKey } from "./keychain.ts";
import { logNote, logWarning } from "./notice.ts";
import { type OwnDeviceEntry, OwnDeviceStore } from "./own-devices.ts";
import { fetchProjectMemberships } from "./project-list.ts";
import { compareCodePoints, requireScopeEnvironmentsExist, sameScope } from "./scope.ts";
import {
  type CliSession,
  importMasterKeys,
  loadMasterKeys,
  type MasterKeys,
  storeMasterKeyAndReport,
} from "./session.ts";
import { sweepRotateFor } from "./sweep-rotate.ts";
import { resyncExtended, type VerifiedProject } from "./sync.ts";

/** One registry row (server-reported). */
interface RegistryRow {
  readonly keyFingerprintHex: string;
  readonly encPubHex: string;
  readonly sigPubHex: string;
  readonly label: string;
  readonly tokenId?: string | undefined;
  readonly createdAtMs: number;
}

const FULL_FINGERPRINT = /^[0-9a-f]{32}$/;
const FINGERPRINT_PREFIX = /^[0-9a-f]{8,32}$/;
const WORD_COUNT = 12;

/** Recomputes the FP from the public key (the claimed FP of a registry or request row is never trusted — §13-11). */
function recomputeFingerprint(
  encPubHex: string,
  sigPubHex: string,
): Effect.Effect<string | null, CliError> {
  const enc = decodeHex(encPubHex);
  const sig = decodeHex(sigPubHex);
  if (enc === null || sig === null) {
    return Effect.succeed(null);
  }
  return Effect.tryPromise({
    try: () => computeUserKeyFingerprint(enc, sig),
    catch: () => cliError("Failed to compute a key fingerprint (crypto error)"),
  }).pipe(Effect.map((result) => (result.ok ? encodeHex(result.value) : null)));
}

/** Fetches the registry (null when unreadable — used only for display and the signal, so never fails). */
function fetchRegistry(client: MaruhiClient): Effect.Effect<readonly RegistryRow[] | null, never> {
  return client.devices.list({}).pipe(
    Effect.map((response) => response.devices as readonly RegistryRow[]),
    Effect.catch(() => Effect.succeed(null)),
  );
}

/** Resolves the project set: `--project` only when given, otherwise the membership list (claimed = for discovery). */
function resolveProjectIds(
  client: MaruhiClient,
  project: string | undefined,
): Effect.Effect<readonly string[], CliError> {
  return project === undefined
    ? fetchProjectMemberships(client).pipe(
        Effect.map((rows) => rows.map((row) => row.projectId).toSorted(compareCodePoints)),
      )
    : Effect.succeed([project]);
}

// ---------------------------------------------------------------------------
// device add
// ---------------------------------------------------------------------------

/** The wait interval (registry polling — K4-5. Tests shorten it). */
const DEVICE_ADD_POLL_INTERVAL_MS = 3_000;

/**
 * The threshold of the guidance shown once mid-wait (K7-3): if this time
 * has passed since the request's creation with no signal, "check the
 * approving device's output" is printed. When approval fails on every
 * project the signal never comes (K4-31), so we never wait silently for
 * 15 minutes. Elapsed is derived backwards from the request's expiry (even
 * a resumed wait judges by the request's age). Since docs (`devices.mdx`)
 * transcribe it as "five minutes", the value is pinned by
 * `cli-vocabulary.test.ts`.
 */
export const DEVICE_ADD_WAIT_HINT_AFTER_MS = DEVICE_ADD_REQUEST_TTL_MS / 3;

/** `maruhi device add [--label <name>] [--replace]` (the new device). */
export function deviceAddOp(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly label: string;
  readonly replace: boolean;
  readonly pollIntervalMs?: number | undefined;
}): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const keychain = yield* Keychain;
    const entryName = masterKeyEntryName(input.session.origin, input.session.userId);
    const existing = yield* keychain.get(entryName);
    if (existing !== null && !input.replace) {
      // An existing key (DK K13-2 — K4-21 (c)'s revision K13-9): a live
      // request resumes the wait; without one the branch follows the chain
      // standing. Neither path goes to create a request (the server
      // consumes the 1-hour/5-attempt window before the collision check.
      // The resume expiry lives in the lookup response)
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
      // The new key's FP already has a registry row (only possible via an
      // FP collision). There is no request we were waiting for, so we don't
      // say "Approved" — report by chain standing (DK K13-3 — hole 5's
      // defense)
      return yield* settleExistingKey(input, started.keys);
    }
    return yield* awaitApproval(input, started.keys, started.request.expiresAtMs);
  });
}

/** This key's live request (null if none. A lookup failure other than 404 is reported — K4-33). */
function pendingRequestOf(
  client: MaruhiClient,
  fingerprintHex: string,
): Effect.Effect<{ readonly expiresAtMs: number } | null, CliError> {
  return client.devices.requestGet({ params: { fp: fingerprintHex } }).pipe(
    Effect.map((request) => ({ expiresAtMs: request.expiresAtMs })),
    Effect.catchTag("DeviceNotFound", () => Effect.succeed(null)),
    Effect.mapError(toCliError),
  );
}

/** The pre-wait display (the FP is shown only for a saved key — never let an unsaved key be approved: K13-8). */
function announceFingerprint(keys: MasterKeys): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const words = yield* fingerprintWords(keys.fingerprintHex, "The key fingerprint is malformed");
    yield* io.log(`This device's key fingerprint: ${keys.fingerprintHex}`);
    yield* io.log(`fp words: ${formatWordList(words)}`);
  });
}

/** Waits for the request's signal (a registry row), then confirms on the chain (K4-5). */
function awaitApproval(
  input: {
    readonly session: CliSession;
    readonly client: MaruhiClient;
    readonly pollIntervalMs?: number | undefined;
  },
  keys: MasterKeys,
  expiresAtMs: number,
): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
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
      intervalMs: input.pollIntervalMs ?? DEVICE_ADD_POLL_INTERVAL_MS,
      hintAfterMs: DEVICE_ADD_WAIT_HINT_AFTER_MS,
    });
    const standings = yield* keyStandingsOf({
      session: input.session,
      client: input.client,
      fingerprintHex: keys.fingerprintHex,
    });
    if (!signalled) {
      // Expiry: the 2 branches conditioned on the approver's output
      // (K7-1 / K9-3) stay — an approval started just before the deadline
      // may not have been appended yet (a race). On top of that, the
      // chain's facts at this moment are added with a timestamp
      // (DK K13-4 — the partial reclaim of K9-3 3-c)
      return yield* Effect.fail(
        cliError(
          `The device-add request expired before this machine saw the completion signal (requests live 15 minutes). Check the output on the approving device: if it registered nothing, run \`maruhi device add --replace\` on this machine — this key (${keys.fingerprintHex}) is registered nowhere, so discarding it loses nothing — and approve the new fingerprint it prints from a registered device with \`maruhi device approve\`. If it registered this device but could not list it in your device registry, keep this key: it is already registered on the projects that output lists (\`maruhi device list\` on this machine shows where), and only its row in your device registry is missing. ${describeChainsNow(standings)}`,
        ),
      );
    }
    if (standings.listFailure !== null) {
      // If the list can't be fetched nothing can be counted ("0 projects" is not a fact — K13-3)
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
    // The completion sentence is emitted once the standing is known; the
    // key-arrival checks (per-environment fetches) come after (K12-14. The
    // output order stays K12-3's)
    yield* reportStandings(groups, keys, { approved: true });
  });
}

/** The chain facts at this moment appended to the expiry sentence (DK K13-4 — the conditions stay). */
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

/**
 * The count sentence's range (Bugbot's catch — K13-16): when a project
 * could not be synced the count is a lower bound over what was checked, so
 * its count accompanies it ("0" is not a fact when none synced).
 */
function describeUnchecked(groups: StandingGroups): string {
  return groups.unsynced.length === 0
    ? ""
    : `, and ${countNoun(groups.unsynced.length, "project")} could not be checked`;
}

/** The listing of project ids (for wording). */
function projectList(projectIds: readonly string[]): string {
  return projectIds.map(displayText).join(", ");
}

/**
 * The branch when an existing key has no live request (DK K13-2 — the
 * design record §18 table). exit 0 only for "a valid key added via
 * `add_device` on some project" (since pre-DK keys can also become
 * `add_device` via a registration from an observation record, a first key
 * defers to a human — hole 1). With zero valid, stop in the order: could
 * not sync → revoked somewhere → on nothing, stating the assertion's
 * range.
 */
function settleExistingKey(
  input: { readonly session: CliSession; readonly client: MaruhiClient },
  keys: MasterKeys,
): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const standings = yield* keyStandingsOf({ ...input, fingerprintHex: keys.fingerprintHex });
    const groups = groupStandings(standings);
    if (groups.active.length > 0) {
      return yield* reportActiveKey(input.client, keys, groups);
    }
    return yield* Effect.fail(cliError(yield* refusalWithoutActiveKey(keys, standings, groups)));
  });
}

/** An existing key with a valid project: a first key stops with 2 choices; otherwise report and exit 0. */
function reportActiveKey(
  client: MaruhiClient,
  keys: MasterKeys,
  groups: StandingGroups,
): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const fingerprintHex = keys.fingerprintHex;
    const first = groups.active.filter((project) => project.standing.firstKey);
    if (first.length > 0) {
      return yield* Effect.fail(
        cliError(
          `This machine's device key (${fingerprintHex}) is your first key on ${projectList(first.map((project) => project.projectId))} (the key you created or joined that project with), and it has no pending device-add request. maruhi cannot tell whether this machine is the device that key belongs to or holds a copy of it from an install before device keys. If this machine is that device, nothing is needed: it is already registered. If it holds a copy, re-run with --replace: it generates a new key for this machine and prints its fingerprint to approve from a registered device (the machine the copy came from keeps its key). Do not pass --replace if this is your only device`,
        ),
      );
    }
    yield* io.log(`This device's key fingerprint: ${fingerprintHex}`);
    yield* io.log(
      `This key is registered on ${countNoun(groups.active.length, "project")} (verified on each project's chain)${describeUnchecked(groups)}`,
    );
    const registry = yield* fetchRegistry(client);
    if (registry !== null && !registry.some((row) => row.keyFingerprintHex === fingerprintHex)) {
      // T3 (the approver's registry PUT failed — K9-3): a display note only (the registry never drives branching)
      yield* logNote(
        "this key has no row in your device registry (an approval whose registry write failed leaves it so). The registry only labels devices, so nothing else is needed; `maruhi device list` shows this key without a label",
      );
    }
    yield* reportStandings(groups, keys, { approved: false });
  });
}

/**
 * How an existing key with zero valid stops (in the order: could not sync
 * → revoked somewhere → on nothing). Every sentence states the assertion's
 * range (no assertion when it could not sync — K13-2).
 */
function refusalWithoutActiveKey(
  keys: MasterKeys,
  standings: KeyStandings,
  groups: StandingGroups,
): Effect.Effect<string, never, CliServices> {
  return Effect.gen(function* () {
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
}

/**
 * Option B (DK K13-7 — informational only): projects in this device's
 * floor but absent from the list. The floor is not separated by server or
 * account, so it is not used for judgment — it only supplements the
 * "on nothing" assertion's range. Unreadable = nothing added.
 */
function unlistedFloorProjects(standings: KeyStandings): Effect.Effect<string, never, CliServices> {
  return Effect.gen(function* () {
    const floor = yield* FloorStore;
    const ids = yield* floor
      .listProjectIds()
      .pipe(Effect.catch(() => Effect.succeed<readonly string[]>([])));
    const listed = new Set(standings.projects.map((project) => project.projectId));
    const unlisted = ids.filter((id) => !listed.has(id));
    if (unlisted.length === 0) {
      return "";
    }
    return `. This machine also has local records of ${countNoun(unlisted.length, "project")} that list does not include (${unlisted.map(displayText).join(", ")}); those records are not separated by server or account, so they may not be yours here — if one is, check it with \`maruhi project verify --project <id>\` before replacing`;
  });
}

/** A chain that failed verification (a sign of tampering — not folded into the same Note as a network failure). */
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

/**
 * The standing report (after the completion sentence / the "registered on
 * N" sentence — in the order: key arrival → revoked → could not sync →
 * unregistered. K12-3). `approved` = whether it follows the awaited
 * request's signal (the approver-side narrative is only true then —
 * K13-3).
 */
function reportStandings(
  groups: StandingGroups,
  keys: MasterKeys,
  options: { readonly approved: boolean },
): Effect.Effect<void, never, CliIo> {
  return Effect.gen(function* () {
    for (const project of groups.active) {
      const issues = yield* checkKeyReach({ ...project.standing, keys });
      for (const issue of issues) {
        yield* reportKeyReachIssue(project.projectId, issue);
      }
    }
    if (groups.revoked.length > 0) {
      // State the revocation fact on this chain and the re-add procedure (not the approver-side narrative — K12-6)
      yield* logNote(
        `this key was revoked on ${groups.revoked.map(displayText).join(", ")}, so it is not registered there again. To put this machine back there, ${reAddDeviceRoute("this machine")}${groups.active.length > 0 ? `. This keychain then no longer holds this key, so revoke it on ${groups.active.map((project) => displayText(project.projectId)).join(", ")}, where it is still registered (\`maruhi device revoke ${keys.fingerprintHex}\` from a registered device)` : ""}`,
      );
    }
    yield* warnEvidence(groups.unsynced);
    const unsyncedNotes = groups.unsynced.filter((project) => !project.evidence);
    for (const project of unsyncedNotes) {
      // Never say "none" about a project that could not be synced (K13-3)
      yield* logNote(
        `${displayText(project.projectId)}: could not sync this project (${project.message}), so whether this key is registered there is unknown; \`maruhi device list\` checks again`,
      );
    }
    if (groups.absent.length === 0) {
      return;
    }
    const absent = groups.absent.map(displayText).join(", ");
    if (options.approved) {
      // The signal (a registry row) is PUT after the approver's project
      // loop, so by the time we get here the approver's work is done and
      // the request is cancelled (K4-31). Registering the deficit is done
      // by a keyed command that "a device whose cap covers it" issues
      // **targeting that project** (`device-sync.ts` — the prologue is one
      // project per command: DK K10-5. A cap-caused skip cannot be fixed
      // by the approver re-syncing: K6-V supplement 2 / K7-2). Approval
      // folds a failure into `failed`, so a partial-success signal may
      // still carry failed projects (K7-15). Revoked / could-not-sync
      // never enter here (K12-6 / K13-3)
      yield* logNote(
        `not registered yet on ${absent} — the approving device skipped or failed on them (its output says which, and why: its cap does not cover them, you are not a member there, or the append failed there), or you approved with --project. The request is used up. A device of yours whose cap covers them registers this key on each of them when it runs a keyed command on that project at a terminal (\`maruhi pull --project <id>\`, for instance) — the approving device itself if its cap was not the cause, another device otherwise, once it has synced a project that did register this key. \`maruhi device list\` shows where this key is registered`,
      );
      return;
    }
    // No approval happened (the existing-key path), so the approver-side narrative is not stated
    yield* logNote(
      `this key is not registered on ${absent}. A device of yours whose cap covers them registers it on each of them when it runs a keyed command on that project at a terminal (\`maruhi pull --project <id>\`, for instance), once it has synced a project that has this key. \`maruhi device list\` shows where this key is registered`,
    );
  });
}

/**
 * Starts a request with a new key (when there is no key, or `--replace`).
 * The order is "generate → create the request → save / replace guarded on
 * success" (DK K13-8): if request creation fails (limit, full, network),
 * the keychain changes nothing (the old key stays, and no key stays no
 * key). With `--replace`, the discarded key's standing is displayed before
 * the replacement (no stop — the explicit consent: K4-18).
 */
function startWithNewKey(
  input: {
    readonly session: CliSession;
    readonly client: MaruhiClient;
    readonly label: string;
  },
  entryName: string,
  previous: string | null,
): Effect.Effect<
  { readonly keys: MasterKeys; readonly request: RequestState },
  CliError,
  CliServices
> {
  return Effect.gen(function* () {
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
}

/** The standing of the key discarded by `--replace` (display only — DK K13-8). */
function describeReplacedKey(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
}): Effect.Effect<void, never, CliServices> {
  return Effect.gen(function* () {
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
    const added = groups.active.filter((project) => !project.standing.firstKey);
    const first = groups.active.filter((project) => project.standing.firstKey);
    const parts = [
      added.length > 0
        ? `registered on ${projectList(added.map((project) => project.projectId))}`
        : null,
      first.length > 0
        ? `registered on ${projectList(first.map((project) => project.projectId))} as your first key there`
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
}

/** The facts reported by one environment's key-arrival check (DK K12-3 — if it arrived, nothing is carried). */
type KeyReachIssue =
  | {
      readonly kind: "missing";
      readonly environmentId: string;
      readonly epochs: readonly number[];
    }
  | {
      readonly kind: "unchecked";
      /** null = enumerating the environments itself failed. */
      readonly environmentId: string | null;
      readonly message: string;
    };

/**
 * Whether a DEK addressed to this device reached every epoch of each
 * environment the approver should have distributed (`deviceEnvironmentsOf`
 * — the same set as the backfill) (DK K12-2): the same fetch path as the
 * value-carrying pull (`environmentKeysFor` — the §5.1 / §5.2 verification
 * and unsealing) and the same absence judgment (`missingEpochsOf`). The
 * opened DEKs are used only for the judgment and never leave here. A
 * failure is folded into a fact (never changes `device add`'s outcome —
 * K12-4).
 */
function checkKeyReach(input: {
  readonly context: ProjectContextBase;
  readonly member: ChainMember;
  readonly device: ChainDevice;
  readonly keys: MasterKeys;
}): Effect.Effect<readonly KeyReachIssue[]> {
  return Effect.gen(function* () {
    const { client, verified } = input.context;
    const environments = yield* Effect.result(
      deviceEnvironmentsOf({
        client,
        verified,
        targetMember: input.member,
        targetDevice: input.device,
      }),
    );
    if (Result.isFailure(environments)) {
      return [{ kind: "unchecked", environmentId: null, message: environments.failure.message }];
    }
    const recipient: DekRecipient = {
      userId: input.context.session.userId,
      encPubHex: input.keys.record.encPubHex,
      encKeyPair: input.keys.encKeyPair,
    };
    const issues: KeyReachIssue[] = [];
    for (const environmentId of environments.success) {
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
}

/** One entry of the key-arrival check (an absence uses the pull's warning wording — K12-3. A check failure is a Note). */
function reportKeyReachIssue(
  projectId: string,
  issue: KeyReachIssue,
): Effect.Effect<void, never, CliIo> {
  const project = displayText(projectId);
  if (issue.kind === "missing") {
    return logWarning(
      `${project}: environment ${displayText(issue.environmentId)}: ${describeMissingOwnEpochs(projectId, issue.environmentId, issue.epochs)}`,
    );
  }
  return logNote(
    issue.environmentId === null
      ? `${project}: could not list its environments to check that their keys reached this device (${issue.message}); \`maruhi pull --project ${project} --env <environment>\` on this machine reports any missing epochs`
      : `${project}: could not check that the keys of environment ${displayText(issue.environmentId)} reached this device (${issue.message}); \`${gapFillCommandOf(projectId, issue.environmentId)}\` on this machine reports any missing epochs`,
  );
}

/** The result of creating the request: a pending request (with expiry) or a key already on the registry. */
type RequestState =
  | { readonly kind: "pending"; readonly expiresAtMs: number }
  | { readonly kind: "already-registered" };

/** Creating the request (a 409 is a resumption — request-exists / device-registered). */
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
      Effect.catch((error) =>
        Effect.gen(function* () {
          if (error instanceof DeviceRegistryConflictError) {
            const conflict: DeviceRegistryConflictError = error;
            if (conflict.reason === "device-registered") {
              // The registry already carrying my row = the signal is up (there is no request row)
              return { kind: "already-registered" } satisfies RequestState;
            }
            // The same key's request being live = resuming the wait
            // (K4-5 round 2). A lookup failure is reported, never
            // swallowed (never falsely guide "it was revoked" — a 409 is
            // proof of life)
            const request = yield* input.client.devices
              .requestGet({ params: { fp: keys.fingerprintHex } })
              .pipe(Effect.mapError(toCliError));
            return { kind: "pending", expiresAtMs: request.expiresAtMs } satisfies RequestState;
          }
          if (error instanceof DeviceRegistryLimitError) {
            const limit: DeviceRegistryLimitError = error;
            return yield* Effect.fail(
              cliError(
                limit.reason === "add-requests"
                  ? `Too many device-add requests in the last hour (limit ${limit.limit}). Wait${limit.retryAfterSeconds === undefined ? "" : ` about ${Math.ceil(limit.retryAfterSeconds / 60)} minutes`} and re-run`
                  : `Your device registry is full (${limit.limit} rows). On a registered device, remove old rows with \`maruhi device list\` / \`maruhi device revoke\`, then re-run`,
              ),
            );
          }
          return yield* Effect.fail(toCliError(error));
        }),
      ),
    );
}

/**
 * Waits until my FP's row appears in the registry (up to the TTL). true =
 * it appeared. When `hintAfterMs` is set, on the first round where that
 * time passed since the request's creation (= expiry − TTL), "check the
 * approving device's output" is printed once (K7-3 — state only the fact
 * that there is no signal; the cause is left to the approver's screen).
 */
function waitForRegistryRow(input: {
  readonly client: MaruhiClient;
  readonly fingerprintHex: string;
  readonly expiresAtMs: number;
  readonly intervalMs: number;
  readonly hintAfterMs: number | null;
}): Effect.Effect<boolean, never, CliIo> {
  return Effect.gen(function* () {
    let hinted = false;
    for (;;) {
      const rows = yield* fetchRegistry(input.client);
      if (rows?.some((row) => row.keyFingerprintHex === input.fingerprintHex) === true) {
        return true;
      }
      if (Date.now() >= input.expiresAtMs) {
        return false;
      }
      const requestedAtMs = input.expiresAtMs - DEVICE_ADD_REQUEST_TTL_MS;
      if (
        !hinted &&
        input.hintAfterMs !== null &&
        Date.now() - requestedAtMs >= input.hintAfterMs
      ) {
        hinted = true;
        yield* logNote(
          `still waiting (${Math.round((Date.now() - requestedAtMs) / 60_000)} minutes since the request): this key is not in your device registry yet. If \`maruhi device approve\` already ran on the approving device and failed on every project, or could not list this device in your device registry, the cause is in its output and this request stays valid until ${formatUtcMinutes(input.expiresAtMs)} — fix it there and re-run it. Otherwise nothing is needed here`,
        );
      }
      yield* Effect.sleep(Duration.millis(input.intervalMs));
    }
  });
}

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
      recordedAtMs: Date.now(),
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

/** Reporting the approval result (called by effect-cli). */
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

// ---------------------------------------------------------------------------
// device list
// ---------------------------------------------------------------------------

/** The display rows' material: FP → on-chain appearances (one row per project) and the synced chains. */
interface ListRows {
  readonly rows: Map<string, { readonly projectId: string; readonly line: string }[]>;
  readonly chains: readonly { readonly projectId: string; readonly verified: VerifiedProject }[];
}

/** Collects my device from each project's chain (a project that cannot sync is a Note). */
function collectChainRows(input: {
  readonly session: CliSession;
  readonly projectIds: readonly string[];
}): Effect.Effect<ListRows, never, CliServices> {
  return Effect.gen(function* () {
    const rows: ListRows["rows"] = new Map();
    const chains: ListRows["chains"][number][] = [];
    for (const projectId of input.projectIds) {
      const context = yield* openMetadataProject({
        server: input.session.origin,
        project: projectId,
      }).pipe(Effect.catch(() => Effect.succeed<ProjectContextBase | null>(null)));
      if (context === null) {
        yield* logNote(
          `${displayText(projectId)}: could not sync this project; its devices are not shown`,
        );
        continue;
      }
      chains.push({ projectId, verified: context.verified });
      const self = context.verified.state.members.get(input.session.userId);
      for (const device of self === undefined ? [] : devicesOf(self)) {
        const provenance = deviceProvenanceOf(context.verified, input.session.userId, device);
        const adder =
          provenance.addedByFingerprintHex === null
            ? "first key"
            : `added by ${provenance.addedByFingerprintHex}${provenance.adderStillActive ? "" : " (that device is now revoked)"}`;
        const lines = rows.get(device.keyFingerprintHex) ?? [];
        lines.push({
          projectId,
          line: `${displayText(projectId)}: cap=${describeCap(device)} seq=${device.addedSeq} ${adder}`,
        });
        rows.set(device.keyFingerprintHex, lines);
      }
    }
    return { rows, chains };
  });
}

/**
 * One device's on-chain appearance: the valid rows (cap, provenance) and
 * the revoked-project rows (the standing judgment is `keyStandingIn` — the
 * same predicate as `device add`: DK K13-6).
 */
function chainLinesOf(input: {
  readonly listed: ListRows;
  readonly userId: string;
  readonly fingerprintHex: string;
}): readonly string[] {
  const active = (input.listed.rows.get(input.fingerprintHex) ?? []).map((row) => row.line);
  const revoked = input.listed.chains
    .filter(
      (chain) =>
        keyStandingIn(chain.verified, input.userId, input.fingerprintHex).kind === "revoked",
    )
    .map(
      (chain) =>
        `${displayText(chain.projectId)}: revoked (a revoked key is never registered again)`,
    );
  return [...active, ...revoked];
}

/** One device's heading (the registry's display name and token id are server-reported; the local record is provenance). */
function describeListRow(input: {
  readonly fingerprintHex: string;
  readonly ownFingerprintHex: string | null;
  readonly registryRow: RegistryRow | undefined;
  readonly record: OwnDeviceEntry | undefined;
}): string {
  const tags: string[] = [];
  if (input.ownFingerprintHex === input.fingerprintHex) {
    tags.push("this machine");
  }
  if (input.registryRow !== undefined) {
    tags.push(`label "${displayText(input.registryRow.label)}" (server-reported)`);
    if (input.registryRow.tokenId !== undefined) {
      tags.push(`token ${displayText(input.registryRow.tokenId)} (server-reported)`);
    }
  }
  if (input.record !== undefined) {
    tags.push(
      input.record.revokedAtMs === null
        ? `recorded here as ${input.record.source}`
        : "recorded here as revoked",
    );
  }
  return `${input.fingerprintHex}${tags.length === 0 ? "" : `\t${tags.join(", ")}`}`;
}

/** `maruhi device list [--project]` (no values, no keys needed, no gate). */
export function deviceListOp(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly project: string | undefined;
}): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const store = yield* OwnDeviceStore;
    const registry = yield* fetchRegistry(input.client);
    const lookup = yield* store.load(input.session.origin, input.session.userId);
    const local = lookup.state === "loaded" ? lookup.devices : [];
    // Even when the project list cannot be fetched, the registry and local records can still be shown, so it isn't dropped (DK K13-6)
    const projectIds = yield* resolveProjectIds(input.client, input.project).pipe(
      Effect.catch((error) =>
        logNote(
          `your projects could not be listed (${error.message}), so no project chain is shown`,
        ).pipe(Effect.as<readonly string[]>([])),
      ),
    );
    const localKeys = yield* Effect.catch(loadMasterKeys(input.session), () =>
      Effect.succeed<MasterKeys | null>(null),
    );
    // FP → display rows (the chain is the truth. The registry and local records sit alongside as annotations)
    const listed = yield* collectChainRows({ session: input.session, projectIds });
    const active = local.filter((entry) => entry.revokedAtMs === null);
    // This device's key is printed even when absent from every chain,
    // the registry, and every valid record (the place a revoked device's
    // error defers to with "check with `maruhi device list`" — DK K13-6)
    const fingerprints = [
      ...new Set([
        ...listed.rows.keys(),
        ...(registry ?? []).map((row) => row.keyFingerprintHex),
        ...active.map((entry) => entry.keyFingerprintHex),
        ...(localKeys === null ? [] : [localKeys.fingerprintHex]),
      ]),
    ].toSorted(compareCodePoints);
    if (fingerprints.length === 0) {
      yield* io.log(
        "No devices found (no project chain lists a device of yours, and the registry is empty)",
      );
      return;
    }
    if (registry === null) {
      yield* logNote(
        "the device registry could not be read (labels are server-reported and advisory anyway)",
      );
    }
    for (const fingerprintHex of fingerprints) {
      yield* io.log(
        describeListRow({
          fingerprintHex,
          ownFingerprintHex: localKeys?.fingerprintHex ?? null,
          registryRow: registry?.find((row) => row.keyFingerprintHex === fingerprintHex),
          record: local.find((entry) => entry.keyFingerprintHex === fingerprintHex),
        }),
      );
      yield* printChainLines({
        lines: chainLinesOf({ listed, userId: input.session.userId, fingerprintHex }),
        project: input.project,
        unsynced: projectIds.length - listed.chains.length,
      });
    }
  });
}

/**
 * One device's on-chain appearances (when none, say the shown range to
 * that effect — DK K13-6). Never says "none" about a project that could
 * not be synced (Bugbot's catch — K13-16).
 */
function printChainLines(input: {
  readonly lines: readonly string[];
  readonly project: string | undefined;
  /** The count of projects that could not be synced (the ones `collectChainRows` noted). */
  readonly unsynced: number;
}): Effect.Effect<void, never, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    if (input.lines.length === 0) {
      yield* io.log(describeNoChainLines(input.project, input.unsynced));
    }
    for (const line of input.lines) {
      yield* io.log(`  ${line}`);
    }
  });
}

function describeNoChainLines(project: string | undefined, unsynced: number): string {
  if (project !== undefined) {
    return unsynced > 0
      ? `  (project ${displayText(project)} could not be synced, so whether this key is on its chain is unknown)`
      : `  (not on the chain of project ${displayText(project)}, the only project shown)`;
  }
  return unsynced > 0
    ? `  (not on any synced project chain; ${countNoun(unsynced, "project")} could not be synced)`
    : "  (not on any synced project chain)";
}

// ---------------------------------------------------------------------------
// device revoke
// ---------------------------------------------------------------------------

/** Interpreting the references (K4-7: an FP prefix of 8+ chars, or the registry's display name — your own only). */
function resolveRevokeRefs(input: {
  readonly refs: readonly string[];
  readonly registry: readonly RegistryRow[] | null;
  readonly self: boolean;
}): Effect.Effect<readonly RevokeRef[], CliError> {
  return Effect.gen(function* () {
    const resolved: RevokeRef[] = [];
    for (const ref of input.refs) {
      const lowered = ref.trim().toLowerCase();
      if (FINGERPRINT_PREFIX.test(lowered)) {
        resolved.push({ ref, prefix: lowered, viaLabel: false });
        continue;
      }
      if (!input.self) {
        return yield* Effect.fail(
          usageError(
            `"${displayText(ref)}" is not a fingerprint prefix (at least 8 hex characters). Another member's devices are named by fingerprint only (see \`maruhi member list\`)`,
          ),
        );
      }
      const byLabel = (input.registry ?? []).filter((row) => row.label === ref.trim());
      if (byLabel.length !== 1) {
        return yield* Effect.fail(
          usageError(
            byLabel.length === 0
              ? `"${displayText(ref)}" matches neither a fingerprint prefix (at least 8 hex characters) nor a label in your device registry (\`maruhi device list\`)`
              : `label "${displayText(ref)}" names ${byLabel.length} registry rows; use the fingerprint instead`,
          ),
        );
      }
      resolved.push({ ref, prefix: byLabel[0]!.keyFingerprintHex, viaLabel: true });
    }
    return resolved;
  });
}

/** One project's revocation plan (one stage of the confirmation table). */
interface ProjectRevokePlan {
  readonly context: ProjectContext;
  readonly target: ChainMember;
  readonly revoking: readonly ChainDevice[];
  readonly remaining: readonly ChainDevice[];
  readonly warnings: readonly string[];
}

/** The revocation result on one project (reported by effect-cli). */
export interface ProjectRevokeOutcome {
  readonly projectId: string;
  readonly revoked: readonly string[];
  readonly sweep: DeviceSweepOutcome | null;
  readonly skipped: string | null;
  /** The `revoke_device` append failed (nothing was revoked). */
  readonly failed: string | null;
  /** The append was accepted, but the post-acceptance resync or sweep failed (the revocation is on the chain). */
  readonly sweepFailed: string | null;
}

/** The overall result of `device revoke`. */
export interface DeviceRevokeSummary {
  readonly projects: readonly ProjectRevokeOutcome[];
  /** Tokens proposed but not revoked (name, expiry — K4-13). */
  readonly tokenProposal: readonly string[];
}

/** The reference-resolution result (whether it came via a display name goes on the confirmation table). */
type RevokeRef = { readonly ref: string; readonly prefix: string; readonly viaLabel: boolean };

/** The confirmation table (K4-7): per-project revoked FPs (full) and remaining devices, and the derived warnings. */
function printRevokePlans(input: {
  readonly targetUserId: string;
  readonly plans: readonly ProjectRevokePlan[];
  readonly refs: readonly RevokeRef[];
}): Effect.Effect<void, never, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* io.log(`Revoking devices of ${displayText(input.targetUserId)}:`);
    for (const plan of input.plans) {
      yield* io.log(`  ${displayText(plan.context.projectId)}:`);
      for (const device of plan.revoking) {
        const via = input.refs.find((ref) => device.keyFingerprintHex.startsWith(ref.prefix));
        yield* io.log(
          `    revoke  ${device.keyFingerprintHex} (cap ${describeCap(device)})${via?.viaLabel === true ? ` — matched registry label "${displayText(via.ref)}"; check the fingerprint against \`maruhi device list\`` : ""}`,
        );
      }
      yield* io.log(`    remain  ${plan.remaining.map(describeDevice).join(", ")}`);
      for (const warning of plan.warnings) {
        yield* io.log(`    warning ${warning}`);
      }
    }
  });
}

/** The cleanup after revoking your own device: revoked in the local record, delete the registry row (advisory). */
function finishOwnRevocation(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly revoked: readonly string[];
}): Effect.Effect<void, CliError, OwnDeviceStore> {
  return Effect.gen(function* () {
    const store = yield* OwnDeviceStore;
    // revoked in the local record (prevents re-registering — K4-3 counterexample 1)
    yield* store.markRevoked(input.session.origin, input.session.userId, input.revoked, Date.now());
    for (const fp of input.revoked) {
      yield* input.client.devices.remove({ params: { fp } }).pipe(
        Effect.asVoid,
        Effect.catch(() => Effect.void),
      );
    }
  });
}

/** `maruhi device revoke <ref…> [--user] [--project] [--yes] [--revoke-token]`. */
export function deviceRevokeOp(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly refs: readonly string[];
  readonly user: string | undefined;
  readonly project: string | undefined;
  readonly yes: boolean;
  readonly revokeToken: boolean;
}): Effect.Effect<DeviceRevokeSummary, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const targetUserId = input.user ?? input.session.userId;
    const self = targetUserId === input.session.userId;
    const masterKeys = yield* loadMasterKeys(input.session);
    const { registry, refs, reserveFps } = yield* prepareRevokeRefs({
      session: input.session,
      client: input.client,
      refs: input.refs,
      self,
    });
    const projectIds = yield* resolveProjectIds(input.client, input.project);
    const { plans, outcomes } = yield* planRevokeAll({
      session: input.session,
      projectIds,
      targetUserId,
      refs,
      reserveFps,
      ownFingerprintHex: masterKeys.fingerprintHex,
    });
    if (plans.length === 0) {
      yield* io.log("Nothing to revoke: no synced project lists a matching active device");
    } else {
      yield* printRevokePlans({ targetUserId, plans, refs });
    }
    for (const outcome of outcomes) {
      yield* logNote(`${displayText(outcome.projectId)}: ${outcome.skipped ?? ""}`);
    }
    if (plans.length === 0) {
      return { projects: outcomes, tokenProposal: [] };
    }
    yield* confirmRevoke(input.yes);
    const revoked = yield* executeRevokeAll({
      session: input.session,
      plans,
      targetUserId,
      masterKeys,
      outcomes,
    });
    if (!self) {
      return { projects: outcomes, tokenProposal: [] };
    }
    if (revoked.length > 0) {
      yield* finishOwnRevocation({ session: input.session, client: input.client, revoked });
    }
    const tokenProposal = yield* proposeTokenRevocation({
      client: input.client,
      registry,
      revoked,
      revokeToken: input.revokeToken,
      interactive: !input.yes,
    });
    return { projects: outcomes, tokenProposal };
  });
}

/** The material needed to resolve a reference (for your own device the registry and reserve-key records; for others' just the FP). */
function prepareRevokeRefs(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly refs: readonly string[];
  readonly self: boolean;
}): Effect.Effect<
  {
    readonly registry: readonly RegistryRow[] | null;
    readonly refs: readonly RevokeRef[];
    readonly reserveFps: ReadonlySet<string>;
  },
  CliError,
  OwnDeviceStore
> {
  return Effect.gen(function* () {
    const registry = input.self ? yield* fetchRegistry(input.client) : null;
    const refs = yield* resolveRevokeRefs({ refs: input.refs, registry, self: input.self });
    const reserveFps = input.self
      ? yield* recordedReserveFingerprints(input.session)
      : new Set<string>();
    return { registry, refs, reserveFps };
  });
}

/** Executes the revocation on each project and accumulates the results. Return value = the union of revoked FPs. */
function executeRevokeAll(input: {
  readonly session: CliSession;
  readonly plans: readonly ProjectRevokePlan[];
  readonly targetUserId: string;
  readonly masterKeys: MasterKeys;
  readonly outcomes: ProjectRevokeOutcome[];
}): Effect.Effect<readonly string[], never, CliServices> {
  return Effect.gen(function* () {
    const revokedAll = new Set<string>();
    for (const plan of input.plans) {
      const outcome = yield* executeRevoke({
        session: input.session,
        plan,
        targetUserId: input.targetUserId,
        masterKeys: input.masterKeys,
      });
      for (const fp of outcome.revoked) {
        revokedAll.add(fp);
      }
      input.outcomes.push(outcome);
    }
    return [...revokedAll];
  });
}

/** Each project's revocation plan (a skipped project is accumulated into the result as skipped first). */
function planRevokeAll(input: {
  readonly session: CliSession;
  readonly projectIds: readonly string[];
  readonly targetUserId: string;
  readonly refs: readonly RevokeRef[];
  readonly reserveFps: ReadonlySet<string>;
  readonly ownFingerprintHex: string;
}): Effect.Effect<
  { readonly plans: ProjectRevokePlan[]; readonly outcomes: ProjectRevokeOutcome[] },
  CliError,
  CliServices
> {
  return Effect.gen(function* () {
    const plans: ProjectRevokePlan[] = [];
    const outcomes: ProjectRevokeOutcome[] = [];
    for (const projectId of input.projectIds) {
      const planned = yield* planRevoke({ ...input, projectId });
      if (typeof planned === "string") {
        outcomes.push({
          projectId,
          revoked: [],
          sweep: null,
          skipped: planned,
          failed: null,
          sweepFailed: null,
        });
      } else {
        plans.push(planned);
      }
    }
    return { plans, outcomes };
  });
}

/** The yes confirmation (skipped by `--yes` — a revocation is not a ceremony. K4-7). */
function confirmRevoke(yes: boolean): Effect.Effect<void, CliError, CliIo> {
  if (yes) {
    return Effect.void;
  }
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const answer = yield* io.promptLine({ prompt: "Type yes to revoke: " });
    if (answer.trim().toLowerCase() !== "yes") {
      return yield* Effect.fail(cliError("Cancelled: nothing was revoked"));
    }
  });
}

/** The FP set of the local records' reserve keys (the non-revoked ones) (warning material for the confirmation table — K4-7). */
function recordedReserveFingerprints(
  session: CliSession,
): Effect.Effect<ReadonlySet<string>, CliError, OwnDeviceStore> {
  return Effect.gen(function* () {
    const store = yield* OwnDeviceStore;
    const lookup = yield* store.load(session.origin, session.userId);
    return new Set(
      (lookup.state === "loaded" ? lookup.devices : [])
        .filter((entry) => entry.source === "reserve" && entry.revokedAtMs === null)
        .map((entry) => entry.keyFingerprintHex),
    );
  });
}

/** The current devices matching a reference (a non-unique prefix is a usage error). */
function matchRevokeTargets(input: {
  readonly projectId: string;
  readonly devices: readonly ChainDevice[];
  readonly refs: readonly { readonly prefix: string }[];
}): Effect.Effect<readonly ChainDevice[], CliError> {
  return Effect.gen(function* () {
    const revoking: ChainDevice[] = [];
    for (const ref of input.refs) {
      const hits = input.devices.filter((device) =>
        device.keyFingerprintHex.startsWith(ref.prefix),
      );
      if (hits.length > 1) {
        return yield* Effect.fail(
          usageError(
            `fingerprint prefix ${ref.prefix} matches ${hits.length} devices on ${displayText(input.projectId)}; use a longer prefix`,
          ),
        );
      }
      const hit = hits[0];
      if (hit !== undefined && !revoking.includes(hit)) {
        revoking.push(hit);
      }
    }
    return revoking;
  });
}

/** Warnings derived from the remaining devices' caps (K4-7 / K4-8 / §2-bis). */
function revokeWarnings(input: {
  readonly verified: VerifiedProject;
  readonly target: ChainMember;
  readonly remaining: readonly ChainDevice[];
  readonly revokingFps: ReadonlySet<string>;
  readonly self: boolean;
  readonly reserveFps: ReadonlySet<string>;
  readonly ownFingerprintHex: string;
}): readonly string[] {
  const { target, remaining } = input;
  const warnings: string[] = [];
  if (
    target.role === "owner" &&
    remaining.every((device) => ROLE_RANK[device.roleCap] < ROLE_RANK.owner)
  ) {
    warnings.push(
      "no remaining device carries an owner cap — the owner could no longer act as owner (approve proposals, change roles) from any device until a device without the cap is added",
    );
  }
  const uncovered = uncoveredEnvironments(input.verified, target, remaining);
  if (uncovered.length > 0) {
    warnings.push(
      `no remaining device's cap covers ${uncovered.map(displayText).join(", ")} — the person keeps those environments in scope but no device could open them`,
    );
  }
  if (input.self && !remaining.some((device) => input.reserveFps.has(device.keyFingerprintHex))) {
    warnings.push(
      "no remaining device is recorded as your reserve key on this machine — if the reserve key is among the revoked ones, create a new one afterwards with `maruhi key recovery --replace`",
    );
  }
  if (input.revokingFps.has(input.ownFingerprintHex)) {
    warnings.push(
      "this revokes the device you are running on: after the entry lands this machine can no longer sign here, and the rotation sweep cannot be fulfilled from it (another of your devices, or a member whose scope covers the environments, must rotate)",
    );
  }
  if (ROLE_RANK[target.role] < ROLE_RANK.member) {
    warnings.push(
      "the person is a reader, so the rotation the revocation mandates cannot be run by them — a member whose scope covers the environments converges it",
    );
  }
  return warnings;
}

/** Assembles one project's worth of confirmation-table material (string = the skip reason). */
function planRevoke(input: {
  readonly session: CliSession;
  readonly projectId: string;
  readonly targetUserId: string;
  readonly refs: readonly { readonly prefix: string }[];
  readonly reserveFps: ReadonlySet<string>;
  readonly ownFingerprintHex: string;
}): Effect.Effect<ProjectRevokePlan | string, CliError, CliServices> {
  return Effect.gen(function* () {
    const context = yield* openProject({ server: input.session.origin, project: input.projectId });
    const target = context.verified.state.members.get(input.targetUserId);
    if (target === undefined) {
      return `${displayText(input.targetUserId)} is not a member of this project`;
    }
    const self = context.verified.state.members.get(input.session.userId);
    if (
      self === undefined ||
      findOwnDevice(self, { keyFingerprintHex: input.ownFingerprintHex }) === undefined
    ) {
      return "this machine's key is not one of your registered devices here (revoke from a device that is)";
    }
    const devices = devicesOf(target);
    const revoking = yield* matchRevokeTargets({
      projectId: input.projectId,
      devices,
      refs: input.refs,
    });
    if (revoking.length === 0) {
      return "no active device matches the reference (already revoked, or never registered here)";
    }
    const revokingFps = new Set(revoking.map((device) => device.keyFingerprintHex));
    const remaining = devices.filter((device) => !revokingFps.has(device.keyFingerprintHex));
    if (remaining.length === 0) {
      return "it would revoke the last device (last-device-protected — CRYPTO_SPEC §6.2). To remove the person, use `maruhi member remove`";
    }
    const warnings = revokeWarnings({
      verified: context.verified,
      target,
      remaining,
      revokingFps,
      self: input.targetUserId === input.session.userId,
      reserveFps: input.reserveFps,
      ownFingerprintHex: input.ownFingerprintHex,
    });
    return { context, target, revoking, remaining, warnings };
  });
}

/** Within the target scope, the environments no remaining device's effective scope includes (K4-7's warning material). */
function uncoveredEnvironments(
  verified: VerifiedProject,
  target: ChainMember,
  remaining: readonly ChainDevice[],
): readonly string[] {
  const covered = remaining.map((device) => effectivePermissionOf(target, device).scope);
  return [...verified.state.environments.keys()]
    .filter(
      (environmentId) =>
        scopeIncludesEnvironment(target.scope, environmentId) &&
        !covered.some((scope: MemberScope) => scopeIncludesEnvironment(scope, environmentId)),
    )
    .toSorted(compareCodePoints);
}

/** `revoke_device` → sweep on one project (a failure folds into the result). */
function executeRevoke(input: {
  readonly session: CliSession;
  readonly plan: ProjectRevokePlan;
  readonly targetUserId: string;
  readonly masterKeys: MasterKeys;
}): Effect.Effect<ProjectRevokeOutcome, never, CliServices> {
  const { context } = input.plan;
  const base = {
    projectId: context.projectId,
    revoked: [] as readonly string[],
    sweep: null,
    skipped: null,
    failed: null,
    sweepFailed: null,
  } satisfies ProjectRevokeOutcome;
  return Effect.gen(function* () {
    const appended = yield* appendRevokeDevice({
      client: context.client,
      verified: context.verified,
      resync: context.resync,
      signer: { userId: input.session.userId, signingKeyPair: input.masterKeys.sigKeyPair },
      targetUserId: input.targetUserId,
      fingerprintsHex: input.plan.revoking.map((device) => device.keyFingerprintHex),
    });
    const { revoked } = appended;
    // After the append is accepted the revocation is on the chain: a
    // resync / sweep failure is not folded into "revocation failed" — the
    // revocation stays and it is reported as a sweep failure (never skip
    // the local-record / registry aftermath)
    return yield* sweepAfterRevoke({ ...input, appended }).pipe(
      Effect.map((sweep) => ({ ...base, revoked, sweep })),
      Effect.catch((error) =>
        Effect.succeed({
          ...base,
          revoked,
          sweepFailed: error.message,
        } satisfies ProjectRevokeOutcome),
      ),
    );
  }).pipe(Effect.catch((error) => Effect.succeed({ ...base, failed: error.message })));
}

/** The post-acceptance resync and sweep (failures are returned as-is — the caller folds them into sweepFailed). */
function sweepAfterRevoke(input: {
  readonly session: CliSession;
  readonly plan: ProjectRevokePlan;
  readonly targetUserId: string;
  readonly masterKeys: MasterKeys;
  readonly appended: { readonly verified: VerifiedProject; readonly revoked: readonly string[] };
}): Effect.Effect<DeviceSweepOutcome | null, CliError, CliServices> {
  const { context } = input.plan;
  return Effect.gen(function* () {
    // The post-acceptance resync (the pre-append view has no revocation
    // duty — the sweep is derived on the view that confirmed the listing.
    // Same discipline as member remove: the server's claim is never the
    // source of truth)
    const verified =
      input.appended.revoked.length === 0
        ? input.appended.verified
        : yield* resyncExtended(context.resync, input.appended.verified);
    const self = verified.state.members.get(input.session.userId);
    const actorDevice =
      self === undefined
        ? undefined
        : findOwnDevice(self, { keyFingerprintHex: input.masterKeys.fingerprintHex });
    // When this device revoked itself, the sweep cannot be fulfilled from this device (K4-7 counterexample 5)
    return actorDevice === undefined
      ? null
      : yield* sweepAfterDeviceRevoke({
          client: context.client,
          verified,
          targetUserId: input.targetUserId,
          actorUserId: input.session.userId,
          actorDevice,
          rotate: sweepRotateFor({ ...context, verified }, DEVICE_REVOKED_ROTATION_REASON),
        });
  });
}

/**
 * Proposing token revocation (K4-13): the candidate is the registry's
 * `tokenId`, else the name `cli:<label>`. With `--revoke-token` it revokes;
 * interactively it asks for yes; non-interactively (`--yes`) it only
 * returns the proposal. A 403 on the list (a non-admin token) reports only
 * the fact.
 */
function proposeTokenRevocation(input: {
  readonly client: MaruhiClient;
  readonly registry: readonly RegistryRow[] | null;
  readonly revoked: readonly string[];
  readonly revokeToken: boolean;
  readonly interactive: boolean;
}): Effect.Effect<readonly string[], CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    if (input.revoked.length === 0) {
      return [];
    }
    const listed = yield* input.client.auth.listTokens({}).pipe(
      Effect.map((response) => response.tokens),
      Effect.catch((error) =>
        error instanceof ForbiddenError ? Effect.succeed(null) : Effect.fail(toCliError(error)),
      ),
    );
    if (listed === null) {
      yield* logNote(
        "revoking a device does not revoke its API token (AUTH_SPEC §6). This token cannot list tokens; revoke the lost device's token from the web dashboard or with an admin token (`maruhi token revoke <id>`)",
      );
      return [];
    }
    const rows = (input.registry ?? []).filter((row) =>
      input.revoked.includes(row.keyFingerprintHex),
    );
    const candidates = listed.filter((token) =>
      rows.some((row) =>
        row.tokenId === undefined ? token.name === `cli:${row.label}` : row.tokenId === token.id,
      ),
    );
    if (candidates.length === 0) {
      yield* logNote(
        "revoking a device does not revoke its API token (AUTH_SPEC §6). No token could be matched to the revoked devices (the registry row carries no token id and no token is named after its label) — check `maruhi token list`",
      );
      return [];
    }
    const describe = describeToken;
    yield* io.log(
      `The revoked devices' API tokens are still valid (the match is server-reported): ${candidates.map(describe).join("; ")}`,
    );
    let revoke = input.revokeToken;
    if (!revoke && input.interactive) {
      const answer = yield* io.promptLine({ prompt: "Revoke these tokens too? Type yes: " });
      revoke = answer.trim().toLowerCase() === "yes";
    }
    if (!revoke) {
      yield* logNote(
        "tokens were left as they are — revoke them later with `maruhi token revoke <id>` (pass --revoke-token to do it in the same run)",
      );
      return candidates.map(describe);
    }
    for (const token of candidates) {
      yield* input.client.auth.revokeTokenById({ params: { tokenId: token.id } }).pipe(
        Effect.asVoid,
        Effect.catch((error) =>
          error instanceof TokenNotFoundError ? Effect.void : Effect.fail(toCliError(error)),
        ),
      );
      yield* io.log(`Revoked token ${describe(token)}`);
    }
    return [];
  });
}

/** One token-candidate row (id, name, expiry — K4-13's proposal display). */
function describeToken(token: {
  readonly id: string;
  readonly name: string;
  readonly expiresAtMs: number | null;
}): string {
  return `${displayText(token.id)} (${displayText(token.name)}, expires ${token.expiresAtMs === null ? "never" : formatUtcMinutes(token.expiresAtMs)})`;
}

/** Assembling the cap (`--cap <role>` + the scope flags). */
export function parseCapRole(raw: string | undefined): Effect.Effect<Role, CliError> {
  if (raw === undefined) {
    return Effect.succeed("owner");
  }
  const roles: readonly Role[] = ["owner", "admin", "member", "reader"];
  const role = roles.find((candidate) => candidate === raw);
  return role === undefined
    ? Effect.fail(usageError(`--cap must be one of ${roles.join(", ")}`))
    : Effect.succeed(role);
}
