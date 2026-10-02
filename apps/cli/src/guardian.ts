// Guardian groups (CRYPTO_SPEC §8.3 / §8.4 / AUTH_SPEC §13-7 — KL3,
// 2026-09-19 DK).
//
// `maruhi guardian add`: picks guardians from the chain-derived
// members of the shared project and registers to the ledger a segment
// sealed to the enc public key of each of their **currently valid
// device keys** (on-chain keys — §8.3's device expansion). The wrapped
// target B is the **reserve key**'s record (§8.1 — the caller obtains
// it by opening the ledger. ledger-open.ts / design record §9 K4-2).
// Key confirmation follows the §6.5 fulfilment form (the 12-word
// reading ceremony / a verified fingerprint-book hit + yes) — no
// global public-key directory is built. `all` splits by random XOR
// and needs everyone. `any` needs any one person.
//
// `maruhi guardian approve <code>` (formerly `key approve` — renamed
// when the old-device path was removed. K4-15): restores E.pub and
// the request_id from the code and queries the request. Opens the
// my-addressed segment with **this device's device key** (selects the
// row of my FP from `deviceShares` — K3-10) and re-seals it to E.pub
// on the spot. The server does not relay E.pub (a human carries the
// code).
//
// `list` / `remove` / `wards`: viewing the ledger, deleting, and
// listing the wards I am a guardian of. With `list --project`, the
// ledger's segment rows (per device) are collated against the
// chain-derived current device set, warning about rows that can no
// longer be opened (a revoked device) and segments that became
// unopenable because every device was revoked (under `all`, one
// person's mismatch makes the whole group unrestorable).
//
// Plaintext KEK, segments, and B exist only in local variables.

import {
  type ChainDevice,
  type ChainMember,
  computeHandoffRequestId,
  decodeHandoffCode,
  decodeHex,
  encodeHex,
  type EncryptionKey,
  generateMasterWrapKek,
  type GuardianMode,
  importEncryptionPublicKey,
  sealGuardianShare,
  splitGuardianKek,
  wrapMasterBlob,
} from "@maruhi/crypto";
import { Effect, Stdio } from "effect";
import type { HttpClient } from "effect/http";

import { ensureSensitiveTerminalAllowed } from "./agent-gate.ts";
import type { MaruhiClient } from "./api.ts";
import { type CliServices, type CommonFlags, openMetadataProject, openSession } from "./context.ts";
import { devicesOf } from "./device-key.ts";
import { countNoun, displayText } from "./display.ts";
import { cliError, type CliError, usageError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { confirmByLastWord, fingerprintWords, formatWordList } from "./fp-words.ts";
import { CliIo, type CliIoShape } from "./io.ts";
import type { Keychain } from "./keychain.ts";
import { serializeStoredMasterKey } from "./keychain.ts";
import {
  confirmKnownFingerprint,
  consultFingerprintBook,
  FingerprintBook,
  usableBookHit,
} from "./known-fingerprints.ts";
import {
  decodeWrapped,
  newLedgerId,
  openOwnGuardianShare,
  sealForRequester,
} from "./master-ops.ts";
import { logNote, logWarning } from "./notice.ts";
import type { ReserveKeys } from "./reserve.ts";
import { type CliSession, loadMasterKeys, type MasterKeys } from "./session.ts";

/** The same cap as the acceptance policy (AUTH_SPEC §13-8) (guidance ahead of the server's 422). */
const MAX_GUARDIANS = 5;

/**
 * The naming ceremony takes the same gate as the handoff request /
 * approve (ADR-0016 decision 7): only on a human's interactive
 * terminal; agent environments are refused. Naming a guardian has no
 * flag route (never let a non-interactive caller decide where key
 * material is sealed), so the form that fills the ceremony prompt
 * via piped stdin is dropped here too.
 */
function ensureGuardianCeremonyAllowed(io: CliIoShape): Effect.Effect<void, CliError, Stdio.Stdio> {
  return ensureSensitiveTerminalAllowed({
    agent: io.agentProfile(),
    stderrIsTerminal: io.stderrIsTerminal(),
    agentError:
      "Refused to run the guardian key confirmation ceremony: an AI agent environment was detected. Run `maruhi guardian add` yourself in a terminal",
    terminalError:
      "Designating guardians is only allowed on an interactive terminal (stdin, stdout, and stderr must all be terminals; pipes, redirects, CI, and AI agents are refused)",
  });
}

/**
 * Explicit confirmation of guardian keys (the §6.5 fulfilment form
 * applied to guardian naming): a fingerprint-book hit excuses the
 * re-reading, but a per-naming yes confirmation remains. What is
 * confirmed is the FP of **each device** of the guardian (the
 * segment is sealed to that device).
 */
function confirmGuardianFingerprint(input: {
  readonly origin: string;
  readonly userId: string;
  readonly fingerprintHex: string;
}): Effect.Effect<void, CliError, CliIo | FingerprintBook | Stdio.Stdio> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const words = yield* fingerprintWords(
      input.fingerprintHex,
      "The guardian's key fingerprint is malformed",
    );
    const book = yield* consultFingerprintBook({
      origin: input.origin,
      userId: input.userId,
      fingerprintHex: input.fingerprintHex,
    });
    const hit = yield* usableBookHit({ book, flagProvided: false, isAgent: false });
    yield* io.log(`Guardian ${displayText(input.userId)} — device key fingerprint:`);
    yield* io.log(`  hex:  ${input.fingerprintHex}`);
    yield* io.log(`  word: ${formatWordList(words)}`);
    if (hit === null) {
      yield* io.log(
        "Check that this word list matches the 12 words this person reads to you out of band (e.g. over a call — `maruhi key show` on that device prints them). This device will be able to help restore your reserve key",
      );
    }
    yield* book.warnIfChanged;
    if (hit !== null) {
      yield* confirmKnownFingerprint({
        entry: hit,
        filePath: book.filePath,
        prompt: `Type yes to seal a share to this previously verified device of ${displayText(input.userId)}`,
        cancelText: "guardian add was cancelled.",
      });
      return;
    }
    yield* confirmByLastWord({
      words,
      promptText:
        "Once you have checked against this person's out-of-band read-out (e.g. a call), type the last of the 12 words shown above",
      mismatchText: "That does not match. Type the last word of the list shown above",
      exhaustedText:
        "Guardian key fingerprint confirmation failed (the re-typed word does not match). No guardian group was created — re-run once you can check with this person",
    });
    yield* book.record;
  });
}

/** Preconditions of naming (the same rules as the server's 422, stated here first). */
function guardianInputRejection(input: {
  readonly selfUserId: string;
  readonly mode: GuardianMode;
  readonly userIds: readonly string[];
}): string | null {
  if (input.userIds.length > MAX_GUARDIANS) {
    return `At most ${MAX_GUARDIANS} guardians per group`;
  }
  if (input.mode === "all" && input.userIds.length < 2) {
    return "Mode all needs at least 2 guardians (use mode any for a single guardian)";
  }
  if (new Set(input.userIds).size !== input.userIds.length) {
    return "The same user was given more than once";
  }
  if (input.userIds.includes(input.selfUserId)) {
    return "You cannot be your own guardian";
  }
  return null;
}

/** A chain-derived current member (a guardian candidate) and their current device set. */
interface GuardianMember {
  readonly userId: string;
  readonly devices: readonly ChainDevice[];
}

/** The registration form of a segment (wire — AUTH_SPEC §13-9 GuardianShare. One element per device). */
interface SealedShare {
  readonly shareIndex: number;
  readonly guardianUserId: string;
  readonly guardianEncPubHex: string;
  readonly guardianKeyFingerprintHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
}

/** Resolves guardian candidates from the chain's current members (§8.3 — no public-key directory is built). */
function resolveGuardians(input: {
  readonly projectId: string;
  readonly members: ReadonlyMap<string, ChainMember>;
  readonly userIds: readonly string[];
}): Effect.Effect<readonly GuardianMember[], CliError> {
  return Effect.forEach(input.userIds, (userId) => {
    const member = input.members.get(userId);
    if (member === undefined) {
      return Effect.fail(
        cliError(
          `${displayText(userId)} is not a current member of project ${displayText(input.projectId)}. Guardians must be members of a project you share (their keys come from that project's verified chain)`,
        ),
      );
    }
    // A guardian's keys = all of the person's currently valid device keys (§8.3 — the same segment is sealed once per device)
    return Effect.succeed({ userId, devices: devicesOf(member) });
  });
}

/** Seals one device's worth of a segment to the guardian's chain key. */
function sealShareFor(input: {
  readonly wardUserId: string;
  readonly groupId: string;
  readonly mode: GuardianMode;
  readonly shareIndex: number;
  readonly guardianUserId: string;
  readonly device: ChainDevice;
  readonly share: Uint8Array;
}): Effect.Effect<SealedShare, CliError> {
  return Effect.gen(function* () {
    const encPub = decodeHex(input.device.encPubHex);
    const publicKey =
      encPub === null ? null : yield* Effect.promise(() => importEncryptionPublicKey(encPub));
    if (publicKey === null || !publicKey.ok) {
      return yield* Effect.fail(
        cliError(`The chain key of ${displayText(input.guardianUserId)} cannot be imported`),
      );
    }
    const sealed = yield* Effect.tryPromise({
      try: () =>
        sealGuardianShare({
          guardianPublicKey: publicKey.value,
          share: input.share,
          context: {
            userId: input.wardUserId,
            groupId: input.groupId,
            mode: input.mode,
            shareIndex: input.shareIndex,
            guardianUserId: input.guardianUserId,
          },
        }),
      catch: () => cliError("Failed to seal a guardian share (crypto error)"),
    });
    if (!sealed.ok) {
      return yield* Effect.fail(cliError("Failed to seal a guardian share"));
    }
    return {
      shareIndex: input.shareIndex,
      guardianUserId: input.guardianUserId,
      guardianEncPubHex: input.device.encPubHex,
      guardianKeyFingerprintHex: input.device.keyFingerprintHex,
      encHex: encodeHex(sealed.value.enc),
      ciphertextHex: encodeHex(sealed.value.ciphertext),
    };
  });
}

/** Wraps B (the reserve key) with a random KEK and splits the KEK into segments sealed to each guardian's each device (§8.3). */
function prepareGroup(input: {
  readonly wardUserId: string;
  readonly reserve: ReserveKeys;
  readonly groupId: string;
  readonly mode: GuardianMode;
  readonly guardians: readonly GuardianMember[];
}): Effect.Effect<
  {
    readonly wrap: { readonly nonceHex: string; readonly ciphertextHex: string };
    readonly shares: readonly SealedShare[];
  },
  CliError
> {
  return Effect.gen(function* () {
    const kek = generateMasterWrapKek();
    const blob = new TextEncoder().encode(serializeStoredMasterKey(input.reserve.record));
    const wrapped = yield* Effect.tryPromise({
      try: () =>
        wrapMasterBlob({
          kek,
          masterSecretBlob: blob,
          context: {
            userId: input.wardUserId,
            kind: "guardian",
            wrapRef: input.groupId,
            mode: input.mode,
          },
        }),
      catch: () => cliError("Failed to wrap the reserve key for the guardian group (crypto error)"),
    });
    const split = splitGuardianKek({ kek, mode: input.mode, count: input.guardians.length });
    if (!wrapped.ok || !split.ok || split.value.length !== input.guardians.length) {
      return yield* Effect.fail(cliError("Failed to prepare the guardian group"));
    }
    const shares: SealedShare[] = [];
    for (const [index, guardian] of input.guardians.entries()) {
      for (const device of guardian.devices) {
        shares.push(
          yield* sealShareFor({
            wardUserId: input.wardUserId,
            groupId: input.groupId,
            mode: input.mode,
            shareIndex: index + 1,
            guardianUserId: guardian.userId,
            device,
            share: split.value[index] ?? new Uint8Array(),
          }),
        );
      }
    }
    return {
      wrap: {
        nonceHex: encodeHex(wrapped.value.nonce),
        ciphertextHex: encodeHex(wrapped.value.ciphertext),
      },
      shares,
    };
  });
}

/**
 * `maruhi guardian add --project <p> --mode any|all <user>...`: register a
 * guardian group whose members can approve restoring your reserve key.
 * `openReserve` opens the ledger (ledger-open.ts — the
 * qualification for changing the ledger. K4-2); run it exactly
 * once, after input checks and the ceremony, just before sealing.
 */
export function guardianAddOp(input: {
  readonly flags: CommonFlags;
  readonly mode: GuardianMode;
  readonly userIds: readonly string[];
  readonly openReserve: (
    session: CliSession,
    client: MaruhiClient,
  ) => Effect.Effect<ReserveKeys, CliError, CliServices>;
}): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* ensureGuardianCeremonyAllowed(io);
    const context = yield* openMetadataProject(input.flags);
    const rejection = guardianInputRejection({
      selfUserId: context.session.userId,
      mode: input.mode,
      userIds: input.userIds,
    });
    if (rejection !== null) {
      return yield* Effect.fail(usageError(rejection));
    }
    const guardians = yield* resolveGuardians({
      projectId: context.projectId,
      members: context.verified.state.members,
      userIds: input.userIds,
    });
    for (const guardian of guardians) {
      for (const device of guardian.devices) {
        yield* confirmGuardianFingerprint({
          origin: context.origin,
          userId: guardian.userId,
          fingerprintHex: device.keyFingerprintHex,
        });
      }
    }
    // Changing the ledger requires opening the reserve key (CRYPTO_SPEC §8 revision (4))
    const reserve = yield* input.openReserve(context.session, context.client);
    const groupId = newLedgerId();
    const prepared = yield* prepareGroup({
      wardUserId: context.session.userId,
      reserve,
      groupId,
      mode: input.mode,
      guardians,
    });
    yield* context.client.keyWraps
      .guardianCreate({
        payload: {
          groupId,
          mode: input.mode,
          wrap: { suite: "maruhi/v1", ...prepared.wrap },
          shares: prepared.shares,
        },
      })
      .pipe(
        Effect.catchTag("KeyWrapPolicy", (error) =>
          Effect.fail(cliError(`The server rejected the guardian group (${error.reason})`)),
        ),
        Effect.mapError(toCliError),
      );
    yield* io.log(
      `Registered guardian group ${groupId} (mode ${input.mode}: ${input.mode === "any" ? "any one guardian can approve" : "all guardians must approve"})`,
    );
    for (const [index, guardian] of guardians.entries()) {
      yield* io.log(
        `  ${index + 1}. ${displayText(guardian.userId)} (${guardian.devices.length === 1 ? "1 device" : `${guardian.devices.length} devices`}: ${guardian.devices.map((device) => device.keyFingerprintHex).join(", ")})`,
      );
    }
    yield* logNote(
      "shares are sealed to the guardians' current devices; a guardian who adds a device later or revokes one cannot open the share on it. Check with `maruhi guardian list --project <id>` and re-add the group if needed. To restore on a machine with no device key, run `maruhi key recover --handoff` there and send the code to a guardian",
    );
  });
}

/** One guardian row of the ledger (the distribution form of a status — per device). */
interface GuardianRow {
  readonly shareIndex: number;
  readonly guardianUserId: string;
  readonly guardianKeyFingerprintHex: string;
}

/** Collation result against the chain's current device set (null = not collated / matches). */
type Staleness = "left" | "device-gone" | null;

function stalenessOf(
  guardian: GuardianRow,
  chainMembers: ReadonlyMap<string, ChainMember> | null,
): Staleness {
  if (chainMembers === null) {
    return null;
  }
  const current = chainMembers.get(guardian.guardianUserId);
  if (current === undefined) {
    return "left";
  }
  // Whether the key the segment was sealed to is still a valid device of that person (2026-09-19 DK — per device)
  return current.devices.has(guardian.guardianKeyFingerprintHex) ? null : "device-gone";
}

function reportGroup(
  group: {
    readonly groupId: string;
    readonly mode: GuardianMode;
    readonly guardians: readonly GuardianRow[];
  },
  chainMembers: ReadonlyMap<string, ChainMember> | null,
): Effect.Effect<void, never, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const shareIndexes = [...new Set(group.guardians.map((row) => row.shareIndex))].toSorted(
      (a, b) => a - b,
    );
    yield* io.log(`${group.groupId}  mode ${group.mode}  ${shareIndexes.length} guardians`);
    for (const shareIndex of shareIndexes) {
      yield* reportShare(
        group.mode,
        shareIndex,
        group.guardians.filter((row) => row.shareIndex === shareIndex),
        chainMembers,
      );
    }
  });
}

/** Display of one logical segment (one guardian, per-device rows) and the notes for unopenable / partially revoked. */
function reportShare(
  mode: GuardianMode,
  shareIndex: number,
  rows: readonly GuardianRow[],
  chainMembers: ReadonlyMap<string, ChainMember> | null,
): Effect.Effect<void, never, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const userId = rows[0]?.guardianUserId ?? "";
    const live = rows.filter((row) => stalenessOf(row, chainMembers) === null);
    const gone = rows.filter((row) => stalenessOf(row, chainMembers) !== null);
    const stale = chainMembers !== null && live.length === 0;
    yield* io.log(
      `  ${shareIndex}. ${displayText(userId)} (${countNoun(rows.length, "device")}: ${fingerprintsOf(rows)})${stale ? "  STALE" : ""}`,
    );
    if (stale) {
      const left = rows.some((row) => stalenessOf(row, chainMembers) === "left");
      yield* logWarning(staleShareWarning(userId, left, mode));
    } else if (chainMembers !== null && gone.length > 0) {
      // Some devices revoked (K1-13 — SHOULD: propose recreation without waiting for every device to be revoked)
      yield* logNote(partiallyRevokedNote(userId, gone, live.length));
    }
  });
}

function fingerprintsOf(rows: readonly GuardianRow[]): string {
  return rows.map((row) => row.guardianKeyFingerprintHex).join(", ");
}

function staleShareWarning(userId: string, left: boolean, mode: GuardianMode): string {
  const why = left
    ? "is no longer a member of that project"
    : "has none of these devices on the chain any more";
  const consequence =
    mode === "all" ? " — this all-mode group can no longer restore your reserve key" : "";
  return `${displayText(userId)} ${why}, so their share cannot be opened${consequence}. Remove the group and add it again`;
}

function partiallyRevokedNote(
  userId: string,
  gone: readonly GuardianRow[],
  liveCount: number,
): string {
  return `${displayText(userId)}: ${countNoun(gone.length, "sealed device")} (${fingerprintsOf(gone)}) ${gone.length === 1 ? "is" : "are"} no longer active on the chain; the share still opens on the remaining ${liveCount === 1 ? "device" : "devices"}. Consider re-creating the group (\`maruhi guardian remove\` + \`add\`) so the revoked device's copy of the share is retired`;
}

/** `maruhi guardian list [--project <p>]`: list your guardian groups. */
export function guardianListOp(input: {
  readonly flags: CommonFlags;
}): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const session = yield* openSession(input.flags.server);
    const status = yield* session.client.keyWraps.status({}).pipe(Effect.mapError(toCliError));
    if (status.guardianGroups.length === 0) {
      yield* io.log("No guardian groups. Add one with `maruhi guardian add`");
      return;
    }
    // With --project, collate the ledger's guardian-key FPs against the chain-derived current device set
    const chainMembers =
      input.flags.project === undefined
        ? null
        : (yield* openMetadataProject(input.flags)).verified.state.members;
    for (const group of status.guardianGroups) {
      yield* reportGroup(group, chainMembers);
    }
  });
}

/** `maruhi guardian remove <group-id>`: delete a guardian group. */
export function guardianRemoveOp(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly groupId: string;
}): Effect.Effect<void, CliError, CliIo | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* input.client.keyWraps.guardianDelete({ params: { groupId: input.groupId } }).pipe(
      Effect.catchTag("KeyWrapNotFound", () =>
        Effect.fail(
          cliError("No guardian group with that ID (list them with `maruhi guardian list`)"),
        ),
      ),
      Effect.mapError(toCliError),
    );
    yield* io.log(`Removed guardian group ${displayText(input.groupId)}`);
  });
}

/** `maruhi guardian wards`: list the people who made you a guardian. */
export function guardianWardsOp(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
}): Effect.Effect<void, CliError, CliIo | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const { wards } = yield* input.client.keyWraps.wards({}).pipe(Effect.mapError(toCliError));
    if (wards.length === 0) {
      yield* io.log("Nobody has made you a guardian");
      return;
    }
    for (const ward of wards) {
      const label =
        ward.wardLogin === null
          ? displayText(ward.wardUserId)
          : `${displayText(ward.wardLogin)} (${displayText(ward.wardUserId)})`;
      yield* io.log(
        `${label}  group ${displayText(ward.groupId)}  mode ${ward.mode}  share ${ward.shareIndex}`,
      );
    }
    yield* io.log(
      "When one of them asks you to help restore their reserve key, run `maruhi guardian approve` with the code they send you",
    );
  });
}

// ---------------------------------------------------------------------------
// guardian approve (§8.4 — guardian approval. The old-device path was removed in 2026-09-19 DK)
// ---------------------------------------------------------------------------

function ensureApproveCeremonyAllowed(io: CliIoShape): Effect.Effect<void, CliError, Stdio.Stdio> {
  return ensureSensitiveTerminalAllowed({
    agent: io.agentProfile(),
    stderrIsTerminal: io.stderrIsTerminal(),
    agentError:
      "Refused to approve a key handoff because an AI agent environment was detected (approving hands out key material; run this yourself on a human interactive terminal)",
    terminalError:
      "Key handoff approvals are only allowed on an interactive terminal (stdin, stdout, and stderr must all be terminals; pipes, redirects, CI, and AI agents are refused)",
  });
}

/** The request as seen by the approver (the code's decryption result + the server's query). */
interface ApprovalTarget {
  readonly requestId: string;
  readonly ephemeralPublicKey: EncryptionKey;
  readonly wardUserId: string;
  readonly wardLabel: string;
  readonly roles: readonly {
    readonly groupId: string;
    readonly mode: GuardianMode;
    readonly shareIndex: number;
  }[];
}

/** Decrypts the code and queries the request. */
function resolveApprovalTarget(
  client: MaruhiClient,
  code: string,
): Effect.Effect<ApprovalTarget, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const decoded = yield* Effect.promise(() => decodeHandoffCode(code));
    if (!decoded.ok) {
      return yield* Effect.fail(
        cliError(
          "The handoff code is malformed (58 characters in groups of 4; hyphens, spaces, and letter case are ignored). Copy it again from the requesting device",
        ),
      );
    }
    const requestId = yield* Effect.promise(() => computeHandoffRequestId(decoded.value));
    const ephemeralPublicKey = yield* Effect.promise(() =>
      importEncryptionPublicKey(decoded.value),
    );
    if (!requestId.ok || !ephemeralPublicKey.ok) {
      return yield* Effect.fail(cliError("The handoff code does not encode a usable key"));
    }
    const lookup = yield* client.keyWraps
      .handoffLookup({ params: { requestId: requestId.value } })
      .pipe(
        Effect.catchTag("HandoffNotFound", () =>
          Effect.fail(
            cliError(
              "No pending handoff request matches this code (it is unknown, expired, or you are not one of the requester's guardians)",
            ),
          ),
        ),
        Effect.mapError(toCliError),
      );
    return {
      requestId: requestId.value,
      ephemeralPublicKey: ephemeralPublicKey.value,
      wardUserId: lookup.wardUserId,
      wardLabel:
        lookup.wardLogin === null
          ? displayText(lookup.wardUserId)
          : `${displayText(lookup.wardLogin)} (${displayText(lookup.wardUserId)})`,
      roles: lookup.roles,
    };
  });
}

/** Description of the request and a yes confirmation (nothing is sent for anything but yes). */
function confirmApproval(io: CliIoShape, target: ApprovalTarget): Effect.Effect<void, CliError> {
  return Effect.gen(function* () {
    const groups = target.roles.map(
      (role) => `${displayText(role.groupId)} (${role.mode}, share ${role.shareIndex})`,
    );
    yield* io.log(`Handoff request from ${target.wardLabel} — you are their guardian`);
    yield* io.log(`  groups: ${groups.join(", ")}`);
    yield* io.log(
      "Confirm out of band (e.g. a call to a number you already know) that this person asked you for the approval right now. Anyone who took over their account could show you this code",
    );
    const answer = yield* io.promptLine({
      prompt: `Type yes to approve the handoff for ${target.wardLabel}: `,
    });
    if (answer.trim() !== "yes") {
      return yield* Effect.fail(cliError("The handoff approval was cancelled (nothing was sent)"));
    }
  });
}

/** Sends the approval (the sealed segment). */
function sendApproval(input: {
  readonly client: MaruhiClient;
  readonly requestId: string;
  readonly approverKeyFingerprintHex: string;
  readonly source: string;
  readonly shareIndex: number;
  readonly sealed: { readonly enc: Uint8Array; readonly ciphertext: Uint8Array };
}): Effect.Effect<void, CliError, HttpClient.HttpClient> {
  return input.client.keyWraps
    .handoffApprove({
      params: { requestId: input.requestId },
      payload: {
        source: input.source,
        shareIndex: input.shareIndex,
        approverKeyFingerprintHex: input.approverKeyFingerprintHex,
        encHex: encodeHex(input.sealed.enc),
        ciphertextHex: encodeHex(input.sealed.ciphertext),
      },
    })
    .pipe(
      Effect.catchTag("HandoffConflict", () =>
        Effect.fail(cliError("This request was already approved from this account")),
      ),
      Effect.catchTag("KeyWrapRateLimited", (error) =>
        Effect.fail(
          cliError(
            `The approval limit was reached. Retry after ${error.retryAfterSeconds} seconds`,
          ),
        ),
      ),
      Effect.mapError(toCliError),
    );
}

/** Among the my-addressed segment rows, selects the row sealed to this device's key (K3-10 — `deviceShares`). */
function ownDeviceShare(
  share: {
    readonly deviceShares: readonly {
      readonly guardianKeyFingerprintHex: string;
      readonly encHex: string;
      readonly ciphertextHex: string;
    }[];
  },
  masterKeys: MasterKeys,
): { readonly encHex: string; readonly ciphertextHex: string } | null {
  const mine = share.deviceShares.find(
    (row) => row.guardianKeyFingerprintHex === masterKeys.fingerprintHex,
  );
  return mine === undefined ? null : { encHex: mine.encHex, ciphertextHex: mine.ciphertextHex };
}

/** Approving as a guardian: opens the my-addressed segment with this device's key and re-seals it to E.pub on the spot (§8.4). */
function approveAsGuardian(input: {
  readonly client: MaruhiClient;
  readonly target: ApprovalTarget;
  readonly masterKeys: MasterKeys;
  readonly selfUserId: string;
}): Effect.Effect<void, CliError, CliIo | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    for (const role of input.target.roles) {
      const share = yield* input.client.keyWraps
        .myShare({ params: { groupId: role.groupId } })
        .pipe(Effect.mapError(toCliError));
      const mine = ownDeviceShare(share, input.masterKeys);
      if (mine === null) {
        return yield* Effect.fail(
          cliError(
            `Your share of group ${displayText(role.groupId)} is not sealed to this device (fingerprint ${input.masterKeys.fingerprintHex}). Approve from one of your devices it was sealed to, or ask ${input.target.wardLabel} to re-add the group after this device was registered`,
          ),
        );
      }
      const opened = yield* openOwnGuardianShare({
        masterKeys: input.masterKeys,
        wrapped: yield* decodeWrapped(mine),
        context: {
          userId: input.target.wardUserId,
          groupId: role.groupId,
          mode: role.mode,
          shareIndex: role.shareIndex,
          guardianUserId: input.selfUserId,
        },
      });
      const sealed = yield* sealForRequester({
        ephemeralPublicKey: input.target.ephemeralPublicKey,
        value: opened,
        context: {
          userId: input.target.wardUserId,
          requestId: input.target.requestId,
          source: role.groupId,
          shareIndex: role.shareIndex,
          approverUserId: input.selfUserId,
        },
      });
      yield* sendApproval({
        client: input.client,
        requestId: input.target.requestId,
        approverKeyFingerprintHex: input.masterKeys.fingerprintHex,
        source: role.groupId,
        shareIndex: role.shareIndex,
        sealed,
      });
      yield* io.log(
        `Approved share ${role.shareIndex} of group ${displayText(role.groupId)}${role.mode === "all" ? " (the other guardians must approve too)" : ""}`,
      );
    }
    yield* logNote(
      "the approval was sealed to the requester's one-time key and nothing was stored on this device",
    );
  });
}

/**
 * `maruhi guardian approve <code>`: approve a reserve-key handoff request as one
 * of the requester's guardians (formerly `key approve` — K4-15).
 */
export function guardianApproveOp(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly code: string;
}): Effect.Effect<void, CliError, Keychain | CliIo | Stdio.Stdio | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* ensureApproveCeremonyAllowed(io);
    const target = yield* resolveApprovalTarget(input.client, input.code);
    if (target.wardUserId === input.session.userId) {
      // The server never shows the request to the ward themself (§13-7), but do not trust the response — refuse locally too
      return yield* Effect.fail(
        cliError(
          "This handoff request is your own. Only your guardians can approve it (device migration no longer goes through a handoff — register a new device with `maruhi device add` / `maruhi device approve`)",
        ),
      );
    }
    const masterKeys = yield* loadMasterKeys(input.session);
    yield* confirmApproval(io, target);
    yield* approveAsGuardian({
      client: input.client,
      target,
      masterKeys,
      selfUserId: input.session.userId,
    });
  });
}
