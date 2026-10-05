// Reserve-key handoff — the requesting side (CRYPTO_SPEC §8.4 /
// AUTH_SPEC §13-7 — KL3, 2026-09-19 DK).
//
// `maruhi key recover --handoff` (a device holding no keys): generates
// an ephemeral X25519 key E in memory, displays its handoff code (=
// the encoding of E.pub; public information), and waits for the
// **guardians'** approvals. Once approvals arrive, it opens the
// segments, assembles the KEK, decrypts reserve key B from the
// ledger's group wrap, and returns the record (it does not persist —
// the downstream key-recover.ts issues a new device key, signs
// `add_device` with B, then discards B). E is never persisted.
//
// The approving side is `maruhi guardian approve <code>`
// (guardian.ts). The old-device approval path (`source = "device"` —
// device migration) was removed in DK K4: everyday devices do not
// hold B so it cannot work, and adding a device is handled by
// `maruhi device add` / `approve` (which carry no secret).
//
// Ceremonies (request, recovery) run only on a human's interactive
// terminal and are refused in AI agent environments (ADR-0016
// decision 7's existing gate). Plaintext segments, KEK, and B exist
// only in local variables.

import { cryptoEffect, cryptoPromise, fromCryptoResult } from "@maruhi/core";
import {
  computeHandoffRequestId,
  decodeHex,
  encodeHandoffCode,
  type EncryptionKeyPair,
  exportEncryptionPublicKey,
  generateEncryptionKeyPair,
  type GuardianMode,
  joinGuardianShares,
  openHandoffValue,
  unwrapMasterBlob,
} from "@maruhi/crypto";
import { Duration, Effect, Stdio } from "effect";
import type { HttpClient } from "effect/http";

import { ensureSensitiveTerminalAllowed } from "./agent-gate.ts";
import type { MaruhiClient } from "./api.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo, type CliIoShape } from "./io.ts";
import { parseStoredMasterKey, type StoredMasterKey } from "./keychain.ts";
import { decodeWrapped } from "./master-ops.ts";
import type { CliSession } from "./session.ts";

/** Polling interval while waiting for approvals. */
const POLL_INTERVAL = Duration.seconds(3);

function ensureHandoffRequestAllowed(io: CliIoShape): Effect.Effect<void, CliError, Stdio.Stdio> {
  return ensureSensitiveTerminalAllowed({
    agent: io.agentProfile(),
    stderrIsTerminal: io.stderrIsTerminal(),
    agentError:
      "Refused to request a key handoff because an AI agent environment was detected (the restored reserve key would land in the agent's session; run this yourself on a human interactive terminal)",
    terminalError:
      "Key handoff requests are only allowed on an interactive terminal (stdin, stdout, and stderr must all be terminals; pipes, redirects, CI, and AI agents are refused)",
  });
}

/** One approval as returned by the server (wire shape). */
interface ApprovalWire {
  readonly source: string;
  readonly shareIndex: number;
  readonly approverUserId: string;
  readonly approverKeyFingerprintHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
}

interface GroupSummary {
  readonly groupId: string;
  readonly mode: GuardianMode;
  readonly guardianCount: number;
}

/** An assembled set of approvals (any: one piece, all: every piece). */
interface Assembled {
  readonly group: GroupSummary;
  readonly approvals: readonly ApprovalWire[];
}

/** Selects a set sufficient for recovery from the arrived approvals. */
function assemble(
  approvals: readonly ApprovalWire[],
  groups: readonly GroupSummary[],
): Assembled | null {
  for (const group of groups) {
    const shares = approvals.filter((a) => a.source === group.groupId);
    if (group.mode === "any" && shares.length >= 1) {
      return { group, approvals: shares.slice(0, 1) };
    }
    if (group.mode === "all") {
      const indexes = new Set(shares.map((s) => s.shareIndex));
      const complete =
        indexes.size === group.guardianCount &&
        Array.from({ length: group.guardianCount }, (_, i) => i + 1).every((i) => indexes.has(i));
      if (complete) {
        return { group, approvals: shares };
      }
    }
  }
  return null;
}

function decodeBlobWrap(blob: {
  readonly nonceHex: string;
  readonly ciphertextHex: string;
}): Effect.Effect<{ readonly nonce: Uint8Array; readonly ciphertext: Uint8Array }, CliError> {
  const nonce = decodeHex(blob.nonceHex);
  const ciphertext = decodeHex(blob.ciphertextHex);
  return nonce === null || ciphertext === null
    ? Effect.fail(cliError("The server response is malformed (cannot decode hex)"))
    : Effect.succeed({ nonce, ciphertext });
}

/** Opens an approval's value (segment) with the ephemeral key. A context mismatch = decryption failure = abort. */
function openApproval(input: {
  readonly ephemeral: EncryptionKeyPair;
  readonly userId: string;
  readonly requestId: string;
  readonly approval: ApprovalWire;
}): Effect.Effect<Uint8Array, CliError> {
  return Effect.gen(function* () {
    const wrapped = yield* decodeWrapped(input.approval);
    return yield* cryptoEffect(() =>
      openHandoffValue({
        ephemeralKeyPair: input.ephemeral,
        wrapped,
        context: {
          userId: input.userId,
          requestId: input.requestId,
          source: input.approval.source,
          shareIndex: input.approval.shareIndex,
          approverUserId: input.approval.approverUserId,
        },
      }),
    ).pipe(
      Effect.mapError(() =>
        cliError(
          `Cannot open the approval from ${displayText(input.approval.approverUserId)}: it was not sealed to this request's key, or its context was altered in transit. The handoff was aborted — re-run and hand the new code to the guardians again`,
        ),
      ),
    );
  });
}

/** Assembles the KEK from the assembled set and decrypts the ledger's group wrap. */
function recoverBlob(input: {
  readonly client: MaruhiClient;
  readonly ephemeral: EncryptionKeyPair;
  readonly userId: string;
  readonly requestId: string;
  readonly assembled: Assembled;
}): Effect.Effect<Uint8Array, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const values: Uint8Array[] = [];
    for (const approval of input.assembled.approvals) {
      values.push(yield* openApproval({ ...input, approval }));
    }
    const kek = yield* fromCryptoResult(
      joinGuardianShares({
        mode: input.assembled.group.mode,
        shares: values,
        expectedCount: input.assembled.group.guardianCount,
      }),
    ).pipe(Effect.mapError(() => cliError("Failed to reassemble the group key from the shares")));
    const group = yield* input.client.keyWraps
      .guardianGet({ params: { groupId: input.assembled.group.groupId } })
      .pipe(Effect.mapError(toCliError));
    const wrapped = yield* decodeBlobWrap(group.wrap);
    return yield* cryptoEffect(() =>
      unwrapMasterBlob({
        kek,
        wrapped,
        context: {
          userId: input.userId,
          kind: "guardian",
          wrapRef: group.groupId,
          mode: group.mode,
        },
      }),
    ).pipe(
      Effect.mapError(() =>
        cliError(
          "Cannot decrypt the wrapped reserve key with the approvals received. The wrap and the approvals do not match (the ledger or the approvals were altered) — the handoff was aborted",
        ),
      ),
    );
  });
}

/** The ephemeral key E and its code / request_id (E exists only in this process's memory — §8.4). */
interface HandoffRequest {
  readonly ephemeral: EncryptionKeyPair;
  readonly code: string;
  readonly requestId: string;
}

function newHandoffRequest(): Effect.Effect<HandoffRequest, CliError> {
  return Effect.gen(function* () {
    const ephemeral = yield* cryptoPromise("generateEncryptionKeyPair", () =>
      generateEncryptionKeyPair(),
    ).pipe(Effect.mapError(() => cliError("Failed to generate the handoff key (crypto error)")));
    const publicKey = yield* cryptoPromise("exportEncryptionPublicKey", () =>
      exportEncryptionPublicKey(ephemeral.publicKey),
    ).pipe(Effect.mapError(() => cliError("Failed to export the handoff key (crypto error)")));
    const code = yield* cryptoEffect(() => encodeHandoffCode(publicKey)).pipe(
      Effect.mapError(() => cliError("Failed to derive the handoff code")),
    );
    const requestId = yield* cryptoEffect(() => computeHandoffRequestId(publicKey)).pipe(
      Effect.mapError(() => cliError("Failed to derive the handoff code")),
    );
    return { ephemeral, code, requestId };
  });
}

/** Displays the code and the guidance (the code is a public key = not secret, but it goes to the same stderr as the guidance). */
function announceCode(
  io: CliIoShape,
  code: string,
  groups: readonly GroupSummary[],
): Effect.Effect<void> {
  return Effect.gen(function* () {
    yield* io.logError("");
    yield* io.logError("Handoff code (this is a public key, not a secret):");
    yield* io.logError("");
    yield* io.logError(`    ${code}`);
    yield* io.logError("");
    yield* io.logError(
      "Send this code to a guardian and ask them to run `maruhi guardian approve` with it (confirm with them out of band that it is you)",
    );
    yield* io.logError(
      `Registered guardian groups: ${groups.map((g) => `${g.groupId} (${g.mode}, ${g.guardianCount} guardians)`).join(", ")}`,
    );
    yield* io.logError(
      "Waiting for approvals (the request expires after 15 minutes; press Ctrl+C to cancel)",
    );
  });
}

/** Polls until the approvals arrive (expiry is a failure). */
function awaitApprovals(input: {
  readonly client: MaruhiClient;
  readonly requestId: string;
  readonly groups: readonly GroupSummary[];
  readonly expiresAtMs: number;
}): Effect.Effect<Assembled, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    let received = 0;
    while (Date.now() < input.expiresAtMs) {
      const page = yield* input.client.keyWraps
        .handoffApprovals({ params: { requestId: input.requestId } })
        .pipe(Effect.mapError(toCliError));
      received = page.approvals.length;
      const assembled = assemble(page.approvals, input.groups);
      if (assembled !== null) {
        return assembled;
      }
      yield* Effect.sleep(POLL_INTERVAL);
    }
    return yield* Effect.fail(
      cliError(
        `The handoff request expired without enough approvals (${received} received). Re-run to issue a new code`,
      ),
    );
  });
}

/**
 * `maruhi key recover --handoff`'s pre-stage: request approvals from
 * your guardians and open the reserve key (memory only —
 * key-recover.ts owns the downstream).
 */
export function requestHandoffReserve(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
}): Effect.Effect<StoredMasterKey, CliError, CliIo | Stdio.Stdio | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* ensureHandoffRequestAllowed(io);
    const status = yield* input.client.keyWraps.status({}).pipe(Effect.mapError(toCliError));
    const groups: GroupSummary[] = status.guardianGroups.map((g) => ({
      groupId: g.groupId,
      mode: g.mode,
      guardianCount: new Set(g.guardians.map((row) => row.shareIndex)).size,
    }));
    if (groups.length === 0) {
      return yield* Effect.fail(
        cliError(
          "You have no guardians registered, so nobody can approve a handoff. Open the reserve key with your recovery code (`maruhi key recover`) or a passkey (`--passkey`) instead",
        ),
      );
    }
    const request = yield* newHandoffRequest();
    const created = yield* input.client.keyWraps
      .handoffCreate({ payload: { requestId: request.requestId } })
      .pipe(
        Effect.catchTag("KeyWrapRateLimited", (error) =>
          Effect.fail(
            cliError(
              `The handoff request limit was reached. Retry after ${error.retryAfterSeconds} seconds`,
            ),
          ),
        ),
        Effect.mapError(toCliError),
      );
    yield* announceCode(io, request.code, groups);
    const assembled = yield* awaitApprovals({
      client: input.client,
      requestId: request.requestId,
      groups,
      expiresAtMs: created.expiresAtMs,
    });
    const blob = yield* recoverBlob({
      client: input.client,
      ephemeral: request.ephemeral,
      userId: input.session.userId,
      requestId: request.requestId,
      assembled,
    });
    const record = parseStoredMasterKey(new TextDecoder().decode(blob));
    if (record === null) {
      return yield* Effect.fail(
        cliError(
          "The decrypted blob is not a key record. The ledger holds a broken record, or a newer maruhi wrote it — update maruhi, or open the reserve key another way",
        ),
      );
    }
    for (const approval of assembled.approvals) {
      yield* io.log(
        `approved by ${displayText(approval.approverUserId)} (guardian, group ${displayText(approval.source)}; device key fingerprint ${approval.approverKeyFingerprintHex})`,
      );
    }
    // The request has served its purpose (the approvals become worthless together with E, but still delete the row)
    yield* input.client.keyWraps
      .handoffCancel({ params: { requestId: request.requestId } })
      .pipe(Effect.ignore);
    return record;
  });
}
