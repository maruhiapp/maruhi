// Client-side sync verification (CRYPTO_SPEC §6.3).
//
// On every sync, fetches the whole chain, re-verifies all of it
// with verifyChain (prev_hash continuity, signatures, and §6.2's
// authorization rules — including key uniqueness), and confirms
// that the recomputed genesis entry hash equals the project ID
// (the §6.4 binding — mechanical detection of the server
// swapping the chain). v1 has no local cache or incremental
// verification (fetching and re-verifying everything each time
// is simplest — if incremental verification is introduced,
// follow session-10 §5's key-index-rebuild cautions).
//
// It also builds the index of "keys bound to user_id in the
// chain history" that §5.1's distribution-time verification uses
// (the genesis / add_member payloads; includes deleted members'
// then-current keys). Head gossip (§6.3 / §6.6): other members'
// declarations bundled into the chain-fetch response are carried
// on VerifiedProject **still unverified** — the verification and
// collation is done by attestation.ts
// (reconcileDistributedAttestations). A lease response bundles no
// declarations (§14-2), so it is always empty there.

import type { ProjectId } from "@maruhi/core";
import type { ChainEntry, ChainHistoryIndex, ChainState } from "@maruhi/crypto";
import {
  computeChainEntryHash,
  computeUserKeyFingerprint,
  decodeHex,
  encodeHex,
  verifyChainWithHistory,
} from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { type AppliedOperation, appliedOperations } from "./chain-applied.ts";
import { type CliError, cliError, evidenceError } from "./errors.ts";
import { toCliError } from "./failure.ts";

/** One key set the chain history binds to a user id (genesis / add_member payload). */
export interface KeyBinding {
  readonly encPubHex: string;
  readonly sigPubHex: string;
  readonly keyFingerprintHex: string;
}

/**
 * The wire form of a distributed head declaration (AUTH_SPEC
 * §16-1 — `attestations` of the chain-fetch response). Carried
 * as **unverified raw data**: it feeds no judgment until it
 * passes §6.6's verification and collation (attestation.ts).
 */
export interface DistributedAttestationWire {
  readonly suite: "maruhi/v1";
  readonly attesterUserId: string;
  readonly attesterKeyFingerprintHex: string;
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  readonly signatureHex: string;
}

/**
 * A fully verified project chain (§6.3) plus the §5.1 signer-key history
 * index and the §4.1 chain-history index (the seq → hash /
 * tenure / epoch-validity-interval lookups — the input of a
 * value signature's declared-head-point verification).
 */
export interface VerifiedProject {
  readonly projectId: ProjectId;
  readonly state: ChainState;
  /** History queries over this verified snapshot (CRYPTO_SPEC §6.3 / §4.1). */
  readonly history: ChainHistoryIndex;
  /**
   * Every key set ever bound to each user id (append-only
   * history — §5.1). For the DEK wraps' distribution-time
   * verification (deks.ts — §5.1's semantics hold no head
   * binding). A value signature's key selection and tenure
   * lookups use the history side instead (dedupe must not erase
   * tenure — session-14 ruling A).
   */
  readonly keyHistory: ReadonlyMap<string, readonly KeyBinding[]>;
  /**
   * The verified chain's entry list (in seq order). A read-only
   * view for consulting historical facts that do not appear in
   * the derived state (e.g. the last revoke_server's seq — the
   * reference of server revoke's interruption recovery).
   */
  readonly entries: readonly ChainEntry[];
  /**
   * The applied operations' list (in seq order — design record
   * K6-C). Carries a directly appended op and the inner op of a
   * quorum-reaching `approve` (seq = the approve's seq, actor =
   * the proposer) in the same shape. Rotation obligations,
   * deletion records, scope history, and the key index scan this
   * one rather than the entry list (never miss an application
   * that arrived via a proposal).
   */
  readonly applied: readonly AppliedOperation[];
  /**
   * Other members' head declarations bundled in the same
   * response (§6.6 — **unverified**. omission is §6.3's normative
   * non-guarantee, not refused). Always empty in a
   * lease-response-derived view (§14-2 — not bundled).
   */
  readonly attestations: readonly DistributedAttestationWire[];
}

function bindingKey(binding: KeyBinding): string {
  return `${binding.encPubHex}:${binding.sigPubHex}`;
}

/**
 * The internal contradiction when a precondition that should
 * hold after verifyChain (hex's canonical form, key length) is
 * violated. A silent omission from the key index would turn into
 * a disguising "the signer does not exist in the chain history"
 * error at §5.1 verification, so it is made a typed failure
 * here.
 */
class ChainDerivationError extends Error {}

async function buildKeyHistory(
  applied: readonly AppliedOperation[],
): Promise<ReadonlyMap<string, readonly KeyBinding[]>> {
  const history = new Map<string, KeyBinding[]>();
  const seen = new Set<string>();
  const add = (userId: string, binding: KeyBinding) => {
    const dedupe = `${userId}#${bindingKey(binding)}`;
    if (seen.has(dedupe)) {
      return;
    }
    seen.add(dedupe);
    const list = history.get(userId);
    if (list === undefined) {
      history.set(userId, [binding]);
    } else {
      list.push(binding);
    }
  };
  for (const { seq, operation, actorUserId } of applied) {
    // The ops that register a key are genesis / add_member /
    // add_device (§6.2 — 2026-09-19 DK: a device key also lands
    // on the history as a key bound to its person. Revocation
    // does not erase the history). An add_member applied via a
    // proposal (four-eyes — K6) lands in the same shape too.
    // Post-verifyChain, hex is in canonical form. The FP is
    // recomputed from the payload's key (genesis's actor FP is
    // already verified to match the payload key)
    if (
      operation.op !== "genesis" &&
      operation.op !== "add_member" &&
      operation.op !== "add_device"
    ) {
      continue;
    }
    const enc = decodeHex(operation.payload.encPubHex);
    const sig = decodeHex(operation.payload.sigPubHex);
    if (enc === null || sig === null) {
      throw new ChainDerivationError(
        `Cannot decode the public-key hex in ${operation.op} (seq=${seq})`,
      );
    }
    const fingerprint = await computeUserKeyFingerprint(enc, sig);
    if (!fingerprint.ok) {
      throw new ChainDerivationError(
        `Cannot compute the key fingerprint for ${operation.op} (seq=${seq})`,
      );
    }
    // genesis / add_device's target = the actor themself; add_member's target = the payload's target
    add(operation.op === "add_member" ? operation.payload.targetUserId : actorUserId, {
      encPubHex: operation.payload.encPubHex,
      sigPubHex: operation.payload.sigPubHex,
      keyFingerprintHex: encodeHex(fingerprint.value),
    });
  }
  return history;
}

/**
 * Fully verifies one distributed chain snapshot (§6.3), checks the genesis
 * hash against the project id (§6.4), and cross-checks the server's claimed
 * head against the locally derived one.
 *
 * **Both** syncProject (fetching from the chain API) and the
 * lease response's bundled chain (AUTH_SPEC §14-2 — the only
 * distribution path to non-members) pass through here.
 * Splitting the verification implementation into two lineages
 * would be a silent regression where only one side loses genesis
 * pinning and head consistency (the same reason as values.ts's
 * decryptVerifiedValue).
 */
export function verifyChainSnapshot(input: {
  readonly projectId: ProjectId;
  readonly entries: readonly ChainEntry[];
  /** The server-declared head (not trusted — checked for equality against the derived head). */
  readonly claimedHeadSeq: number;
  readonly claimedHeadHashHex: string;
  /** The bundled head declarations (carried unverified — the lease path passes none = empty). */
  readonly attestations?: readonly DistributedAttestationWire[];
}): Effect.Effect<VerifiedProject, CliError> {
  return Effect.gen(function* () {
    const { projectId, entries } = input;
    const verified = yield* Effect.tryPromise({
      try: () => verifyChainWithHistory(entries),
      catch: () => cliError("Chain verification failed to run (crypto error)"),
    });
    if (!verified.ok) {
      const { seq, reason } =
        verified.error.kind === "ChainInvalid"
          ? verified.error
          : { seq: 0, reason: "invalid-payload" };
      // A distributed chain failing verification = a
      // contradiction in signed data (evidence — re-running does
      // not resolve it. Must never be folded into a cleanup
      // warning)
      return yield* Effect.fail(
        evidenceError(
          `Chain verification failed (seq=${seq}, reason=${reason}). The server may be distributing an invalid chain`,
        ),
      );
    }
    const { state, history } = verified.value;

    // §6.4: the project ID = the genesis entry hash. The swap
    // where the server distributes a different chain under the
    // same ID is detected mechanically here
    const genesis = entries[0];
    if (genesis === undefined) {
      return yield* Effect.fail(cliError("The chain is empty"));
    }
    const genesisHash = yield* Effect.tryPromise({
      try: () => computeChainEntryHash(genesis),
      catch: () => cliError("Failed to compute the genesis hash (crypto error)"),
    });
    if (genesisHash !== projectId) {
      return yield* Effect.fail(
        evidenceError(
          `The genesis hash does not match the project ID (suspected server-side chain replacement): expected=${projectId} actual=${genesisHash}`,
        ),
      );
    }

    // Consistency between the server-declared head and the derived head (declared values are not trusted)
    if (state.headSeq !== input.claimedHeadSeq || state.headHashHex !== input.claimedHeadHashHex) {
      return yield* Effect.fail(
        evidenceError(
          "The server-declared chain head does not match the fetched entries (the response contradicts itself)",
        ),
      );
    }

    // The applied-operations list (K6-C) — the completion judgment is core's indexProposals (K5-F)
    const applied = appliedOperations(
      entries,
      (seq) => history.entryHashAt(seq),
      new Set(state.pendingProposals.keys()),
    );
    const keyHistory = yield* Effect.tryPromise({
      try: () => buildKeyHistory(applied),
      catch: (error) =>
        cliError(
          `Chain-derivation inconsistency: ${
            error instanceof ChainDerivationError ? error.message : String(error)
          } (cannot build the key index from the verified chain)`,
        ),
    });
    return {
      projectId,
      state,
      history,
      keyHistory,
      entries,
      applied,
      attestations: input.attestations ?? [],
    } satisfies VerifiedProject;
  });
}

/**
 * Fetches and fully verifies the project chain (§6.3) through
 * {@link verifyChainSnapshot}.
 */
export function syncProject(
  client: MaruhiClient,
  projectId: ProjectId,
): Effect.Effect<VerifiedProject, CliError> {
  return Effect.gen(function* () {
    const snapshot = yield* client.membership
      .get({ params: { projectId } })
      .pipe(Effect.mapError(toCliError));
    return yield* verifyChainSnapshot({
      projectId,
      entries: snapshot.entries,
      claimedHeadSeq: snapshot.headSeq,
      claimedHeadHashHex: snapshot.headHashHex,
      attestations: snapshot.attestations,
    });
  });
}

/**
 * The check that the post-resync new snapshot is an **extension**
 * of the old verified view (§6.3-2b's resync branch). Assuming
 * syncProject has already done full verification and the genesis
 * match, it requires (1) the new head is at or above the old
 * head, (2) the old verified head's seq/hash matches inside the
 * new snapshot. Replacement by a different consistent chain, a
 * missing old head, and a hash mismatch at the same seq all fail
 * here.
 */
function ensureExtensionOf(
  previous: VerifiedProject,
  next: VerifiedProject,
): Effect.Effect<VerifiedProject, CliError> {
  if (
    next.state.headSeq < previous.state.headSeq ||
    next.history.entryHashAt(previous.state.headSeq) !== previous.state.headHashHex
  ) {
    return Effect.fail(
      evidenceError(
        `The re-synced chain is not an extension of the verified view (seq=${previous.state.headSeq}) (evidence of server-side chain replacement / divergence)`,
      ),
    );
  }
  return Effect.succeed(next);
}

/** Re-sync with the extension check (§6.3-2b / session-14 ruling G). */
export function resyncExtended(
  resync: Effect.Effect<VerifiedProject, CliError>,
  previous: VerifiedProject,
): Effect.Effect<VerifiedProject, CliError> {
  return Effect.flatMap(resync, (next) => ensureExtensionOf(previous, next));
}
