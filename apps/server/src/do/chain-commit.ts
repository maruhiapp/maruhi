// Shared write phase that records §3.4 mirror events alongside acceptance
// of a chain append (generic append = chain-do.ts / standalone checkpoint
// = checkpoint-accept.ts). A single synchronous block (= one event-loop
// task) writes the chain insert, mirror append, and acceptance side
// effects (+ path-specific extra synchronous writes), so a crash cannot
// leave the inconsistency "chain written but mirror missing" (the mirror
// has no v1 backfill — AUDIT_SPEC §3.4 — so a gap would be permanent).
// serverTs is acquired after all checks and immediately before the write
// phase (the same timing as the composite path — see insertAcceptedEntrySync
// in chain-accept.ts).

import type { ChainMirrorSubject } from "@maruhi/core";
import { cryptoEffect } from "@maruhi/core";
import type { ChainEntry } from "@maruhi/crypto";
import { computeUserKeyFingerprint, decodeHex, encodeHex } from "@maruhi/crypto";
import { Clock, Effect } from "effect";

import { AuditStore } from "../audit-store.ts";
import { DataStore } from "../data/data-store.ts";
import type { AppliedProposal } from "./chain-accept.ts";
import { insertAcceptedEntrySync, proposalIndexOf } from "./chain-accept.ts";
import type { StoredChain, VerifiedChainView } from "./chain-store.ts";
import { ChainStore } from "./chain-store.ts";

/**
 * Atomic commit of an accepted entry. `chain` is the stored chain before
 * acceptance (the sequence with the accepted entry appended is the input
 * to §3.4's proposal index — chain-accept.ts). `extraSync` is the hook for
 * additional writes inside the same synchronous block (the standalone
 * checkpoint's snapshot store — §6.4) and shares serverTs (nowMs). The
 * return value is the proposal a completed approve applied (null
 * otherwise).
 */
/** The device FP carried by `add_device` (CRYPTO_SPEC §3 — first 16 bytes of SHA-256 over enc ‖ sig). */
const mirrorSubjectOf = (entry: ChainEntry): Effect.Effect<ChainMirrorSubject> =>
  Effect.gen(function* () {
    if (entry.op !== "add_device") {
      return {};
    }
    // The payload already passed verifyChain (lowercase hex, 64 chars), so
    // decode / computation succeed. Failure is a verifier bug = defect (do
    // not quietly produce a row with no FP — the K2-12 contract)
    const enc = decodeHex(entry.payload.encPubHex);
    const sig = decodeHex(entry.payload.sigPubHex);
    if (enc === null || sig === null) {
      return yield* Effect.die(new Error("add_device payload keys are not valid hex"));
    }
    const fingerprint = yield* cryptoEffect(() => computeUserKeyFingerprint(enc, sig)).pipe(
      Effect.orDie,
    );
    return { addedDeviceKeyFingerprintHex: encodeHex(fingerprint) };
  });

export const commitAcceptedEntry = (
  chain: StoredChain,
  entry: ChainEntry,
  applied: VerifiedChainView,
  canonicalBytes: number,
  extraSync?: (nowMs: number) => void,
): Effect.Effect<AppliedProposal | null, never, ChainStore | AuditStore | DataStore> =>
  Effect.gen(function* () {
    const chainStore = yield* ChainStore;
    const audit = yield* AuditStore;
    // Acceptance side effects (chain-accept.ts): add_member's old-key wrap
    // sweep deletes wrap rows, so generic chain acceptance is also handed
    // the data store's write surface
    const dataStore = yield* DataStore;
    const nowMs = yield* Clock.currentTimeMillis;
    const proposals = proposalIndexOf([...chain.entries, entry], applied);
    // add_device's mirror row (AUDIT_SPEC §3.4) needs the carried device's
    // FP. SHA-256 is async, so the acceptance side computes it before the
    // synchronous write phase and hands it to the mapping (design record
    // dk-design.md §7 K2-12)
    const subject = yield* mirrorSubjectOf(entry);
    return yield* Effect.sync(() => {
      const appliedProposal = insertAcceptedEntrySync(
        { chainStore, audit, dataStore },
        entry,
        applied,
        canonicalBytes,
        nowMs,
        proposals,
        subject,
      );
      extraSync?.(nowMs);
      return appliedProposal;
    });
  });
