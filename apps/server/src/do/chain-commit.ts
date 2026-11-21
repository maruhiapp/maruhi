import type { ChainMirrorSubject } from "@maruhi/core";
import { userKeyFingerprintHex } from "@maruhi/core";
import type { ChainEntry } from "@maruhi/crypto";
import { decodeHex } from "@maruhi/crypto";
import { Clock, Effect } from "effect";

import { AuditStore } from "../audit-store.ts";
import { DataStore } from "../data.package/index.ts";
import type { AppliedProposal } from "./chain-accept.ts";
import { insertAcceptedEntrySync, proposalIndexOf } from "./chain-accept.ts";
import type { StoredChain, VerifiedChainView } from "./chain-store.ts";
import { ChainStore } from "./chain-store.ts";

const mirrorSubjectOf = Effect.fn("chain-commit.mirrorSubjectOf")(function* (
  entry: ChainEntry,
): Effect.fn.Return<ChainMirrorSubject> {
  if (entry.op !== "add_device") {
    return {};
  }
  const enc = decodeHex(entry.payload.encPubHex);
  const sig = decodeHex(entry.payload.sigPubHex);
  if (enc === null || sig === null) {
    return yield* Effect.die(new Error("add_device payload keys are not valid hex"));
  }
  const fingerprint = yield* userKeyFingerprintHex(enc, sig).pipe(Effect.orDie);
  return { addedDeviceKeyFingerprintHex: fingerprint };
});

export const commitAcceptedEntry = Effect.fn("chain-commit.commitAcceptedEntry")(function* (
  chain: StoredChain,
  entry: ChainEntry,
  applied: VerifiedChainView,
  canonicalBytes: number,
  extraSync?: (nowMs: number) => void,
): Effect.fn.Return<AppliedProposal | null, never, ChainStore | AuditStore | DataStore> {
  const chainStore = yield* ChainStore;
  const audit = yield* AuditStore;
  const dataStore = yield* DataStore;
  const nowMs = yield* Clock.currentTimeMillis;
  const proposals = proposalIndexOf([...chain.entries, entry], applied);
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
