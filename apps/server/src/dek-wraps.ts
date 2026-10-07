// Acceptance verification of DEK wraps (AUTH_SPEC §12-6 = the server side of
// the CRYPTO_SPEC §6.3 ghost-member countermeasure) and assembly of the
// dek.registered event (AUDIT_SPEC §3.3).
//
// Device-axis (2026-09-19 DK — K3; design record dk-design.md §8 K3-1 / K3-4 /
// K3-5): the recipient set R(E) expands into (person, device) pairs ×
// effective scope, and the slot primary key includes the recipient's enc
// public key. The signer of the registration signature (the calling
// principal's device) is resolved from the first wrap (tried in ascending FP
// order — key uniqueness means at most one device can verify), and the
// remaining wraps are verified with that key alone.

import { cryptoEffect } from "@maruhi/core";
import type { ChainMember, ChainState, KeyFingerprintHex } from "@maruhi/crypto";
import {
  decodeHex,
  effectivePermissionOf,
  importSigningPublicKey,
  scopeIncludesEnvironment,
  verifyDekWrapSignature,
} from "@maruhi/crypto";
import { Effect } from "effect";

import type { AuditEventInput } from "./audit-store.ts";
import type {
  DataActor,
  DataRejection,
  DekRecipientClass,
  DekWrapInput,
  MemberWithDevice,
} from "./data/data-plane.ts";
import { dataEvent, dekRecipientTarget, rejectData, withSigningDevice } from "./data/data-plane.ts";
import { DataStore } from "./data/data-store.ts";
import { MAX_DEK_WRAPS_PER_REQUEST } from "./policy.ts";
import { ensureWrapRowCapacity } from "./quotas.ts";

/**
 * Duplicate-detection key of (epoch × recipient class × recipient × device
 * key) — the deletion path (programs-dek). The class's source of truth is the
 * stored row's recipient_class column; beyond duplicate detection on this key,
 * the deletion path is guarded by matching the class against the stored value.
 */
export function wrapRefKey(ref: {
  readonly epoch: number;
  readonly recipientClass: DekRecipientClass;
  readonly recipientUserId: string;
  readonly recipientEncPubHex: string;
}): string {
  return `${ref.epoch}:${ref.recipientClass}:${ref.recipientUserId}:${ref.recipientEncPubHex}`;
}

/**
 * The **registration path**'s duplicate-detection key = same granularity as
 * the stored row's uniqueness unit (environment, epoch, recipient_user_id,
 * recipient_enc_pub_hex) — no class. A member's user_id (ULID) and a server's
 * FP (32 lowercase hex characters) never actually collide in format, but
 * add_member's target user_id is an intentionally unvalidated free-form string
 * (AUTH_SPEC §11-1), so neither the type nor the consensus rules guarantee it.
 * Checking a class-inclusive key would let the collision set "a member's
 * user_id = a valid grant's server key FP, with the same key" pass the
 * acceptance stage, hit a primary-key violation in the write phase = defect
 * (500), and block that environment's rotations and creations (A-1). Here we
 * fail it to a 422 (duplicate-recipient) before acceptance.
 */
function wrapStorageKey(ref: {
  readonly epoch: number;
  readonly recipientUserId: string;
  readonly recipientEncPubHex: string;
}): string {
  return `${ref.epoch}:${ref.recipientUserId}:${ref.recipientEncPubHex}`;
}

/**
 * The member-side membership predicate of recipient set R(E) (CRYPTO_SPEC §6.2
 * — device axis; 2026-09-19 DK): E ∈ the device's effective scope (the
 * person's scope ∩ the device's scope — `effectivePermissionOf` is the only
 * computation point). Paired with the grant side's
 * `scopeEnvironmentIds.includes(E)`, the expected count (below) and the
 * recipient check (checkWrapRecipient) use the same predicate — "the check is,
 * across recipient classes, the single predicate 'identification (id + key) ∧
 * E ∈ effective scope'" (§6.2 / AUTH_SPEC §12-6).
 */
export function deviceReceivesEnvironment(
  member: ChainMember,
  device: { readonly roleCap: ChainMember["role"]; readonly scope: ChainMember["scope"] },
  environmentId: string,
): boolean {
  return scopeIncludesEnvironment(effectivePermissionOf(member, device).scope, environmentId);
}

/**
 * The expected recipient count of a complete wrap set for (environment, epoch)
 * (AUTH_SPEC §12-4 / §12-6) = recipient set R(E) (CRYPTO_SPEC §6.2 — device
 * axis): every device of each current member whose effective scope contains E,
 * plus the server keys of valid grant_servers whose disclosure scope contains
 * the environment. Both the exact match of initial registration and the count
 * check of composite requests use this single definition (the acceptance
 * boundary does not shift).
 */
export function expectedWrapRecipientCount(state: ChainState, environmentId: string): number {
  // Because the storage key (= the registration path's duplicate-detection key
  // wrapStorageKey) carries no recipient class, if a member's user_id and a
  // valid grant's server key FP collide on the same key, those two recipients
  // can only occupy one slot. The expected count uses the same granularity as
  // the storage key — the deduplicated union of identifier + key (the residual
  // boundary of A-1 is unchanged. With the key inside the primary key on the
  // device axis, a collision shrank to "same id and same key")
  const recipients = new Set<string>();
  for (const [userId, member] of state.members) {
    for (const device of member.devices.values()) {
      if (deviceReceivesEnvironment(member, device, environmentId)) {
        recipients.add(`${userId}:${device.encPubHex}`);
      }
    }
  }
  for (const [fingerprintHex, grant] of state.serverGrants) {
    if (grant.scopeEnvironmentIds.includes(environmentId)) {
      recipients.add(`${fingerprintHex}:${grant.serverEncPubHex}`);
    }
  }
  return recipients.size;
}

/** Per-request wrap-count limit (shared by the registration and deletion paths). Returns null when ok. */
export function checkWrapRequestCount(count: number): DataRejection | null {
  if (count > MAX_DEK_WRAPS_PER_REQUEST) {
    return {
      kind: "limit-exceeded",
      resource: "dek-wraps-per-request",
      limit: MAX_DEK_WRAPS_PER_REQUEST,
    };
  }
  return null;
}

/**
 * Recipient identification (per class — AUTH_SPEC §12-6). member = the user_id
 * is a current member, the enc public key strictly equals one of that person's
 * **live device keys**, and the target environment is inside that device's
 * **effective scope** (out of scope is 422 `scope-out-of-range` — 2026-09-15
 * ES K3 / 2026-09-19 DK; the device-axis version of CRYPTO_SPEC §6.3's
 * "accepting a wrap addressed to a revoked device or a device outside its
 * scope is forbidden" = the ghost-member countermeasure).
 * server = both the server key FP at the recipientUserId position and the enc
 * public key strictly match the payload of a chain-derived valid grant_server,
 * and the target environment is inside the disclosure scope (out of scope is
 * the same 422). The reason-code order (identify → key → scope) is the same
 * across classes.
 */
function checkWrapRecipient(
  state: ChainState,
  environmentId: string,
  wrap: DekWrapInput,
): DataRejection | null {
  if (wrap.recipientClass === "server") {
    const grant = state.serverGrants.get(wrap.recipientUserId);
    if (grant === undefined) {
      return { kind: "dek-wrap-rejected", reason: "recipient-not-granted" };
    }
    if (grant.serverEncPubHex !== wrap.recipientEncPubHex) {
      return { kind: "dek-wrap-rejected", reason: "recipient-key-mismatch" };
    }
    if (!grant.scopeEnvironmentIds.includes(environmentId)) {
      return { kind: "dek-wrap-rejected", reason: "scope-out-of-range" };
    }
    return null;
  }
  const member = state.members.get(wrap.recipientUserId);
  if (member === undefined) {
    return { kind: "dek-wrap-rejected", reason: "recipient-not-member" };
  }
  // The recipient's key = one of that person's live device keys (the device
  // expansion of R(E) — AUTH_SPEC §12-6). A wrap addressed to a revoked or
  // unregistered key falls to the non-matching side
  const device = [...member.devices.values()].find(
    (candidate) => candidate.encPubHex === wrap.recipientEncPubHex,
  );
  if (device === undefined) {
    return { kind: "dek-wrap-rejected", reason: "recipient-key-mismatch" };
  }
  if (!deviceReceivesEnvironment(member, device, environmentId)) {
    return { kind: "dek-wrap-rejected", reason: "scope-out-of-range" };
  }
  return null;
}

/**
 * The predicate for a reader's self-backfill (AUTH_SPEC §12-3 — 2026-09-19 DK;
 * design record §8 K3-5): every wrap has recipient class member, recipient =
 * the calling principal, and an enc public key that is one of the calling
 * principal's live device keys. If any wrap deviates, member-or-higher is
 * required as before. The check is id + key (id alone would mistake a wrap
 * addressed to someone else's key for "addressed to me").
 */
export function allRecipientsAreOwnDevices(
  caller: ChainMember,
  wraps: readonly DekWrapInput[],
): boolean {
  const ownKeys = new Set([...caller.devices.values()].map((device) => device.encPubHex));
  return wraps.every(
    (wrap) =>
      wrap.recipientClass === "member" &&
      wrap.recipientUserId === caller.userId &&
      ownKeys.has(wrap.recipientEncPubHex),
  );
}

/** Per-wrap check (split for cognitive complexity). Returns null when ok. */
function checkOneWrap(
  state: ChainState,
  environmentId: string,
  currentEpoch: number,
  wrap: DekWrapInput,
  seen: Set<string>,
): DataRejection | null {
  if (wrap.epoch < 1 || wrap.epoch > currentEpoch) {
    return { kind: "dek-wrap-rejected", reason: "epoch-out-of-range" };
  }
  const recipientRejection = checkWrapRecipient(state, environmentId, wrap);
  if (recipientRejection !== null) {
    return recipientRejection;
  }
  // Duplicate detection at storage granularity (class-agnostic). The same
  // (epoch, recipient, key) in different classes cannot coexist as stored rows
  // either, so they are rejected for the same reason as same-class duplicates
  const key = wrapStorageKey(wrap);
  if (seen.has(key)) {
    return { kind: "dek-wrap-rejected", reason: "duplicate-recipient" };
  }
  seen.add(key);
  return null;
}

function checkWrapRecipients(
  state: ChainState,
  environmentId: string,
  currentEpoch: number,
  wraps: readonly DekWrapInput[],
): DataRejection | null {
  const countRejection = checkWrapRequestCount(wraps.length);
  if (countRejection !== null) {
    return countRejection;
  }
  const seen = new Set<string>();
  for (const wrap of wraps) {
    const rejection = checkOneWrap(state, environmentId, currentEpoch, wrap, seen);
    if (rejection !== null) {
      return rejection;
    }
  }
  return null;
}

/** Verify one wrap's registration signature with one key (the signed signer = the calling principal — §12-6). */
const verifyOneWrapSignature = (
  projectId: string,
  environmentId: string,
  signer: MemberWithDevice,
  signerPublicKey: CryptoKey,
  wrap: DekWrapInput,
) =>
  cryptoEffect(() =>
    verifyDekWrapSignature({
      context: {
        suite: wrap.suite,
        projectId,
        environmentId,
        epoch: wrap.epoch,
        recipientUserId: wrap.recipientUserId,
        recipientEncPubHex: wrap.recipientEncPubHex,
        encHex: wrap.encHex,
        ciphertextHex: wrap.ciphertextHex,
        // The signed signer = the calling principal (§12-6). Key-duplicated
        // members are forbidden by the chain layer (CRYPTO_SPEC §6.2), but
        // even if one existed, reattribution is caught here (an independent
        // defense layer of §5.1)
        signerUserId: signer.userId,
      },
      signatureHex: wrap.signatureHex,
      signerPublicKey,
    }),
  ).pipe(
    // Fold every crypto failure — including InvalidInput (structural
    // badness) — into signature-rejected (on a Schema-validated wire,
    // effectively only DekWrapSignatureInvalid reaches here)
    Effect.mapError(() => rejectData({ kind: "dek-wrap-rejected", reason: "signature-invalid" })),
  );

/** Import a sig public key derived from a verified chain (failure is a storage / verifier bug = defect). */
const importSignerKey = Effect.fn("dek-wraps.importSignerKey")(function* (
  signer: MemberWithDevice,
) {
  // Note: the import succeeding below also relies on the current runtime
  // behavior that "WebCrypto's raw Ed25519 import only checks length" (the
  // target keys of add_member / add_device are not imported at chain
  // acceptance). If the runtime introduces point validation, requests from a
  // member who holds a bad 32-byte key become defects (self-harm only;
  // unusable as an attack)
  const signerKeyBytes = decodeHex(signer.sigPubHex);
  if (signerKeyBytes === null) {
    return yield* Effect.die(new Error("chain-derived signing key is not valid hex"));
  }
  return yield* cryptoEffect(() => importSigningPublicKey(signerKeyBytes)).pipe(Effect.orDie);
});

/**
 * §12-6 / CRYPTO_SPEC §5.1: verify every wrap's registration signature and
 * return the signing device. Since signer = the API calling principal is an
 * exact-match acceptance condition, the verification key is the calling
 * principal's **chain-derived sig public key at acceptance time** (= the key
 * at registration time; all operations are serialized under the permit). The
 * device is resolved on the first wrap (`withSigningDevice` — design record §8
 * K3-1) and the rest are verified with that key alone (not all-wraps ×
 * all-devices). A wrap signed by someone else (including a third party
 * re-injecting into a deleted slot) falls to signature-invalid here. With no
 * wraps, returns null (the device is undetermined — the caller's count check
 * rejects with recipient-missing).
 */
const ensureWrapSignatures = Effect.fn("dek-wraps.ensureWrapSignatures")(function* (
  projectId: string,
  environmentId: string,
  caller: ChainMember,
  wraps: readonly DekWrapInput[],
) {
  const [first, ...rest] = wraps;
  if (first === undefined) {
    return null;
  }
  const { device: signer, value: signerPublicKey } = yield* withSigningDevice(caller, (candidate) =>
    Effect.gen(function* () {
      const key = yield* importSignerKey(candidate);
      yield* verifyOneWrapSignature(projectId, environmentId, candidate, key, first);
      return key;
    }),
  );
  for (const wrap of rest) {
    yield* verifyOneWrapSignature(projectId, environmentId, signer, signerPublicKey, wrap);
  }
  return signer;
});

/**
 * Per-epoch set check (§12-6): initial registration (no existing wraps)
 * requires an exact match against the recipient set R(E) (every device of each
 * current member whose effective scope contains E + the server keys of valid
 * grant_servers inside the disclosure scope) — recipients are already checked,
 * so a count match = complete; the check is applied identically across
 * recipient classes. Appending to an existing epoch rejects duplicates of an
 * existing (epoch, recipient, device key).
 */
const checkWrapSets = Effect.fn("dek-wraps.checkWrapSets")(function* (
  environmentId: string,
  state: ChainState,
  wraps: readonly DekWrapInput[],
) {
  const store = yield* DataStore;
  const epochs = [...new Set(wraps.map((wrap) => wrap.epoch))];
  for (const epoch of epochs) {
    const epochWraps = wraps.filter((wrap) => wrap.epoch === epoch);
    const existing = yield* store.countWrapsForEpoch(environmentId, epoch);
    if (existing === 0) {
      if (epochWraps.length !== expectedWrapRecipientCount(state, environmentId)) {
        return yield* rejectData({ kind: "dek-wrap-rejected", reason: "recipient-missing" });
      }
      continue;
    }
    for (const wrap of epochWraps) {
      // The existence check is at the same granularity as the storage key
      // (environment, epoch, recipient_user_id, recipient_enc_pub_hex) — an
      // identical (ID, key) in a different class would still be a primary-key
      // collision on insert, so fail it to a 409 here
      const stored = yield* store.wrapStoredRecipient(
        environmentId,
        epoch,
        wrap.recipientUserId,
        wrap.recipientEncPubHex,
      );
      if (stored !== null) {
        // Return the occupying wrap's stored recipient enc public key
        // (AUTH_SPEC §12-6). Under the device-axis primary key it always
        // equals the key that was sent (an old-key wrap is a separate slot =
        // it does not block registration of the new key), so its role as
        // material shrinks to the "already registered = idempotent" decision
        // — the wire is unchanged (design record §8 K3-3)
        return yield* rejectData({
          kind: "dek-wrap-exists",
          epoch,
          recipientUserId: wrap.recipientUserId,
          storedRecipientEncPubHex: stored.recipientEncPubHex,
        });
      }
    }
  }
});

/**
 * Acceptance verification of a wrap set (§12-6) + quantity policy (§12-8) +
 * registration-signature verification (CRYPTO_SPEC §5.1). Insertion happens in
 * the caller's synchronous write phase. Every wrap-insertion path — the
 * standalone registration API (backfill, repair re-registration) and composite
 * requests (environment creation, rotation — composite-programs.ts) — passes
 * through here, so wiring the cumulative-row limit and signature requirement
 * once in this place suffices. Signature verification (Ed25519 × count) is the
 * most expensive step, so it runs after all the cheap checks (count,
 * recipients, duplicates, sets) pass.
 * Return value = the signing device (the caller uses it for the second-stage
 * authorization — ensureDevicePermission — and as the signer FP for writes and
 * audit. null when there are no wraps).
 */
export const ensureWrapSetAcceptable = Effect.fn("dek-wraps.ensureWrapSetAcceptable")(function* (
  projectId: string,
  environmentId: string,
  state: ChainState,
  caller: ChainMember,
  currentEpoch: number,
  wraps: readonly DekWrapInput[],
) {
  const rejection = checkWrapRecipients(state, environmentId, currentEpoch, wraps);
  if (rejection !== null) {
    return yield* rejectData(rejection);
  }
  yield* ensureWrapRowCapacity(wraps.length);
  yield* checkWrapSets(environmentId, state, wraps);
  return yield* ensureWrapSignatures(projectId, environmentId, caller, wraps);
});

/**
 * dek.registered (AUDIT_SPEC §3.3): one row per recipient (the §5.1 column
 * structure = one target per row). A member recipient goes on target_user_id,
 * so the (target_user_id, seq) index directly yields "the registration history
 * of wraps addressed to this recipient". A server recipient has no user_id
 * (the §2 actor model), so the server key FP goes on target_key_fingerprint
 * (the same column as chain.server_granted — §3.4 — ; do not mix
 * non-provider identifiers into the user_id column).
 * actor_key_fingerprint carries the signer FP of the registration signature
 * (the signing device) (§3.3 — session 07 ruling B, "record E's signer FP so
 * it can be cross-checked").
 */
export function dekRegisteredEvent(
  actor: DataActor,
  signer: { readonly keyFingerprintHex: KeyFingerprintHex },
  nowMs: number,
  environmentId: string,
  wrap: DekWrapInput,
): AuditEventInput {
  return dataEvent(actor, nowMs, "dek.registered", {
    environmentId,
    epoch: wrap.epoch,
    ...dekRecipientTarget(wrap.recipientClass, wrap.recipientUserId),
    actorKeyFingerprintHex: signer.keyFingerprintHex,
  });
}
