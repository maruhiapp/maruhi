import type { EnvironmentId, ProjectId, UserId } from "@maruhi/core";
import { cryptoEffect } from "@maruhi/core";
import type { ChainMember, ChainState, KeyFingerprintHex } from "@maruhi/crypto";
import {
  decodeHex,
  deviceReceivesEnvironment,
  importSigningPublicKey,
  verifyDekWrapSignature,
  wrapRecipientsOf,
} from "@maruhi/crypto";
import { Effect } from "effect";

import type { AuditEventInput } from "./audit-store.ts";
import type {
  DataActor,
  DataRejection,
  DekRecipientClass,
  DekWrapInput,
  MemberWithDevice,
} from "./data.package/index.ts";
import {
  dataEvent,
  DataStore,
  dekRecipientTarget,
  rejectData,
  withSigningDevice,
} from "./data.package/index.ts";
import { MAX_DEK_WRAPS_PER_REQUEST } from "./policy.ts";
import { ensureWrapRowCapacity } from "./quotas.ts";

export function wrapRefKey(ref: {
  readonly epoch: number;
  readonly recipientClass: DekRecipientClass;
  readonly recipientUserId: UserId | KeyFingerprintHex;
  readonly recipientEncPubHex: string;
}): string {
  return `${ref.epoch}:${ref.recipientClass}:${ref.recipientUserId}:${ref.recipientEncPubHex}`;
}

function wrapStorageKey(ref: {
  readonly epoch: number;
  readonly recipientUserId: UserId | KeyFingerprintHex;
  readonly recipientEncPubHex: string;
}): string {
  return `${ref.epoch}:${ref.recipientUserId}:${ref.recipientEncPubHex}`;
}

export function expectedWrapRecipientCount(
  state: ChainState,
  environmentId: EnvironmentId,
): number {
  return wrapRecipientsOf(state, environmentId).length;
}

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

function checkServerRecipient(
  state: ChainState,
  environmentId: EnvironmentId,
  wrap: Extract<DekWrapInput, { readonly recipientClass: "server" }>,
): DataRejection | null {
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

function checkMemberRecipient(
  state: ChainState,
  environmentId: EnvironmentId,
  wrap: Extract<DekWrapInput, { readonly recipientClass: "member" }>,
): DataRejection | null {
  const member = state.members.get(wrap.recipientUserId);
  if (member === undefined) {
    return { kind: "dek-wrap-rejected", reason: "recipient-not-member" };
  }
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

function checkWrapRecipient(
  state: ChainState,
  environmentId: EnvironmentId,
  wrap: DekWrapInput,
): DataRejection | null {
  return wrap.recipientClass === "server"
    ? checkServerRecipient(state, environmentId, wrap)
    : checkMemberRecipient(state, environmentId, wrap);
}

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

function checkOneWrap(
  state: ChainState,
  environmentId: EnvironmentId,
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
  const key = wrapStorageKey(wrap);
  if (seen.has(key)) {
    return { kind: "dek-wrap-rejected", reason: "duplicate-recipient" };
  }
  seen.add(key);
  return null;
}

function checkWrapRecipients(
  state: ChainState,
  environmentId: EnvironmentId,
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

const verifyOneWrapSignature = (
  projectId: ProjectId,
  environmentId: EnvironmentId,
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
        signerUserId: signer.userId,
      },
      signatureHex: wrap.signatureHex,
      signerPublicKey,
    }),
  ).pipe(
    Effect.mapError(() => rejectData({ kind: "dek-wrap-rejected", reason: "signature-invalid" })),
  );

const importSignerKey = Effect.fn("dek-wraps.importSignerKey")(function* (
  signer: MemberWithDevice,
) {
  const signerKeyBytes = decodeHex(signer.sigPubHex);
  if (signerKeyBytes === null) {
    return yield* Effect.die(new Error("chain-derived signing key is not valid hex"));
  }
  return yield* cryptoEffect(() => importSigningPublicKey(signerKeyBytes)).pipe(Effect.orDie);
});

const ensureWrapSignatures = Effect.fn("dek-wraps.ensureWrapSignatures")(function* (
  projectId: ProjectId,
  environmentId: EnvironmentId,
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

const checkWrapSets = Effect.fn("dek-wraps.checkWrapSets")(function* (
  environmentId: EnvironmentId,
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
      const stored = yield* store.wrapStoredRecipient(
        environmentId,
        epoch,
        wrap.recipientUserId,
        wrap.recipientEncPubHex,
      );
      if (stored !== null) {
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

export const ensureWrapSetAcceptable = Effect.fn("dek-wraps.ensureWrapSetAcceptable")(function* (
  projectId: ProjectId,
  environmentId: EnvironmentId,
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

export function dekRegisteredEvent(
  actor: DataActor,
  signer: { readonly keyFingerprintHex: KeyFingerprintHex },
  nowMs: number,
  environmentId: EnvironmentId,
  wrap: DekWrapInput,
): AuditEventInput {
  return dataEvent(actor, nowMs, {
    event: "dek.registered",
    environmentId,
    epoch: wrap.epoch,
    ...dekRecipientTarget(wrap),
    actorKeyFingerprintHex: signer.keyFingerprintHex,
  });
}
