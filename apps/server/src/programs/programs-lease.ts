import type { EnvironmentId, LeaseDenialReason } from "@maruhi/core";
import type { ChainEntry, ChainState, ServerGrant } from "@maruhi/crypto";
import { Clock, Effect } from "effect";

import { AuditStore, type AuditEventInput } from "../audit-store.ts";
import type { EnvironmentPullValue, InitializedChain } from "../data.package/index.ts";
import {
  currentEpochOf,
  DataStore,
  loadInitializedChain,
  optionalCheckpointSnapshot,
  projectIdOf,
} from "../data.package/index.ts";
import type { StateCache } from "../do/chain-store.ts";
import { ChainStore, deriveStoredState } from "../do/chain-store.ts";
import { grantCoversEnvironment, leasePolicyAuthorizes } from "../lease-policy.ts";
import { MAX_LEASE_DENIED_ROWS_PER_WINDOW, MAX_LEASES_PER_WINDOW } from "../policy.ts";
import { requireActiveEnvironment } from "../quotas.ts";
import type { LeaseWrapOutput, ServerKeyInfo } from "../server-key.ts";
import { ServerKey } from "../server-key.ts";
import { observeStorageLevel, StorageMeter } from "../storage-guard.ts";

export interface LeaseTokenFacts {
  readonly issuer: string;
  readonly subject: string;
  readonly audiences: readonly string[];
  readonly claims: Readonly<Record<string, unknown>>;
  readonly claimsDigestHex: string;
  readonly bindingKeyHex: string;
  readonly bindingExpiresAtMs: number;
}

export interface LeaseValue extends Omit<EnvironmentPullValue, "deks" | "schemaPolicy"> {
  readonly headSeq: number;
  readonly headHashHex: string;
  readonly leases: readonly LeaseWrapOutput[];
}

export type LeaseRejection =
  | { readonly kind: "not-found" }
  | { readonly kind: "rate-limited"; readonly retryAfterSeconds: number }
  | {
      readonly kind: "unavailable";
      readonly reason: "server-wraps-missing" | "server-key-unconfigured";
    }
  | { readonly kind: "replayed" };

export type LeaseOutcome =
  | {
      readonly kind: "ok";
      readonly value: LeaseValue;
      readonly chainToken: string;
    }
  | { readonly kind: "rejected"; readonly rejection: LeaseRejection };

export const recordDenied = Effect.fn("programs-lease.recordDenied")(function* (
  reason: LeaseDenialReason,
  claimsDigestHex: string,
  nowMs: number,
) {
  const store = yield* DataStore;
  const decision = yield* store.checkLeaseWindow("denied", MAX_LEASE_DENIED_ROWS_PER_WINDOW, nowMs);
  if (!decision.allowed) {
    return;
  }
  const audit = yield* AuditStore;
  yield* Effect.sync(() => {
    store.recordLeaseWindowUse("denied", nowMs);
    audit.appendSync({
      event: "server.lease_denied",
      serverTs: nowMs,
      actorType: "system",
      payload: { reason, claimsDigest: claimsDigestHex },
    });
  });
});

const denyWithAudit = Effect.fn("programs-lease.denyWithAudit")(function* (
  reason: LeaseDenialReason,
  facts: LeaseTokenFacts,
  nowMs: number,
) {
  yield* recordDenied(reason, facts.claimsDigestHex, nowMs);
  return yield* Effect.fail<LeaseRejection>({ kind: "not-found" });
});

const rejectReplayedToken = Effect.fn("programs-lease.rejectReplayedToken")(function* (
  facts: LeaseTokenFacts,
  ephemeralPubHex: string,
  nowMs: number,
) {
  const store = yield* DataStore;
  const boundPubHex = yield* store.leaseBinding(facts.bindingKeyHex, nowMs);
  if (boundPubHex !== null && boundPubHex !== ephemeralPubHex) {
    yield* recordDenied("token-replayed", facts.claimsDigestHex, nowMs);
    return yield* Effect.fail<LeaseRejection>({ kind: "replayed" });
  }
});

interface AuthorizedWorkload {
  readonly serverKeyInfo: ServerKeyInfo;
  readonly chain: InitializedChain;
  readonly state: ChainState;
  readonly grant: ServerGrant;
  readonly nowMs: number;
}

export const authorizeWorkload = Effect.fn("programs-lease.authorizeWorkload")(function* (
  environmentId: EnvironmentId,
  ephemeralPubHex: string,
  facts: LeaseTokenFacts,
  cache: StateCache,
): Effect.fn.Return<
  AuthorizedWorkload,
  LeaseRejection,
  ChainStore | DataStore | AuditStore | ServerKey
> {
  const serverKey = yield* ServerKey;
  const serverKeyInfo = yield* serverKey.info;
  const nowMs = yield* Clock.currentTimeMillis;
  if (serverKeyInfo === null) {
    return yield* Effect.fail<LeaseRejection>({
      kind: "unavailable",
      reason: "server-key-unconfigured",
    });
  }
  const chain = yield* loadInitializedChain.pipe(
    Effect.mapError((): LeaseRejection => ({ kind: "not-found" })),
  );
  const { state } = yield* deriveStoredState(chain, cache);

  const grant = state.serverGrants.get(serverKeyInfo.serverKeyFingerprintHex);
  if (grant === undefined) {
    return yield* denyWithAudit("no-grant", facts, nowMs);
  }
  if (!leasePolicyAuthorizes(grant, facts)) {
    return yield* denyWithAudit("policy-mismatch", facts, nowMs);
  }
  if (!grantCoversEnvironment(grant, environmentId)) {
    return yield* denyWithAudit("scope-out-of-range", facts, nowMs);
  }

  yield* rejectReplayedToken(facts, ephemeralPubHex, nowMs);
  yield* requireActiveEnvironment(environmentId).pipe(
    Effect.matchEffect({
      onFailure: () => denyWithAudit("environment-not-found", facts, nowMs),
      onSuccess: () => Effect.void,
    }),
  );

  return { serverKeyInfo, chain, state, grant, nowMs };
});

export const leaseProgram = Effect.fn("programs-lease.leaseProgram")(function* (
  environmentId: EnvironmentId,
  ephemeralPubHex: string,
  facts: LeaseTokenFacts,
  cache: StateCache,
): Effect.fn.Return<
  LeaseValue,
  LeaseRejection,
  ChainStore | DataStore | AuditStore | ServerKey | StorageMeter
> {
  const serverKey = yield* ServerKey;
  const { serverKeyInfo, chain, state, grant, nowMs } = yield* authorizeWorkload(
    environmentId,
    ephemeralPubHex,
    facts,
    cache,
  );
  const store = yield* DataStore;

  const window = yield* store.checkLeaseWindow("issued", MAX_LEASES_PER_WINDOW, nowMs);
  if (!window.allowed) {
    yield* recordDenied("rate-limited", facts.claimsDigestHex, nowMs);
    return yield* Effect.fail<LeaseRejection>({
      kind: "rate-limited",
      retryAfterSeconds: window.retryAfterSeconds,
    });
  }

  const serverWraps = yield* store.listServerWraps(
    environmentId,
    serverKeyInfo.serverKeyFingerprintHex,
  );
  const currentEpoch = currentEpochOf(state, environmentId);
  const statement = yield* store.environmentStatement(environmentId);
  if (statement === null) {
    return yield* Effect.die(new Error("environment meta statement row missing"));
  }
  const variables = yield* store.latestVersions(environmentId);
  const deletedVariables = yield* store.deletedVariableStatements(environmentId);
  const declaredVariables = yield* store.declaredVariableStatements(environmentId);
  const manifest = yield* store.environmentManifest(environmentId);
  if (manifest === null) {
    return yield* Effect.die(new Error("environment manifest row missing"));
  }
  const checkpointSnapshot = yield* store.checkpointSnapshot(environmentId);

  const neededEpochs = [
    ...new Set([currentEpoch, ...variables.map((variable) => variable.epoch)]),
  ].toSorted((a, b) => a - b);
  const available = new Map(serverWraps.map((wrap) => [wrap.epoch, wrap]));
  const usable = neededEpochs.map((epoch) => available.get(epoch));
  if (usable.some((wrap) => wrap === undefined)) {
    yield* recordDenied("server-wraps-missing", facts.claimsDigestHex, nowMs);
    return yield* Effect.fail<LeaseRejection>({
      kind: "unavailable",
      reason: "server-wraps-missing",
    });
  }
  const wraps = usable.filter((wrap) => wrap !== undefined);

  const leases = yield* serverKey
    .reseal({
      projectId: projectIdOf(chain),
      environmentId,
      claimsDigestHex: facts.claimsDigestHex,
      workloadPubHex: ephemeralPubHex,
      wraps,
    })
    .pipe(
      Effect.matchEffect({
        onFailure: (failure) =>
          Effect.gen(function* () {
            yield* recordDenied(`reseal-${failure}`, facts.claimsDigestHex, nowMs);
            return yield* Effect.fail<LeaseRejection>({
              kind: "unavailable",
              reason: "server-wraps-missing",
            });
          }),
        onSuccess: (value) => Effect.succeed(value),
      }),
    );

  yield* observeStorageLevel;
  const audit = yield* AuditStore;
  yield* Effect.sync(() => {
    store.recordLeaseWindowUse("issued", nowMs);
    store.recordLeaseBinding(facts.bindingKeyHex, ephemeralPubHex, facts.bindingExpiresAtMs, nowMs);
    audit.appendManySync([
      ...leases.map((lease): AuditEventInput => ({
        event: "server.dek_unwrapped",
        serverTs: nowMs,
        actorType: "server" as const,
        actorKeyFingerprintHex: serverKeyInfo.serverKeyFingerprintHex,
        environmentId,
        epoch: lease.epoch,
      })),
      {
        event: "server.lease_issued",
        serverTs: nowMs,
        actorType: "server" as const,
        actorKeyFingerprintHex: serverKeyInfo.serverKeyFingerprintHex,
        environmentId,
        payload: {
          grantChainSeq: grant.grantSeq,
          claimsDigest: facts.claimsDigestHex,
          epochs: leases.map((lease) => lease.epoch),
        },
      },
    ]);
  });

  return {
    environmentId,
    currentEpoch,
    headSeq: chain.headSeq,
    headHashHex: chain.headHashHex,
    statement,
    variables,
    deletedVariables,
    ...(declaredVariables.length === 0 ? {} : { declaredVariables }),
    leases,
    manifest,
    ...optionalCheckpointSnapshot(checkpointSnapshot),
  } satisfies LeaseValue;
});

export const leaseChainProgram = Effect.fn("programs-lease.leaseChainProgram")(function* (
  head: { readonly seq: number; readonly hashHex: string },
  cache: StateCache,
): Effect.fn.Return<readonly ChainEntry[], never, ChainStore> {
  const chain = yield* loadInitializedChain.pipe(Effect.orDie);
  const { history } = yield* deriveStoredState(chain, cache);
  if (history.entryHashAt(head.seq) !== head.hashHex) {
    return yield* Effect.die(new Error("the lease head is not on the stored chain"));
  }
  return chain.entries.slice(0, head.seq);
});
