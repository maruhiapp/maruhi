// The Effect program for workload leases (AUTH_SPEC §14 = CRYPTO_SPEC §9.1).
//
// **Why unwrap and re-wrap inside the DO**: a lease involves three audit
// events (server.dek_unwrapped / server.lease_issued / server.lease_denied —
// AUDIT_SPEC §3.5), and to "record only what was distributed", the code that
// reads the response material and the audit append must be inside the same
// permit and the same synchronous block. Unwrapping on the worker side would
// split it into "the RPC that fetches wraps" and "the RPC that writes audit",
// breaking atomicity.
//
// No plaintext DEK appears in this program either: unwrap + re-wrap happen as
// one unit inside a ServerKey closure (server-key.ts), and only lease wraps
// come back.
//
// Check order (§14-3; OIDC verification is already done on the worker side =
// everything here is post-authorization):
//   1. A chain-derived valid grant (identified by server key FP) +
//      existential quantification of lease_policy + disclosure scope → every
//      mismatch is uniformly 404 (§11-2 existence concealment).
//      **What is indistinguishable is the response (status + body), not the
//      latency**: an unknown project short-circuits after one storage read,
//      while a real project goes through chain verification and audit writes,
//      so there is a measurable difference. The judgment is that timing is
//      outside the threat model (aiming for constant time on the
//      unauthenticated surface is unrealistic)
//   1.5 First-come binding (§14-1; 2026-08-15 ruling) — the same token + a
//      different key gets a 401 `token-replayed`. Placed right after
//      authorization and before the environment-existence check (returns a
//      uniform 401 to a holder of a copy of a bound token regardless of
//      whether the environment exists — §14-3). Read-only; does not consume
//      the rate window
//   2. Environment existence (a deleted one is 404 — same treatment as §12-4)
//   3. Rate limit (429) — after authorization (the rationale in
//      errors/lease.ts)
//   4. Existence of wraps addressed to the server (missing = 503
//      server-wraps-missing)
//   5. Unwrap → re-wrap → audit → response (the first-come-binding record is
//      in the same synchronous block)

import type { ChainEntry, ChainState, ServerGrant } from "@maruhi/crypto";
import { Clock, Effect } from "effect";

import { AuditStore, type AuditEventInput } from "../audit-store.ts";
import type { EnvironmentPullValue, InitializedChain } from "../data/data-plane.ts";
import {
  currentEpochOf,
  loadInitializedChain,
  optionalCheckpointSnapshot,
} from "../data/data-plane.ts";
import { DataStore } from "../data/data-store.ts";
import type { StateCache } from "../do/chain-store.ts";
import { ChainStore, deriveStoredState } from "../do/chain-store.ts";
import { grantCoversEnvironment, leasePolicyAuthorizes } from "../lease-policy.ts";
import { MAX_LEASE_DENIED_ROWS_PER_WINDOW, MAX_LEASES_PER_WINDOW } from "../policy.ts";
import { requireActiveEnvironment } from "../quotas.ts";
import type { LeaseWrapOutput, ServerKeyInfo } from "../server-key.ts";
import { ServerKey } from "../server-key.ts";
import { observeStorageLevel, StorageMeter } from "../storage-guard.ts";

/** Only the parts of a verified OIDC token that authorization and binding need, passed by the worker. */
export interface LeaseTokenFacts {
  readonly issuer: string;
  readonly subject: string;
  readonly audiences: readonly string[];
  /**
   * The evaluation target of claim constraints (§14-1). Must be a plain
   * structured-clone-safe object because it crosses the RPC boundary.
   * **Appears in neither audit nor the response** (do not carry in external
   * identifiers — §14-4 / AUDIT_SPEC §1-2).
   */
  readonly claims: Readonly<Record<string, unknown>>;
  /** claims_digest_hex of CRYPTO_SPEC §9.1 (already computed by the worker via crypto). */
  readonly claimsDigestHex: string;
  /**
   * The dedup key of the first-come binding (§14-1; 2026-08-15 ruling) = the
   * SHA-256 of the JWS signing input (`header.payload`), lowercase hex
   * (computed by the worker's verifier after signature verification —
   * VerifiedOidcToken.signingInputHashHex). **Not a hash of the raw token**:
   * the raw token's signature segment is malleable and could slip past the
   * binding (same doc). Nor is it jti — jti's presence and semantics depend on
   * the issuer, while the signing-input hash requires nothing of the issuer
   * (docs/notes/session-24.md §4).
   */
  readonly bindingKeyHex: string;
  /**
   * Lifetime of the binding row (ms). The worker computes it as "the token's
   * exp + retention margin (policy.ts — the derivation guarantees it is at
   * least the clock skew of time validation)".
   */
  readonly bindingExpiresAtMs: number;
}

/**
 * The lease response's RPC value. The bulk pull-with-values shape (§12-7)
 * minus `deks`, plus the whole chain (the §14-2 bundling — a non-member gets
 * 404 from the chain API, so this is the only distribution path) and the
 * lease wraps.
 */
// The advisory bundling of schemaPolicy targets only the environment list and
// the two pull responses (§12-7 / §12-11) — it is not carried on the lease
// response
export interface LeaseValue extends Omit<EnvironmentPullValue, "deks" | "schemaPolicy"> {
  readonly chain: readonly ChainEntry[];
  readonly headSeq: number;
  readonly headHashHex: string;
  readonly leases: readonly LeaseWrapOutput[];
}

/** Lease-specific rejections (a different vocabulary from the data plane's DataRejection). */
export type LeaseRejection =
  | { readonly kind: "not-found" }
  | { readonly kind: "rate-limited"; readonly retryAfterSeconds: number }
  | {
      readonly kind: "unavailable";
      readonly reason: "server-wraps-missing" | "server-key-unconfigured";
    }
  // First-come-binding violation (§14-1): the same token was already issued to
  // a different ephemeral key. Becomes a 401 `token-replayed` on the worker
  // side (not folded into 404 — keeping the legitimate job's failure
  // diagnosable is half of the first-come binding's observability. Compatible
  // with existence concealment: reachable only after authorization)
  | { readonly kind: "replayed" };

/** The lease result crossing the RPC boundary. */
export type LeaseOutcome =
  | { readonly kind: "ok"; readonly value: LeaseValue }
  | { readonly kind: "rejected"; readonly rejection: LeaseRejection };

/**
 * server.lease_denied (AUDIT_SPEC §3.5): records **only rejections after OIDC
 * signature verification passed**, under a fixed-window global bound (the same
 * discipline as auth.login_failed). The actor is `{ type: "system" }` — an
 * external workload has no identity on maruhi and it is not an exercise of the
 * server key. Only the reason code and claims_digest go on the payload;
 * external identifiers such as repository names are not written (§14-4).
 */
export const recordDenied = Effect.fn("programs-lease.recordDenied")(function* (
  reason: string,
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

/** Fold rejection + audit recording into one (leaves no path that forgets to record). */
const denyWithAudit = Effect.fn("programs-lease.denyWithAudit")(function* (
  reason: string,
  facts: LeaseTokenFacts,
  nowMs: number,
) {
  yield* recordDenied(reason, facts.claimsDigestHex, nowMs);
  return yield* Effect.fail<LeaseRejection>({ kind: "not-found" });
});

/**
 * The first-come-binding check stage (§14-1; 2026-08-15 ruling —
 * docs/notes/session-24.md): reject when the same token was already issued to
 * a **different** ephemeral key. The same token + the same key passes
 * (idempotency of a legitimate retry after losing the response — do not break
 * pre-issuing issuers whose tokens cannot be reissued at runtime). The check
 * is read-only and does not consume the rate window.
 */
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

/** What the shared authorization front stage hands the lease and the proposal programs. */
interface AuthorizedWorkload {
  readonly serverKeyInfo: ServerKeyInfo;
  readonly chain: InitializedChain;
  readonly state: ChainState;
  readonly grant: ServerGrant;
  readonly nowMs: number;
}

/**
 * The front stage shared by the lease (§14-2) and the sealed-proposal
 * mint (§14-5): steps 0–2 of the check order — the server key's
 * presence, the initialized chain, our own grant × lease_policy × scope
 * (every mismatch a uniform 404 with a lease_denied row), the first-come
 * binding (401 replayed), the environment's existence. Everything after
 * it (windows, material, writes) is per program.
 */
export const authorizeWorkload = Effect.fn("programs-lease.authorizeWorkload")(function* (
  environmentId: string,
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
  // 0. A deployment with no server key configured fails **before reading the
  // project**. Order matters: if chain loading (uninitialized = 404) ran
  // first, a keyless deployment would produce the "unknown = 404 / real =
  // 503" split and leak the project's existence (§11-2). Failing first makes
  // every request uniformly 503 and leaks nothing. The reason is not 404
  // because missing configuration does not mean "this project does not
  // exist" (without the private key the unwrap path itself does not exist)
  if (serverKeyInfo === null) {
    return yield* Effect.fail<LeaseRejection>({
      kind: "unavailable",
      reason: "server-key-unconfigured",
    });
  }
  // An uninitialized project is 404 with no audit left behind: letting the
  // unauthenticated path create DO rows for arbitrary project IDs would be
  // an audit-log inflation DoS. The project ID is a genesis hash =
  // effectively a capability and cannot be guessed. **Note the fixed window
  // below bounds the number of audit rows, not the probe itself** (someone
  // holding one valid token from an allowed issuer can repeat requests to a
  // known project ID to impose chain-derivation cost, and after exhausting
  // the 100 rows/hour can create a state where subsequent denials go
  // unrecorded). Also, the DO constructor creates the empty tables on reach,
  // so a probe to an arbitrary project ID consumes DO-instantiation storage
  // even without leaving an audit row.
  // A limit on the request rate itself is unimplemented and is deferred as a
  // design decision separate from AUDIT_SPEC §3.5's recording bound
  const chain = yield* loadInitializedChain.pipe(
    Effect.mapError((): LeaseRejection => ({ kind: "not-found" })),
  );
  // Derivation cannot fail (verification failure of a stored chain is a
  // defect — chain-store.ts)
  const { state } = yield* deriveStoredState(chain, cache);

  // 1. Authorization: a valid grant of our own server key × lease_policy
  // (existential quantification) × disclosure scope. What matches is always
  // "the grant of our own FP" — the server can only unwrap wraps addressed
  // to itself, so grant identification has no nondeterminism
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

  // 1.5 First-come binding (§14-1). Placed right after authorization and
  // **before** the environment-existence check — a holder of a copy of a
  // bound token gets a uniform 401 regardless of whether the target
  // environment exists or is deleted, so no existence information is given
  // (§14-3)
  yield* rejectReplayedToken(facts, ephemeralPubHex, nowMs);
  // 2. Environment existence (a deleted tombstone is 404)
  yield* requireActiveEnvironment(environmentId).pipe(
    Effect.matchEffect({
      onFailure: () => denyWithAudit("environment-not-found", facts, nowMs),
      onSuccess: () => Effect.void,
    }),
  );

  return { serverKeyInfo, chain, state, grant, nowMs };
});

export const leaseProgram = Effect.fn("programs-lease.leaseProgram")(function* (
  environmentId: string,
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

  // 3. The rate limit **check** (after authorization — for existence
  // concealment; errors/lease.ts). Consumption happens only "when a lease is
  // actually issued" (step 6 below). Consuming here would make a project
  // that 503s on missing server wraps (4) or unwrap failure (5) burn its
  // window on every CI retry, and from the 300th retry onward the 503 — a
  // "diagnosable, fixable" failure — turns into an unrelated 429, defeating
  // the point of §14-3 deliberately providing a 503
  const window = yield* store.checkLeaseWindow("issued", MAX_LEASES_PER_WINDOW, nowMs);
  if (!window.allowed) {
    yield* recordDenied("rate-limited", facts.claimsDigestHex, nowMs);
    return yield* Effect.fail<LeaseRejection>({
      kind: "rate-limited",
      retryAfterSeconds: window.retryAfterSeconds,
    });
  }

  // 4. Existence of wraps addressed to the server (missing = 503; do not
  // let the "granted but re-wrap incomplete" state become an opaque failure
  // — §14-3. Per the A1 ruling, this is the last line of defense against a
  // missed backfill)
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
  // Statements of declared variables (apply the §12-7 distribution rules to
  // the lease response too — material for the workload's manifest-digest
  // recomputation [§9.1 (5)])
  const declaredVariables = yield* store.declaredVariableStatements(environmentId);
  // The latest manifest (§14-2 — material for the workload's verification
  // obligation §9.1 (5); the receiving side rejects any missing uniformly)
  // — a required response field since 0.28-draft: a created environment
  // always has a stored row (§12-4's atomic write), so a missing row is
  // an invariant violation = defect, never an omission
  const manifest = yield* store.environmentManifest(environmentId);
  if (manifest === null) {
    return yield* Effect.die(new Error("environment manifest row missing"));
  }
  // The value snapshot at the checkpoint (§14-2 — the same material as
  // §12-7; null for an environment without a baseline = not included)
  const checkpointSnapshot = yield* store.checkpointSnapshot(environmentId);

  // Every epoch used by the latest values in the response + the current
  // epoch (§14-2). Require the full set with no gaps — if even one is
  // missing, an undecryptable value would ride on the response
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

  // 5. Unwrap → re-wrap (no plaintext DEK escapes the ServerKey closure)
  const leases = yield* serverKey
    .reseal({
      projectId: chain.genesisHashHex,
      environmentId,
      claimsDigestHex: facts.claimsDigestHex,
      workloadPubHex: ephemeralPubHex,
      wraps,
    })
    .pipe(
      Effect.matchEffect({
        onFailure: (failure) =>
          Effect.gen(function* () {
            // Unwrap failure = a poisoned wrap (the target of the §12-6
            // repair path); re-wrap failure = the workload public key is
            // invalid as a point. Both are "a grant exists but no usable
            // material", so they fold into the same 503 as
            // server-wraps-missing (the finer reason lives in the
            // operator-facing audit row)
            yield* recordDenied(`reseal-${failure}`, facts.claimsDigestHex, nowMs);
            return yield* Effect.fail<LeaseRejection>({
              kind: "unavailable",
              reason: "server-wraps-missing",
            });
          }),
        onSuccess: (value) => Effect.succeed(value),
      }),
    );

  // Observation only for the DO storage total guard (AUTH_SPEC §12-8 — no
  // rejection. A lease is one of the surfaces accepted even under rejection
  // (e), but since it is a read that writes audit rows it carries a warning
  // observation point — same reason as pull-with-values). After
  // authorization = compatible with existence concealment (§11-2)
  yield* observeStorageLevel;
  // Audit (AUDIT_SPEC §3.5): one server.dek_unwrapped row per epoch + one
  // server.lease_issued row per environment. The actor is `{ server, key FP
  // }`. **No var.read is recorded** (that is the evidence of a human actor's
  // read; disclosure to workloads is carried by the server.* family — §14-4)
  const audit = yield* AuditStore;
  yield* Effect.sync(() => {
    // 6. Window consumption and the first-come-binding record happen in the
    // same synchronous block as issuance (count only what was recorded /
    // create neither intermediate state — "a binding left without an
    // issuance" nor "issued but no binding left" — §14-1)
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
          // The matching policy element is held by the chain (the grant
          // payload) and can be cross-checked via grant_chain_seq +
          // claims_digest. No external identifiers (repository names etc.)
          // are written (§14-4)
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
    chain: chain.entries,
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
