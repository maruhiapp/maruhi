// Verifying, opening, and decrypting workload lease responses (the
// receiving workload's verification obligations of CRYPTO_SPEC §9.1 /
// AUTH_SPEC §14-2).
//
// A lease response is **self-contained**: the chain, the current
// epoch, the latest values of every active variable, the latest
// meta-statements, and the lease-wrapped DEKs are all bundled in one
// response (the chain API returns 404 to non-members, so this is the
// only distribution path — §14-2). Verification material is never
// fetched from other endpoints.
//
// Verification obligations, mapped:
//   (1) Chain verification — verifyChainSnapshot (the same
//       implementation as chain-sync.ts). genesis = projectId is checked
//       against the value pre-pinned in the CI config (--project)
//   (2) Repository anchor (SHOULD) — anchor.ts (when --anchor is
//       given)
//   (3) DEK commitment check (§5.2) — after unwrapLeaseDek's open,
//       before use. A lease wrap carries no §5.1 registration
//       signature (server-generated, response-scoped — the LeasedDek
//       type distinguishes it structurally), so deks.ts's
//       signature-verification stage does not apply; the epoch-cap,
//       duplicate, and commitment-presence checks live here. No DEK
//       length check is invented (a Seal that is not 32 bytes fails
//       the commitment check)
//   (4) Value-signature / meta-statement verification — values.ts's
//       verifyLeaseDistribution (a future head is refused outright,
//       no re-sync — since the chain is bundled, there is no honest
//       explanation of "my chain is just old")
//   (5) Manifest / checkpoint-consistency verification — also inside
//       verifyLeaseDistribution
//   (6) Lease authorization — requireLeaseGrant, right after (1) and
//       (2): some active grant on the verified chain names the
//       environment (server-disclosure.ts's derivation), or the lease
//       is refused before any lease wrap is opened
//
// No floor is used: the workload is a floorless first-sync class
// (§14.3-3), and its main mitigation is the anchor of (2).

import type {
  CheckpointValueSnapshot,
  DistributedEnvironmentManifest,
  DistributedEnvironmentMetaStatement,
  DistributedVariableMetaStatement,
  LeasedDek,
} from "@maruhi/api-schema";
import { cryptoEffect } from "@maruhi/core";
import type { EnvironmentId, ProjectId } from "@maruhi/core";
import type { ChainEntry, EncryptionKeyPair, LeaseClaims } from "@maruhi/crypto";
import {
  computeLeaseClaimsDigest,
  decodeHex,
  SUITE_ID,
  unwrapLeaseDek,
  verifyDekCommitment,
} from "@maruhi/crypto";
import { Effect, Redacted } from "effect";

import type { RepositoryAnchor } from "./anchor.ts";
import { checkRepositoryAnchor } from "./anchor.ts";
import { verifyChainSnapshot, type VerifiedProject } from "./chain-sync.ts";
import { requireChainEnvironment } from "./deks.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import type { DeclaredVariable, DecryptedVariable } from "./pull.ts";
import { decryptVerifiedValue, toDeclaredVariables } from "./pull.ts";
import { serverDisclosures, serverKeysDisclosing } from "./server-disclosure.ts";
import type { PulledWire, VerifiedPulledValue } from "./values-verify.ts";
import { verifyLeaseDistribution } from "./values.ts";

/** The wire shape of a lease response (the structural type of api-schema's LeaseResponseSchema). */
export interface LeaseResponseWire {
  readonly projectId: string;
  readonly environmentId: string;
  readonly currentEpoch: number;
  readonly chain: readonly ChainEntry[];
  readonly headSeq: number;
  readonly headHashHex: string;
  readonly statement: DistributedEnvironmentMetaStatement;
  readonly variables: readonly PulledWire[];
  readonly deletedVariables: readonly DistributedVariableMetaStatement[];
  /**
   * The latest statements of declared variables (§14-2 — no values.
   * The material of `ci run`'s presence check. Absent = nothing
   * declared).
   */
  readonly declaredVariables?: readonly DistributedVariableMetaStatement[] | undefined;
  /**
   * The latest manifest (§14-2 — required on the wire; the schema
   * refuses an omission at decode — the same verdict as a dropped
   * environment statement, §9.1 (5) / §6.3).
   */
  readonly manifest: DistributedEnvironmentManifest;
  /**
   * The value-snapshot enumeration at the checkpoint (§14-2 — the
   * material of rule 2. A response that omits it despite a baseline
   * existing on the bundled chain is refused by
   * checkpoint-integrity.ts).
   */
  readonly checkpointSnapshot?: CheckpointValueSnapshot | undefined;
  readonly leases: readonly LeasedDek[];
}

/** The execution material verified and decrypted from a lease response (crosses the same injection boundary as run). */
export interface VerifiedLeaseMaterial {
  /** The verified chain view the material was checked under (the recipient set of a sealed proposal — ci-rotate.ts). */
  readonly verified: VerifiedProject;
  readonly variables: readonly DecryptedVariable[];
  /** The verified declared (no values — the presence check is the caller ci-run.ts). */
  readonly declared: readonly DeclaredVariable[];
  /** SHOULD warnings such as non-NFC-name distribution (the caller displays them). */
  readonly warnings: readonly string[];
}

/**
 * Opens one lease wrap + commitment check (§5.2 / §9.1 verification
 * obligation (3)). The DEK never leaves this function until the
 * check succeeds. The coordinates are built from my own verified
 * values (genesis hash, requested environment).
 */
function unwrapOneLease(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly workloadKeyPair: EncryptionKeyPair;
  readonly claimsDigestHex: string;
  readonly lease: LeasedDek;
  /** The chain-derived commitment for that (environment, epoch) (§5.2). */
  readonly expectedCommitmentHex: string;
}): Effect.Effect<Uint8Array, CliError> {
  const { verified, environmentId, lease } = input;
  return Effect.gen(function* () {
    const enc = decodeHex(lease.encHex);
    const ciphertext = decodeHex(lease.ciphertextHex);
    if (enc === null || ciphertext === null) {
      return yield* Effect.fail(cliError(`The leased DEK is malformed (epoch=${lease.epoch})`));
    }
    const dek = yield* cryptoEffect(() =>
      unwrapLeaseDek({
        workloadKeyPair: input.workloadKeyPair,
        wrapped: { enc, ciphertext },
        context: {
          projectId: verified.projectId,
          environmentId,
          epoch: lease.epoch,
          claimsDigestHex: input.claimsDigestHex,
        },
      }),
    ).pipe(
      Effect.mapError(() =>
        cliError(
          `Cannot open the leased DEK (epoch=${lease.epoch}). The lease was issued for a different workload identity or context (claims-digest mismatch), or the response is corrupt`,
        ),
      ),
    );
    yield* cryptoEffect(() =>
      verifyDekCommitment({
        context: {
          suite: SUITE_ID,
          projectId: verified.projectId,
          environmentId,
          epoch: lease.epoch,
        },
        dek,
        expectedCommitmentHex: input.expectedCommitmentHex,
      }),
    ).pipe(
      Effect.mapError(() =>
        cliError(
          `The leased DEK does not match the commitment on the chain (epoch=${lease.epoch}). This may be a fake DEK injected by a compromised server — do not trust this response`,
        ),
      ),
    );
    return dek;
  });
}

/**
 * Set checks of lease wraps (declared epoch vs the chain cap,
 * duplicate refusal, commitment presence). The same discipline as
 * the pre-loop stage of deks.ts's verifyAndUnwrapDeks; on pass it
 * returns that epoch's expected commitment.
 */
function leaseEpochProblem(
  chainEpoch: number,
  seen: ReadonlySet<number>,
  lease: LeasedDek,
): string | null {
  if (lease.suite !== SUITE_ID) {
    return `The leased DEK uses an unknown suite (${lease.suite})`;
  }
  if (lease.epoch > chainEpoch) {
    return `A leased DEK for epoch ${lease.epoch}, beyond the chain's current epoch (${chainEpoch}), was served (the response contradicts the chain)`;
  }
  if (seen.has(lease.epoch)) {
    return `Duplicate leased DEKs for the same epoch (epoch=${lease.epoch})`;
  }
  return null;
}

/**
 * Opens lease-wrapped DEKs and checks commitments (§9.1's
 * verification obligation (3)). The same discipline as deks.ts's
 * verifyAndUnwrapDeks (declared epoch vs the chain cap, duplicate
 * refusal, DEK unused until the check against the chain-derived
 * commitment), applied to lease wraps that carry no §5.1
 * registration signature.
 */
const unwrapLeases = Effect.fn("lease-client.unwrapLeases")(function* (input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly workloadKeyPair: EncryptionKeyPair;
  readonly claims: LeaseClaims;
  readonly leases: readonly LeasedDek[];
}): Effect.fn.Return<ReadonlyMap<number, Redacted.Redacted<Uint8Array>>, CliError> {
  const { verified, environmentId } = input;
  const environment = yield* requireChainEnvironment(verified, environmentId);
  const chainEpoch = environment.currentEpoch;
  // Only the verified entry point (computeLeaseClaimsDigest) is
  // used for the claims digest — using the builder directly bypasses
  // the empty-field guards
  const digest = yield* cryptoEffect(() => computeLeaseClaimsDigest(input.claims)).pipe(
    Effect.mapError(() =>
      cliError("Failed to compute the lease claims digest (the OIDC claims are unusable)"),
    ),
  );
  const byEpoch = new Map<number, Redacted.Redacted<Uint8Array>>();
  for (const lease of input.leases) {
    const problem = leaseEpochProblem(chainEpoch, new Set(byEpoch.keys()), lease);
    if (problem !== null) {
      return yield* Effect.fail(cliError(problem));
    }
    const expectedCommitmentHex = environment.dekCommitments.get(lease.epoch);
    if (expectedCommitmentHex === undefined) {
      return yield* Effect.fail(
        cliError(
          `No commitment for epoch ${lease.epoch} exists on the chain (a chain-derivation inconsistency)`,
        ),
      );
    }
    const dek = yield* unwrapOneLease({
      verified,
      environmentId,
      workloadKeyPair: input.workloadKeyPair,
      claimsDigestHex: digest,
      lease,
      expectedCommitmentHex,
    });
    // The opened DEK is wrapped here (after passing the §5.2 check
    // — a pre-check DEK never leaves unwrapOneLease's inside)
    byEpoch.set(lease.epoch, Redacted.make(dek, { label: "dek" }));
  }
  return byEpoch;
});

/**
 * The lease authorization check (§9.1 verification obligation (6)): the
 * verified chain must carry an active grant whose scope names the leased
 * environment. A union over the active grants — a project may hold one grant
 * per server key (mirrors — §9.2), and the workload cannot authenticate which
 * key served it. The lease policy is not evaluated here (the server enforces
 * it; claims_digest binds the workload identity — §9.1). Without an anchor
 * this is defense in depth only: a server can serve an older prefix in which
 * the grant was still active (the workload is floorless — §14.3-3).
 */
function requireLeaseGrant(
  verified: VerifiedProject,
  environmentId: string,
): Effect.Effect<void, CliError> {
  if (serverKeysDisclosing(serverDisclosures(verified), environmentId).length > 0) {
    return Effect.void;
  }
  return Effect.fail(
    cliError(
      `The verified chain grants no server environment ${displayText(environmentId)} of project ${displayText(verified.projectId)} (no active grant_server names it — CRYPTO_SPEC §9.1 (6)). The lease was not used: no leased DEK was opened and no value was decrypted. Likely causes: the grant was revoked or never covered this environment (a project owner grants it with \`maruhi server grant\`), or the server served a stale chain (pin a recent head with --anchor so a stale chain is refused)`,
    ),
  );
}

/**
 * Verifies a lease response end to end (CRYPTO_SPEC §9.1 duties (1)–(6)) and
 * decrypts every latest value. Nothing in the response is trusted before it
 * passes: the chain is re-verified against the pre-pinned genesis, declared
 * coordinates are cross-checked against derived state, every statement and
 * value signature is verified, and every DEK must match its chain-published
 * commitment before use.
 */
export const verifyLeaseResponse = Effect.fn("lease-client.verifyLeaseResponse")(function* (input: {
  /** The genesis pre-pinned in the CI config (= `--project` — §9.1 verification obligation (1)). */
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId;
  readonly response: LeaseResponseWire;
  readonly claims: LeaseClaims;
  readonly workloadKeyPair: EncryptionKeyPair;
  /** The repository anchor (§6.3 (b) — SHOULD. Only when --anchor is given). */
  readonly anchor: RepositoryAnchor | null;
}): Effect.fn.Return<VerifiedLeaseMaterial, CliError> {
  const response = input.response;
  // Consistency of the declared coordinates (same posture as
  // §6.3-5): a response whose declared coordinates differ from the
  // requested ones would be dropped by later verification anyway,
  // but what differed is surfaced first
  if (response.projectId !== input.projectId || response.environmentId !== input.environmentId) {
    return yield* Effect.fail(
      cliError(
        "The lease response declares coordinates that do not match the requested project / environment (an inconsistent server response)",
      ),
    );
  }
  // (1) Chain verification: full re-verification of the bundled
  // chain + genesis hash = the pre-pinned projectId + consistency
  // of declared head vs derived head (the same implementation as
  // chain-sync.ts)
  const verified = yield* verifyChainSnapshot({
    projectId: input.projectId,
    entries: response.chain,
    claimedHeadSeq: response.headSeq,
    claimedHeadHashHex: response.headHashHex,
  });
  // (2) Repository anchor (SHOULD): containment of the pinned head
  // + non-regression of the environment epoch (detection of rewind
  // distribution — CI has no floor, so this substitutes)
  if (input.anchor !== null) {
    yield* checkRepositoryAnchor({ anchor: input.anchor, verified });
  }
  // A deleted or unknown environment is refused first (its own message —
  // a deletion also prunes the id from every grant scope, §6.2)
  const chainEnvironment = yield* requireChainEnvironment(verified, input.environmentId);
  // (6) Lease authorization: an active grant on the verified chain names
  // the environment — before any lease wrap is opened
  yield* requireLeaseGrant(verified, input.environmentId);
  // Only the chain-derived value is used for the current epoch
  // (§6.2). The declared currentEpoch is checked only for agreement
  // with the derived value (declared values are not trusted)
  const chainEpoch = chainEnvironment.currentEpoch;
  if (response.currentEpoch !== chainEpoch) {
    return yield* Effect.fail(
      cliError(
        `The lease response declares epoch ${response.currentEpoch}, but the chain derives epoch ${chainEpoch} (the response contradicts the chain)`,
      ),
    );
  }
  // (4) Value-signature / meta-statement verification (a future head is refused outright)
  const distribution = yield* verifyLeaseDistribution({
    verified,
    environmentId: input.environmentId,
    wire: {
      statement: response.statement,
      variables: response.variables,
      deletedVariables: response.deletedVariables,
      declaredVariables: response.declaredVariables,
      manifest: response.manifest,
      checkpointSnapshot: response.checkpointSnapshot,
    },
  });
  // (3) Opening the lease wraps + DEK commitment check
  const deksByEpoch = yield* unwrapLeases({
    verified,
    environmentId: input.environmentId,
    workloadKeyPair: input.workloadKeyPair,
    claims: input.claims,
    leases: response.leases,
  });
  // Decryption (the same decryptVerifiedValue as run / rotate — the
  // decryption context is built from verified coordinates; a
  // missing wrap for a value's epoch is a strict failure)
  const variables = yield* decryptDistributed({
    verified,
    environmentId: input.environmentId,
    variables: distribution.variables,
    deksByEpoch,
    chainEpoch,
  });
  return {
    verified,
    variables,
    declared: toDeclaredVariables(distribution.declared),
    warnings: distribution.warnings,
  };
});

/** Decrypts every verified distributed value (into the same material shape as pull.ts's pullVariables). */
function decryptDistributed(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly variables: readonly VerifiedPulledValue[];
  readonly deksByEpoch: ReadonlyMap<number, Redacted.Redacted<Uint8Array>>;
  readonly chainEpoch: number;
}): Effect.Effect<readonly DecryptedVariable[], CliError> {
  return Effect.forEach(input.variables, (variable) =>
    Effect.map(
      decryptVerifiedValue({
        verified: input.verified,
        environmentId: input.environmentId,
        variable,
        deksByEpoch: input.deksByEpoch,
        chainEpoch: input.chainEpoch,
      }),
      (plaintext): DecryptedVariable => ({
        variableId: variable.variableId,
        name: variable.name,
        version: variable.version,
        epoch: variable.epoch,
        varType: variable.schema?.varType ?? "",
        required: variable.schema?.required ?? false,
        maxAgeDays: variable.schema?.maxAgeDays ?? null,
        value: plaintext,
      }),
    ),
  );
}
