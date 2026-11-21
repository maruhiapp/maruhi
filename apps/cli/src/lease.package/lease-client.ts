import type {
  CheckpointValueSnapshot,
  DistributedEnvironmentManifest,
  DistributedEnvironmentMetaStatement,
  DistributedVariableMetaStatement,
  LeasedDek,
} from "@maruhi/api-schema";
import { cryptoEffect, type EnvironmentId, type ProjectId } from "@maruhi/core";
import type { ChainEntry, EncryptionKeyPair, LeaseClaims } from "@maruhi/crypto";
import {
  computeLeaseClaimsDigest,
  decodeHex,
  SUITE_ID,
  unwrapLeaseDek,
  verifyDekCommitment,
} from "@maruhi/crypto";
import { Effect, Redacted } from "effect";

import type { RepositoryAnchor } from "../anchor.ts";
import { checkRepositoryAnchor } from "../anchor.ts";
import { verifyChainSnapshot, type VerifiedProject } from "../chain-sync.ts";
import { requireChainEnvironment } from "../deks.ts";
import { displayText } from "../display.ts";
import { cliError, type CliError } from "../errors.ts";
import type { DeclaredVariable, DecryptedVariable } from "../pull.ts";
import { decryptVerifiedValue, toDeclaredVariables } from "../pull.ts";
import { serverDisclosures, serverKeysDisclosing } from "../server-disclosure.ts";
import type { PulledWire, VerifiedPulledValue } from "../values-verify.ts";
import { verifyLeaseDistribution } from "../values.ts";

export interface LeaseResponseWire {
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId;
  readonly currentEpoch: number;
  readonly chain: readonly ChainEntry[];
  readonly headSeq: number;
  readonly headHashHex: string;
  readonly statement: DistributedEnvironmentMetaStatement;
  readonly variables: readonly PulledWire[];
  readonly deletedVariables: readonly DistributedVariableMetaStatement[];
  readonly declaredVariables?: readonly DistributedVariableMetaStatement[] | undefined;
  readonly manifest: DistributedEnvironmentManifest;
  readonly checkpointSnapshot?: CheckpointValueSnapshot | undefined;
  readonly leases: readonly LeasedDek[];
}

export interface VerifiedLeaseMaterial {
  readonly verified: VerifiedProject;
  readonly variables: readonly DecryptedVariable[];
  readonly declared: readonly DeclaredVariable[];
  readonly warnings: readonly string[];
}

function unwrapOneLease(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly workloadKeyPair: EncryptionKeyPair;
  readonly claimsDigestHex: string;
  readonly lease: LeasedDek;
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

declare const leaseGrantCheckBrand: unique symbol;

interface LeaseGrantCheck {
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly [leaseGrantCheckBrand]: "LeaseGrantCheck";
}

function requireLeaseGrant(
  verified: VerifiedProject,
  environmentId: EnvironmentId,
): Effect.Effect<LeaseGrantCheck, CliError> {
  if (serverKeysDisclosing(serverDisclosures(verified), environmentId).length > 0) {
    return Effect.succeed({ verified, environmentId } as LeaseGrantCheck);
  }
  const environment = displayText(environmentId);
  return Effect.fail(
    cliError(
      `The server issued a lease for environment ${environment} of project ${displayText(verified.projectId)}, but the chain it sent carries no active grant_server naming that environment (CRYPTO_SPEC §9.1 (6)). The lease was not used: no leased DEK was opened and no value was decrypted. A conforming server answers 404 instead (AUTH_SPEC §14-1), so this server is not following the protocol: it served a chain other than the one it authorized against (for example one from before the grant), or it ignored the grant. Do not widen the grant to work around it; look at the server, and pin the current head with --anchor`,
    ),
  );
}

const unwrapLeases = Effect.fn("lease-client.unwrapLeases")(function* (input: {
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly grantCheck: LeaseGrantCheck;
  readonly workloadKeyPair: EncryptionKeyPair;
  readonly claims: LeaseClaims;
  readonly leases: readonly LeasedDek[];
}): Effect.fn.Return<ReadonlyMap<number, Redacted.Redacted<Uint8Array>>, CliError> {
  const { verified, environmentId } = input;
  if (input.grantCheck.verified !== verified || input.grantCheck.environmentId !== environmentId) {
    return yield* Effect.fail(
      cliError(
        "Internal error: the lease authorization check was made for another chain view or environment; the lease was not used",
      ),
    );
  }
  const environment = yield* requireChainEnvironment(verified, environmentId);
  const chainEpoch = environment.currentEpoch;
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
    byEpoch.set(lease.epoch, Redacted.make(dek, { label: "dek" }));
  }
  return byEpoch;
});

export const verifyLeaseResponse = Effect.fn("lease-client.verifyLeaseResponse")(function* (input: {
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId;
  readonly response: LeaseResponseWire;
  readonly claims: LeaseClaims;
  readonly workloadKeyPair: EncryptionKeyPair;
  readonly anchor: RepositoryAnchor | null;
}): Effect.fn.Return<VerifiedLeaseMaterial, CliError> {
  const response = input.response;
  if (response.projectId !== input.projectId || response.environmentId !== input.environmentId) {
    return yield* Effect.fail(
      cliError(
        "The lease response declares coordinates that do not match the requested project / environment (an inconsistent server response)",
      ),
    );
  }
  const verified = yield* verifyChainSnapshot({
    projectId: input.projectId,
    entries: response.chain,
    claimedHeadSeq: response.headSeq,
    claimedHeadHashHex: response.headHashHex,
  });
  if (input.anchor !== null) {
    yield* checkRepositoryAnchor({ anchor: input.anchor, verified });
  }
  const chainEnvironment = yield* requireChainEnvironment(verified, input.environmentId);
  const grantCheck = yield* requireLeaseGrant(verified, input.environmentId);
  const chainEpoch = chainEnvironment.currentEpoch;
  if (response.currentEpoch !== chainEpoch) {
    return yield* Effect.fail(
      cliError(
        `The lease response declares epoch ${response.currentEpoch}, but the chain derives epoch ${chainEpoch} (the response contradicts the chain)`,
      ),
    );
  }
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
  const deksByEpoch = yield* unwrapLeases({
    verified,
    environmentId: input.environmentId,
    grantCheck,
    workloadKeyPair: input.workloadKeyPair,
    claims: input.claims,
    leases: response.leases,
  });
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
