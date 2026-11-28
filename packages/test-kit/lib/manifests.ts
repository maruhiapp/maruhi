import { computeEnvManifestSignedBytesHash, signEnvManifest, SUITE_ID } from "@maruhi/crypto";
import {
  testEnvironmentId,
  testProjectId,
  testUserId,
  unwrapResult,
} from "@maruhi/crypto/test-support";

import type { ChainHead } from "./chain.ts";
import type { SigningIdentity, TestIdentity } from "./identity.ts";
import { signingKeyOf } from "./identity.ts";
import { distributedStatementHashOf, distributedVariablesDigestOf } from "./statements.ts";
import type {
  WireDistributedEnvironmentStatement,
  WireDistributedManifest,
  WireDistributedVariableStatement,
  WireEnvironmentManifest,
} from "./wire.ts";

export type UnsignedManifest = Omit<WireEnvironmentManifest, "signatureHex" | "suite"> & {
  readonly suite: string;
};

function manifestContextOf(projectId: string, manifest: UnsignedManifest, issuerUserId: string) {
  return {
    suite: manifest.suite,
    projectId: testProjectId(projectId),
    environmentId: testEnvironmentId(manifest.environmentId),
    epoch: manifest.epoch,
    manifestVersion: manifest.manifestVersion,
    variablesDigestHex: manifest.variablesDigestHex,
    envMetaVersion: manifest.envMetaVersion,
    envMetaSigHashHex: manifest.envMetaSigHashHex,
    prevManifestSigHashHex: manifest.prevManifestSigHashHex,
    issuerUserId: testUserId(issuerUserId),
    chainHeadHashHex: manifest.chainHeadHashHex,
    chainHeadSeq: manifest.chainHeadSeq,
  };
}

export async function signManifest<const T extends UnsignedManifest>(
  issuer: SigningIdentity & Pick<TestIdentity, "userId">,
  projectId: string,
  unsigned: T,
): Promise<T & { readonly signatureHex: string }> {
  const signatureHex = unwrapResult(
    await signEnvManifest({
      context: manifestContextOf(projectId, unsigned, issuer.userId),
      signingKey: await signingKeyOf(issuer),
    }),
    "signEnvManifest",
  );
  return { ...unsigned, signatureHex };
}

export async function manifestSignedBytesHashOf(
  projectId: string,
  manifest: UnsignedManifest,
  issuerUserId: string,
): Promise<string> {
  return unwrapResult(
    await computeEnvManifestSignedBytesHash(manifestContextOf(projectId, manifest, issuerUserId)),
    "computeEnvManifestSignedBytesHash",
  );
}

export async function distributedManifest(input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly epoch: number;
  readonly issuer: TestIdentity;
  readonly head: ChainHead;
  readonly envStatement: WireDistributedEnvironmentStatement;
  readonly statements?: readonly WireDistributedVariableStatement[];
  readonly manifestVersion?: number;
  readonly prevManifestSigHashHex?: string;
  readonly variablesDigestHex?: string;
}): Promise<WireDistributedManifest> {
  const manifestVersion = input.manifestVersion ?? 1;
  const signed = await signManifest(input.issuer, input.projectId, {
    suite: SUITE_ID,
    environmentId: input.environmentId,
    epoch: input.epoch,
    manifestVersion,
    variablesDigestHex:
      input.variablesDigestHex ??
      (await distributedVariablesDigestOf(input.projectId, input.statements ?? [])),
    envMetaVersion: input.envStatement.metaVersion,
    envMetaSigHashHex: await distributedStatementHashOf(input.projectId, input.envStatement),
    prevManifestSigHashHex:
      input.prevManifestSigHashHex ?? (manifestVersion === 1 ? "" : "cd".repeat(32)),
    chainHeadHashHex: input.head.hashHex,
    chainHeadSeq: input.head.seq,
  });
  return {
    ...signed,
    issuerUserId: input.issuer.userId,
    issuerKeyFingerprintHex: input.issuer.fingerprintHex,
  };
}

export async function distributedManifestHashOf(
  projectId: string,
  manifest: WireDistributedManifest,
): Promise<string> {
  return manifestSignedBytesHashOf(projectId, manifest, manifest.issuerUserId);
}
