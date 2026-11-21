import { cryptoPromise, type EnvironmentId, type ProjectId } from "@maruhi/core";
import type { EncryptionKeyPair, LeaseClaims } from "@maruhi/crypto";
import { encodeHex, exportEncryptionPublicKey, generateEncryptionKeyPair } from "@maruhi/crypto";
import { Clock, Effect, Redacted } from "effect";
import type { HttpClient } from "effect/http";

import { loadRepositoryAnchor } from "../anchor.ts";
import { makeApiClient, type MaruhiClient } from "../api.ts";
import { countNoun, logWarnings } from "../display.ts";
import { cliError, type CliError } from "../errors.ts";
import { toCliError } from "../failure.ts";
import { CliIo } from "../io.ts";
import type { LeaseResponseWire, VerifiedLeaseMaterial } from "../lease.package/index.ts";
import { verifyLeaseResponse } from "../lease.package/index.ts";
import {
  fetchGitHubOidcToken,
  issuanceBoundFor,
  readLeaseClaims,
  tokenExpiresAtMs,
} from "../oidc-github.ts";
import { noteServerDisclosure } from "../server-disclosure.ts";

export interface CiLeaseInput {
  readonly origin: string;
  readonly projectId: ProjectId;
  readonly audience: string;
  readonly anchorPath: string | undefined;
}

type LeaseIssueError = Effect.Error<ReturnType<MaruhiClient["lease"]["issue"]>>;

const issueLease = Effect.fn("ci-lease.issueLease")(function* (input: {
  readonly client: MaruhiClient;
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId;
  readonly token: Redacted.Redacted<string>;
  readonly ephemeralPubHex: string;
}): Effect.fn.Return<LeaseResponseWire, LeaseIssueError> {
  const oidcToken = Redacted.value(input.token);
  return yield* input.client.lease.issue({
    params: { projectId: input.projectId, environmentId: input.environmentId },
    payload: { oidcToken, ephemeralPubHex: input.ephemeralPubHex },
  });
});

type IssueOutcome =
  | { readonly kind: "ok"; readonly response: LeaseResponseWire }
  | { readonly kind: "replayed" };

export const LEASE_NOT_FOUND_MESSAGE =
  "The server answered 404 for the lease. The lease endpoint folds these into one uniform answer (existence hiding — AUTH_SPEC §14-1): unknown project, no active grant, a lease-policy mismatch (issuer / audience / claim constraints), and an out-of-scope or unknown environment. Check --server, --project, and the environment in the workflow, and that a project owner granted this workload's identity with `maruhi server grant --lease-policy`";

const TOKEN_REPLAYED_AGAIN_MESSAGE =
  "The lease was rejected as token-replayed again with a freshly minted token. Someone else is using this job's OIDC tokens — investigate the job's steps and network path for token exfiltration (AUTH_SPEC §14-1)";

function attemptLease(
  input: Parameters<typeof issueLease>[0],
): Effect.Effect<IssueOutcome, CliError> {
  return issueLease(input).pipe(
    Effect.map((response) => ({ kind: "ok", response }) as const),
    Effect.catchTags(
      {
        LeaseUnauthorized: (error) =>
          error.reason === "token-replayed"
            ? Effect.succeed({ kind: "replayed" } as const)
            : Effect.fail(toCliError(error)),
        ProjectNotFound: () => Effect.fail(cliError(LEASE_NOT_FOUND_MESSAGE)),
      },
      (error) => Effect.fail(toCliError(error)),
    ),
  );
}

export function leaseEnvironments(
  input: CiLeaseInput & { readonly environmentIds: readonly EnvironmentId[] },
): Effect.Effect<
  ReadonlyMap<EnvironmentId, VerifiedLeaseMaterial>,
  CliError,
  CliIo | HttpClient.HttpClient
> {
  return Effect.map(leaseEnvironmentsWithCredential(input), (leased) => leased.materials);
}

export interface WorkloadCredential {
  readonly token: Redacted.Redacted<string>;
  readonly ephemeralPubHex: string;
  readonly keyPair: EncryptionKeyPair;
}

const REUSE_MARGIN_MS = 30_000;

export interface LeasedEnvironments {
  readonly materials: ReadonlyMap<EnvironmentId, VerifiedLeaseMaterial>;
  readonly credential: WorkloadCredential;
  readonly client: MaruhiClient;
}

export const leaseEnvironmentsWithCredential = Effect.fn(
  "ci-lease.leaseEnvironmentsWithCredential",
)(function* (
  input: CiLeaseInput & {
    readonly environmentIds: readonly EnvironmentId[];
    readonly credential?: WorkloadCredential;
  },
): Effect.fn.Return<LeasedEnvironments, CliError, CliIo | HttpClient.HttpClient> {
  const io = yield* CliIo;
  const anchor =
    input.anchorPath === undefined ? null : yield* loadRepositoryAnchor(input.anchorPath);
  const client = yield* makeApiClient({ baseUrl: input.origin });
  const nowMs = yield* Clock.currentTimeMillis;
  const credential =
    reusableCredential(input.credential, nowMs) ??
    (yield* freshCredential(
      input.audience,
      input.credential === undefined ? undefined : issuanceBoundFor(input.credential.token, nowMs),
    ).pipe(
      Effect.catch((error) =>
        Effect.gen(function* () {
          const inHand = input.credential;
          if (inHand === undefined || !unexpired(inHand, yield* Clock.currentTimeMillis)) {
            return yield* Effect.fail(error);
          }
          return yield* Effect.as(
            io.logError(
              `Could not mint a fresh OIDC token for the lease (${error.message}); presenting the token in hand`,
            ),
            inHand,
          );
        }),
      ),
    ));
  const { keyPair: workloadKeyPair, ephemeralPubHex } = credential;
  let { token } = credential;
  let claims: LeaseClaims = yield* readLeaseClaims(token);
  let retried = false;
  const materials = new Map<EnvironmentId, VerifiedLeaseMaterial>();
  for (const environmentId of input.environmentIds) {
    const common = { client, projectId: input.projectId, environmentId, ephemeralPubHex };
    let outcome = yield* attemptLease({ ...common, token });
    if (outcome.kind === "replayed") {
      if (retried) {
        return yield* Effect.fail(cliError(TOKEN_REPLAYED_AGAIN_MESSAGE));
      }
      yield* io.logError(
        "The lease was rejected as token-replayed (the token was already bound to a different ephemeral key). Minting a fresh token and retrying once",
      );
      retried = true;
      token = yield* fetchGitHubOidcToken(input.audience);
      claims = yield* readLeaseClaims(token);
      outcome = yield* attemptLease({ ...common, token });
      if (outcome.kind === "replayed") {
        return yield* Effect.fail(cliError(TOKEN_REPLAYED_AGAIN_MESSAGE));
      }
    }
    const material = yield* verifyLeaseResponse({
      projectId: input.projectId,
      environmentId,
      response: outcome.response,
      claims,
      workloadKeyPair,
      anchor,
    });
    yield* logWarnings(material.warnings);
    yield* noteServerDisclosure(material.verified);
    yield* io.logError(
      `Lease verified (chain, grant, statements, value signatures, DEK commitments${anchor === null ? "" : ", repository anchor"}): ${countNoun(material.variables.length, "variable")} (environment ${environmentId})`,
    );
    materials.set(environmentId, material);
  }
  return { materials, credential: { token, ephemeralPubHex, keyPair: workloadKeyPair }, client };
});

const freshCredential = Effect.fn("ci-lease.freshCredential")(function* (
  audience: string,
  timeoutMs?: number,
): Effect.fn.Return<WorkloadCredential, CliError, CliIo> {
  const keyPair = yield* cryptoPromise("generateEncryptionKeyPair", () =>
    generateEncryptionKeyPair(),
  ).pipe(
    Effect.mapError(() => cliError("Failed to generate the ephemeral key pair (crypto error)")),
  );
  const ephemeralPubHex = encodeHex(
    yield* cryptoPromise("exportEncryptionPublicKey", () =>
      exportEncryptionPublicKey(keyPair.publicKey),
    ).pipe(
      Effect.mapError(() => cliError("Failed to export the ephemeral public key (crypto error)")),
    ),
  );
  const token = yield* fetchGitHubOidcToken(audience, timeoutMs);
  return { token, ephemeralPubHex, keyPair };
});

function reusableCredential(
  credential: WorkloadCredential | undefined,
  nowMs: number,
): WorkloadCredential | null {
  if (credential === undefined) {
    return null;
  }
  const expiresAtMs = tokenExpiresAtMs(credential.token);
  return expiresAtMs !== null && expiresAtMs - REUSE_MARGIN_MS > nowMs ? credential : null;
}

function unexpired(credential: WorkloadCredential, nowMs: number): boolean {
  const expiresAtMs = tokenExpiresAtMs(credential.token);
  return expiresAtMs !== null && expiresAtMs > nowMs;
}
