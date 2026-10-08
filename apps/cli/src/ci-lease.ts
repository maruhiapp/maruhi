// Acquiring a CI job's workload lease (CRYPTO_SPEC §9.1 / AUTH_SPEC §14) —
// the shared front stage of `maruhi ci run` (ci-run.ts) and `maruhi ci
// sync` (sync-ci.ts).
//
// The point of this module is that its **prerequisite structure is entirely
// different** from a normal command:
//   - auth = only the OIDC token embedded in the request (§14-1). It does
//     not depend on a maruhi token, the OS keychain, session context, or a
//     config file at all — the absence of dependencies is shown by the
//     required-services type (CliIo | HttpClient)
//   - verification material = bundled in the lease response (§14-2). No
//     other API is called
//   - floor / pins = none (a disposable runner — §14.3-3). The substitute
//     rollback detection is the repository anchor (--anchor — anchor.ts)
//
// Multiple environments (the sync source and the token environment of
// `ci sync`) are requested in turn with **one OIDC token and one ephemeral
// key**: the server's first-come binding spans every environment in the
// project per token, so all requests under the same token must present the
// same ephemeral key (AUTH_SPEC §14-1 / CRYPTO_SPEC §9.1).

import { cryptoPromise, type EnvironmentId, type ProjectId } from "@maruhi/core";
import type { EncryptionKeyPair, LeaseClaims } from "@maruhi/crypto";
import { encodeHex, exportEncryptionPublicKey, generateEncryptionKeyPair } from "@maruhi/crypto";
import { Clock, Effect, Redacted } from "effect";
import type { HttpClient } from "effect/http";

import { loadRepositoryAnchor } from "./anchor.ts";
import { makeApiClient, type MaruhiClient } from "./api.ts";
import { countNoun, logWarnings } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo } from "./io.ts";
import type { LeaseResponseWire, VerifiedLeaseMaterial } from "./lease-client.ts";
import { verifyLeaseResponse } from "./lease-client.ts";
import {
  fetchGitHubOidcToken,
  issuanceBoundFor,
  readLeaseClaims,
  tokenExpiresAtMs,
} from "./oidc-github.ts";
import { noteServerDisclosure } from "./server-disclosure.ts";

/** Input shared by the CI commands (all from explicit flags — session-25 §2). */
export interface CiLeaseInput {
  /** Normalized server origin (`--server`). */
  readonly origin: string;
  /** Pre-pinned genesis (`--project` — §9.1 verification obligation (1)). */
  readonly projectId: ProjectId;
  /** OIDC audience (`--audience`; default is the server origin — the AUTH_SPEC §14-1 recommended value). */
  readonly audience: string;
  /** Path of the repository anchor (`--anchor` — §6.3 (b). Optional = SHOULD). */
  readonly anchorPath: string | undefined;
}

/** The typed lease-issue call's error union (endpoint errors | HttpClientError | SchemaError). */
type LeaseIssueError = Effect.Error<ReturnType<MaruhiClient["lease"]["issue"]>>;

/** One lease issuance (the wire boundary). Errors are returned typed, for classification. */
const issueLease = Effect.fn("ci-lease.issueLease")(function* (input: {
  readonly client: MaruhiClient;
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId;
  readonly token: Redacted.Redacted<string>;
  readonly ephemeralPubHex: string;
}): Effect.fn.Return<LeaseResponseWire, LeaseIssueError> {
  // Why it is unwrapped: the wire boundary of the lease request (the
  // payload's oidcToken field). The plaintext token rides only in the
  // request body and never appears in logs or errors
  const oidcToken = Redacted.value(input.token);
  return yield* input.client.lease.issue({
    params: { projectId: input.projectId, environmentId: input.environmentId },
    payload: { oidcToken, ephemeralPubHex: input.ephemeralPubHex },
  });
});

type IssueOutcome =
  | { readonly kind: "ok"; readonly response: LeaseResponseWire }
  | { readonly kind: "replayed" };

/**
 * A lease 404 is a **uniform response** (AUTH_SPEC §14-1 existence
 * concealment), and the likeliest real cause in CI is not a wrong project
 * ID but a policy mismatch (repository transfer, running a different
 * branch). The shared mapping (failure.ts) "Project not found — check the
 * ID and your access" is member-oriented guidance and would send CI to the
 * wrong fix, so it is replaced with lease-specific guidance here.
 */
export const LEASE_NOT_FOUND_MESSAGE =
  "The server answered 404 for the lease. The lease endpoint folds these into one uniform answer (existence hiding — AUTH_SPEC §14-1): unknown project, no active grant, a lease-policy mismatch (issuer / audience / claim constraints), and an out-of-scope or unknown environment. Check --server, --project, and the environment in the workflow, and that a project owner granted this workload's identity with `maruhi server grant --lease-policy`";

/**
 * Losing the first-come race twice in a row = a copy is being used right
 * after minting. No further retries (cap of 1) — prompt investigation as a
 * sign of token leakage.
 */
const TOKEN_REPLAYED_AGAIN_MESSAGE =
  "The lease was rejected as token-replayed again with a freshly minted token. Someone else is using this job's OIDC tokens — investigate the job's steps and network path for token exfiltration (AUTH_SPEC §14-1)";

/** One issuance attempt. Only `token-replayed` is classified as retryable. */
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

/**
 * Leases every requested environment through OIDC (CRYPTO_SPEC §9.1 /
 * AUTH_SPEC §14): generate an in-memory ephemeral X25519 key pair, mint a
 * fresh GitHub Actions OIDC token, request each lease with that one token
 * and key, and run every §9.1 verification duty against the pre-pinned
 * genesis. Values are decrypted in memory only.
 */
export function leaseEnvironments(
  input: CiLeaseInput & { readonly environmentIds: readonly EnvironmentId[] },
): Effect.Effect<
  ReadonlyMap<EnvironmentId, VerifiedLeaseMaterial>,
  CliError,
  CliIo | HttpClient.HttpClient
> {
  return Effect.map(leaseEnvironmentsWithCredential(input), (leased) => leased.materials);
}

/**
 * The credential a job leased with: the OIDC token and the ephemeral key
 * the server's first-come binding tied it to (AUTH_SPEC §14-1). The
 * sealed-proposal mint (ci-rotate.ts) presents the same pair — a second
 * key under the same token would be refused as replayed.
 */
export interface WorkloadCredential {
  readonly token: Redacted.Redacted<string>;
  readonly ephemeralPubHex: string;
  /** The ephemeral key pair itself (in memory, non-extractable) — a re-lease under the same credential needs it. */
  readonly keyPair: EncryptionKeyPair;
}

/** How long before its `exp` a token is still presented for a re-lease (clock skew and the request's own time). */
const REUSE_MARGIN_MS = 30_000;

export interface LeasedEnvironments {
  readonly materials: ReadonlyMap<EnvironmentId, VerifiedLeaseMaterial>;
  readonly credential: WorkloadCredential;
  readonly client: MaruhiClient;
}

/**
 * {@link leaseEnvironments} plus the credential and client for a follow-up
 * call under the same lease. A `credential` from an earlier lease of this
 * job is presented again while its token is unexpired (AUTH_SPEC §14-1 —
 * a re-claim under the same token and key is idempotent): the re-lease
 * then needs no issuance endpoint, which is the one that may have stopped
 * answering (ruling O revision, round 4); a fresh token and key otherwise.
 */
export const leaseEnvironmentsWithCredential = Effect.fn(
  "ci-lease.leaseEnvironmentsWithCredential",
)(function* (
  input: CiLeaseInput & {
    readonly environmentIds: readonly EnvironmentId[];
    readonly credential?: WorkloadCredential;
  },
): Effect.fn.Return<LeasedEnvironments, CliError, CliIo | HttpClient.HttpClient> {
  const io = yield* CliIo;
  // The anchor is read before the network and key generation (do not put
  // detecting a broken file behind a round trip)
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
          // No fresh token, but an unexpired one in hand (within the reuse
          // margin): present it — the same fallback shape as the mint's
          // (ruling O revision, round 6)
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
  // GitHub is a runtime-minting issuer, so one automatic retry with a
  // fresh token is allowed (session-24 §8 MAY — cap of 1, total 1 even
  // across multiple environments)
  let retried = false;
  const materials = new Map<EnvironmentId, VerifiedLeaseMaterial>();
  for (const environmentId of input.environmentIds) {
    const common = { client, projectId: input.projectId, environmentId, ephemeralPubHex };
    let outcome = yield* attemptLease({ ...common, token });
    if (outcome.kind === "replayed") {
      if (retried) {
        return yield* Effect.fail(cliError(TOKEN_REPLAYED_AGAIN_MESSAGE));
      }
      // Present the same ephemeral key (the fresh token is unbound and binds to this key)
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
    // §9.1 verification obligations (1)–(6). No value is decrypted until all of them pass
    const material = yield* verifyLeaseResponse({
      projectId: input.projectId,
      environmentId,
      response: outcome.response,
      claims,
      workloadKeyPair,
      anchor,
    });
    yield* logWarnings(material.warnings);
    // §9's constant display on the workload side (ci run / ci sync / ci
    // rotate): from the bundled chain this lease just verified
    yield* noteServerDisclosure(material.verified);
    // Leave the verification success in the CI log (keep stdout free for
    // the child process's output — decision 9; stderr is the destination
    // for diagnostics and info)
    yield* io.logError(
      `Lease verified (chain, grant, statements, value signatures, DEK commitments${anchor === null ? "" : ", repository anchor"}): ${countNoun(material.variables.length, "variable")} (environment ${environmentId})`,
    );
    materials.set(environmentId, material);
  }
  return { materials, credential: { token, ephemeralPubHex, keyPair: workloadKeyPair }, client };
});

/**
 * A fresh credential: the ephemeral X25519 key pair is generated in memory
 * (the private key is non-extractable) and disappears with the job (§9.1);
 * the token is minted right before the lease request (session-24 §8 SHOULD
 * — minimize the exposure window of the first-come binding). One call = one
 * token = one key (session-25 §3 — §14-1's "the same key for all requests
 * under one token" is satisfied by construction).
 */
const freshCredential = Effect.fn("ci-lease.freshCredential")(function* (
  audience: string,
  /** The fetch's bound (the life of a token in hand — O-18); undefined = the default. */
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

/** The earlier credential when its token is still presentable (its `exp` is known and not within the margin), else null. */
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

/** Whether a credential's token is unexpired by its `exp` alone (no margin — the last resort when no fresh token can be minted). */
function unexpired(credential: WorkloadCredential, nowMs: number): boolean {
  const expiresAtMs = tokenExpiresAtMs(credential.token);
  return expiresAtMs !== null && expiresAtMs > nowMs;
}
