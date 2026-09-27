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

import { LeaseUnauthorizedError, ProjectNotFoundError } from "@maruhi/api-schema";
import type { EnvironmentId, ProjectId } from "@maruhi/core";
import type { LeaseClaims } from "@maruhi/crypto";
import { encodeHex, exportEncryptionPublicKey, generateEncryptionKeyPair } from "@maruhi/crypto";
import { Effect, Redacted } from "effect";
import type { HttpClient } from "effect/unstable/http";

import { loadRepositoryAnchor } from "./anchor.ts";
import { makeApiClient, type MaruhiClient } from "./api.ts";
import { countNoun, logWarnings } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo } from "./io.ts";
import type { LeaseResponseWire, VerifiedLeaseMaterial } from "./lease-client.ts";
import { verifyLeaseResponse } from "./lease-client.ts";
import { fetchGitHubOidcToken, readLeaseClaims } from "./oidc-github.ts";

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

/** One lease issuance (the wire boundary). Errors are returned typed, for classification. */
function issueLease(input: {
  readonly client: MaruhiClient;
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId;
  readonly token: Redacted.Redacted<string>;
  readonly ephemeralPubHex: string;
}): Effect.Effect<LeaseResponseWire, unknown> {
  return Effect.gen(function* () {
    // Why it is unwrapped: the wire boundary of the lease request (the
    // payload's oidcToken field). The plaintext token rides only in the
    // request body and never appears in logs or errors
    const oidcToken = Redacted.value(input.token);
    return yield* input.client.lease.issue({
      params: { projectId: input.projectId, environmentId: input.environmentId },
      payload: { oidcToken, ephemeralPubHex: input.ephemeralPubHex },
    });
  });
}

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
const LEASE_NOT_FOUND_MESSAGE =
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
    Effect.catch((error) => {
      if (error instanceof LeaseUnauthorizedError && error.reason === "token-replayed") {
        return Effect.succeed({ kind: "replayed" } as const);
      }
      if (error instanceof ProjectNotFoundError) {
        return Effect.fail(cliError(LEASE_NOT_FOUND_MESSAGE));
      }
      return Effect.fail(toCliError(error));
    }),
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
  return Effect.gen(function* () {
    const io = yield* CliIo;
    // The anchor is read before the network and key generation (do not put
    // detecting a broken file behind a round trip)
    const anchor =
      input.anchorPath === undefined ? null : yield* loadRepositoryAnchor(input.anchorPath);
    const client = yield* makeApiClient({ baseUrl: input.origin });
    // The ephemeral X25519 key pair is generated in memory (the private key
    // is non-extractable) and disappears with the job (§9.1). One call =
    // one token = one key (session-25 §3 — §14-1's "the same key for all
    // requests under one token" is satisfied by construction)
    const workloadKeyPair = yield* Effect.tryPromise({
      try: () => generateEncryptionKeyPair(),
      catch: () => cliError("Failed to generate the ephemeral key pair (crypto error)"),
    });
    const ephemeralPubHex = encodeHex(
      yield* Effect.tryPromise({
        try: () => exportEncryptionPublicKey(workloadKeyPair.publicKey),
        catch: () => cliError("Failed to export the ephemeral public key (crypto error)"),
      }),
    );

    // The token is minted right before the lease request (session-24 §8
    // SHOULD — minimize the exposure window of the first-come binding)
    let token = yield* fetchGitHubOidcToken(input.audience);
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
      // §9.1 verification obligations (1)–(4). No value is decrypted until all of them pass
      const material = yield* verifyLeaseResponse({
        projectId: input.projectId,
        environmentId,
        response: outcome.response,
        claims,
        workloadKeyPair,
        anchor,
      });
      yield* logWarnings(material.warnings);
      // Leave the verification success in the CI log (keep stdout free for
      // the child process's output — decision 9; stderr is the destination
      // for diagnostics and info)
      yield* io.logError(
        `Lease verified (chain, statements, value signatures, DEK commitments${anchor === null ? "" : ", repository anchor"}): ${countNoun(material.variables.length, "variable")} (environment ${environmentId})`,
      );
      materials.set(environmentId, material);
    }
    return materials;
  });
}
