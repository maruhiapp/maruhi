// `maruhi server grant` (CRYPTO_SPEC §9 / AUTH_SPEC §12-6).
//
// Appends a grant_server to the chain, then back-fills a server-
// addressed wrap for every environment in the disclosure scope × every
// epoch (the grant's executor = the owner is the wraps' executor —
// CRYPTO_SPEC §7). The flow:
//   1. Early checks: the owner check, the environment-existence check,
//      the two layers of duplicate-server-key / re-grant checks
//   2. Fetch the server key's public face from `/auth/config` and
//      recompute-and-verify FP = SHA-256(enc_pub)[:16] (machine
//      detection of transport corruption / config drift)
//   3. The server-key confirmation ceremony (§9): the FP's BIP39
//      12-word display + explicit confirmation (interactive = re-typing
//      the last word, non-interactive = matching the out-of-band value
//      of --expect-fingerprint)
//   4. The grant_server append (parent-head CAS retry)
//   5. Backfill: bulk-register every epoch's server-addressed wrap per
//      environment, and keep going past a 409 (already registered) at
//      epoch granularity — **a re-run always converges** (no progress
//      file. The distributed state is the resumption state — the same
//      discipline as env rotate)
//
// Interrupted recovery: even if the process dies after the grant lands
// on the chain, a re-run converges through "detect a valid grant of
// identical content → skip the append → backfill (409 = already
// registered)". A lease in shortage falls to 503 `server-wraps-missing`
// (AUTH_SPEC §14-3).

import { ChainHeadConflictError } from "@maruhi/api-schema";
import { cryptoEffect, type EnvironmentId } from "@maruhi/core";
import type {
  ChainEntry,
  LeasePolicyIssuer,
  ProposableOperation,
  ServerGrant,
  SigningKeyPair,
} from "@maruhi/crypto";
import { computeServerKeyFingerprint, decodeHex, encodeHex } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { isApprovalTarget } from "./approval-rules.ts";
import {
  ensureStillTarget,
  type ProposalInput,
  proposeOperation,
  proposeRecheck,
  type ProposedSummary,
} from "./approval.ts";
import { type BackfillEnvironmentOutcome, backfillEnvironmentFor } from "./backfill.ts";
import { appendEntry, signEntryAtHead } from "./chain-append.ts";
import { resyncExtended, type VerifiedProject } from "./chain-sync.ts";
import type { DekRecipient } from "./deks.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { confirmByLastWord, fingerprintWords, formatWordList } from "./fp-words.ts";
import { CliIo } from "./io.ts";
import { retryOnConflict } from "./retry.ts";

const MAX_ATTEMPTS = 5;

/** The server key's public face (`/auth/config` — AUTH_SPEC §4). */
interface ServerKeyConfig {
  readonly serverEncPubHex: string;
  readonly serverKeyFingerprintHex: string;
}

interface GrantSummary {
  /** Whether it appended to the chain (false = detected a valid grant of identical content and skipped). */
  readonly appended: boolean;
  readonly serverKeyFingerprintHex: string;
  readonly scopeEnvironmentIds: readonly string[];
  readonly leasePolicyCount: number;
  /** The count of wraps newly registered by the backfill. */
  readonly registered: number;
  /** The count of wraps already registered (the re-run's convergence). */
  readonly alreadyRegistered: number;
}

/** Whether every environment in the scope exists on the chain (the reason's string when not). */
function scopeExistsRejection(verified: VerifiedProject, scope: readonly string[]): string | null {
  for (const environmentId of scope) {
    if (!verified.state.environments.has(environmentId)) {
      return `Environment ${environmentId} does not exist on the chain (no create_environment observed). Pass existing environment IDs to --environments`;
    }
  }
  return null;
}

/**
 * The early check of duplicate-server-key (§6.2): a grant whose server
 * enc public key equals a current member's enc public key is invalid
 * under the consensus rule.
 */
function duplicateServerKeyRejection(
  verified: VerifiedProject,
  serverEncPubHex: string,
): string | null {
  // The comparison target is every device key of the current member set (§6.2 — 2026-09-19 DK)
  for (const chainMember of verified.state.members.values()) {
    for (const device of chainMember.devices.values()) {
      if (device.encPubHex === serverEncPubHex) {
        return "The server enc public key equals a current member's enc public key (consensus rule duplicate-server-key — CRYPTO_SPEC §6.2). Check the deployment's key configuration";
      }
    }
  }
  return null;
}

/**
 * The re-grant layer (§6.3): scope may only grow. A narrowing is guided
 * toward revoke_server (carrying the all-environment rotation mandate).
 * lease_policy is freely revised.
 */
function scopeNarrowedRejection(
  existing: ServerGrant | null,
  scope: readonly string[],
): string | null {
  if (existing === null) {
    return null;
  }
  const missing = existing.scopeEnvironmentIds.filter((id) => !scope.includes(id));
  if (missing.length === 0) {
    return null;
  }
  return `The disclosure scope can only grow (re-grant rule — CRYPTO_SPEC §6.3). Environments in the existing grant's scope are missing from this invocation: ${missing.join(", ")}. To narrow the scope, run \`maruhi server revoke\` (which rotates every environment — §7) and grant again`;
}

/** The check set before running grant_server (a retry after resync goes through the same checks). */
function ensureGrantable(input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: string;
  readonly scope: readonly string[];
  readonly serverConfig: ServerKeyConfig;
}): Effect.Effect<{ readonly existing: ServerGrant | null }, CliError> {
  const member = input.verified.state.members.get(input.signerUserId);
  if (member === undefined || member.role !== "owner") {
    return Effect.fail(cliError("Only an owner can run grant_server (CRYPTO_SPEC §6.2)"));
  }
  const existing =
    input.verified.state.serverGrants.get(input.serverConfig.serverKeyFingerprintHex) ?? null;
  const rejection =
    scopeExistsRejection(input.verified, input.scope) ??
    duplicateServerKeyRejection(input.verified, input.serverConfig.serverEncPubHex) ??
    scopeNarrowedRejection(existing, input.scope);
  return rejection !== null ? Effect.fail(cliError(rejection)) : Effect.succeed({ existing });
}

/** Compared via a canonical form (array form) independent of the object's key order. */
function canonicalPolicyKey(policy: readonly LeasePolicyIssuer[]): string {
  return JSON.stringify(
    policy.map((element) => [
      element.issuerUrl,
      element.audience,
      element.claimConstraints.map((constraint) => [constraint.claimName, constraint.claimValue]),
    ]),
  );
}

function samePolicy(a: readonly LeasePolicyIssuer[], b: readonly LeasePolicyIssuer[]): boolean {
  return canonicalPolicyKey(a) === canonicalPolicyKey(b);
}

function sameScope(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((id, index) => b[index] === id);
}

/**
 * Fetches `/auth/config`'s server-key public face and recomputes-and-
 * verifies the FP. What the FP is checked **against** is the out-of-band
 * record (the ceremony — §9); the recomputation here is the response's
 * self-consistency check (machine detection of transport corruption /
 * a mix-up of sources).
 */
const fetchServerKeyConfig = Effect.fn("server-grant.fetchServerKeyConfig")(function* (
  client: MaruhiClient,
): Effect.fn.Return<ServerKeyConfig, CliError> {
  const config = yield* client.auth.authConfig({}).pipe(Effect.mapError(toCliError));
  const encPubHex = config.serverEncPubHex;
  const fingerprintHex = config.serverKeyFingerprintHex;
  if (encPubHex === undefined || fingerprintHex === undefined) {
    return yield* Effect.fail(
      cliError(
        "The server has no deployment keypair configured (/auth/config has no serverKeyFingerprintHex). Register SERVER_ENC_KEY_IKM following docs/SELF_HOSTING.md",
      ),
    );
  }
  const encPub = decodeHex(encPubHex);
  if (encPub === null || encPub.length !== 32) {
    return yield* Effect.fail(cliError("serverEncPubHex in /auth/config is malformed"));
  }
  const mismatch = cliError(
    "The server-provided enc public key does not match serverKeyFingerprintHex (the response contradicts itself). Check the deployment configuration or the transport path",
  );
  const computed = yield* cryptoEffect(() => computeServerKeyFingerprint(encPub)).pipe(
    Effect.mapError(() => mismatch),
  );
  if (encodeHex(computed) !== fingerprintHex) {
    return yield* Effect.fail(mismatch);
  }
  return { serverEncPubHex: encPubHex, serverKeyFingerprintHex: fingerprintHex };
});

/**
 * The server-key confirmation ceremony (§9): the FP's word display and
 * the explicit confirmation of matching against the deployment's public
 * configuration. The authenticity confirmation imposed on member keys
 * (§6.5) is not waived for the server key alone — a grant is the
 * operation that makes the server "member N+1".
 *
 * The confirmation comes in two forms:
 * - `--expect-fingerprint <hex>`: supplies the out-of-band FP as an
 *   argument (the non-interactive explicit confirmation. An immediate
 *   error unless it matches the record from deploy time)
 * - Interactive: shows the 12 words and demands **re-typing the last
 *   word** (the same ceremony as the recovery code's save confirmation —
 *   recovery.ts. Blocks the shape of typing y without reading)
 */
const confirmServerKey = Effect.fn("server-grant.confirmServerKey")(function* (input: {
  readonly fingerprintHex: string;
  readonly expectFingerprintHex: string | null;
}): Effect.fn.Return<void, CliError, CliIo> {
  const io = yield* CliIo;
  const words = yield* fingerprintWords(
    input.fingerprintHex,
    "The server key fingerprint is malformed",
  );
  const lines = [
    "Server key fingerprint (first 16 bytes of SHA-256(enc public key) — CRYPTO_SPEC §9):",
    `  hex:  ${input.fingerprintHex}`,
    "  word: " + formatWordList(words),
    "Check against your out-of-band record that this word list matches the server key fingerprint noted at deploy time (see the recording step in docs/SELF_HOSTING.md).",
  ];
  for (const line of lines) {
    yield* io.log(line);
  }
  if (input.expectFingerprintHex !== null) {
    if (input.expectFingerprintHex !== input.fingerprintHex) {
      return yield* Effect.fail(
        cliError(
          "--expect-fingerprint does not match the fingerprint of the server-provided key. The deployment's key is not the one you expected — the grant was aborted (verify the key out of band)",
        ),
      );
    }
    yield* io.log(
      "--expect-fingerprint matches (continuing; the out-of-band record counts as checked)",
    );
    return;
  }
  // Never let an AI-agent environment perform the ceremony on the
  // user's behalf (the matching is a human's out-of-band
  // confirmation — §9 / ADR-0014. The grant version of the same posture
  // as the value-display refusal — agent.ts)
  if (io.agentProfile().isAgent) {
    return yield* Effect.fail(
      cliError(
        "Refused to run the server-key confirmation ceremony: an AI agent environment was detected. Run this yourself in a terminal, or pass the fingerprint noted out of band via --expect-fingerprint",
      ),
    );
  }
  return yield* confirmByLastWord({
    words,
    promptText: "Once checked, type the last of the 12 words shown above",
    mismatchText: "That does not match. Type the last word of the list shown above",
    exhaustedText:
      "Server key fingerprint confirmation failed (the re-typed word does not match). The grant was not performed — re-run once you can check against your out-of-band record",
  });
});

/** Signs the grant_server entry right after the current head (the shared core = chain-append.ts). */
const signGrantEntry = Effect.fn("server-grant.signGrantEntry")(function* (input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  readonly serverConfig: ServerKeyConfig;
  readonly scope: readonly string[];
  readonly leasePolicy: readonly LeasePolicyIssuer[];
}): Effect.fn.Return<ChainEntry, CliError> {
  return yield* signEntryAtHead({
    verified: input.verified,
    signerUserId: input.signerUserId,
    operation: {
      op: "grant_server",
      payload: {
        serverEncPubHex: input.serverConfig.serverEncPubHex,
        serverKeyFingerprintHex: input.serverConfig.serverKeyFingerprintHex,
        scopeEnvironmentIds: input.scope,
        leasePolicy: input.leasePolicy,
      },
    },
    signingKeyPair: input.signingKeyPair,
    failureText: "Failed to sign the grant_server entry",
  });
});

/**
 * Registers the server-addressed wraps for every epoch (1..current
 * epoch) of one environment (the shared core = backfill.ts). A per-epoch
 * 409 is absorbed as "already registered" (there is no list API for
 * server-addressed wraps — distribution is to-the-principal only §12-6 —
 * so "treat a 409 as done" is the only and sufficient means of
 * reconciliation).
 */
function backfillEnvironment(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly recipient: DekRecipient;
  readonly grant: ServerGrant;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<BackfillEnvironmentOutcome, CliError> {
  return backfillEnvironmentFor({
    client: input.client,
    verified: input.verified,
    environmentId: input.environmentId,
    recipient: input.recipient,
    wrapRecipient: { kind: "server", grant: input.grant },
    recipientLabel: "server-addressed",
    signerUserId: input.signerUserId,
    signingKeyPair: input.signingKeyPair,
  });
}

/** Whether a valid grant of identical content (scope and lease_policy) already exists (the skip-append / skip-proposal judgment). */
function grantUnchanged(
  existing: ServerGrant | null,
  scope: readonly string[],
  leasePolicy: readonly LeasePolicyIssuer[],
): boolean {
  return (
    existing !== null &&
    sameScope([...existing.scopeEnvironmentIds].toSorted(), scope) &&
    samePolicy(existing.leasePolicy, leasePolicy)
  );
}

/** The grant's outcome: a proposal (four-eyes — K6) or an application. */
type ServerGrantOutcome =
  | { readonly kind: "proposed"; readonly proposal: ProposedSummary }
  | { readonly kind: "applied"; readonly summary: GrantSummary };

/**
 * The post-grant-application server-addressed backfill (every
 * environment in the disclosure scope × every epoch — AUTH_SPEC §12-6).
 * Shared by a directly-appended grant and the fulfillment of an approver
 * who completed the application under four-eyes (approval-approve.ts —
 * §12-6's fifth path).
 */
export const backfillServerGrant = Effect.fn("server-grant.backfillServerGrant")(function* (input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly grant: ServerGrant;
  readonly recipient: DekRecipient;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.fn.Return<
  { readonly registered: number; readonly alreadyRegistered: number },
  CliError
> {
  let registered = 0;
  let alreadyRegistered = 0;
  for (const environmentId of input.grant.scopeEnvironmentIds) {
    const result = yield* backfillEnvironment({
      client: input.client,
      verified: input.verified,
      environmentId,
      recipient: input.recipient,
      grant: input.grant,
      signerUserId: input.signerUserId,
      signingKeyPair: input.signingKeyPair,
    });
    registered += result.registered;
    alreadyRegistered += result.alreadyRegistered;
  }
  return { registered, alreadyRegistered };
});

export const serverGrantOp = Effect.fn("server-grant.serverGrantOp")(function* (input: {
  readonly client: MaruhiClient;
  /**
   * The deployment whose server key is granted (`--key-from <mirror url>`
   * — AUTH_SPEC §11-7 ruling F: a mirror's key is granted on the server,
   * the only place that accepts appends; the grant and the wraps reach
   * the mirror by replication). Default: the server itself.
   */
  readonly keySource?: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentIds: readonly EnvironmentId[];
  readonly leasePolicy: readonly LeasePolicyIssuer[];
  readonly expectFingerprintHex: string | null;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  readonly recipient: DekRecipient;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly proposal: ProposalInput;
}): Effect.fn.Return<ServerGrantOutcome, CliError, CliIo> {
  const io = yield* CliIo;
  // Normalizing the scope: ascending code-point order, no duplicates (§6.2's SHOULD)
  const scope = [...new Set<string>(input.environmentIds)].toSorted();
  const serverConfig = yield* fetchServerKeyConfig(input.keySource ?? input.client);
  const { existing } = yield* ensureGrantable({
    verified: input.verified,
    signerUserId: input.signerUserId,
    scope,
    serverConfig,
  });

  const unchanged = grantUnchanged(existing, scope, input.leasePolicy);

  // The ceremony (§9) runs whether or not an append happens (even on a
  // backfill-only re-run, never skip matching the key that will
  // continue to receive disclosure)
  yield* confirmServerKey({
    fingerprintHex: serverConfig.serverKeyFingerprintHex,
    expectFingerprintHex: input.expectFingerprintHex,
  });

  const inner: ProposableOperation = {
    op: "grant_server",
    payload: {
      serverEncPubHex: serverConfig.serverEncPubHex,
      serverKeyFingerprintHex: serverConfig.serverKeyFingerprintHex,
      scopeEnvironmentIds: scope,
      leasePolicy: input.leasePolicy,
    },
  };
  // Four-eyes (K6-A): when the policy targets grant_server, propose and
  // stop (the server-addressed backfill is performed by the approver
  // who completes the application — approval item 22). The proposer has
  // already done the ceremony
  if (!unchanged && isApprovalTarget(inner, input.verified.state.approvalPolicy)) {
    // Never propose when a grant of identical content is already valid after resync (Cursor Bugbot finding — a redundant proposal)
    const proposal = yield* proposeOperation(
      input,
      inner,
      proposeRecheck(
        (view) =>
          ensureGrantable({
            verified: view,
            signerUserId: input.signerUserId,
            scope,
            serverConfig,
          }),
        (checked) => grantUnchanged(checked.existing, scope, input.leasePolicy),
        "An active grant with identical content was appended by a concurrent run — nothing to propose. Re-run `maruhi server grant` to resume the backfill",
      ),
    );
    return { kind: "proposed", proposal };
  }

  let verified = input.verified;
  if (unchanged) {
    yield* io.log(
      "An active grant with identical content (both scope and lease_policy) already exists — skipping the chain append and running only the backfill (crash recovery)",
    );
  } else {
    const appended = yield* retryOnConflict(
      { verified },
      {
        maxAttempts: MAX_ATTEMPTS,
        attempt: (state) =>
          Effect.gen(function* () {
            const entry = yield* signGrantEntry({
              verified: state.verified,
              signerUserId: input.signerUserId,
              signingKeyPair: input.signingKeyPair,
              serverConfig,
              scope,
              leasePolicy: input.leasePolicy,
            });
            yield* appendEntry(input.client, state.verified, entry);
            return state.verified;
          }),
        classify: (error) => (error instanceof ChainHeadConflictError ? "head-conflict" : null),
        recover: (state) =>
          Effect.gen(function* () {
            // Resync with the extended check (blocks re-signing onto a
            // shortened / forked chain — the same discipline as env
            // create / rotate's CAS retry)
            const resynced = yield* resyncExtended(input.resync, state.verified);
            yield* ensureStillTarget(resynced, inner, false);
            yield* ensureGrantable({
              verified: resynced,
              signerUserId: input.signerUserId,
              scope,
              serverConfig,
            });
            return { verified: resynced };
          }),
        exhaustedMessage: `grant_server's chain-head conflict did not resolve (${MAX_ATTEMPTS} attempts). Wait a moment and re-run`,
      },
    );
    // Confirm the grant's listing via the post-acceptance resync (never make the server's claim the source of truth)
    verified = yield* resyncExtended(input.resync, appended);
    const granted = verified.state.serverGrants.get(serverConfig.serverKeyFingerprintHex);
    if (granted === undefined) {
      return yield* Effect.fail(
        cliError(
          "The resync after grant_server was accepted does not show the grant (the server's response contradicts the chain). Investigate the served chain",
        ),
      );
    }
    yield* io.log(
      `Appended grant_server to the chain (seq=${verified.state.headSeq}, scope=${scope.join(", ")})`,
    );
  }

  const grant = verified.state.serverGrants.get(serverConfig.serverKeyFingerprintHex);
  if (grant === undefined) {
    return yield* Effect.fail(
      cliError("Cannot confirm an active grant (contradicts the resync result)"),
    );
  }

  // The backfill (every environment in the disclosure scope × every epoch — AUTH_SPEC §12-6)
  const { registered, alreadyRegistered } = yield* backfillServerGrant({
    client: input.client,
    verified,
    grant,
    recipient: input.recipient,
    signerUserId: input.signerUserId,
    signingKeyPair: input.signingKeyPair,
  });

  return {
    kind: "applied",
    summary: {
      appended: !unchanged,
      serverKeyFingerprintHex: serverConfig.serverKeyFingerprintHex,
      scopeEnvironmentIds: grant.scopeEnvironmentIds,
      leasePolicyCount: grant.leasePolicy.length,
      registered,
      alreadyRegistered,
    },
  };
});
