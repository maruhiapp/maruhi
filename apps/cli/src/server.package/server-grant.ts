import {
  type EnvironmentId,
  type KeyFingerprintHex,
  serverKeyFingerprintHex,
  type UserId,
} from "@maruhi/core";
import type {
  LeasePolicyIssuer,
  ProposableOperation,
  ServerGrant,
  SigningKeyPair,
} from "@maruhi/crypto";
import { decodeHex, isApprovalTarget } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "../api.ts";
import {
  ensureStillTarget,
  type ProposalInput,
  proposeOperation,
  proposeRecheck,
  type ProposedSummary,
} from "../approval.package/index.ts";
import { type BackfillEnvironmentOutcome, backfillEnvironmentFor } from "../backfill.ts";
import { appendOperationWithRetry } from "../chain-append.ts";
import { resyncExtended, type VerifiedProject } from "../chain-sync.ts";
import type { DekRecipient } from "../deks.ts";
import { cliError, type CliError } from "../errors.ts";
import { toCliError } from "../failure.ts";
import { confirmByLastWord, fingerprintWords, formatWordList } from "../fp-words.ts";
import { CliIo } from "../io.ts";

interface ServerKeyConfig {
  readonly serverEncPubHex: string;
  readonly serverKeyFingerprintHex: KeyFingerprintHex;
}

interface GrantSummary {
  readonly appended: boolean;
  readonly serverKeyFingerprintHex: string;
  readonly scopeEnvironmentIds: readonly EnvironmentId[];
  readonly leasePolicyCount: number;
  readonly registered: number;
  readonly alreadyRegistered: number;
}

function scopeExistsRejection(
  verified: VerifiedProject,
  scope: readonly EnvironmentId[],
): string | null {
  for (const environmentId of scope) {
    if (!verified.state.environments.has(environmentId)) {
      return `Environment ${environmentId} does not exist on the chain (no create_environment observed). Pass existing environment IDs to --environments`;
    }
  }
  return null;
}

function duplicateServerKeyRejection(
  verified: VerifiedProject,
  serverEncPubHex: string,
): string | null {
  for (const chainMember of verified.state.members.values()) {
    for (const device of chainMember.devices.values()) {
      if (device.encPubHex === serverEncPubHex) {
        return "The server enc public key equals a current member's enc public key (consensus rule duplicate-server-key — CRYPTO_SPEC §6.2). Check the deployment's key configuration";
      }
    }
  }
  return null;
}

function scopeNarrowedRejection(
  existing: ServerGrant | null,
  scope: readonly EnvironmentId[],
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

function ensureGrantable(input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: UserId;
  readonly scope: readonly EnvironmentId[];
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

function sameScope(a: readonly EnvironmentId[], b: readonly EnvironmentId[]): boolean {
  return a.length === b.length && a.every((id, index) => b[index] === id);
}

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
  const computed = yield* serverKeyFingerprintHex(encPub).pipe(Effect.mapError(() => mismatch));
  if (computed !== fingerprintHex) {
    return yield* Effect.fail(mismatch);
  }
  return { serverEncPubHex: encPubHex, serverKeyFingerprintHex: computed };
});

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

function backfillEnvironment(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly recipient: DekRecipient;
  readonly grant: ServerGrant;
  readonly signerUserId: UserId;
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

function grantUnchanged(
  existing: ServerGrant | null,
  scope: readonly EnvironmentId[],
  leasePolicy: readonly LeasePolicyIssuer[],
): boolean {
  return (
    existing !== null &&
    sameScope([...existing.scopeEnvironmentIds].toSorted(), scope) &&
    samePolicy(existing.leasePolicy, leasePolicy)
  );
}

type ServerGrantOutcome =
  | { readonly kind: "proposed"; readonly proposal: ProposedSummary }
  | { readonly kind: "applied"; readonly summary: GrantSummary };

export const backfillServerGrant = Effect.fn("server-grant.backfillServerGrant")(function* (input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly grant: ServerGrant;
  readonly recipient: DekRecipient;
  readonly signerUserId: UserId;
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
  readonly keySource?: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentIds: readonly EnvironmentId[];
  readonly leasePolicy: readonly LeasePolicyIssuer[];
  readonly expectFingerprintHex: string | null;
  readonly signerUserId: UserId;
  readonly signingKeyPair: SigningKeyPair;
  readonly recipient: DekRecipient;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly proposal: ProposalInput;
}): Effect.fn.Return<ServerGrantOutcome, CliError, CliIo> {
  const io = yield* CliIo;
  const scope = [...new Set(input.environmentIds)].toSorted();
  const serverConfig = yield* fetchServerKeyConfig(input.keySource ?? input.client);
  const { existing } = yield* ensureGrantable({
    verified: input.verified,
    signerUserId: input.signerUserId,
    scope,
    serverConfig,
  });

  const unchanged = grantUnchanged(existing, scope, input.leasePolicy);

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
  if (!unchanged && isApprovalTarget(inner, input.verified.state.approvalPolicy)) {
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
    const outcome = yield* appendOperationWithRetry(input, {
      operation: inner,
      initial: { verified },
      recheck: (resynced) =>
        Effect.gen(function* () {
          yield* ensureStillTarget(resynced, inner, false);
          yield* ensureGrantable({
            verified: resynced,
            signerUserId: input.signerUserId,
            scope,
            serverConfig,
          });
          return { verified: resynced };
        }),
    });
    verified = yield* resyncExtended(input.resync, outcome.state.verified);
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
