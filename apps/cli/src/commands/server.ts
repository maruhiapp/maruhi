// `maruhi server` (discipline: see commands/index.ts).

import { type EnvironmentId, isEnvironmentId } from "@maruhi/core";
import { Effect } from "effect";
import { Command } from "effect/cli";

import { type MaruhiClient, makeApiClient } from "../api.ts";
import { type CliServices, type CommonFlags, openProject } from "../context.ts";
import { countNoun } from "../display.ts";
import { CliError, usageError } from "../errors.ts";
import { parseFingerprintFlag } from "../fingerprint-flag.ts";
import { CliIo, type CliIoShape } from "../io.ts";
import { loadLeasePolicy } from "../lease-policy.ts";
import { logNote } from "../notice.ts";
import { reportRotationChecklist } from "../rotation.ts";
import { serverGrantOp } from "../server-grant.ts";
import { REVOKE_ROTATION_REASON, type RevokeSummary, serverRevokeOp } from "../server-revoke.ts";
import { normalizeHttpOrigin } from "../session.ts";
import { sweepRotateFor } from "../sweep-rotate.ts";
import { projectFlags, proposalFlags, singleValued } from "./flags.ts";
import { proposalInputOf, reportProposed, reportSweepOutcome } from "./shared.ts";

export const serverGrantConfig = {
  ...projectFlags(),
  ...proposalFlags(),
  environments: singleValued(
    "environments",
    "Comma-separated environment IDs to disclose (required; environments are always explicit)",
  ),
  "lease-policy": singleValued(
    "lease-policy",
    "Path to a workload lease-policy JSON file (defaults to no lease path)",
  ),
  "expect-fingerprint": singleValued(
    "expect-fingerprint",
    "Server key fingerprint noted out of band (32 hex chars; replaces the interactive check)",
  ),
  "key-from": singleValued(
    "key-from",
    "URL of the deployment whose server key to grant, such as a mirror (its /auth/config supplies the key; the grant is appended on the server and reaches the mirror by replication). Default: the server itself",
  ),
};

export const serverRevokeConfig = {
  ...projectFlags(),
  ...proposalFlags(),
  fingerprint: singleValued(
    "fingerprint",
    "Server key fingerprint to revoke (may be omitted when exactly one grant is active)",
  ),
};

/**
 * Interpreting `--environments dev,prod` (mandatory on grant — the
 * minimal-disclosure default is environments are explicitly listed.
 * session-22 §2's ruling). An empty element is refused as a misspelling.
 */
function parseEnvironmentsFlag(
  value: string | undefined,
): Effect.Effect<readonly EnvironmentId[], CliError> {
  if (value === undefined) {
    return Effect.fail(
      usageError(
        "grant requires --environments (list the environments to disclose, comma-separated — e.g. --environments dev,prod)",
      ),
    );
  }
  const ids = value.split(",").map((part) => part.trim());
  if (ids.length === 0 || ids.some((id) => id.length === 0)) {
    return Effect.fail(
      usageError(
        "--environments is malformed (comma-separated environment IDs; empty items are not allowed)",
      ),
    );
  }
  const invalid = ids.filter((id) => !isEnvironmentId(id));
  if (invalid.length > 0) {
    return Effect.fail(
      usageError(
        "--environments contains malformed environment IDs (each must start with an alphanumeric character, followed by up to 63 alphanumerics, _ or -)",
      ),
    );
  }
  return Effect.succeed(ids.filter(isEnvironmentId));
}

/** The deployment whose server key `server grant --key-from` grants (a mirror — AUTH_SPEC §11-7 ruling F). */
interface GrantKeySource {
  readonly origin: string;
  readonly client: MaruhiClient;
}

/**
 * The client whose `/auth/config` supplies the key (`--key-from`; null = the
 * server itself). The endpoint is unauthenticated, so a tokenless client
 * reads it; naming the server itself is the default spelled out.
 */
const grantKeySource = Effect.fn("commands-server.grantKeySource")(function* (
  keyOrigin: string | null,
  serverOrigin: string,
): Effect.fn.Return<GrantKeySource | null, CliError, CliServices> {
  if (keyOrigin === null) {
    return null;
  }
  if (keyOrigin === serverOrigin) {
    yield* logNote("--key-from names the server itself; granting its own key");
    return null;
  }
  return { origin: keyOrigin, client: yield* makeApiClient({ baseUrl: keyOrigin }) };
});

/** After a grant of another deployment's key: how the grant reaches it. */
function noteGrantKeySource(keySource: GrantKeySource | null) {
  return keySource === null
    ? Effect.void
    : logNote(
        `the grant and the wraps reach ${keySource.origin} with the next \`maruhi mirror sync\` (a mirror accepts no write of its own)`,
      );
}

const serverGrantCommand = Effect.fn("commands-server.serverGrantCommand")(function* (
  flags: CommonFlags & {
    readonly environments?: string | undefined;
    readonly leasePolicyPath?: string | undefined;
    readonly expectFingerprint?: string | undefined;
    readonly expires?: string | undefined;
    readonly keyFrom?: string | undefined;
  },
): Effect.fn.Return<number, CliError, CliServices> {
  const io = yield* CliIo;
  const environmentIds = yield* parseEnvironmentsFlag(flags.environments);
  const leasePolicy = yield* loadLeasePolicy(flags.leasePolicyPath);
  const expectFingerprintHex = yield* parseFingerprintFlag(
    "--expect-fingerprint",
    flags.expectFingerprint,
  );
  const proposal = yield* proposalInputOf(flags.expires);
  // The key of another deployment (a mirror — AUTH_SPEC §11-7 ruling F);
  // the URL's format check precedes any network
  const keyOrigin =
    flags.keyFrom === undefined
      ? null
      : yield* normalizeHttpOrigin(flags.keyFrom, "the --key-from URL");
  const context = yield* openProject(flags);
  const keySource = yield* grantKeySource(keyOrigin, context.origin);
  const outcome = yield* serverGrantOp({
    client: context.client,
    ...(keySource === null ? {} : { keySource: keySource.client }),
    verified: context.verified,
    environmentIds,
    leasePolicy,
    expectFingerprintHex,
    signerUserId: context.session.userId,
    signingKeyPair: context.masterKeys.sigKeyPair,
    recipient: context.recipient,
    resync: context.resync,
    proposal,
  });
  if (outcome.kind === "proposed") {
    return yield* reportProposed(io, outcome.proposal);
  }
  const summary = outcome.summary;
  const policyNote =
    summary.leasePolicyCount === 0
      ? "no lease path (lease_policy is empty)"
      : `lease_policy has ${countNoun(summary.leasePolicyCount, "element")}`;
  const keyNote = keySource === null ? "" : ` (the key of ${keySource.origin})`;
  yield* io.log(
    `Done: disclosure to server key ${summary.serverKeyFingerprintHex}${keyNote} is active (scope=${summary.scopeEnvironmentIds.join(", ")}, ${policyNote}). Backfill: ${summary.registered} newly registered, ${summary.alreadyRegistered} already registered`,
  );
  yield* noteGrantKeySource(keySource);
  // §9: always indicate that it is being disclosed (the revocation path is also guided on the spot)
  yield* logNote(
    "the epoch DEKs of environments in the disclosure scope are disclosed to the server (CRYPTO_SPEC §9). To withdraw, run `maruhi server revoke` (it forces a rotation of every environment — §7)",
  );
  return 0;
});

/** `maruhi server revoke [--fingerprint <hex>]` (§7 / §9). */
const serverRevokeCommand = Effect.fn("commands-server.serverRevokeCommand")(function* (
  flags: CommonFlags & {
    readonly fingerprint?: string | undefined;
    readonly expires?: string | undefined;
  },
): Effect.fn.Return<number, CliError, CliServices> {
  const io = yield* CliIo;
  const fingerprintHex = yield* parseFingerprintFlag("--fingerprint", flags.fingerprint);
  const proposal = yield* proposalInputOf(flags.expires);
  // A convergent command: the always-on warning of unconverged duties is suppressed (its own sweep report carries it)
  const context = yield* openProject(flags, { quietMandateWarning: true });
  // One environment's rotation (reusing envRotateOp — sweepRotateFor)
  const outcome = yield* serverRevokeOp({
    client: context.client,
    verified: context.verified,
    fingerprintHex,
    signerUserId: context.session.userId,
    signingKeyPair: context.masterKeys.sigKeyPair,
    resync: context.resync,
    rotate: sweepRotateFor(context, REVOKE_ROTATION_REASON),
    proposal,
  });
  if (outcome.kind === "proposed") {
    return yield* reportProposed(io, outcome.proposal);
  }
  const summary = outcome.summary;
  yield* reportRevokeAppend(io, summary);
  const exitCode = yield* reportSweepOutcome(summary, {
    rerunCommand: "`maruhi server revoke`",
    alreadyRotatedBasis: "the revocation",
  });
  if (exitCode === 0) {
    yield* io.log("Done: the revocation and the rotation of every environment completed");
  }
  // The needs-rotation-flag count and route (the revoke variant of AUDIT_SPEC §4.1)
  if (summary.serverKeyFingerprintHex !== null) {
    yield* reportRotationChecklist({
      context,
      target: { kind: "server", fingerprintHex: summary.serverKeyFingerprintHex },
    });
  }
  return exitCode;
});

/** Reporting revoke's append result (the sweep's shared part is carried by reportSweepOutcome). */
function reportRevokeAppend(io: CliIoShape, summary: RevokeSummary): Effect.Effect<void, CliError> {
  if (summary.appended) {
    return io.log(
      `Appended revoke_server to the chain (FP=${summary.serverKeyFingerprintHex ?? ""}). Forcing a rotation of every environment (§7)`,
    );
  }
  if (summary.serverKeyFingerprintHex !== null) {
    // The target grant existed, but the CAS-conflict resync found it
    // already revoked (a concurrent revoke). The fact that someone revoked
    // the same key is operationally significant, so it is made explicit
    return io.log(
      `The targeted grant (FP=${summary.serverKeyFingerprintHex}) was already revoked by a concurrent run — skipping the append and proceeding to rotate every environment (§7)`,
    );
  }
  return io.log(
    "No active grant — resuming the post-revocation rotation of every environment from where it left off (crash recovery)",
  );
}

export function makeServerCommands(onExitCode: (code: number) => void) {
  const serverGrant = Command.make(
    "grant",
    serverGrantConfig,
    Effect.fn("commands-server.serverGrant")(function* (values) {
      onExitCode(
        yield* serverGrantCommand({
          server: values.server,
          project: values.project,
          environments: values.environments,
          leasePolicyPath: values["lease-policy"],
          expectFingerprint: values["expect-fingerprint"],
          expires: values.expires,
          keyFrom: values["key-from"],
        }),
      );
    }),
  ).pipe(
    Command.withDescription(
      "Disclose the epoch DEKs of selected environments to the server (selective disclosure)",
    ),
  );

  const serverRevoke = Command.make(
    "revoke",
    serverRevokeConfig,
    Effect.fn("commands-server.serverRevoke")(function* (values) {
      onExitCode(
        yield* serverRevokeCommand({
          server: values.server,
          project: values.project,
          fingerprint: values.fingerprint,
          expires: values.expires,
        }),
      );
    }),
  ).pipe(Command.withDescription("Revoke a server disclosure and force-rotate every environment"));

  const server = Command.make("server").pipe(
    Command.withDescription("Manage selective disclosure to the server (grant / revoke)"),
    Command.withSubcommands([serverGrant, serverRevoke]),
  );

  return server;
}
