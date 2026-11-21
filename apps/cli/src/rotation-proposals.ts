import type { RotationProposal } from "@maruhi/api-schema";
import { type EnvironmentId, type VariableId, cryptoEffect } from "@maruhi/core";
import { decodeHex, openProposedValue } from "@maruhi/crypto";
import { Effect, Redacted } from "effect";

import {
  describeShape,
  lineCountWarning,
  shapeOf,
  type ValueShape,
} from "./connector.package/index.ts";
import type { CliServices, EnvironmentContext, ProjectContextBase } from "./context.ts";
import { cryptoErrorKind } from "./crypto-error-kind.ts";
import { environmentKeysFor } from "./deks.ts";
import { countNoun, displayText, formatUtcDate, formatUtcMinutes, logWarnings } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo } from "./io.ts";
import { decryptVerifiedValue } from "./pull.ts";
import { type PushedVersion, pushVariable } from "./push.package/index.ts";
import { fetchRotationProposals, resolveVariableStates, type StateIndex } from "./rotation.ts";
import type { VerifiedPulledValue } from "./values-verify.ts";
import { pullVerifiedEnvironment, type VerifiedEnvironmentPull } from "./values.ts";
import { ensureConfirmed } from "./var.package/index.ts";

function describeVariables(proposal: RotationProposal, states: StateIndex | undefined): string {
  return proposal.variables
    .map((variable) => {
      const state = states?.get(variable.variableId);
      const label =
        state === undefined
          ? displayText(variable.variableId)
          : `${displayText(state.name)} (${displayText(variable.variableId)})`;
      return `${label} replacing version ${variable.baseVersion}`;
    })
    .join(", ");
}

export const rotationProposalsOp = Effect.fn("rotation-proposals.rotationProposalsOp")(function* (
  context: ProjectContextBase,
  options: { readonly environmentId?: EnvironmentId | undefined } = {},
): Effect.fn.Return<void, CliError, CliServices> {
  const io = yield* CliIo;
  const all = yield* fetchRotationProposals(context);
  const proposals =
    options.environmentId === undefined
      ? all
      : all.filter((proposal) => proposal.environmentId === options.environmentId);
  if (proposals.length === 0) {
    yield* io.log(
      options.environmentId === undefined
        ? "No sealed proposals are pending"
        : `No sealed proposals are pending for environment ${displayText(options.environmentId)}`,
    );
    return;
  }
  const environmentIds = [
    ...new Set(proposals.map((proposal) => proposal.environmentId)),
  ].toSorted();
  const states = yield* resolveVariableStates(context, environmentIds);
  yield* io.log(
    `Pending sealed proposals: ${countNoun(proposals.length, "proposal")} (minted by CI jobs under a workload lease — each waits for a member's accept or reject)`,
  );
  for (const proposal of proposals) {
    yield* io.log(
      `  ${proposal.proposalId}\tenvironment=${displayText(proposal.environmentId)}\tconnector=${proposal.connector}\tminted=${formatUtcMinutes(proposal.createdAtMs)}\texpires=${formatUtcDate(proposal.expiresAtMs)}`,
    );
    yield* io.log(
      `    variables: ${describeVariables(proposal, states.get(proposal.environmentId))}`,
    );
    yield* io.log(
      `    minted by: the workload whose lease claims digest is ${proposal.claimsDigestHex.slice(0, 16)}… under the grant at chain seq ${proposal.grantChainSeq} (\`maruhi audit list --event rotation.proposed\` shows the row)`,
    );
    for (const fact of proposal.facts) {
      yield* io.log(`    ${displayText(fact)}`);
    }
    yield* io.log(
      `    next: \`maruhi rotation accept ${proposal.proposalId}\` (pushes the new value signed as you) or \`maruhi rotation reject ${proposal.proposalId}\``,
    );
  }
});

export function findProposal(
  proposals: readonly RotationProposal[],
  proposalId: string,
): Effect.Effect<RotationProposal, CliError> {
  const exact = proposals.find((proposal) => proposal.proposalId === proposalId);
  if (exact !== undefined) {
    return Effect.succeed(exact);
  }
  const prefixed =
    proposalId.length >= 8
      ? proposals.filter((proposal) => proposal.proposalId.startsWith(proposalId))
      : [];
  const [single] = prefixed;
  if (prefixed.length === 1 && single !== undefined) {
    return Effect.succeed(single);
  }
  return Effect.fail(
    cliError(
      prefixed.length > 1
        ? `${displayText(proposalId)} matches several pending proposals; give more of the id (\`maruhi rotation proposals\`)`
        : `No pending sealed proposal has the id ${displayText(proposalId)} (it was resolved, expired, or never existed; \`maruhi rotation proposals\` lists the pending ones)`,
    ),
  );
}

interface AcceptInput {
  readonly context: EnvironmentContext;
  readonly proposal: RotationProposal;
  readonly yes: boolean;
}

export interface AcceptResult {
  readonly proposalId: string;
  readonly pushed: readonly { readonly name: string; readonly version: PushedVersion }[];
  readonly stored: readonly { readonly name: string; readonly version: number }[];
  readonly warnings: readonly string[];
}

interface OpenedValue {
  readonly variableId: VariableId;
  readonly name: string;
  readonly value: Redacted.Redacted<Uint8Array>;
  readonly storedAs: number | null;
  readonly shape: ValueShape;
  readonly currentShape: ValueShape;
}

const storedValue = Effect.fn("rotation-proposals.storedValue")(function* (
  context: EnvironmentContext,
  pulled: VerifiedEnvironmentPull,
  current: VerifiedPulledValue,
): Effect.fn.Return<Redacted.Redacted<Uint8Array>, CliError> {
  const keys = yield* environmentKeysFor({
    client: context.client,
    verified: pulled.verified,
    environmentId: context.environmentId,
    recipient: context.recipient,
    prefetched: pulled.deks,
  });
  return yield* decryptVerifiedValue({
    verified: pulled.verified,
    environmentId: context.environmentId,
    variable: current,
    deksByEpoch: keys.deksByEpoch,
    chainEpoch: keys.currentEpoch,
  }).pipe(
    Effect.mapError((error) =>
      cliError(
        `The current value of ${displayText(current.name)} cannot be opened on this device (${error.message}); the acceptance compares the proposed value with it before the push. Accept from a device that can read the environment (the one that approved this device's registration backfills its wraps — \`maruhi key device approve\`), or reject the proposal`,
      ),
    ),
  );
});

function sameBytes(stored: Uint8Array, proposed: Uint8Array): boolean {
  return stored.length === proposed.length && stored.every((byte, i) => byte === proposed[i]);
}

function currentOf(
  input: AcceptInput,
  pulled: VerifiedEnvironmentPull,
  variable: RotationProposal["variables"][number],
): Effect.Effect<VerifiedPulledValue, CliError> {
  const { context, proposal } = input;
  const current = pulled.variables.find((entry) => entry.variableId === variable.variableId);
  if (current === undefined) {
    return Effect.fail(
      cliError(
        `The proposal targets variable ${displayText(variable.variableId)}, which has no active value in environment ${displayText(context.environmentId)} any more. Reject the proposal (\`maruhi rotation reject ${proposal.proposalId}\`) and retire the credential it created at the issuer`,
      ),
    );
  }
  if (current.version < variable.baseVersion) {
    return Effect.fail(
      cliError(
        `${displayText(current.name)} is at version ${current.version}, behind the version ${variable.baseVersion} the proposal replaces (the server's view is older than the job's — a rollback or a stale server). Refusing; sync and try again`,
      ),
    );
  }
  return Effect.succeed(current);
}

const openOwnWrap = Effect.fn("rotation-proposals.openOwnWrap")(function* (
  input: AcceptInput,
  variable: RotationProposal["variables"][number],
  name: string,
): Effect.fn.Return<Uint8Array, CliError> {
  const { context, proposal } = input;
  const wrap = variable.wraps.find(
    (candidate) => candidate.recipientEncPubHex === context.recipient.encPubHex,
  );
  if (wrap === undefined) {
    return yield* Effect.fail(
      cliError(
        `The proposal carries no value sealed to this device (key ${context.masterKeys.fingerprintHex}) for ${displayText(name)}: it was minted before this device was registered, or this device is not in the environment's scope. Accept it from another device, or reject it`,
      ),
    );
  }
  const enc = decodeHex(wrap.encHex);
  const ciphertext = decodeHex(wrap.ciphertextHex);
  if (enc === null || ciphertext === null) {
    return yield* Effect.fail(cliError("The proposal's sealed value is malformed (not hex)"));
  }
  const opened = yield* cryptoEffect(() =>
    openProposedValue({
      recipientKeyPair: context.recipient.encKeyPair,
      sealed: { enc, ciphertext },
      context: {
        projectId: context.projectId,
        environmentId: context.environmentId,
        proposalId: proposal.proposalId,
        variableId: variable.variableId,
        baseVersion: variable.baseVersion,
        recipientUserId: context.session.userId,
      },
    }),
  ).pipe(
    Effect.mapError((error) =>
      cliError(
        `Cannot open the sealed value of ${displayText(name)} with this device's key (${cryptoErrorKind(error)}): the proposal was sealed to another key or another context, or it is corrupt. Reject it and let the job run again`,
      ),
    ),
  );
  return opened;
});

const openOne = Effect.fnUntraced(function* (
  input: AcceptInput,
  pulled: VerifiedEnvironmentPull,
  variable: RotationProposal["variables"][number],
): Effect.fn.Return<OpenedValue, CliError> {
  const { context, proposal } = input;
  const current = yield* currentOf(input, pulled, variable);
  const value = yield* openOwnWrap(input, variable, current.name);
  const stored = Redacted.value(yield* storedValue(context, pulled, current));
  const moved = current.version > variable.baseVersion;
  if (moved && !sameBytes(stored, value)) {
    return yield* Effect.fail(
      cliError(
        `${displayText(current.name)} moved since the proposal was minted (it replaces version ${variable.baseVersion}, the current version is ${current.version}). Reject the proposal (\`maruhi rotation reject ${proposal.proposalId}\`), retire the credential it created at the issuer, and let the job run again`,
      ),
    );
  }
  return {
    variableId: variable.variableId,
    name: current.name,
    value: Redacted.make(value, { label: "variable-value" }),
    storedAs: moved ? current.version : null,
    shape: shapeOf(value),
    currentShape: shapeOf(stored),
  };
});

export const rotationAcceptOp = Effect.fn("rotation-proposals.rotationAcceptOp")(function* (
  input: AcceptInput,
): Effect.fn.Return<AcceptResult, CliError, CliServices> {
  const { context, proposal } = input;
  if (proposal.environmentId !== context.environmentId) {
    return yield* Effect.fail(
      cliError(
        `Proposal ${proposal.proposalId} belongs to environment ${displayText(proposal.environmentId)}, not ${displayText(context.environmentId)}`,
      ),
    );
  }
  const pulled = yield* pullVerifiedEnvironment({
    client: context.client,
    verified: context.verified,
    environmentId: context.environmentId,
    resync: context.resync,
    floor: context.floorHandle,
  });
  const opened = yield* Effect.forEach(proposal.variables, (variable) =>
    openOne(input, pulled, variable),
  );
  const toPush = opened.filter((entry) => entry.storedAs === null);
  yield* logWarnings(
    toPush.flatMap((entry) => {
      const warning = lineCountWarning(
        displayText(entry.name),
        entry.shape,
        entry.currentShape,
        proposal.connector,
      );
      return warning === null ? [] : [warning];
    }),
  );
  yield* ensureConfirmed({
    facts: acceptanceFacts(proposal, context.environmentId, opened),
    prompt: "Accept and push? [y/N]: ",
    refusal: `Refusing to accept proposal ${proposal.proposalId} in a non-interactive environment without --yes (it pushes new versions signed by you). Re-run with --yes to accept that explicitly`,
    abort: "Aborted: nothing was pushed and the proposal stays pending",
    yes: input.yes,
  });
  const pushed = yield* pushProposed(context, proposal, pulled, toPush);
  const versions = opened.map((entry) => ({
    variableId: entry.variableId,
    version:
      pushed.find((candidate) => candidate.name === entry.name)?.version.version ??
      entry.storedAs ??
      0,
  }));
  yield* resolveAccepted(context, proposal, opened, versions);
  return {
    proposalId: proposal.proposalId,
    pushed,
    stored: opened.flatMap((entry) =>
      entry.storedAs === null ? [] : [{ name: entry.name, version: entry.storedAs }],
    ),
    warnings: [...pulled.warnings, ...pushed.flatMap((entry) => entry.version.warnings)],
  };
});

function acceptanceFacts(
  proposal: RotationProposal,
  environmentId: EnvironmentId,
  opened: readonly OpenedValue[],
): string[] {
  const toPush = opened.filter((entry) => entry.storedAs === null);
  const already = opened
    .filter((entry) => entry.storedAs !== null)
    .map((entry) => `${displayText(entry.name)} version ${entry.storedAs}`);
  const minter = `It was minted with the ${proposal.connector} connector by the workload whose lease claims digest is ${proposal.claimsDigestHex.slice(0, 16)}… (grant at chain seq ${proposal.grantChainSeq})`;
  const head =
    toPush.length === 0
      ? `Accepting proposal ${proposal.proposalId}: every proposed value is already stored in environment ${displayText(environmentId)} (${already.join(", ")} — an earlier accept pushed it); nothing is pushed, the proposal is resolved as accepted. ${minter}`
      : `Accepting proposal ${proposal.proposalId} pushes ${toPush.map((entry) => displayText(entry.name)).join(", ")} in environment ${displayText(environmentId)} as new versions signed by you${already.length === 0 ? "" : ` (already stored: ${already.join(", ")})`}. ${minter}`;
  const shapes = toPush.map(
    (entry) =>
      `  ${displayText(entry.name)}: ${describeShape(entry.shape)} (opened on this device; the current value: ${describeShape(entry.currentShape)})`,
  );
  return [head, ...proposal.facts.map((fact) => `  ${displayText(fact)}`), ...shapes];
}

const pushProposed = Effect.fn("rotation-proposals.pushProposed")(function* (
  context: EnvironmentContext,
  proposal: RotationProposal,
  pulled: VerifiedEnvironmentPull,
  toPush: readonly OpenedValue[],
): Effect.fn.Return<
  readonly { readonly name: string; readonly version: PushedVersion }[],
  CliError
> {
  const pushed: { readonly name: string; readonly version: PushedVersion }[] = [];
  for (const entry of toPush) {
    const version = yield* pushVariable({
      client: context.client,
      environmentId: context.environmentId,
      recipient: context.recipient,
      name: entry.name,
      value: entry.value,
      verified: pulled.verified,
      resync: context.resync,
      writerUserId: context.session.userId,
      signingKey: context.masterKeys.sigKeyPair.privateKey,
      floor: context.floorHandle,
    }).pipe(
      Effect.mapError((error) =>
        cliError(
          `Storing ${displayText(entry.name)} failed: ${error.message}. ${pushed.length === 0 ? "Nothing was stored" : `Stored so far: ${pushed.map((done) => `${displayText(done.name)} (version ${done.version.version})`).join(", ")}`}; the proposal stays pending — fix the cause and run \`maruhi rotation accept ${proposal.proposalId}\` again (a value already stored is recognized and not pushed twice)`,
        ),
      ),
    );
    pushed.push({ name: entry.name, version });
  }
  return pushed;
});

function resolveAccepted(
  context: EnvironmentContext,
  proposal: RotationProposal,
  opened: readonly OpenedValue[],
  versions: readonly { readonly variableId: VariableId; readonly version: number }[],
): Effect.Effect<void, CliError> {
  const named = versions
    .map(
      (entry) =>
        `${displayText(opened.find((candidate) => candidate.variableId === entry.variableId)?.name ?? entry.variableId)} version ${entry.version}`,
    )
    .join(", ");
  return context.client.rotation
    .resolveProposal({
      params: { projectId: context.projectId, proposalId: proposal.proposalId },
      payload: { outcome: "accepted", versions },
    })
    .pipe(
      Effect.mapError((error) =>
        cliError(
          `The new versions are stored (${named}) but resolving the proposal failed: ${toCliError(error).message}. Run \`maruhi rotation accept ${proposal.proposalId}\` again: it recognizes the stored values, pushes nothing, and only resolves the proposal`,
        ),
      ),
    );
}

export function describeAcceptance(result: AcceptResult, environmentId: EnvironmentId): string[] {
  const versions = [
    ...result.pushed.map(
      (entry) =>
        `${displayText(entry.name)} version=${entry.version.version}, epoch=${entry.version.epoch}`,
    ),
    ...result.stored.map(
      (entry) => `${displayText(entry.name)} version=${entry.version} (already stored)`,
    ),
  ].join("; ");
  return [
    `Accepted proposal ${result.proposalId} in environment ${displayText(environmentId)}: ${versions}`,
    `Deploy the new value (${countNoun(result.pushed.length, "variable")} pushed${result.stored.length === 0 ? "" : `, ${countNoun(result.stored.length, "variable")} already stored`}). If the connector left the previous credential valid, invalidate it after the deploy with \`maruhi var rotate <name> --finalize\` from a machine that holds the rotation config`,
  ];
}

export const rotationRejectOp = Effect.fn("rotation-proposals.rotationRejectOp")(function* (input: {
  readonly context: ProjectContextBase;
  readonly proposal: RotationProposal;
}): Effect.fn.Return<void, CliError, CliServices> {
  const io = yield* CliIo;
  const { context, proposal } = input;
  yield* context.client.rotation
    .resolveProposal({
      params: { projectId: context.projectId, proposalId: proposal.proposalId },
      payload: { outcome: "rejected" },
    })
    .pipe(Effect.mapError(toCliError));
  yield* io.log(
    `Rejected proposal ${proposal.proposalId} (environment ${displayText(proposal.environmentId)}; rotation.proposal_rejected recorded in the audit log). The credential the job created still exists at the issuer — retire it by hand:`,
  );
  for (const fact of proposal.facts) {
    yield* io.log(`  ${displayText(fact)}`);
  }
});
