// `maruhi rotation proposals | accept | reject`: the member side of sealed
// value proposals (CRYPTO_SPEC §5.3 / AUTH_SPEC §14-5 — PF7b).
//
// A proposal is a value a CI job minted at the issuer and sealed to the
// devices of the members who may accept it (ci-rotate.ts). Accepting is
// an ordinary push: this device opens its own wrap with its enc key,
// checks that the proposal still targets the verified current version,
// shows the connector's facts and which workload identity minted it, and
// pushes the plaintext signed as this member — then tells the server the
// proposal is resolved. Rejecting only tells the server; the credential
// that exists at the issuer is named so a human can retire it.
//
// Values are never displayed (the report names variables, versions, and
// the facts).

import type { RotationProposal } from "@maruhi/api-schema";
import type { EnvironmentId } from "@maruhi/core";
import { decodeHex, openProposedValue } from "@maruhi/crypto";
import { Effect, Redacted } from "effect";

import type { CliServices, EnvironmentContext, ProjectContextBase } from "./context.ts";
import { environmentKeysFor } from "./deks.ts";
import { countNoun, displayText, formatUtcDate, formatUtcMinutes } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo } from "./io.ts";
import { logWarning } from "./notice.ts";
import { decryptVerifiedValue } from "./pull.ts";
import { type PushedVersion, pushVariable } from "./push.ts";
import { describeShape, lineCountWarning, shapeOf, type ValueShape } from "./rotate-connector.ts";
import { fetchRotationProposals, resolveVariableStates, type StateIndex } from "./rotation.ts";
import {
  pullVerifiedEnvironment,
  type VerifiedEnvironmentPull,
  type VerifiedPulledValue,
} from "./values.ts";
import { ensureConfirmed } from "./var-rotate.ts";

/** A proposal's variables for display: the verified name when known, else the identifier. */
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

/** `maruhi rotation proposals [--env]`: the pending proposals with their next step (no value is opened). */
export function rotationProposalsOp(
  context: ProjectContextBase,
  options: { readonly environmentId?: string | undefined } = {},
): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const all = yield* fetchRotationProposals(context.client, context.projectId);
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
}

/** Finds the pending proposal with the given id (a full id; a unique prefix of at least 8 characters is accepted). */
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

export interface AcceptInput {
  readonly context: EnvironmentContext;
  readonly proposal: RotationProposal;
  /** true = skip the confirmation (the only non-interactive path). */
  readonly yes: boolean;
}

export interface AcceptResult {
  readonly proposalId: string;
  readonly pushed: readonly { readonly name: string; readonly version: PushedVersion }[];
  /** The proposed values an earlier accept had already pushed (resolved now, not pushed again). */
  readonly stored: readonly { readonly name: string; readonly version: number }[];
  readonly warnings: readonly string[];
}

interface OpenedValue {
  readonly variableId: string;
  readonly name: string;
  readonly value: Redacted.Redacted<Uint8Array>;
  /**
   * The version that already holds this value (an earlier accept pushed
   * it but did not get to resolve) — nothing to push; null = to push on
   * top of the base version.
   */
  readonly storedAs: number | null;
  /** The opened value's shape, for the report (D-8) — computed where the value was opened, so the report unwraps nothing. */
  readonly shape: ValueShape;
  /** The verified current value's shape, opened on this device for the report's comparison (D-18). */
  readonly currentShape: ValueShape;
}

/**
 * The verified current value, decrypted on this device: its shape stands
 * beside the proposed value's in the acceptance (D-18 — the acceptor is
 * the pusher, so the comparison is made where the decision is), and its
 * bytes tell whether an earlier `accept` already pushed the proposed value
 * (a push that succeeded while the resolution, or a later variable's push,
 * failed leaves exactly that state). Decrypts the current
 * value with this device's DEK and compares the bytes; a different value
 * means the variable moved.
 */
function storedValue(
  context: EnvironmentContext,
  pulled: VerifiedEnvironmentPull,
  current: VerifiedPulledValue,
): Effect.Effect<Redacted.Redacted<Uint8Array>, CliError> {
  return Effect.gen(function* () {
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
    });
  });
}

function sameBytes(stored: Uint8Array, proposed: Uint8Array): boolean {
  return stored.length === proposed.length && stored.every((byte, i) => byte === proposed[i]);
}

/** The verified current value a proposed variable targets (missing or behind the base = refused). */
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

/** Opens the wrap sealed to this device (by its enc key) under the §5.3 info of the proposed variable. */
function openOwnWrap(
  input: AcceptInput,
  variable: RotationProposal["variables"][number],
  name: string,
): Effect.Effect<Uint8Array, CliError> {
  return Effect.gen(function* () {
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
    const opened = yield* Effect.promise(() =>
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
    );
    if (!opened.ok) {
      return yield* Effect.fail(
        cliError(
          `Cannot open the sealed value of ${displayText(name)} with this device's key (${opened.error.kind}): the proposal was sealed to another key or another context, or it is corrupt. Reject it and let the job run again`,
        ),
      );
    }
    return opened.value;
  });
}

/** Opens this device's wrap of one proposed variable after checking the target still is the verified current version. */
function openOne(
  input: AcceptInput,
  pulled: VerifiedEnvironmentPull,
  variable: RotationProposal["variables"][number],
): Effect.Effect<OpenedValue, CliError> {
  return Effect.gen(function* () {
    const { context, proposal } = input;
    const current = yield* currentOf(input, pulled, variable);
    const value = yield* openOwnWrap(input, variable, current.name);
    // Reason for unwrapping: the shape and the byte comparison (both values are this device's to know)
    const stored = Redacted.value(yield* storedValue(context, pulled, current));
    // A current version past the base is either an earlier accept's own
    // push (the same bytes — nothing to push, only to resolve) or a
    // move, which makes the proposal stale
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
}

/**
 * `maruhi rotation accept <id>`: opens this device's wraps, confirms, pushes
 * every proposed value as an ordinary signed version (companions first —
 * the server's variable order), then resolves the proposal.
 */
export function rotationAcceptOp(
  input: AcceptInput,
): Effect.Effect<AcceptResult, CliError, CliServices> {
  return Effect.gen(function* () {
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
      environmentId: context.environmentId as EnvironmentId,
      resync: context.resync,
      floor: context.floorHandle,
    });
    // The server's variable order is the minted order (companions first)
    const opened = yield* Effect.forEach(proposal.variables, (variable) =>
      openOne(input, pulled, variable),
    );
    const toPush = opened.filter((entry) => entry.storedAs === null);
    // A line count that changed is worth a look before the push, here
    // where the decision is made (D-18; the CI job's report already showed it)
    yield* Effect.forEach(
      toPush.flatMap((entry) => {
        const warning = lineCountWarning(displayText(entry.name), entry.shape, entry.currentShape);
        return warning === null ? [] : [warning];
      }),
      (warning) => logWarning(warning),
      { discard: true },
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
}

/** The confirmation's lines: what is pushed, what is already stored, who minted it, and the connector's facts. */
function acceptanceFacts(
  proposal: RotationProposal,
  environmentId: string,
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
  // The shape of each value to push, from the opened plaintext on this
  // device (D-8), beside the current value's (D-18): a job that produced
  // chatter instead of a credential shows here, verified, before anything
  // is pushed — the server never saw it
  const shapes = toPush.map(
    (entry) =>
      `  ${displayText(entry.name)}: ${describeShape(entry.shape)} (opened on this device; the current value: ${describeShape(entry.currentShape)})`,
  );
  return [head, ...proposal.facts.map((fact) => `  ${displayText(fact)}`), ...shapes];
}

/** Pushes the opened values that are not stored yet, in the proposal's order, as ordinary signed versions. */
function pushProposed(
  context: EnvironmentContext,
  proposal: RotationProposal,
  pulled: VerifiedEnvironmentPull,
  toPush: readonly OpenedValue[],
): Effect.Effect<readonly { readonly name: string; readonly version: PushedVersion }[], CliError> {
  return Effect.gen(function* () {
    const pushed: { readonly name: string; readonly version: PushedVersion }[] = [];
    for (const entry of toPush) {
      const version = yield* pushVariable({
        client: context.client,
        environmentId: context.environmentId as EnvironmentId,
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
}

/** Tells the server the proposal is accepted, naming the versions that hold its values (a failure says how to finish). */
function resolveAccepted(
  context: EnvironmentContext,
  proposal: RotationProposal,
  opened: readonly OpenedValue[],
  versions: readonly { readonly variableId: string; readonly version: number }[],
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

/** The report lines of an acceptance (values never appear). */
export function describeAcceptance(result: AcceptResult, environmentId: string): string[] {
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

/** `maruhi rotation reject <id>`: drops the proposal; the credential it created at the issuer is named for retirement. */
export function rotationRejectOp(input: {
  readonly context: ProjectContextBase;
  readonly proposal: RotationProposal;
}): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
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
}
