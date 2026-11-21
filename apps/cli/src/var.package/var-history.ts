import type { DistributedEncryptedPayload, VariableVersionHistoryEntry } from "@maruhi/api-schema";
import { type EnvironmentId, type UserId, type VariableId, cryptoEffect } from "@maruhi/core";
import { verifyDistributedValue } from "@maruhi/crypto";
import { Effect, Redacted, Stdio } from "effect";

import type { MaruhiClient } from "../api.ts";
import type { VerifiedProject } from "../chain-sync.ts";
import { cryptoErrorKind } from "../crypto-error-kind.ts";
import { type DekRecipient, environmentKeysFor } from "../deks.ts";
import { countNoun, displayText, formatUtcSeconds } from "../display.ts";
import { cliError, type CliError, evidenceError } from "../errors.ts";
import { toCliError } from "../failure.ts";
import type { FloorHandle, VerifiedVariableStatement } from "../floor-check.ts";
import { CliIo } from "../io.ts";
import { decryptVerifiedValue } from "../pull.ts";
import { type PushedVersion, pushVariable, sameRedactedBytes } from "../push.package/index.ts";
import { resolveSchemaTarget } from "../schema.package/index.ts";
import type { VerifiedPulledValue } from "../values-verify.ts";
import { pullVerifiedEnvironment, type VerifiedEnvironmentPull } from "../values.ts";

interface VarHistoryBase {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly name: string;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly floor: FloorHandle;
}

export interface VarHistoryResult {
  readonly name: string;
  readonly variableId: VariableId;
  readonly status: "active" | "declared";
  readonly versions: readonly VariableVersionHistoryEntry[];
  readonly warnings: readonly string[];
}

const resolveLiveVariable = Effect.fn("var-history.resolveLiveVariable")(function* (
  input: VarHistoryBase,
  name: string,
): Effect.fn.Return<
  {
    readonly verified: VerifiedProject;
    readonly target: VerifiedVariableStatement;
    readonly warnings: readonly string[];
  },
  CliError
> {
  const state = yield* resolveSchemaTarget(input, input.verified, name);
  const target = state.target;
  if (target === null) {
    return yield* Effect.fail(
      cliError(
        state.tombstones.some((tombstone) => tombstone.name === name)
          ? `Variable ${displayText(name)} is deleted (deletion destroys every stored version, so it has no history to show or restore)`
          : `Variable ${displayText(name)} does not exist in this environment`,
      ),
    );
  }
  return { verified: state.verified, target, warnings: state.warnings };
});

const fetchHistory = Effect.fn("var-history.fetchHistory")(function* (
  client: MaruhiClient,
  verified: VerifiedProject,
  environmentId: EnvironmentId,
  variableId: VariableId,
): Effect.fn.Return<readonly VariableVersionHistoryEntry[], CliError> {
  const response = yield* client.variables
    .history({ params: { projectId: verified.projectId, environmentId, variableId } })
    .pipe(Effect.mapError(toCliError));
  if (response.variableId !== variableId) {
    return yield* Effect.fail(
      cliError(
        `The server answered the history of ${displayText(response.variableId)} for a request about ${displayText(variableId)} (an inconsistent server response)`,
      ),
    );
  }
  return response.versions.toSorted((a, b) => a.version - b.version);
});

export const varHistoryOp = Effect.fn("var-history.varHistoryOp")(function* (
  input: VarHistoryBase,
): Effect.fn.Return<VarHistoryResult, CliError> {
  const name = input.name.normalize("NFC");
  const resolved = yield* resolveLiveVariable(input, name);
  const status = resolved.target.status === "declared" ? "declared" : "active";
  const versions =
    status === "declared"
      ? []
      : yield* fetchHistory(
          input.client,
          resolved.verified,
          input.environmentId,
          resolved.target.variableId,
        );
  return {
    name,
    variableId: resolved.target.variableId,
    status,
    versions,
    warnings: resolved.warnings,
  };
});

function describeEntry(entry: VariableVersionHistoryEntry, latestVersion: number): string {
  const notes: string[] = [];
  if (entry.version === latestVersion) {
    notes.push("current");
  }
  if (entry.sameValueAs !== undefined) {
    notes.push(
      entry.sameValueAs === entry.version - 1
        ? `re-encryption of v${entry.sameValueAs}`
        : `rollback to v${entry.sameValueAs}`,
    );
  }
  if (entry.flagsIfCurrent > 0) {
    notes.push(
      `${countNoun(entry.flagsIfCurrent, "rotation flag")} while this value is current (a former holder could read it)`,
    );
  }
  return notes.join("; ");
}

export function formatVarHistory(result: VarHistoryResult, environmentId: EnvironmentId): string[] {
  const header = `History of ${displayText(result.name)} (${displayText(result.variableId)}) in environment ${displayText(environmentId)}`;
  if (result.versions.length === 0) {
    return [
      header,
      result.status === "declared"
        ? "  (declared — no value has been pushed yet)"
        : "  (the server listed no version)",
    ];
  }
  const latestVersion = result.versions.at(-1)?.version ?? 0;
  const lines = [header];
  for (const entry of result.versions.toReversed()) {
    const note = describeEntry(entry, latestVersion);
    lines.push(
      `  v${entry.version}\tepoch=${entry.epoch}\t${formatUtcSeconds(entry.pushedAtMs)}\twriter=${displayText(entry.writerUserId)}\tfp=${entry.writerKeyFingerprintHex}${note === "" ? "" : `\t${note}`}`,
    );
  }
  lines.push(
    "Server-declared metadata (not signature-verified). `maruhi var rollback <name> --to <version>` verifies its target against the latest value before restoring it",
  );
  return lines;
}

export function varHistoryJson(result: VarHistoryResult, environmentId: EnvironmentId): string {
  return JSON.stringify(
    {
      environmentId,
      name: result.name,
      variableId: result.variableId,
      status: result.status,
      serverDeclared: true,
      versions: result.versions,
    },
    null,
    2,
  );
}

interface AncestorInput extends VarHistoryBase {
  readonly recipient: DekRecipient;
  readonly toVersion: number;
}

interface VarRollbackInput extends AncestorInput {
  readonly force: boolean;
  readonly writerUserId: UserId;
  readonly signingKey: CryptoKey;
}

interface VarRollbackResult {
  readonly name: string;
  readonly fromVersion: number;
  readonly toVersion: number;
  readonly pushed: PushedVersion;
  readonly flagsIfCurrent: number;
  readonly warnings: readonly string[];
}

function appendPage(
  collected: DistributedEncryptedPayload[],
  page: readonly DistributedEncryptedPayload[],
  next: number,
  latestVersion: number,
): Effect.Effect<number, CliError> {
  let expected = next;
  for (const value of page) {
    if (expected > latestVersion) {
      break;
    }
    if (value.aad.version !== expected) {
      return Effect.fail(
        evidenceError(
          `The version range is not contiguous (expected version ${expected}, got ${value.aad.version}) — an inconsistent server response`,
        ),
      );
    }
    collected.push(value);
    expected += 1;
  }
  return Effect.succeed(expected);
}

const fetchVersionRange = Effect.fn("var-history.fetchVersionRange")(function* (input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly variableId: VariableId;
  readonly fromVersion: number;
  readonly latestVersion: number;
}): Effect.fn.Return<readonly DistributedEncryptedPayload[], CliError> {
  const collected: DistributedEncryptedPayload[] = [];
  const params = {
    projectId: input.verified.projectId,
    environmentId: input.environmentId,
    variableId: input.variableId,
  };
  let next = input.fromVersion;
  while (next <= input.latestVersion) {
    const response = yield* input.client.variables
      .versionValues({ params, query: { fromVersion: next } })
      .pipe(Effect.mapError(toCliError));
    if (response.variableId !== input.variableId || response.values.length === 0) {
      return yield* Effect.fail(
        evidenceError(
          `The server returned no version ${next} of ${displayText(input.variableId)} although the verified latest is version ${input.latestVersion} (an inconsistent server response)`,
        ),
      );
    }
    next = yield* appendPage(collected, response.values, next, input.latestVersion);
  }
  return collected;
});

const verifyVersion = Effect.fnUntraced(function* (input: {
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly latest: VerifiedPulledValue;
  readonly payload: DistributedEncryptedPayload;
  readonly predecessor: { readonly signedBytesHashHex: string; readonly epoch: number } | undefined;
}): Effect.fn.Return<string, CliError> {
  const { verified, environmentId, latest, payload } = input;
  const aad = payload.aad;
  if (
    aad.projectId !== verified.projectId ||
    aad.environmentId !== environmentId ||
    aad.variableId !== latest.variableId
  ) {
    return yield* Effect.fail(
      evidenceError(
        `Version ${aad.version} of ${displayText(latest.name)} declares AAD coordinates that do not match the requested variable (possible transplantation)`,
      ),
    );
  }
  const result = yield* cryptoEffect(() =>
    verifyDistributedValue({
      history: verified.history,
      context: {
        suite: payload.suite,
        projectId: verified.projectId,
        environmentId,
        epoch: aad.epoch,
        variableId: latest.variableId,
        version: aad.version,
        nonceHex: payload.nonceHex,
        ciphertextHex: payload.ciphertextHex,
        prevValueSigHashHex: payload.prevValueSigHashHex,
        writerUserId: payload.writerUserId,
        chainHeadHashHex: payload.chainHeadHashHex,
        chainHeadSeq: payload.chainHeadSeq,
      },
      writerKeyFingerprintHex: payload.writerKeyFingerprintHex,
      signatureHex: payload.signatureHex,
      predecessor: input.predecessor,
    }),
  ).pipe(
    Effect.mapError((error) => {
      const reason = "reason" in error ? error.reason : cryptoErrorKind(error);
      return evidenceError(
        `Version ${aad.version} of ${displayText(latest.name)} failed verification against the verified history (reason=${reason}). It may have been replaced or forged by the server — nothing was restored`,
      );
    }),
  );
  return result.signedBytesHashHex;
});

function verifyAncestry(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly latest: VerifiedPulledValue;
  readonly range: readonly DistributedEncryptedPayload[];
}): Effect.Effect<VerifiedPulledValue, CliError> {
  return Effect.map(verifiedRange(input), (versions) => {
    const first = versions[0];
    if (first === undefined) {
      throw new Error("verified range is empty");
    }
    return first;
  });
}

const verifiedRange = Effect.fn("var-history.verifiedRange")(function* (input: {
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly latest: VerifiedPulledValue;
  readonly range: readonly DistributedEncryptedPayload[];
}): Effect.fn.Return<readonly VerifiedPulledValue[], CliError> {
  const versions: VerifiedPulledValue[] = [];
  let predecessor: { readonly signedBytesHashHex: string; readonly epoch: number } | undefined;
  for (const payload of input.range) {
    const signedBytesHashHex = yield* verifyVersion({ ...input, payload, predecessor });
    predecessor = { signedBytesHashHex, epoch: payload.aad.epoch };
    versions.push({
      ...input.latest,
      version: payload.aad.version,
      epoch: payload.aad.epoch,
      nonceHex: payload.nonceHex,
      ciphertextHex: payload.ciphertextHex,
      prevValueSigHashHex: payload.prevValueSigHashHex,
      signedBytesHashHex,
      valueChainHeadSeq: payload.chainHeadSeq,
      valueChainHeadHashHex: payload.chainHeadHashHex,
      valueSignatureHex: payload.signatureHex,
      writerUserId: payload.writerUserId,
      writerKeyFingerprintHex: payload.writerKeyFingerprintHex,
    });
  }
  const last = input.range.at(-1);
  if (
    versions.length === 0 ||
    last?.aad.version !== input.latest.version ||
    predecessor?.signedBytesHashHex !== input.latest.signedBytesHashHex
  ) {
    return yield* Effect.fail(
      evidenceError(
        `The history of ${displayText(input.latest.name)} does not chain into the verified latest version ${input.latest.version} (a forked or substituted history) — nothing was restored`,
      ),
    );
  }
  return versions;
});

const ensureRollbackConfirmed = Effect.fn("var-history.ensureRollbackConfirmed")(function* (input: {
  readonly name: string;
  readonly fromVersion: number;
  readonly toVersion: number;
  readonly flagsIfCurrent: number;
  readonly force: boolean;
}): Effect.fn.Return<void, CliError, CliIo | Stdio.Stdio> {
  const io = yield* CliIo;
  const facts = rollbackFacts(input);
  if (input.force) {
    yield* io.logError(`${facts[0]} without confirmation (--force)`);
    yield* Effect.forEach(facts.slice(1), io.logError, { discard: true });
    return;
  }
  const stdio = yield* Stdio.Stdio;
  const interactive = (yield* stdio.stdinIsTerminal) && (yield* stdio.stdoutIsTerminal);
  if (!interactive) {
    return yield* Effect.fail(
      cliError(
        `Refusing to roll back ${displayText(input.name)} in a non-interactive environment without --force. Re-run with --force to accept that explicitly`,
      ),
    );
  }
  yield* Effect.forEach(facts, io.logError, { discard: true });
  const answer = yield* io.promptLine({ prompt: "Proceed with the rollback? [y/N]: " });
  if (!["y", "yes"].includes(answer.trim().toLowerCase())) {
    return yield* Effect.fail(cliError("Aborted: nothing was signed or sent"));
  }
});

function rollbackFacts(input: {
  readonly name: string;
  readonly fromVersion: number;
  readonly toVersion: number;
  readonly flagsIfCurrent: number;
}): readonly string[] {
  const summary = `Rolling back ${displayText(input.name)} from version ${input.fromVersion} to the value of version ${input.toVersion} (pushed as a new version; the history keeps every version)`;
  if (input.flagsIfCurrent === 0) {
    return [summary];
  }
  const flags = countNoun(input.flagsIfCurrent, "rotation flag");
  const those = input.flagsIfCurrent === 1 ? "that flag" : "those flags";
  return [
    summary,
    `The value of version ${input.toVersion} was readable by the subject of ${flags} (a member, device, or server key that has since lost access). Restoring it keeps or re-opens ${those} — rotating the upstream credential and pushing a new value is safer`,
  ];
}

interface RollbackPlan {
  readonly name: string;
  readonly variableId: VariableId;
  readonly latest: VerifiedPulledValue;
  readonly target: VerifiedPulledValue;
  readonly pulled: VerifiedEnvironmentPull;
  readonly warnings: readonly string[];
}

function checkToVersion(name: string, toVersion: number, latestVersion: number) {
  if (toVersion < latestVersion) {
    return Effect.void;
  }
  return Effect.fail(
    cliError(
      toVersion === latestVersion
        ? `Version ${toVersion} is already the current version of ${displayText(name)} — nothing to roll back`
        : `Variable ${displayText(name)} has no version ${toVersion} (the current version is ${latestVersion})`,
    ),
  );
}

const resolveLatestValue = Effect.fn("var-history.resolveLatestValue")(function* (
  input: VarHistoryBase,
  name: string,
  noValueMessage: string,
): Effect.fn.Return<
  {
    readonly pulled: VerifiedEnvironmentPull;
    readonly latest: VerifiedPulledValue;
    readonly warnings: readonly string[];
  },
  CliError
> {
  const resolved = yield* resolveLiveVariable(input, name);
  if (resolved.target.status === "declared") {
    return yield* Effect.fail(cliError(noValueMessage));
  }
  const variableId = resolved.target.variableId;
  const pulled = yield* pullVerifiedEnvironment({ ...input, verified: resolved.verified });
  const latest = pulled.variables.find((variable) => variable.variableId === variableId);
  if (latest?.name !== name) {
    return yield* Effect.fail(
      cliError(
        `Variable ${displayText(name)} changed between resolution and the value fetch (a concurrent delete or rename). Re-run the command`,
      ),
    );
  }
  return { pulled, latest, warnings: [...resolved.warnings, ...pulled.warnings] };
});

const planRollback = Effect.fn("var-history.planRollback")(function* (
  input: Omit<AncestorInput, "toVersion"> & { readonly toVersion: number | null },
  name: string,
  noValueMessage: string = `Variable ${displayText(name)} is declared but has no value yet — there is nothing to roll back to`,
): Effect.fn.Return<RollbackPlan, CliError> {
  const { pulled, latest, warnings } = yield* resolveLatestValue(input, name, noValueMessage);
  const variableId = latest.variableId;
  if (input.toVersion === null && latest.version < 2) {
    return yield* Effect.fail(
      cliError(
        `Variable ${displayText(name)} has no previous version (the current version is ${latest.version}) — nothing to finalize`,
      ),
    );
  }
  const toVersion = input.toVersion ?? latest.version - 1;
  yield* checkToVersion(name, toVersion, latest.version);
  const range = yield* fetchVersionRange({
    client: input.client,
    verified: pulled.verified,
    environmentId: input.environmentId,
    variableId,
    fromVersion: toVersion,
    latestVersion: latest.version,
  });
  const target = yield* verifyAncestry({
    verified: pulled.verified,
    environmentId: input.environmentId,
    latest,
    range,
  });
  return {
    name,
    variableId,
    latest,
    target,
    pulled,
    warnings,
  };
});

const decryptPair = Effect.fn("var-history.decryptPair")(function* (
  input: Omit<AncestorInput, "toVersion">,
  plan: RollbackPlan,
): Effect.fn.Return<
  {
    readonly target: Redacted.Redacted<Uint8Array>;
    readonly latest: Redacted.Redacted<Uint8Array>;
  },
  CliError
> {
  const keys = yield* environmentKeysFor({
    client: input.client,
    verified: plan.pulled.verified,
    environmentId: input.environmentId,
    recipient: input.recipient,
    prefetched: plan.pulled.deks,
  });
  const decrypt = (variable: VerifiedPulledValue) =>
    decryptVerifiedValue({
      verified: plan.pulled.verified,
      environmentId: input.environmentId,
      variable,
      deksByEpoch: keys.deksByEpoch,
      chainEpoch: keys.currentEpoch,
    });
  return { target: yield* decrypt(plan.target), latest: yield* decrypt(plan.latest) };
});

interface VerifiedAncestorValues {
  readonly name: string;
  readonly variableId: VariableId;
  readonly latestVersion: number;
  readonly ancestorVersion: number;
  readonly ancestor: Redacted.Redacted<Uint8Array>;
  readonly latest: Redacted.Redacted<Uint8Array>;
  readonly warnings: readonly string[];
}

export const verifiedAncestorValues = Effect.fn("var-history.verifiedAncestorValues")(function* (
  input: Omit<AncestorInput, "toVersion"> & { readonly toVersion: number | null },
): Effect.fn.Return<VerifiedAncestorValues, CliError> {
  const name = input.name.normalize("NFC");
  const plan = yield* planRollback(
    input,
    name,
    `Variable ${displayText(name)} is declared but has no value yet — nothing to finalize`,
  );
  const pair = yield* decryptPair(input, plan);
  return {
    name,
    variableId: plan.variableId,
    latestVersion: plan.latest.version,
    ancestorVersion: plan.target.version,
    ancestor: pair.target,
    latest: pair.latest,
    warnings: plan.warnings,
  };
});

interface VerifiedAncestorRange {
  readonly name: string;
  readonly variableId: VariableId;
  readonly latestVersion: number;
  readonly ancestors: readonly {
    readonly version: number;
    readonly value: Redacted.Redacted<Uint8Array>;
  }[];
  readonly warnings: readonly string[];
}

export const verifiedAncestorRange = Effect.fn("var-history.verifiedAncestorRange")(function* (
  input: Omit<AncestorInput, "toVersion">,
): Effect.fn.Return<VerifiedAncestorRange, CliError> {
  const name = input.name.normalize("NFC");
  const resolved = yield* resolveLatestValue(
    input,
    name,
    `Variable ${displayText(name)} is declared but has no value yet`,
  );
  const { pulled, latest } = resolved;
  const warnings = [...resolved.warnings];
  const variableId = latest.variableId;
  if (latest.version < 2) {
    return { name, variableId, latestVersion: latest.version, ancestors: [], warnings };
  }
  const range = yield* fetchVersionRange({
    client: input.client,
    verified: pulled.verified,
    environmentId: input.environmentId,
    variableId,
    fromVersion: 1,
    latestVersion: latest.version,
  });
  const versions = yield* verifiedRange({
    verified: pulled.verified,
    environmentId: input.environmentId,
    latest,
    range,
  });
  const keys = yield* environmentKeysFor({
    client: input.client,
    verified: pulled.verified,
    environmentId: input.environmentId,
    recipient: input.recipient,
    prefetched: pulled.deks,
  });
  const ancestors: { readonly version: number; readonly value: Redacted.Redacted<Uint8Array> }[] =
    [];
  for (const variable of versions.filter((entry) => entry.version < latest.version)) {
    const value = yield* decryptVerifiedValue({
      verified: pulled.verified,
      environmentId: input.environmentId,
      variable,
      deksByEpoch: keys.deksByEpoch,
      chainEpoch: keys.currentEpoch,
    }).pipe(Effect.catch((error) => Effect.succeed(error)));
    if (Redacted.isRedacted(value)) {
      ancestors.push({ version: variable.version, value });
    } else {
      warnings.push(
        `version ${variable.version} of ${displayText(name)} could not be decrypted on this device (${value.message}) — the value it held is not considered`,
      );
    }
  }
  ancestors.reverse();
  return { name, variableId, latestVersion: latest.version, ancestors, warnings };
});

const decryptTarget = Effect.fn("var-history.decryptTarget")(function* (
  input: VarRollbackInput,
  plan: RollbackPlan,
): Effect.fn.Return<Redacted.Redacted<Uint8Array>, CliError> {
  const pair = yield* decryptPair(input, plan);
  if (sameRedactedBytes(pair.target, pair.latest)) {
    return yield* Effect.fail(
      cliError(
        `The current value of ${displayText(plan.name)} (version ${plan.latest.version}) already equals the value of version ${input.toVersion} — nothing to roll back`,
      ),
    );
  }
  return pair.target;
});

export const varRollbackOp = Effect.fn("var-history.varRollbackOp")(function* (
  input: VarRollbackInput,
): Effect.fn.Return<VarRollbackResult, CliError, CliIo | Stdio.Stdio> {
  const plan = yield* planRollback(input, input.name.normalize("NFC"));
  const restored = yield* decryptTarget(input, plan);
  const history = yield* fetchHistory(
    input.client,
    plan.pulled.verified,
    input.environmentId,
    plan.variableId,
  );
  const flagsIfCurrent =
    history.find((entry) => entry.version === input.toVersion)?.flagsIfCurrent ?? 0;
  yield* ensureRollbackConfirmed({
    name: plan.name,
    fromVersion: plan.latest.version,
    toVersion: input.toVersion,
    flagsIfCurrent,
    force: input.force,
  });
  const pushed = yield* pushVariable({
    client: input.client,
    environmentId: input.environmentId,
    recipient: input.recipient,
    name: plan.name,
    value: restored,
    verified: plan.pulled.verified,
    resync: input.resync,
    writerUserId: input.writerUserId,
    signingKey: input.signingKey,
    floor: input.floor,
    restore: {
      variableId: plan.variableId,
      sameValueAs: input.toVersion,
      fromVersion: plan.latest.version,
      fromSignedBytesHashHex: plan.latest.signedBytesHashHex,
    },
  });
  return {
    name: plan.name,
    fromVersion: plan.latest.version,
    toVersion: input.toVersion,
    pushed,
    flagsIfCurrent,
    warnings: [...plan.warnings, ...pushed.warnings],
  };
});
