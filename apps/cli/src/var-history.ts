// `maruhi var history <NAME>` / `maruhi var rollback <NAME> --to <VERSION>`
// (2026-09-27 VH — design record docs/notes/vh-design.md rulings V3 / V4).
//
//   - history is metadata only (AUTH_SPEC §12-7): version, epoch, writer,
//     acceptance time, the lineage declaration (sameValueAs) and the
//     server-derived flagsIfCurrent. No value is fetched, decrypted, or shown,
//     so the agent gate does not apply (the permissive side — same as
//     `member list` / `schema export`). The rows are **server-declared** (a
//     value signature cannot be verified without its ciphertext), which the
//     output says
//   - rollback never trusts that metadata for the write. It fetches the value
//     range from the target to the verified latest and accepts the target only
//     as an **ancestor of the verified latest**: every version passes the full
//     value-signature verification (CRYPTO_SPEC §6.3), consecutive versions
//     satisfy the prev-hash link and epoch monotonicity (§4.1), and the chain
//     ends at the latest the bulk pull verified. A version that verifies alone
//     but does not chain into it (e.g. signed by a removed member's key with a
//     head inside their interval) is refused as evidence
//   - the restore is an ordinary push of the old plaintext re-encrypted under
//     the current epoch, declaring `sameValueAs` (AUTH_SPEC §12-5) so
//     rotation-needed detection sees the lineage (a restore of a value from
//     before a flag re-opens it — AUDIT_SPEC §4.1-5). The plaintext lives only
//     in memory as a Redacted and is never displayed
//   - confirmation: interactive y/N; non-interactive requires --force
//     (fail-closed — the `var rm` shape). Not a ceremony, so an agent with
//     --force may run it

import type { DistributedEncryptedPayload, VariableVersionHistoryEntry } from "@maruhi/api-schema";
import type { EnvironmentId } from "@maruhi/core";
import { verifyDistributedValue } from "@maruhi/crypto";
import { Effect, Redacted, Stdio } from "effect";

import type { MaruhiClient } from "./api.ts";
import { type DekRecipient, environmentKeysFor } from "./deks.ts";
import { countNoun, displayText, formatUtcSeconds } from "./display.ts";
import { cliError, type CliError, evidenceError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import type { FloorHandle, VerifiedVariableStatement } from "./floor-check.ts";
import { CliIo } from "./io.ts";
import { decryptVerifiedValue } from "./pull.ts";
import { type PushedVersion, pushVariable, sameRedactedBytes } from "./push.ts";
import { resolveSchemaTarget } from "./schema.ts";
import type { VerifiedProject } from "./sync.ts";
import {
  pullVerifiedEnvironment,
  type VerifiedEnvironmentPull,
  type VerifiedPulledValue,
} from "./values.ts";

/** The shared input of both commands (the environment prologue's pieces). */
interface VarHistoryBase {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  /** The variable name (NFC normalization is done here — §12-1). */
  readonly name: string;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly floor: FloorHandle;
}

export interface VarHistoryResult {
  readonly name: string;
  readonly variableId: string;
  readonly status: "active" | "declared";
  /** Ascending by version (server-declared metadata). */
  readonly versions: readonly VariableVersionHistoryEntry[];
  readonly warnings: readonly string[];
}

/**
 * Resolves the name through a verified metadata-only pull (§12-7 — no
 * var.read). Deleted and unknown names are explicit errors; duplicate live
 * statements are equivocation.
 */
function resolveLiveVariable(
  input: VarHistoryBase,
  name: string,
): Effect.Effect<
  {
    readonly verified: VerifiedProject;
    readonly target: VerifiedVariableStatement;
    readonly warnings: readonly string[];
  },
  CliError
> {
  return Effect.gen(function* () {
    // The same verified name resolution as `schema set` / `var rm`
    // (duplicate live statements = equivocation, refused there)
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
}

/** The server-declared version history of one variable, ascending (display metadata — never a write or invalidation target). */
function fetchHistory(
  client: MaruhiClient,
  verified: VerifiedProject,
  environmentId: string,
  variableId: string,
): Effect.Effect<readonly VariableVersionHistoryEntry[], CliError> {
  return Effect.gen(function* () {
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
}

export function varHistoryOp(input: VarHistoryBase): Effect.Effect<VarHistoryResult, CliError> {
  return Effect.gen(function* () {
    const name = input.name.normalize("NFC");
    const resolved = yield* resolveLiveVariable(input, name);
    const status = resolved.target.status === "declared" ? "declared" : "active";
    // A declared variable has no version (§4.2) — nothing to ask for
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
}

/** The note column: the lineage kind (derived, never declared — AUTH_SPEC §12-5) and the flag count. */
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

/** The human-readable listing (newest first). */
export function formatVarHistory(result: VarHistoryResult, environmentId: string): string[] {
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

/** One `--json` document (machine-readable. Zero values). */
export function varHistoryJson(result: VarHistoryResult, environmentId: string): string {
  return JSON.stringify(
    {
      environmentId,
      name: result.name,
      variableId: result.variableId,
      status: result.status,
      // Server-declared (§12-7) — carried so a consumer never mistakes it for verified data
      serverDeclared: true,
      versions: result.versions,
    },
    null,
    2,
  );
}

// ---------------------------------------------------------------------------
// rollback
// ---------------------------------------------------------------------------

/** The input of a verified-ancestor lookup (the environment prologue's pieces plus the version asked for). */
export interface AncestorInput extends VarHistoryBase {
  readonly recipient: DekRecipient;
  /** The version whose value is wanted (an ancestor of the verified latest). */
  readonly toVersion: number;
}

export interface VarRollbackInput extends AncestorInput {
  /** true = skip the confirmation (the only non-interactive path). */
  readonly force: boolean;
  readonly writerUserId: string;
  readonly signingKey: CryptoKey;
}

export interface VarRollbackResult {
  readonly name: string;
  /** The version that was current before the rollback. */
  readonly fromVersion: number;
  readonly toVersion: number;
  readonly pushed: PushedVersion;
  /** The server-derived count of flags effective while the restored value is current (advisory). */
  readonly flagsIfCurrent: number;
  readonly warnings: readonly string[];
}

/**
 * Appends one page of the value range, stopping at the verified latest (a
 * version pushed after our verified pull is outside the chain we verify
 * against). Returns the next version to ask for.
 */
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

/** The page loop of the version value range, up to the verified latest (§12-7). */
function fetchVersionRange(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly variableId: string;
  readonly fromVersion: number;
  readonly latestVersion: number;
}): Effect.Effect<readonly DistributedEncryptedPayload[], CliError> {
  return Effect.gen(function* () {
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
}

/** One version of the range through the full value verification, chained to its predecessor. */
function verifyVersion(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly latest: VerifiedPulledValue;
  readonly payload: DistributedEncryptedPayload;
  readonly predecessor: { readonly signedBytesHashHex: string; readonly epoch: number } | undefined;
}): Effect.Effect<string, CliError> {
  return Effect.gen(function* () {
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
    const result = yield* Effect.promise(() =>
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
    );
    if (!result.ok) {
      const reason = "reason" in result.error ? result.error.reason : result.error.kind;
      return yield* Effect.fail(
        evidenceError(
          `Version ${aad.version} of ${displayText(latest.name)} failed verification against the verified history (reason=${reason}). It may have been replaced or forged by the server — nothing was restored`,
        ),
      );
    }
    return result.value.signedBytesHashHex;
  });
}

/**
 * Verifies the fetched range as an ancestry of the verified latest
 * (CRYPTO_SPEC §4.1 / §6.3 — AUTH_SPEC §12-7's client rule): coordinates,
 * every value signature, the prev-hash link and epoch monotonicity between
 * consecutive versions, and the last version being byte-identical (same
 * signed-bytes hash) to the latest the bulk pull verified. Returns the
 * verified target (the first version) as a pulled-value record whose meta
 * fields are the latest statement's (only the value part is old).
 */
function verifyAncestry(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly latest: VerifiedPulledValue;
  readonly range: readonly DistributedEncryptedPayload[];
}): Effect.Effect<VerifiedPulledValue, CliError> {
  return Effect.map(verifiedRange(input), (versions) => {
    const first = versions[0];
    if (first === undefined) {
      // Unreachable: verifiedRange refuses an empty range
      throw new Error("verified range is empty");
    }
    return first;
  });
}

/**
 * Verifies the whole fetched range as the ancestry of the verified latest
 * and returns every version as a pulled-value record (ascending), each
 * one's meta fields being the latest statement's. The caller that needs
 * one version takes the first; `var rotate --finalize` takes them all
 * (the key ids earlier versions held).
 */
function verifiedRange(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly latest: VerifiedPulledValue;
  readonly range: readonly DistributedEncryptedPayload[];
}): Effect.Effect<readonly VerifiedPulledValue[], CliError> {
  return Effect.gen(function* () {
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
}

/**
 * The explicit confirmation (fail-closed): --force proceeds with the facts
 * still stated; a non-interactive run without --force refuses; an interactive
 * one asks y/N (a rollback is reversible — history stays append-only — so no
 * name retyping as for `var rm`). Judgment material comes via the Stdio
 * service (never process.* directly).
 */
function ensureRollbackConfirmed(input: {
  readonly name: string;
  readonly fromVersion: number;
  readonly toVersion: number;
  readonly flagsIfCurrent: number;
  readonly force: boolean;
}): Effect.Effect<void, CliError, CliIo | Stdio.Stdio> {
  return Effect.gen(function* () {
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
}

/** What the confirmation states: the move, then (when any) the exposure of the restored value. */
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

/** The verified pieces a rollback pushes from (the latest, the verified target, the pull's view and wraps). */
interface RollbackPlan {
  readonly name: string;
  readonly variableId: string;
  readonly latest: VerifiedPulledValue;
  readonly target: VerifiedPulledValue;
  readonly pulled: VerifiedEnvironmentPull;
  readonly warnings: readonly string[];
}

/** The refusal of a `--to` that names the current version or no version at all (before any value fetch). */
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

/**
 * The verified latest value of a live variable: the name resolved through
 * the metadata-only pull, then the with-values pull `maruhi push` uses to
 * find its prev anchor (+ the all-epoch wraps). A declared variable has no
 * value; a rename or delete in between is refused.
 */
function resolveLatestValue(
  input: VarHistoryBase,
  name: string,
  noValueMessage: string,
): Effect.Effect<
  {
    readonly pulled: VerifiedEnvironmentPull;
    readonly latest: VerifiedPulledValue;
    readonly warnings: readonly string[];
  },
  CliError
> {
  return Effect.gen(function* () {
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
}

/** Resolve → verified pull of the latest → the value range verified as its ancestry. */
function planRollback(
  input: Omit<AncestorInput, "toVersion"> & { readonly toVersion: number | null },
  name: string,
): Effect.Effect<RollbackPlan, CliError> {
  return Effect.gen(function* () {
    const { pulled, latest, warnings } = yield* resolveLatestValue(
      input,
      name,
      `Variable ${displayText(name)} is declared but has no value yet — there is nothing to roll back to`,
    );
    const variableId = latest.variableId;
    // The default (the version right before the latest) is derived from the
    // verified latest, never from the server-declared history: which
    // credential a finalize destroys must not be the server's to steer
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
}

/**
 * Decrypts the target in memory with its own epoch's DEK and refuses a no-op
 * (the current value already equal — it would only burn a version). Returns
 * the restored plaintext, still wrapped.
 */
/** Both plaintexts of a plan (the ancestor and the latest), each decrypted with its own epoch's DEK. */
function decryptPair(
  input: Omit<AncestorInput, "toVersion">,
  plan: RollbackPlan,
): Effect.Effect<
  {
    readonly target: Redacted.Redacted<Uint8Array>;
    readonly latest: Redacted.Redacted<Uint8Array>;
  },
  CliError
> {
  return Effect.gen(function* () {
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
}

/** A verified ancestor version and the verified latest, decrypted (`maruhi var rotate --finalize` reads the previous credential this way). */
export interface VerifiedAncestorValues {
  readonly name: string;
  readonly variableId: string;
  readonly latestVersion: number;
  readonly ancestorVersion: number;
  readonly ancestor: Redacted.Redacted<Uint8Array>;
  readonly latest: Redacted.Redacted<Uint8Array>;
  readonly warnings: readonly string[];
}

/**
 * Resolves the name, verifies the latest and the version range down to
 * `toVersion` as its ancestry (the rollback's evidence rule — V4 step 3),
 * and decrypts both. `toVersion` null = the version right before the latest
 * (refused when the variable has only one version).
 */
export function verifiedAncestorValues(
  input: Omit<AncestorInput, "toVersion"> & { readonly toVersion: number | null },
): Effect.Effect<VerifiedAncestorValues, CliError> {
  return Effect.gen(function* () {
    const name = input.name.normalize("NFC");
    const plan = yield* planRollback(input, name);
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
}

/** Every version before the verified latest of one variable, lineage-verified and decrypted (newest first). */
export interface VerifiedAncestorRange {
  readonly name: string;
  readonly variableId: string;
  readonly latestVersion: number;
  /** Newest first (version latest−1 … 1). Empty when the variable has one version. */
  readonly ancestors: readonly {
    readonly version: number;
    readonly value: Redacted.Redacted<Uint8Array>;
  }[];
  readonly warnings: readonly string[];
}

/**
 * The values every earlier version held, each verified as an ancestor of
 * the verified latest (the same evidence rule as a rollback) and decrypted
 * with its epoch's DEK. `var rotate --finalize` uses it for the AWS key id
 * variable: a key the issuer lists is deactivated only when one of these
 * versions held its id — the server's history metadata never picks the
 * target.
 */
export function verifiedAncestorRange(
  input: Omit<AncestorInput, "toVersion">,
): Effect.Effect<VerifiedAncestorRange, CliError> {
  return Effect.gen(function* () {
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
      // An ancestor this device cannot decrypt (an old-epoch wrap it never
      // received — device-gaps.ts) is skipped with a warning, not fatal:
      // the set of ids it feeds can only shrink, which never widens what a
      // finalize invalidates. Its signature and lineage were verified above
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
}

function decryptTarget(
  input: VarRollbackInput,
  plan: RollbackPlan,
): Effect.Effect<Redacted.Redacted<Uint8Array>, CliError> {
  return Effect.gen(function* () {
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
}

export function varRollbackOp(
  input: VarRollbackInput,
): Effect.Effect<VarRollbackResult, CliError, CliIo | Stdio.Stdio> {
  return Effect.gen(function* () {
    const plan = yield* planRollback(input, input.name.normalize("NFC"));
    const restored = yield* decryptTarget(input, plan);
    // The advisory exposure count for the confirmation (server-derived —
    // it compares audit seqs, which never reach the client)
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
}
