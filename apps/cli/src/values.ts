// Verification of distributed values and metadata statements (CRYPTO_SPEC
// §6.3).
//
// Before decryption or name resolution, every value's §4.1 value signature
// and the §4.2 meta-statements of the environment and all variables
// (including deleted ones) are verified against the verified chain history.
// The expected coordinates are assembled locally without trusting the
// claimed values: projectId = the verified genesis hash, environmentId = the
// ID used in the request, variableId = the pull response's outer metadata.
// writer / author are the distributed user_id + key FP (matched against the
// chain history). Only names that passed statement verification are trusted
// (§12-2 — the bare name snapshot is gone from the wire).
//
// A future head (declared seq > own view's head), on a value or a
// statement, is not refused immediately: re-sync **exactly once**, pass the
// extension check (chain-sync.ts's ensureExtensionOf), and re-verify everything
// against the new view (bounded — §6.3-2b).
//
// When several same-named active statements in one environment pass
// verification (server equivocation), resolution is refused (§4.2). A
// distributed non-NFC name is a warning (SHOULD — §12-1; byte-exact
// matching never mis-resolves, but the coexistence of visually identical
// names must not be invisible). An active juxtaposed onto an already
// deleted variableId (the transport shape of an unauthorized undeletion) is
// refused.
//
// The latest-only limitation (ruling B): pull carries only the newest
// version, so there is no predecessor — a value's prev-existence match and
// epoch non-decrease, and meta's prev-existence match and re-activation
// after deletion cannot be checked here (shape checks only). Never pretend
// they were checked — detection via the persistent floor is floor-check.ts's
// domain. **Because meta carries no epoch anchor, an injection onto an
// advanced meta_version is not detected even with a floor** (the known
// leftover of §14.3-5).

import type {
  DistributedEnvironmentManifest,
  DistributedEnvironmentMetaStatement,
  DistributedVariableMetaStatement,
  RecipientDek,
  SchemaPolicy,
} from "@maruhi/api-schema";
import type { EnvironmentId } from "@maruhi/core";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { resyncExtended, type VerifiedProject } from "./chain-sync.ts";
import { checkCheckpointIntegrity } from "./checkpoint-integrity.ts";
import { cliError, type CliError, evidenceError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import type {
  FloorHandle,
  VerifiedEnvironmentStatement,
  VerifiedMetaEvidence,
  VerifiedPullSnapshot,
  VerifiedTombstone,
  VerifiedVariableStatement,
} from "./floor-check.ts";
import type { ManifestFloor } from "./floor.ts";
import {
  type ManifestDigestEntry,
  type VerifiedManifest,
  verifyDistributedManifest,
} from "./manifest.ts";
import { enforceFloor, enforceMetadataFloor } from "./values-floor.ts";
import {
  checkVerifiedNames,
  type PullWire,
  type VerifiedPulledValue,
  verifyActiveVariables,
  verifyDeclaredStatements,
  verifyDeletedStatements,
  verifyEnvironmentStatement,
  verifyVariableStatements,
  type VerifyOutcome,
} from "./values-verify.ts";

/** A bulk pull whose values and statements all passed verification (§12-7 / §6.3). */
export interface VerifiedEnvironmentPull {
  /** The view used for verification (may have advanced via a future head's bounded resync). */
  readonly verified: VerifiedProject;
  readonly variables: readonly VerifiedPulledValue[];
  /**
   * Verified declared statements (valueless declarations — §4.2 layout v3).
   * declared is the only legitimate valueless state (CRYPTO_SPEC §6.3's
   * value-distribution requirement).
   */
  readonly declared: readonly VerifiedVariableStatement[];
  /** Verified tombstones (digest material for manifest issuance — §4.3). */
  readonly tombstones: readonly VerifiedTombstone[];
  /** The verified environment meta-statement (the envMeta material for manifest issuance). */
  readonly environment: VerifiedMetaEvidence;
  /** The verified manifest (§4.3 — an omission is already refused, §6.3). */
  readonly manifest: VerifiedManifest;
  /** The wraps addressed to me (verification is the §5.1 / §5.2 path of deks.ts). */
  readonly deks: readonly RecipientDek[];
  /** SHOULD warnings such as a distributed non-NFC name (displayed by the caller). */
  readonly warnings: readonly string[];
}

/** The result of running a verification stage (rejected is already folded into the failure channel — the 2 values future | ok). */
type StageResult<T> = { readonly kind: "ok"; readonly value: T } | { readonly kind: "future" };

/**
 * The shared wrapper of a verification stage: folds a crypto-execution
 * failure into a CliError and a rejected into the failure channel (each
 * stage's leftover is the 2 values future | ok).
 */
const verifyStage = Effect.fn("values.verifyStage")(function* <T>(
  run: () => Promise<VerifyOutcome<T>>,
  description: string,
): Effect.fn.Return<StageResult<T>, CliError> {
  const outcome = yield* Effect.tryPromise({
    try: run,
    catch: () => cliError(`${description} failed to run (crypto error)`),
  });
  if (outcome.kind === "rejected") {
    // Signed distributed data that fails verification = evidence (a
    // re-run does not resolve it — errors.ts's definition of evidence; it
    // must not be folded into cleanup warnings). The exception is the
    // honest breaking mode (UnsupportedMetaLayout)
    return yield* Effect.fail(
      outcome.evidence ? evidenceError(outcome.message) : cliError(outcome.message),
    );
  }
  return outcome.kind === "future"
    ? ({ kind: "future" } as const)
    : ({ kind: "ok", value: outcome.value } as const);
});

/**
 * The manifest stage (§4.3 / §6.3): a required response field — the
 * wire schema already refuses an omission at decode (the same verdict
 * as a dropped environment statement, so it never reaches this stage).
 * The digest is recomputed from every verified statement (tombstones
 * included) and compared.
 */
function verifyManifestStage(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly manifest: DistributedEnvironmentManifest;
  readonly entries: readonly ManifestDigestEntry[];
  readonly environment: VerifiedMetaEvidence;
  /** The floor's manifest record (the predecessor of the adjacent prev verification — M1-A1. null when there is no floor). */
  readonly floorManifest: ManifestFloor | null;
}): Effect.Effect<StageResult<VerifiedManifest>, CliError> {
  return verifyStage(
    () =>
      // A manifest refusal is a contradiction between signed distributed
      // data = evidence (manifest.ts's result type carries no evidence, so
      // it is attached here — there is no honest breaking mode at this
      // stage)
      verifyDistributedManifest({
        verified: input.verified,
        environmentId: input.environmentId,
        manifest: input.manifest,
        entries: input.entries,
        envMeta: {
          metaVersion: input.environment.metaVersion,
          sigHashHex: input.environment.metaSigHashHex,
        },
        floorManifest: input.floorManifest,
      }).then((outcome) =>
        outcome.kind === "rejected" ? { ...outcome, evidence: true } : outcome,
      ),
    "Environment-manifest verification",
  );
}

/**
 * The shared verification skeleton of a pull response (§6.3): environment
 * statement → the active set (swapped by shape: value-bearing /
 * metadata-only) → the declared set (the declaredVariables of a
 * value-bearing response — empty in metadata-only mode where they are
 * mixed into variables) → tombstones → the name check → **the manifest**
 * (digest recomputation and epoch agreement — §4.3. omission =
 * unconditional refusal). The digest recomputation set is every statement
 * of variables ∪ declared ∪ deleted. A future at any stage makes the whole
 * thing future (the bounded-resync entry).
 */
const verifyAllCommon = Effect.fn("values.verifyAllCommon")(function* <
  T extends { readonly variableId: string; readonly name: string },
>(
  verified: VerifiedProject,
  environmentId: string,
  pull: {
    readonly statement: DistributedEnvironmentMetaStatement;
    readonly deletedVariables: readonly DistributedVariableMetaStatement[];
    readonly declaredVariables?: readonly DistributedVariableMetaStatement[] | undefined;
    readonly manifest: DistributedEnvironmentManifest;
  },
  verifyActives: () => Promise<
    VerifyOutcome<{ readonly values: readonly T[]; readonly ids: Set<string> }>
  >,
  /** One verified active → the variables_digest entry (the recomputation material of §4.3 (3)). */
  digestEntryOf: (value: T) => ManifestDigestEntry,
  /** The floor's manifest record (the adjacent prev verification — M1-A1. Paths with no floor pass null). */
  floorManifest: ManifestFloor | null,
): Effect.fn.Return<
  | {
      readonly kind: "ok";
      readonly environment: VerifiedEnvironmentStatement;
      readonly variables: readonly T[];
      readonly declared: readonly VerifiedVariableStatement[];
      readonly tombstones: readonly VerifiedTombstone[];
      readonly manifest: VerifiedManifest;
      readonly warnings: readonly string[];
    }
  | { readonly kind: "future" },
  CliError
> {
  const environment = yield* verifyStage(
    () => verifyEnvironmentStatement(verified, environmentId, pull.statement),
    "Environment-statement verification",
  );
  if (environment.kind === "future") {
    return { kind: "future" } as const;
  }
  const actives = yield* verifyStage(
    verifyActives,
    "Variable-statement / value-signature verification",
  );
  if (actives.kind === "future") {
    return { kind: "future" } as const;
  }
  const declared = yield* verifyStage(
    () =>
      verifyDeclaredStatements(
        verified,
        environmentId,
        pull.declaredVariables ?? [],
        actives.value.ids,
      ),
    "Declared-variable-statement verification",
  );
  if (declared.kind === "future") {
    return { kind: "future" } as const;
  }
  const liveIds = new Set([...actives.value.ids, ...declared.value.ids]);
  const deleted = yield* verifyStage(
    () => verifyDeletedStatements(verified, environmentId, pull.deletedVariables, liveIds),
    "Deleted-variable-statement verification",
  );
  if (deleted.kind === "future") {
    return { kind: "future" } as const;
  }
  const warnings: string[] = [];
  const nameFailure = checkVerifiedNames(
    [...actives.value.values, ...declared.value.values],
    warnings,
  );
  if (nameFailure !== null) {
    return yield* Effect.fail(cliError(nameFailure));
  }
  const manifest = yield* verifyManifestStage({
    verified,
    environmentId,
    manifest: pull.manifest,
    entries: [
      ...actives.value.values.map(digestEntryOf),
      ...declared.value.values.map((statement) => ({
        variableId: statement.variableId,
        status: "declared" as const,
        metaVersion: statement.metaVersion,
        metaSigHashHex: statement.metaSigHashHex,
      })),
      ...deleted.value.map((tombstone) => ({
        variableId: tombstone.variableId,
        status: "deleted" as const,
        metaVersion: tombstone.metaVersion,
        metaSigHashHex: tombstone.metaSigHashHex,
      })),
    ],
    environment: environment.value,
    floorManifest,
  });
  if (manifest.kind === "future") {
    return { kind: "future" } as const;
  }
  return {
    kind: "ok",
    environment: environment.value,
    variables: actives.value.values,
    declared: declared.value.values,
    tombstones: deleted.value,
    manifest: manifest.value,
    warnings,
  } as const;
});

const verifyAll = Effect.fn("values.verifyAll")(function* (
  verified: VerifiedProject,
  environmentId: string,
  pull: PullWire,
  floorManifest: ManifestFloor | null,
  /**
   * The head seq of the view **at the moment the response was fetched**
   * (pull = the fetch-time view, lease = the bundled chain's head). Since
   * the bounded resync's re-verification re-verifies the same response
   * body against the advanced view, distinguishing a benign race where
   * rule 2's baseline is newer than the response needs this
   * (checkpoint-integrity.ts).
   */
  fetchedAtHeadSeq: number,
): Effect.fn.Return<
  | {
      readonly kind: "ok";
      readonly snapshot: VerifiedPullSnapshot;
      readonly warnings: readonly string[];
    }
  | { readonly kind: "future" },
  CliError
> {
  const result = yield* verifyAllCommon(
    verified,
    environmentId,
    pull,
    () => verifyActiveVariables(verified, environmentId, pull.variables),
    (value) => ({
      variableId: value.variableId,
      status: "active" as const,
      metaVersion: value.metaVersion,
      metaSigHashHex: value.metaSignedBytesHashHex,
    }),
    floorManifest,
  );
  if (result.kind === "future") {
    return { kind: "future" } as const;
  }
  // Rule 2 of checkpoint integrity (§6.3 — the value-carrying path only.
  // metadata-only is out of scope since it carries no values, §12-7). The
  // tombstone deletion explanation assumes the manifest-consistent set,
  // so it sits after the manifest stage (inside verifyAllCommon). A
  // refusal with evidence = a contradiction between verified data and the
  // chain notarization (typed so rotate's endgame classification does not
  // downgrade it to the "a re-run fixes it" guidance). A refusal without
  // evidence = a shape a benign race — the baseline advanced past the
  // fetch-time view — can also explain (a re-pull can resolve it)
  const checkpoint = yield* Effect.tryPromise({
    try: () =>
      checkCheckpointIntegrity({
        history: verified.history,
        environmentId,
        snapshot: pull.checkpointSnapshot,
        variables: result.variables,
        tombstoneIds: new Set(result.tombstones.map((tombstone) => tombstone.variableId)),
        fetchedAtHeadSeq,
      }),
    catch: () => cliError("Checkpoint-integrity verification failed to run (crypto error)"),
  });
  if (checkpoint.kind === "rejected") {
    return yield* Effect.fail(
      checkpoint.evidence ? evidenceError(checkpoint.message) : cliError(checkpoint.message),
    );
  }
  if (checkpoint.kind === "future") {
    return { kind: "future" } as const;
  }
  return {
    kind: "ok",
    snapshot: {
      environment: result.environment,
      variables: result.variables,
      declared: result.declared,
      tombstones: result.tombstones,
      manifest: result.manifest,
    },
    warnings: result.warnings,
  } as const;
});

/**
 * The shared skeleton of the pull family (§6.3-2b): fetch → verify →
 * floor check (accept). A future (a declared head beyond the own view =
 * possibly just a stale own chain) at any stage re-syncs **exactly once**,
 * checks that the new view is an extension of the old, then re-verifies
 * everything (bounded. Via the extension check + the prev_hash chain, the
 * advanced view stays consistent with openProject's floor check — every
 * entry at or below the floor's seq matches). A re-verification that is
 * still future is refused with divergedMessage.
 */
export const pullWithBoundedResync = Effect.fn("values.pullWithBoundedResync")(function* <
  TWire,
  TVerified,
>(input: {
  readonly verified: VerifiedProject;
  /** The bounded resync on a future head (once). */
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly fetch: Effect.Effect<TWire, CliError>;
  readonly verify: (
    view: VerifiedProject,
    wire: TWire,
  ) => Effect.Effect<
    { readonly kind: "ok"; readonly value: TVerified } | { readonly kind: "future" },
    CliError
  >;
  /** The floor check / commit. view = the view used for verification (may have advanced via the resync). */
  readonly accept: (view: VerifiedProject, value: TVerified) => Effect.Effect<void, CliError>;
  readonly divergedMessage: string;
}): Effect.fn.Return<
  { readonly view: VerifiedProject; readonly wire: TWire; readonly value: TVerified },
  CliError
> {
  const wire = yield* input.fetch;
  const first = yield* input.verify(input.verified, wire);
  if (first.kind === "ok") {
    yield* input.accept(input.verified, first.value);
    return { view: input.verified, wire, value: first.value };
  }
  const advanced = yield* resyncExtended(input.resync, input.verified);
  const second = yield* input.verify(advanced, wire);
  if (second.kind === "ok") {
    yield* input.accept(advanced, second.value);
    return { view: advanced, wire, value: second.value };
  }
  // A distribution bound to a chain position that still does not exist after the resync = evidence of a fork / forgery
  return yield* Effect.fail(evidenceError(input.divergedMessage));
});

/**
 * Pulls one environment and verifies every value's write signature and every
 * metadata statement (environment, active variables, tombstones) before
 * anything is decrypted or resolved by name (§6.3 / §12-7). A declared head
 * beyond the local view triggers one bounded re-sync with the extension
 * check; everything is then re-verified against the advanced view.
 */
export function pullVerifiedEnvironment(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  /** The bounded resync on a future head (once). */
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  /** The local floor (§6.3). Carries the check (rules (a)(b)(c)) and the atomic commit after verification succeeds. */
  readonly floor: FloorHandle;
}): Effect.Effect<VerifiedEnvironmentPull, CliError> {
  return Effect.map(
    pullWithBoundedResync({
      verified: input.verified,
      resync: input.resync,
      fetch: input.client.variables
        .pull({
          params: { projectId: input.verified.projectId, environmentId: input.environmentId },
        })
        .pipe(Effect.mapError(toCliError)),
      verify: (view, wire) =>
        verifyAll(
          view,
          input.environmentId,
          wire,
          // The adjacent-version prev verification (M1-A1): the floor's manifest record is passed as the predecessor
          input.floor.current()?.manifest ?? null,
          // The response was fetched under input.verified's view (even on
          // a post-resync re-verification the fetch moment does not change
          // — the baseline for rule 2's benign-race discrimination)
          input.verified.state.headSeq,
        ).pipe(
          Effect.map((result) =>
            result.kind === "future"
              ? result
              : ({
                  kind: "ok",
                  value: { snapshot: result.snapshot, warnings: result.warnings },
                } as const),
          ),
        ),
      accept: (view, value) =>
        enforceFloor({
          floor: input.floor,
          // Verification uses the (possibly advanced) view; the rule (c)
          // baseline is derived from the pre-response-fetch view
          // (enforceFloor's baselineView contract — prevents the baseline
          // over-advancing on a resync)
          baselineView: input.verified,
          commitView: view,
          environmentId: input.environmentId,
          snapshot: value.snapshot,
        }),
      divergedMessage:
        "A value, statement or checkpoint snapshot bound to a chain position that still does not exist on the chain after a re-sync was served (evidence of chain divergence or forgery)",
    }),
    ({ view, wire, value }) => ({
      verified: view,
      variables: value.snapshot.variables,
      declared: value.snapshot.declared,
      tombstones: value.snapshot.tombstones,
      environment: value.snapshot.environment,
      manifest: value.snapshot.manifest,
      deks: wire.deks,
      warnings: value.warnings,
    }),
  );
}

/**
 * Verifies the distribution material of a workload-lease response
 * (CRYPTO_SPEC §9.1 duty (4): environment statement, every active variable's
 * statement + write signature, every tombstone). Same discipline as the bulk
 * pull with exactly one difference: **a declared head beyond the chain is an
 * immediate rejection**, never a bounded re-sync — the chain travels in the
 * same response (AUTH_SPEC §14-2), so "our chain is merely stale" is not an
 * honest explanation; the response contradicts itself.
 *
 * No floor is used: a workload is a first-sync class that holds no floor
 * (§14.3-3), and its main relaxation is the repository anchor (anchor.ts —
 * §6.3 out-of-band anchor (b)).
 */
export const verifyLeaseDistribution = Effect.fn("values.verifyLeaseDistribution")(
  function* (input: {
    readonly verified: VerifiedProject;
    readonly environmentId: EnvironmentId;
    readonly wire: PullWire;
  }): Effect.fn.Return<
    {
      readonly variables: readonly VerifiedPulledValue[];
      /** The verified declared (§14-2 — material for ci run's presence check). */
      readonly declared: readonly VerifiedVariableStatement[];
      readonly warnings: readonly string[];
    },
    CliError
  > {
    // Manifest verification is mandatory (CRYPTO_SPEC §9.1 (5)) and a
    // required response field — the wire schema refuses an omission at
    // decode, same as pull. The floor-derived prev check does not apply
    // — a workload is a first-sync class that holds no floor (§14.3-3.
    // session-31 §3 M1-A1's note that leases are out of scope):
    // signature, digest, epoch agreement, and omission refusal stay at
    // the pull's level, and the predecessor is null (the shared
    // verifier's identity). A lease is a
    // self-contained shape where the response bundles the chain — the
    // fetch view = the bundled chain's head itself (the shape where the
    // baseline is newer than the fetch view structurally cannot exist, and
    // rule 2's refusals always classify to the evidence side)
    const result = yield* verifyAll(
      input.verified,
      input.environmentId,
      input.wire,
      null,
      input.verified.state.headSeq,
    );
    if (result.kind === "future") {
      return yield* Effect.fail(
        cliError(
          "A value, statement or checkpoint snapshot in the lease response is bound to a chain position beyond the chain included in the same response (the response contradicts itself)",
        ),
      );
    }
    // The no-baseline warning (§6.3 SHOULD — a client with no floor warns
    // when it detects that an environment it received a value-carrying
    // distribution for has no baseline checkpoint. Silently tolerating the
    // absence would make "this class's main guarantee = checkpoint
    // integrity is not working" invisible — session-36 ruling V)
    const warnings =
      input.verified.history.latestCheckpointFor(input.environmentId) === undefined
        ? [
            ...result.warnings,
            `No checkpoint on the verified chain covers environment ${input.environmentId}, so checkpoint integrity (rollback and stale-epoch injection detection — CRYPTO_SPEC §6.3) does not protect this response. A project member should issue one with: \`maruhi project checkpoint\``,
          ]
        : result.warnings;
    return {
      variables: result.snapshot.variables,
      declared: result.snapshot.declared,
      warnings,
    };
  },
);

/** The verified response of a metadata-only pull (§12-7's metadata-only mode). */
export interface VerifiedEnvironmentMetadata {
  /** The view used for verification (may have advanced via a future head's bounded resync). */
  readonly verified: VerifiedProject;
  /** The verified statements of all non-deleted variables (active and declared mixed — §12-7). */
  readonly variables: readonly VerifiedVariableStatement[];
  /** Verified tombstones (the only source of name resolution for deleted variables — AUDIT_SPEC §7). */
  readonly tombstones: readonly VerifiedTombstone[];
  /** The verified environment meta-statement (the envMeta material for manifest issuance). */
  readonly environment: VerifiedEnvironmentStatement;
  /** The verified manifest (required on the wire — an omission is refused at decode, same as the with-values pull). */
  readonly manifest: VerifiedManifest;
  /**
   * The server-claimed schemaPolicy (§12-7 / §12-11 — advisory). **Never an
   * input to a verification rule** — its only use is UX (advance guidance
   * for schema set). An unsigned claimed value, so this structure carrying
   * the verified name marks it advisory explicitly.
   */
  readonly advisorySchemaPolicy: SchemaPolicy;
  readonly warnings: readonly string[];
}

/**
 * The issuing material of a meta operation's bundled manifest (§12-5): the
 * previous manifest of a verified metadata pull, the current meta set
 * (active / declared / tombstones included — §4.3's digest covers every
 * statement), and the latest shape of the environment meta.
 */
export interface ManifestIssueBase {
  readonly previous: {
    readonly manifestVersion: number;
    readonly signedBytesHashHex: string;
  };
  /** The current meta set (tombstones included) — the caller appends the new variable's entry per attempt. */
  readonly entries: readonly ManifestDigestEntry[];
  readonly envMeta: { readonly metaVersion: number; readonly sigHashHex: string };
}

/**
 * Assembles the manifest issuing material from a verified metadata pull
 * (shared by push's create / activate and schema set / var rm — built from
 * the verified view, not server-claimed values).
 */
export function manifestIssueBaseOf(metadata: VerifiedEnvironmentMetadata): ManifestIssueBase {
  return {
    previous: {
      manifestVersion: metadata.manifest.manifestVersion,
      signedBytesHashHex: metadata.manifest.signedBytesHashHex,
    },
    entries: [
      ...metadata.variables.map((statement) => ({
        variableId: statement.variableId,
        status: statement.status,
        metaVersion: statement.metaVersion,
        metaSigHashHex: statement.metaSigHashHex,
      })),
      ...metadata.tombstones.map((tombstone) => ({
        variableId: tombstone.variableId,
        status: "deleted" as const,
        metaVersion: tombstone.metaVersion,
        metaSigHashHex: tombstone.metaSigHashHex,
      })),
    ],
    envMeta: {
      metaVersion: metadata.environment.metaVersion,
      sigHashHex: metadata.environment.metaSigHashHex,
    },
  };
}

interface MetadataPullWire {
  readonly statement: DistributedEnvironmentMetaStatement;
  readonly variables: readonly DistributedVariableMetaStatement[];
  readonly deletedVariables: readonly DistributedVariableMetaStatement[];
  readonly manifest: DistributedEnvironmentManifest;
  /** The advisory bundling of schemaPolicy (§12-7). */
  readonly schemaPolicy: SchemaPolicy;
}

/** The verified intermediate value of a metadata-only pull (pullWithBoundedResync's TVerified). */
interface VerifiedMetadataValue {
  readonly environment: VerifiedEnvironmentStatement;
  readonly variables: readonly VerifiedVariableStatement[];
  readonly tombstones: readonly VerifiedTombstone[];
  readonly manifest: VerifiedManifest;
  readonly warnings: readonly string[];
}

function verifyAllMetadata(
  verified: VerifiedProject,
  environmentId: string,
  pull: MetadataPullWire,
  floorManifest: ManifestFloor | null,
): Effect.Effect<
  | {
      readonly kind: "ok";
      readonly environment: VerifiedEnvironmentStatement;
      readonly variables: readonly VerifiedVariableStatement[];
      readonly tombstones: readonly VerifiedTombstone[];
      readonly manifest: VerifiedManifest;
      readonly warnings: readonly string[];
    }
  | { readonly kind: "future" },
  CliError
> {
  return verifyAllCommon(
    verified,
    environmentId,
    // In metadata-only mode declared is mixed into variables (§12-7) — a
    // separate declared list exists only on a value-bearing response
    { ...pull, declaredVariables: [] },
    () => verifyVariableStatements(verified, environmentId, pull.variables),
    (statement) => ({
      variableId: statement.variableId,
      // The active / declared distinction is the verified statement's
      // status (§4.3's entry includes status — pinning "active" would make
      // the digest recomputation of an environment containing a declared
      // always disagree)
      status: statement.status,
      metaVersion: statement.metaVersion,
      metaSigHashHex: statement.metaSigHashHex,
    }),
    floorManifest,
  );
}

/**
 * Pulls only the metadata of one environment (§12-7 metadata-only mode: no
 * values, no DEKs — the server records no `var.read`) and verifies the
 * environment statement, every active variable statement and every tombstone
 * against the verified chain history before any name is trusted (§6.3).
 * Future heads get the same single bounded re-sync as the full pull. Used
 * for name → variableId resolution (push) — a write-path read that must not
 * be recorded as having read values it never received.
 */
export function pullVerifiedEnvironmentMetadata(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  /** The bounded resync on a future head (once). */
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  /** The local floor (§6.3). The meta-level check + the environment-level commit (enforceMetadataFloor — M1-A3). */
  readonly floor: FloorHandle;
}): Effect.Effect<VerifiedEnvironmentMetadata, CliError> {
  return Effect.map(
    pullWithBoundedResync({
      verified: input.verified,
      resync: input.resync,
      fetch: input.client.variables
        .pullMetadata({
          params: { projectId: input.verified.projectId, environmentId: input.environmentId },
        })
        .pipe(Effect.mapError(toCliError)),
      verify: (view, wire) =>
        verifyAllMetadata(
          view,
          input.environmentId,
          wire,
          // The adjacent-version prev verification (M1-A1): identical on the metadata-only / value pull paths
          input.floor.current()?.manifest ?? null,
        ).pipe(
          Effect.flatMap(
            (
              result,
            ): Effect.Effect<
              | { readonly kind: "ok"; readonly value: VerifiedMetadataValue }
              | { readonly kind: "future" },
              CliError
            > => {
              if (result.kind === "future") {
                return Effect.succeed({ kind: "future" as const });
              }
              return Effect.succeed({
                kind: "ok" as const,
                value: {
                  environment: result.environment,
                  variables: result.variables,
                  tombstones: result.tombstones,
                  manifest: result.manifest,
                  warnings: result.warnings,
                },
              });
            },
          ),
        ),
      accept: (view, value) =>
        enforceMetadataFloor({
          floor: input.floor,
          verified: view,
          environmentId: input.environmentId,
          environment: value.environment,
          variables: value.variables,
          tombstones: value.tombstones,
          manifest: value.manifest,
        }),
      divergedMessage:
        "A statement bound to a head that still does not exist on the chain after a re-sync was served (evidence of chain divergence or forgery)",
    }),
    ({ view, wire, value }) => ({
      verified: view,
      variables: value.variables,
      tombstones: value.tombstones,
      environment: value.environment,
      manifest: value.manifest,
      // advisory (§12-11): an unverified claimed value — UX use only
      advisorySchemaPolicy: wire.schemaPolicy,
      warnings: value.warnings,
    }),
  );
}
