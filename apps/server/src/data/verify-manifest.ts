// Server-side acceptance of environment manifests (AUTH_SPEC §12-5 =
// CRYPTO_SPEC §4.3 / §6.4).
//
// Meta is plaintext, so the server can verify fully (no E2EE
// constraint — §4.3): on top of signature, declared head,
// authorization-at-head, epoch consistency, and the prev chain,
// **recomputing variablesDigestHex / envMetaVersion /
// envMetaSigHashHex from the post-acceptance meta state (all variable
// statements + the environment meta statement, after applying the
// bundled statement) and matching them against the declared values is
// itself an acceptance condition** (§12-5 (7)). A forged manifest
// brought by a malicious client is all dropped at the acceptance
// stage.
//
// The manifestVersion CAS (§12-5 (6)) is checked against the stored
// latest manifest (only the latest one is kept —
// environment_manifests's PRIMARY KEY = environment_id) and resolves
// in the same transaction as the bundled metaVersion CAS (the same
// program under the DO permit). A 409 returns only the latest
// manifestVersion (same discipline as the metaVersion CAS — it does
// not carry the winner's hash).
//
// The verification body is @maruhi/crypto's
// verifyDistributedEnvManifest (the server / CLI shared
// implementation — §4.3's "the canonical implementation exists only
// once"). The composite form of epoch consistency (the entry after
// the declared head establishes the epoch — §12-5 (4)'s "state after
// applying the bundled entries") is judged by the same verifier
// unchanged, because the composite program passes it the **history
// index after applying the entries**.

import { cryptoEffect } from "@maruhi/core";
import type {
  ChainHistoryIndex,
  EnvManifestEnvMeta,
  ManifestInvalidReason,
  VariablesDigestEntry,
} from "@maruhi/crypto";
import { verifyDistributedEnvManifest } from "@maruhi/crypto";
import { Effect } from "effect";

import { catchCryptoErrors } from "../crypto-catch.ts";
import type { EnvManifestInput, ManifestRejectReason, MemberWithDevice } from "./data-plane.ts";
import { rejectData } from "./data-plane.ts";
import { DataStore } from "./data-store.ts";

/**
 * Mapping of crypto's detailed reasons → the wire reasons (the 3
 * vocabularies shared with values/meta + the 2 manifest-specific
 * reasons — AUTH_SPEC §12-5). Exhaustiveness is statically enforced
 * by the Record type.
 */
const MANIFEST_REJECT_REASONS: Readonly<Record<ManifestInvalidReason, ManifestRejectReason>> = {
  "signature-invalid": "signature-invalid",
  "chain-head-mismatch": "chain-head-unknown",
  "chain-head-future": "chain-head-unknown",
  "issuer-unknown": "chain-head-state-mismatch",
  "issuer-not-member-at-head": "chain-head-state-mismatch",
  "issuer-key-mismatch-at-head": "chain-head-state-mismatch",
  "issuer-role-insufficient-at-head": "chain-head-state-mismatch",
  // §6.3's 3′ (2026-09-14 ES): the issuer is out of scope at the
  // declared head (same class as role insufficiency)
  "issuer-environment-out-of-scope-at-head": "chain-head-state-mismatch",
  "environment-not-created-at-head": "manifest-epoch-mismatch",
  "epoch-not-current-at-head": "manifest-epoch-mismatch",
  // A forward manifestVersion that baked in a stale epoch (an epoch
  // regression against the predecessor) is also rejected as an epoch
  // mismatch (§12-5's 422 classification)
  "epoch-regressed": "manifest-epoch-mismatch",
  "env-meta-mismatch": "manifest-digest-mismatch",
  "variables-digest-mismatch": "manifest-digest-mismatch",
  "prev-shape-mismatch": "chain-head-state-mismatch",
  "prev-hash-mismatch": "chain-head-state-mismatch",
  // The checkpoint binding (CRYPTO_SPEC §4.3 (2) / §6.3 consistency
  // rule 1). The wire also returns the same-named reason (the
  // composite's bundled-payload match [§12-4's tuple ↔ manifest
  // hash match] is uniquely owned by this binding check — §6.4's
  // "the split is unified in the implementation PR")
  "checkpoint-binding-mismatch": "checkpoint-binding-mismatch",
  "checkpoint-equivocation": "checkpoint-equivocation",
  "checkpoint-regressed": "checkpoint-regressed",
};

/**
 * Builds the set of variable statements in the post-acceptance meta
 * state (tombstones included — §4.3): the stored latest shapes with
 * this operation's accepted statement applied (verified —
 * signedBytesHashHex is server-recomputed). Operations that carry
 * no variable (environment rename, rotate, environment creation)
 * take no override.
 */
export const manifestDigestEntries = Effect.fn("verify-manifest.manifestDigestEntries")(function* (
  environmentId: string,
  override: {
    readonly variableId: string;
    readonly status: "active" | "deleted" | "declared";
    readonly metaVersion: number;
    readonly signedBytesHashHex: string;
  } | null,
) {
  const store = yield* DataStore;
  const stored = yield* store.variableDigestEntries(environmentId);
  if (override === null) {
    return stored;
  }
  const entry: VariablesDigestEntry = {
    variableId: override.variableId,
    status: override.status,
    metaVersion: override.metaVersion,
    metaSigHashHex: override.signedBytesHashHex,
  };
  const rest = stored.filter((candidate) => candidate.variableId !== override.variableId);
  return [...rest, entry];
});

/**
 * The latest shape of the stored environment meta statement
 * (metaVersion + the server-recomputed hash). It is the envMeta
 * expectation a manifest must bind for operations that do not
 * change the environment meta (variable meta ops, rotate). A
 * missing row is an invariant violation (the environment row and
 * the statement are created atomically by composite acceptance) =
 * defect.
 */
export const storedEnvMeta = Effect.fn("verify-manifest.storedEnvMeta")(function* (
  environmentId: string,
) {
  const store = yield* DataStore;
  const environment = yield* store.findEnvironment(environmentId);
  if (environment === null) {
    return yield* Effect.die(new Error("environment row missing for manifest acceptance"));
  }
  const anchor = yield* store.environmentMetaAnchor(environmentId, environment.latestMetaVersion);
  if (anchor === null) {
    return yield* Effect.die(new Error("environment meta statement row missing"));
  }
  return { metaVersion: environment.latestMetaVersion, sigHashHex: anchor.signedBytesHashHex };
});

/**
 * The shared shape of the non-composite meta operations (variable
 * create / rename / delete, environment rename): manifest
 * acceptance (§12-5) + a closure for the write phase.
 * `digestOverride` is the variable's entry after applying the
 * bundled statement (null for operations carrying no variable);
 * omitting `envMeta` = the stored environment meta (an environment
 * rename passes the post-apply value = the bundled statement
 * itself).
 */
export const acceptManifestForMetaOp = Effect.fn("verify-manifest.acceptManifestForMetaOp")(
  function* (input: {
    readonly projectId: string;
    readonly environmentId: string;
    readonly history: ChainHistoryIndex;
    readonly member: MemberWithDevice;
    readonly manifest: EnvManifestInput;
    readonly digestOverride: {
      readonly variableId: string;
      readonly status: "active" | "deleted" | "declared";
      readonly metaVersion: number;
      readonly signedBytesHashHex: string;
    } | null;
    readonly envMeta?: EnvManifestEnvMeta;
  }) {
    // The head pinning for v1 bootstrap (a clarification of
    // AUTH_SPEC §12-5 (6)): when no manifest is stored, at v1
    // acceptance a rotation slipped in after the declared head still
    // leaves the manifestVersion CAS (latest stays 0) unable to drop
    // it as a 409, and §12-5's argument "no independent
    // current-epoch check at acceptance" does not hold for v1
    // alone. Isomorphic to the composite path's pinning
    // (manifestChainHead in composite-programs.ts), it requires the
    // declared head = the current head at acceptance, closing off
    // the baking-in of a stale epoch (the hash match is owned by
    // crypto's head-binding check — this is position only).
    // **The pin applies only to v1 with no anchor established (no
    // stored manifest)**: a stale v1 against an initialized
    // environment is not a 422 from the pin; it falls to the CAS's
    // 409 (with currentManifestVersion) — joining the honest
    // client's re-fetch / re-sign loop
    const pinAnchor = yield* Effect.flatMap(DataStore, (store) =>
      store.environmentManifestAnchor(input.environmentId),
    );
    if (
      pinAnchor === null &&
      input.manifest.manifestVersion === 1 &&
      input.manifest.chainHeadSeq !== input.history.headSeq
    ) {
      return yield* rejectData({ kind: "payload-mismatch", field: "manifestChainHead" });
    }
    const signedBytesHashHex = yield* acceptEnvManifest({
      projectId: input.projectId,
      environmentId: input.environmentId,
      history: input.history,
      member: input.member,
      manifest: input.manifest,
      entries: yield* manifestDigestEntries(input.environmentId, input.digestOverride),
      envMeta: input.envMeta ?? (yield* storedEnvMeta(input.environmentId)),
    });
    const store = yield* DataStore;
    return {
      /** Called inside the write phase (a single Effect.sync) — the latest-only upsert (§12-8). */
      writeSync: (nowMs: number): void => {
        store.write.upsertEnvironmentManifest(
          input.environmentId,
          input.manifest,
          signedBytesHashHex,
          { userId: input.member.userId, keyFingerprintHex: input.member.keyFingerprintHex },
          nowMs,
        );
      },
    };
  },
);

/**
 * The manifest acceptance column (§12-5's (1)–(7)): the
 * manifestVersion CAS (6; a 409 carries only the latest number) →
 * fetching the stored previous manifest's anchor (the predecessor
 * for the prev check (5) and epoch monotonicity) → crypto's
 * composite verification (signer match (1), head existence (2),
 * authorization at head (3), epoch consistency (4), digest /
 * environment-meta recomputation (7)).
 * On success returns the server-recomputed signed_bytes hash
 * (written to the stored row).
 *
 * `history` is the chain at acceptance time for non-composite meta
 * operations, and the **post-bundled-entry-application** history
 * index for composites (environment creation, rotate) — §12-5
 * (4)'s judgment basis.
 */
export const acceptEnvManifest = Effect.fn("verify-manifest.acceptEnvManifest")(function* (input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly history: ChainHistoryIndex;
  readonly member: MemberWithDevice;
  readonly manifest: EnvManifestInput;
  /** The set reconstructed from the post-acceptance meta state (manifestDigestEntries). */
  readonly entries: readonly VariablesDigestEntry[];
  /** The latest shape of the post-acceptance environment meta statement (metaVersion + the server-recomputed hash). */
  readonly envMeta: EnvManifestEnvMeta;
}) {
  const store = yield* DataStore;
  const anchor = yield* store.environmentManifestAnchor(input.environmentId);
  // The CAS (§12-5 (6)): only declared == latest + 1. No row
  // (environment creation) goes from latest 0 to v1
  const latestVersion = anchor?.manifestVersion ?? 0;
  if (input.manifest.manifestVersion !== latestVersion + 1) {
    return yield* rejectData({
      kind: "manifest-version-conflict",
      currentManifestVersion: latestVersion,
    });
  }
  const verified = yield* catchCryptoErrors(
    cryptoEffect(() =>
      verifyDistributedEnvManifest({
        history: input.history,
        context: {
          suite: input.manifest.suite,
          // The coordinates are reconstructed from server-side
          // values (§12-5 — not assembled from wire-declared
          // values)
          projectId: input.projectId,
          environmentId: input.environmentId,
          epoch: input.manifest.epoch,
          manifestVersion: input.manifest.manifestVersion,
          variablesDigestHex: input.manifest.variablesDigestHex,
          envMetaVersion: input.manifest.envMetaVersion,
          envMetaSigHashHex: input.manifest.envMetaSigHashHex,
          prevManifestSigHashHex: input.manifest.prevManifestSigHashHex,
          // issuer = the caller (§12-5 (1)). The verification key
          // and the bound-key match at head time are checked by
          // verifyDistributedEnvManifest via the FP (the
          // chain-derived member at acceptance time)
          issuerUserId: input.member.userId,
          chainHeadHashHex: input.manifest.chainHeadHashHex,
          chainHeadSeq: input.manifest.chainHeadSeq,
        },
        issuerKeyFingerprintHex: input.member.keyFingerprintHex,
        signatureHex: input.manifest.signatureHex,
        entries: input.entries,
        envMeta: input.envMeta,
        predecessor:
          anchor === null
            ? undefined
            : { signedBytesHashHex: anchor.signedBytesHashHex, epoch: anchor.epoch },
      }),
    ),
    {
      CryptoEnvManifestInvalid: (error) =>
        rejectData({
          kind: "manifest-rejected",
          reason: MANIFEST_REJECT_REASONS[error.reason],
        }),
      // Every other kind is unreachable (InvalidInput / KeyImportFailed
      // with a Schema-validated wire shape + keys derived from a
      // verified chain; the rest are never returned by this
      // operation): an implementation bug = defect; error values carry
      // no secrets
      CryptoInvalidInput: "die",
      CryptoKeyImport: "die",
      CryptoKeyExport: "die",
      CryptoEncrypt: "die",
      CryptoDecrypt: "die",
      CryptoDekWrap: "die",
      CryptoDekUnwrap: "die",
      CryptoSign: "die",
      CryptoDekWrapSignature: "die",
      CryptoInviteAcceptSignature: "die",
      CryptoInviteLinkSignature: "die",
      CryptoInviteIssueSignature: "die",
      CryptoDekCommitment: "die",
      CryptoValueInvalid: "die",
      CryptoMetaStatementInvalid: "die",
      CryptoUnsupportedMetaLayout: "die",
      CryptoHeadAttestationInvalid: "die",
      ChainInvalid: "die",
    },
  );
  return verified.signedBytesHashHex;
});
