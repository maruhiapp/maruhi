// The project DO: colocates the append-only membership-chain storage
// (CRYPTO_SPEC §6.4), the data plane (environments, variables,
// ciphertexts, wrapped DEKs — AUTH_SPEC §12), and the audit log
// (AUDIT_SPEC §5.1) in one DO (so the §4 queries hold with no
// cross-store join, and a chain append and its mirror append write under
// the same serialization).
//
// - Server-side verification: verifyChain (@maruhi/crypto) is re-run when
//   accepting an append. Client verification (§6.3) defends against an
//   untrusted server; this verification defends against a malicious
//   client — both are required (§6.4)
// - Serialization + CAS: an append request carries the parent head hash
//   and is rejected when it disagrees with the current head. Operations
//   inside the DO are serialized by a Semaphore(1) — the DO's input gate
//   opens during any non-storage await (crypto.subtle inside verifyChain),
//   so leaving it to the gate would let appends interleave. Data-plane
//   changes share the same permit (prevents lost/interleaved concurrent
//   pushes). **Reads serialize under the same permit too**: a read outside
//   the permit would let a remove_member acceptance slip between
//   "membership check (chain-derived) → data read" and could distribute a
//   value to a just-removed member (a TOCTOU violating §11-2). Under the
//   permit every operation linearizes against chain writes. The PRIMARY
//   KEY constraint is the last line of defense
// - Acceptance policy: §6.4 for the chain (1 MiB / 10,000 entries / 32
//   MiB); §12-8 for the data (policy.ts)
// - Storage (DO SQLite) is isolated behind Effect services (ChainStore /
//   DataStore / AuditStore). The DDL lives in do-schema.ts (applied by the
//   constructor)

import type { ChainEntry, ChainState, Role } from "@maruhi/crypto";
import { DurableObject } from "cloudflare:workers";
import { Clock, Data, Effect, Layer, ManagedRuntime, Semaphore } from "effect";

import type { HeadAttestationSubmissionInput } from "../attestation-accept.ts";
import { putHeadAttestationProgram } from "../attestation-accept.ts";
import { AuditStore, auditStoreLayer } from "../audit-store.ts";
import { standaloneCheckpointProgram } from "../checkpoint-accept.ts";
import type {
  DataActor,
  DataOutcome,
  DataRejectedError,
  DataRejection,
  DekWrapInput,
  DekWrapRefInput,
  EnvironmentListValue,
  EnvironmentMetadataPullValue,
  EnvironmentPullValue,
  EnvManifestInput,
  MetaStatementInput,
  RecipientDekValue,
  SchemaPolicy,
  ValueInput,
  VariableVersionValue,
} from "../data/data-plane.ts";
import { rejectData, requireMemberState } from "../data/data-plane.ts";
import type { StoredHeadAttestation } from "../data/data-store.ts";
import { DataStore, dataStoreLayer } from "../data/data-store.ts";
import { MAX_DEVICES_PER_MEMBER } from "../policy.ts";
import type { EnvironmentChainResultValue } from "../programs/composite-programs.ts";
import {
  createEnvironmentCompositeProgram,
  rotateEpochCompositeProgram,
} from "../programs/composite-programs.ts";
import type { AuditEventsQueryInput, AuditEventValue } from "../programs/programs-audit.ts";
import { auditEventsProgram, auditHeadProgram } from "../programs/programs-audit.ts";
import {
  deleteDekWrapsProgram,
  listMyDekWrapsProgram,
  registerDekWrapsProgram,
} from "../programs/programs-dek.ts";
import {
  deleteEnvironmentProgram,
  listEnvironmentsProgram,
  pullEnvironmentMetadataProgram,
  pullEnvironmentProgram,
  renameEnvironmentProgram,
} from "../programs/programs-environment.ts";
import type { ExportMembersValue, ExportPageValue } from "../programs/programs-export.ts";
import { exportMembersProgram, exportPageProgram } from "../programs/programs-export.ts";
import type {
  VariableVersionHistoryValue,
  VariableVersionValuesValue,
} from "../programs/programs-history.ts";
import {
  variableHistoryProgram,
  variableVersionValuesProgram,
} from "../programs/programs-history.ts";
import type { LeaseOutcome, LeaseTokenFacts, LeaseValue } from "../programs/programs-lease.ts";
import { leaseProgram } from "../programs/programs-lease.ts";
import type {
  MirrorPageRequest,
  MirrorPageValue,
  MirrorStatusValue,
} from "../programs/programs-mirror.ts";
import {
  markMirrorProgram,
  mirrorPageProgram,
  mirrorStatusProgram,
  unmarkMirrorProgram,
} from "../programs/programs-mirror.ts";
import type {
  MemberProposalValue,
  PreflightOutcome,
  PreflightRecipientInput,
  PreflightVariableInput,
  ProposalOutcome,
  ProposalReceipt,
  ProposalResolutionInput,
  RotationProposalInput,
} from "../programs/programs-proposal.ts";
import {
  listRotationProposalsProgram,
  preflightRotationProgram,
  proposeRotationProgram,
  resolveRotationProposalProgram,
} from "../programs/programs-proposal.ts";
import type { RotationDismissTargetInput } from "../programs/programs-rotation.ts";
import {
  dismissRotationFlagsProgram,
  rotationFlagsProgram,
} from "../programs/programs-rotation.ts";
import {
  getSchemaPolicyProgram,
  setSchemaPolicyProgram,
} from "../programs/programs-schema-policy.ts";
import {
  activateVariableProgram,
  createVariableProgram,
  deleteVariableProgram,
  pushVersionProgram,
  renameVariableProgram,
} from "../programs/programs-variable.ts";
import { ensureProposalAdmitted } from "../quotas.ts";
import type { EffectiveRotationFlag } from "../rotation-detect.ts";
import { makeServerKey, ServerKey } from "../server-key.ts";
import { ServerLoggerLive } from "../server-logger.ts";
import type { StorageGuardDecision } from "../storage-guard.ts";
import {
  ensureStorageAdmitsGrowth,
  StorageMeter,
  storageGuardDecision,
  storageMeterLayer,
} from "../storage-guard.ts";
import { readWorkerSecrets } from "../worker-env.ts";
import type { AppliedProposal } from "./chain-accept.ts";
import { ensureParentHead, verifyAcceptableEntry } from "./chain-accept.ts";
import { commitAcceptedEntry } from "./chain-commit.ts";
import type { StateCache } from "./chain-store.ts";
import { ChainStore, chainStoreLayer, deriveStoredState, updateStateCache } from "./chain-store.ts";
import { readMirrorState } from "./do-mirror.ts";
import {
  ensureProjectDoTables,
  PROJECT_DO_TABLES,
  readProjectDoSchemaVersion,
} from "./do-schema.ts";
import type { RestoreFailureCode, SnapshotTrailer } from "./do-snapshot.ts";
import {
  readWatermarks,
  RestoreRefusedError,
  restoreSnapshot,
  snapshotObjectKey,
  writeSnapshot,
} from "./do-snapshot.ts";

export interface Env {
  readonly PROJECT_CHAIN: DurableObjectNamespace<ProjectChainDO>;
  readonly DB: D1Database;
  /** The GitHub OAuth App's client_id (Workers Secret / .dev.vars. Public information, but the provisioning path is uniformly secret — AUTH_SPEC §3-2). */
  readonly GITHUB_CLIENT_ID: string;
  /**
   * The GitHub OAuth App's client_secret (Workers Secret / .dev.vars. Only
   * dummy values may be committed). Read only through worker-env.ts's
   * readWorkerSecrets, which wraps it in Redacted.
   */
  readonly GITHUB_CLIENT_SECRET: string;
  /**
   * The deployment keypair's input key material (Workers Secret /
   * .dev.vars. 32 bytes hex — CRYPTO_SPEC §9). The keypair is derived at
   * startup via RFC 9180 DeriveKeyPair (server-key.ts). Unset = a pure
   * E2EE deployment with no selective disclosure (the default). On a
   * deployment lacking the secret it is undefined at runtime. Read only
   * through worker-env.ts's readWorkerSecrets, which wraps it in Redacted.
   */
  readonly SERVER_ENC_KEY_IKM?: string;
  /**
   * The source-IP rate limit of unauthenticated CLI-login start
   * (AUTH_SPEC §4-1 (1) — the ratelimits of wrangler.jsonc. An unrecorded
   * start, so this protects CPU, not the DB).
   */
  readonly CLI_START_RATE_LIMIT: RateLimit;
  /**
   * The source-IP rate limit of unauthenticated CLI-login poll
   * (AUTH_SPEC §4-1 (5) — looser than start so the normal path stays
   * under the polling interval floor of 5 s = 12 req/min. The spec
   * explicitly allows a 429 rejection of excess polling).
   */
  readonly CLI_POLL_RATE_LIMIT: RateLimit;
  /**
   * The source-IP rate limit of the unauthenticated OAuth callback. A
   * callback hits GitHub's token endpoint per request and consumes the
   * shared quota per OAuth App. state is a cookie-and-query double
   * submit (no server-side state), so a non-browser source can supply
   * both itself and pass the check — this binding is the only thing
   * bounding the rate. Browser interactive logins (incl. the CLI browser
   * leg) share one egress, so the cap is looser than start's (the same
   * 30/min as the WAF recommendation of docs/SELF_HOSTING.md).
   */
  readonly OAUTH_CALLBACK_RATE_LIMIT: RateLimit;
  /**
   * The source-IP rate limit of lease issuance. A DO is implicitly
   * created by name, so a valid OIDC token alone could mass-produce DOs
   * for arbitrary project IDs — this request-level limit before
   * projectStub is reached bounds the creation rate.
   */
  readonly LEASE_RATE_LIMIT: RateLimit;
  /**
   * The source-IP rate limit of a `GET /auth/github/start` carrying a
   * signup invite code (AUTH_SPEC §3). A code-bearing start is an
   * unauthenticated surface involving a D1 read for pre-validation (the
   * check itself is a hash comparison of a 256-bit single-use code and
   * is not an existence oracle — the limit protects resources). A plain
   * start is still unlimited (the login funnel — a 302 with no
   * server-side state and no external call).
   */
  readonly SIGNUP_START_RATE_LIMIT: RateLimit;
  /**
   * The destination of DO → R2 evacuations (docs/notes/hosted-ops.md
   * §2-D / §2-F). An optional binding only the hosted environment
   * (`cf deploy --mode hosted`) has. Absent = never evacuates (the
   * self-hosted default; the sweep leaves a static one line and is a
   * no-op).
   */
  readonly OPS_BACKUP_BUCKET?: R2Bucket;
  /**
   * The tripwire-notification webhook (Workers Secret — hosted-ops.md
   * §2-B). Unset = never sends (disabled by default). The body is only
   * static signal names + aggregate values. Read only through
   * worker-env.ts's readWorkerSecrets, which wraps it in Redacted.
   */
  readonly OPS_ALERT_WEBHOOK_URL?: string;
}

// ---------------------------------------------------------------------------
// Inputs and outputs of the ops RPC (hosted-ops.md §2-D / §2-E). Called
// only from inside the worker (the cron sweep, the restore worker); no
// HTTP handler calls them.
// ---------------------------------------------------------------------------

export interface OpsBackupInput {
  /** The object key's prefix (`do`). The project ID never appears on the key. */
  readonly keyPrefix: string;
  readonly nowMs: number;
  /** A DO larger than this is not evacuated (oversize). */
  readonly maxBytes: number;
  /**
   * The watermark of the last success (audit seq, chain seq, the latest
   * acceptance time of a head attestation). Skip when all three match
   * (null = always evacuate).
   */
  readonly skipIfUnchanged: {
    readonly auditSeq: number;
    readonly chainSeq: number;
    readonly attestationMark: number;
  } | null;
  /** For tests: the multipart part length. */
  readonly partBytes?: number;
}

export type OpsBackupOutcome =
  | {
      readonly kind: "uploaded";
      readonly objectKey: string;
      readonly bytes: number;
      readonly auditSeq: number;
      readonly chainSeq: number;
      readonly attestationMark: number;
      readonly storageLevel: StorageGuardDecision;
      readonly databaseSizeBytes: number;
      readonly trailer: SnapshotTrailer;
    }
  | {
      readonly kind: "skipped";
      readonly auditSeq: number;
      readonly chainSeq: number;
      readonly attestationMark: number;
      readonly storageLevel: StorageGuardDecision;
      readonly databaseSizeBytes: number;
    }
  | {
      readonly kind: "oversize";
      readonly storageLevel: StorageGuardDecision;
      readonly databaseSizeBytes: number;
    }
  | {
      readonly kind: "upload-failed";
      readonly storageLevel: StorageGuardDecision;
      readonly databaseSizeBytes: number;
    }
  | { readonly kind: "no-bucket" };

export type OpsRestoreOutcome =
  | {
      readonly kind: "restored";
      readonly rows: Readonly<Record<string, number>>;
      readonly chainHeadSeq: number;
      readonly chainHeadHashHex: string | null;
      readonly auditMaxSeq: number;
      /** The value read after extending the cumulative hash row to MAX(seq) post-restore (empty string when no audit rows). */
      readonly auditHeadHashHex: string;
    }
  | { readonly kind: "refused"; readonly code: RestoreFailureCode }
  | { readonly kind: "no-bucket" };

// ---------------------------------------------------------------------------
// Typed errors (internal to the DO) and the outcome types at the RPC
// boundary
//
// Chain-API rejections also travel as DataRejection (data-plane.ts): the
// tagged-error → outcome mapping is the single toDataOutcome, and the
// rejection → api-schema error mapping is consolidated into the one
// worker-side table rejectionErrors (data-http.ts — a Record shape whose
// exhaustiveness is type-enforced). Only init keeps a dedicated outcome,
// because it has a non-rejection branch — "already initialized" (the
// decision input of idempotent repair).
// ---------------------------------------------------------------------------

class AlreadyInitializedError extends Data.TaggedError("AlreadyInitialized")<{
  readonly genesisActorUserId: string;
  readonly headSeq: number;
  readonly headHashHex: string;
}> {}
class ProjectIdMismatchError extends Data.TaggedError("ProjectIdMismatch")<object> {}
/**
 * An init to an uninitialized DO arrived with the instruction "do not
 * admit a fresh initialization" from the worker's acceptance check (the
 * AUTH_SPEC §11-3 project-count limit). Reached only after the
 * existing-chain check — when already initialized, AlreadyInitialized
 * (the repair path) stands first.
 */
class FreshInitNotAdmittedError extends Data.TaggedError("FreshInitNotAdmitted")<object> {}

/** The chain head (the RPC value of a successful acceptance). */
export interface ChainHeadValue {
  readonly headSeq: number;
  readonly headHashHex: string;
}

/**
 * The acceptance result of a generic append: the new head + the proposal
 * a completed approve applied (four-eyes — K5). The worker runs the same
 * D1 post-processing as a direct append on `appliedProposal.inner`
 * (invite completed cross-check, membership projection). Not carried on
 * the wire (HTTP response)
 */
export interface AppendValue extends ChainHeadValue {
  readonly appliedProposal: AppliedProposal | null;
}

/**
 * A whole-chain snapshot (the RPC value of a successful get).
 * attestations are **only the latest head attestations of the current
 * members' valid devices** (AUTH_SPEC §16-1 — on top of the row deletion
 * at remove / revoke_device acceptance [chain-accept.ts], the
 * distribution side independently narrows to the current members' device
 * set as a separate defensive layer).
 */
export interface ChainSnapshotValue {
  readonly entries: readonly ChainEntry[];
  readonly headSeq: number;
  readonly headHashHex: string;
  readonly attestations: readonly StoredHeadAttestation[];
}

/** The initialization result crossing the RPC boundary (structured clone). */
export type InitOutcome =
  | { readonly kind: "initialized"; readonly headSeq: number; readonly headHashHex: string }
  | {
      /**
       * Already initialized. The genesis actor and the current head are
       * returned as the decision input of the worker-side idempotent
       * repair (AUTH_SPEC §11-3: a missing projects row + requester =
       * genesis actor counts as success).
       */
      readonly kind: "already-initialized";
      readonly genesisActorUserId: string;
      readonly headSeq: number;
      readonly headHashHex: string;
    }
  | {
      /**
       * Was uninitialized, but the worker's acceptance check (AUTH_SPEC
       * §11-3 — the org's project-count limit) did not admit a fresh
       * initialization (admitFresh = false). Nothing was written. The
       * worker maps it to 429 ProjectLimit. An initialized DO never
       * reaches this branch and proceeds to already-initialized (repair
       * path / 409)
       */
      readonly kind: "fresh-not-admitted";
    }
  | { readonly kind: "project-id-mismatch" }
  | { readonly kind: "rejected"; readonly rejection: DataRejection };

/**
 * The acceptance instruction of init (worker → DO). `admitFresh` =
 * whether a fresh initialization of an uninitialized DO is admitted (the
 * decision result of the AUTH_SPEC §11-3 project-count limit). Even with
 * false, the DO decides "already initialized?" inside its own
 * serialization before answering, so at the limit the §11-3 repair path
 * (already-initialized + missing row) is not blocked.
 */
export interface InitAdmission {
  readonly admitFresh: boolean;
}

/** The append result crossing the RPC boundary. */
export type AppendOutcome = DataOutcome<AppendValue>;

/** The chain-get result crossing the RPC boundary. */
export type SnapshotOutcome = DataOutcome<ChainSnapshotValue>;

// ---------------------------------------------------------------------------
// The Effect programs (the body of chain verification and acceptance
// decisions)
// ---------------------------------------------------------------------------

/** §6.2 / §11-2: reject anything that is not a chain-derived member (reader included). */
function ensureChainMember(
  members: ReadonlyMap<string, unknown>,
  userId: string,
): Effect.Effect<void, DataRejectedError> {
  return members.has(userId) ? Effect.void : Effect.fail(rejectData({ kind: "not-member" }));
}

const initProgram = Effect.fn("chain-do.initProgram")(function* (
  expectedProjectId: string,
  entry: ChainEntry,
  admission: InitAdmission,
  cache: StateCache,
) {
  const store = yield* ChainStore;
  const chain = yield* store.load;
  if (chain.headSeq > 0) {
    const genesisActor = chain.entries[0]?.actor.userId;
    if (genesisActor === undefined || chain.headHashHex === null) {
      // With headSeq > 0 both values exist as an invariant. Missing
      // means storage corruption; do not convert it into a success
      // response with an empty string — drop as a defect
      return yield* Effect.die(new Error("initialized chain is missing genesis or head"));
    }
    return yield* new AlreadyInitializedError({
      genesisActorUserId: genesisActor,
      headSeq: chain.headSeq,
      headHashHex: chain.headHashHex,
    });
  }
  // The AUTH_SPEC §11-3 project-count limit (already judged by the
  // worker): at the limit, decline only a fresh initialization. Placing
  // it after the "already initialized?" check (above) lets a repair
  // re-init (already-initialized) of an at-limit org through regardless
  // of the limit — this ordering is the implementation point of §11-3's
  // "do not block the repair path at the limit"
  if (!admission.admitFresh) {
    return yield* new FreshInitNotAdmittedError();
  }
  // The 4 acceptance steps for an empty chain (the capacity check is
  // vacuously satisfied on an empty chain). Anything other than
  // genesis, a bad signature, etc. is rejected by verifyChain with a
  // §6.3 reason code. On the Schema init accepts every op, but a
  // non-genesis at seq 1 always becomes a 422 under verifyChain's
  // framing rule (bad-genesis) — the four-eyes acceptance policy
  // (appendProgram) is not placed on init because of this invariant
  // (independent review D3)
  const { canonicalBytes, applied } = yield* verifyAcceptableEntry(chain, entry);
  // Project ID = genesis entry hash (§6.4). If the binding between the
  // routed DO and the entry is broken, do not accept (defense against a
  // worker-side bug)
  if (applied.state.headHashHex !== expectedProjectId) {
    return yield* new ProjectIdMismatchError();
  }
  yield* commitAcceptedEntry(chain, entry, applied, canonicalBytes);
  updateStateCache(cache, applied);
  return { headSeq: applied.state.headSeq, headHashHex: applied.state.headHashHex };
});

/**
 * The front stage shared by reads and appends: the initialization check
 * and the chain-derived membership check (§6.2 / §11-2). A non-member
 * gets nothing back, including the CAS's current-head information and
 * the acceptance policy's decision (the worker maps not-member to 404).
 */
const loadChainForMember = Effect.fn("chain-do.loadChainForMember")(function* (
  callerUserId: string,
  cache: StateCache,
) {
  const store = yield* ChainStore;
  const chain = yield* store.load;
  if (chain.headSeq === 0 || chain.headHashHex === null) {
    return yield* rejectData({ kind: "not-initialized" });
  }
  const { state } = yield* deriveStoredState(chain, cache);
  yield* ensureChainMember(state.members, callerUserId);
  return {
    entries: chain.entries,
    headSeq: chain.headSeq,
    headHashHex: chain.headHashHex,
    genesisHashHex: chain.genesisHashHex,
    totalCanonicalBytes: chain.totalCanonicalBytes,
    members: state.members,
    // The current derived state (the reference of the four-eyes
    // acceptance policy and the growth guard — appendProgram)
    state,
  };
});

/**
 * Whether the op grows the access set (the target of the AUTH_SPEC §12-8
 * growth guard). Besides a directly appended `add_member` / `grant_server`,
 * the four-eyes path stops **at the entry where the intent first
 * appears** (design record es-design.md §11 K5-D): a `propose` whose
 * inner op is a growth op, and an `approve` whose referenced pending
 * proposal's inner op is a growth op (regardless of whether it
 * completes). An `approve` whose referent is not pending is out of
 * scope (verifyChain rejects it with `unknown-proposal`). `withdraw`
 * (releases), `set_approval_policy` (bounded by chain capacity), and
 * proposals and approvals of remove / revoke / change_role
 * (remediation) are accepted even under rejection (§12-8 (b)(c)).
 */
function growsAccessSet(entry: ChainEntry, state: ChainState): boolean {
  if (entry.op === "propose") {
    return isGrowthOp(entry.payload.inner.op);
  }
  if (entry.op === "approve") {
    const pending = state.pendingProposals.get(entry.payload.proposalHashHex);
    return pending !== undefined && isGrowthOp(pending.inner.op);
  }
  return isGrowthOp(entry.op);
}

const isGrowthOp = (op: ChainEntry["op"]): boolean => op === "add_member" || op === "grant_server";

/**
 * The acceptance program of a generic chain append (public for tests —
 * storage-guard.test.ts pins, under a StorageMeter with substituted
 * measurements, both the rejection of add_member / grant_server and the
 * non-blocking of remove_member / checkpoint).
 */
export const appendProgram = Effect.fn("chain-do.appendProgram")(function* (
  parentHeadHashHex: string,
  entry: ChainEntry,
  callerUserId: string,
  cache: StateCache,
): Effect.fn.Return<
  AppendValue,
  DataRejectedError,
  ChainStore | AuditStore | DataStore | StorageMeter
> {
  // AUTH_SPEC §6 / §12-4: create_environment / rotate_epoch go only
  // through the composite endpoint. The worker handler refuses ahead of
  // it, but the same guard sits on the DO side — the authority of the
  // acceptance decision — so that even if more call paths into the
  // generic append appear later, the state "the epoch / environment is
  // on the chain but the wraps / environment row are missing" can
  // never be created (defense in layers)
  if (entry.op === "create_environment" || entry.op === "rotate_epoch") {
    return yield* rejectData({ kind: "composite-required", op: entry.op });
  }
  // A standalone (periodic) checkpoint (AUTH_SPEC §16-2): the generic
  // append accepts it, but branches into a dedicated path that performs
  // the acceptance verification (content cross-check against the state
  // at acceptance time) and the atomic snapshot save
  if (entry.op === "checkpoint") {
    return yield* standaloneCheckpointProgram(parentHeadHashHex, entry, callerUserId, cache);
  }
  const chain = yield* loadChainForMember(callerUserId, cache);
  // The DO storage total guard (AUTH_SPEC §12-8): only the
  // access-set-growing add_member / grant_server (both direct appends
  // and four-eyes proposals / approvals — growsAccessSet); aligned at
  // the entry because the natural follow-up wrap backfill is what is
  // rejected. remove_member / revoke_server / change_role (revocation,
  // permission narrowing = security remediation) and checkpoint
  // (bounded) are accepted even under rejection. Position: after
  // membership (§11-2), before CAS / verifyChain (resource protection
  // first)
  if (growsAccessSet(entry, chain.state)) {
    yield* ensureStorageAdmitsGrowth;
  }
  // The four-eyes propose acceptance policy (AUTH_SPEC §12-8 /
  // CRYPTO_SPEC §6.4 — not a consensus rule): the expires_at_ms upper
  // bound → the pending cap (expired ones do not count). The decision
  // inputs are the current derived state and the server clock, which
  // only the DO has (never placed on the worker — K5-B). Position: same
  // as the growth guard — "before the semantic checks (CAS /
  // verifyChain)"
  if (entry.op === "propose") {
    yield* ensureProposalAdmitted(
      entry.payload.expiresAtMs,
      chain.state.pendingProposals,
      yield* Clock.currentTimeMillis,
    );
  }
  // The device-count acceptance policy (AUTH_SPEC §12-8 / CRYPTO_SPEC
  // §6.4 — 2026-09-19 DK K3): an `add_device` is not accepted when the
  // actor's **valid** devices have reached the cap (counted on the
  // pre-acceptance derived state — revoked ones do not count). Same
  // position as the four-eyes pending cap (after membership, before
  // CAS / verifyChain). Not a consensus rule
  if (entry.op === "add_device") {
    const active = chain.state.members.get(callerUserId)?.devices.size ?? 0;
    if (active >= MAX_DEVICES_PER_MEMBER) {
      return yield* rejectData({ kind: "device-limit", limit: MAX_DEVICES_PER_MEMBER });
    }
  }
  yield* ensureParentHead(chain, parentHeadHashHex);
  // The 4 acceptance steps (size → capacity → verifyChain → insert +
  // mirror) are shared with the composite path (chain-accept.ts). A
  // completed approve writes the inner op's mirror-application row and
  // its side effects in the same commit, and returns the applied
  // proposal to the worker (K5-H)
  const { canonicalBytes, applied } = yield* verifyAcceptableEntry(chain, entry);
  const appliedProposal = yield* commitAcceptedEntry(chain, entry, applied, canonicalBytes);
  updateStateCache(cache, applied);
  return {
    headSeq: applied.state.headSeq,
    headHashHex: applied.state.headHashHex,
    appliedProposal,
  };
});

/** The chain get (public for tests — pins that reads pass under rejection). */
export const snapshotProgram = Effect.fn("chain-do.snapshotProgram")(function* (
  callerUserId: string,
  cache: StateCache,
): Effect.fn.Return<ChainSnapshotValue, DataRejectedError, ChainStore | DataStore> {
  const chain = yield* loadChainForMember(callerUserId, cache);
  // Bundling the attestations (AUTH_SPEC §16-1): only the latest
  // attestations of current members' **valid devices**. The row
  // deletion at remove_member / revoke_device acceptance
  // (chain-accept.ts) owns the convergence to the source of truth; the
  // narrowing here is an independent defensive layer (also matching
  // the §6.6 (1) client check)
  const dataStore = yield* DataStore;
  const attestations = (yield* dataStore.listHeadAttestations).filter((attestation) =>
    chain.members
      .get(attestation.attesterUserId)
      ?.devices.has(attestation.attesterKeyFingerprintHex),
  );
  return {
    entries: chain.entries,
    headSeq: chain.headSeq,
    headHashHex: chain.headHashHex,
    attestations,
  };
});

/**
 * The calling principal's chain-derived role (the authorization input of
 * the invites API — AUTH_SPEC §15-2). The floor is reader (= being a
 * member): a non-member is rejected as not-member and the worker maps it
 * to 404 (§11-2). The admin / owner level judgment is done on the worker
 * side (per-endpoint rules like "a role=admin invite only by an owner").
 */
const memberRoleProgram = (
  callerUserId: string,
  cache: StateCache,
): Effect.Effect<Role, DataRejectedError, ChainStore> =>
  Effect.map(requireMemberState(callerUserId, "reader", cache), (context) => context.member.role);

// ---------------------------------------------------------------------------
// The Durable Object (the ManagedRuntime pattern; the established shape
// of spike-b)
// ---------------------------------------------------------------------------

type DoServices = ChainStore | DataStore | AuditStore | ServerKey | StorageMeter;

/** Fold a data-plane rejection into an RPC outcome (a success goes to the ok side). */
const toDataOutcome = <T, R>(
  program: Effect.Effect<T, DataRejectedError, R>,
): Effect.Effect<DataOutcome<T>, never, R> =>
  program.pipe(
    Effect.map((value): DataOutcome<T> => ({ kind: "ok", value })),
    Effect.catchTag("DataRejected", (error): Effect.Effect<DataOutcome<T>> =>
      Effect.succeed({ kind: "rejected", rejection: error.rejection }),
    ),
  );

export class ProjectChainDO extends DurableObject<Env> {
  readonly #runtime: ManagedRuntime.ManagedRuntime<DoServices, never>;
  // Serialization of all operations (writes + reads) — see the header comment
  readonly #opLock = Semaphore.makeUnsafe(1);
  // Cache of the chain-derived state + the parsed chain (see chain-store.ts)
  readonly #stateCache: StateCache = { current: null, chain: null };

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ensureProjectDoTables(ctx.storage);
    this.#runtime = ManagedRuntime.make(
      Layer.mergeAll(
        chainStoreLayer(ctx.storage.sql, this.#stateCache),
        dataStoreLayer(ctx.storage.sql),
        auditStoreLayer(ctx.storage.sql),
        // The measurement point of the DO storage total guard (AUTH_SPEC
        // §12-8 — storage-guard.ts). The ops log's once-only flag is
        // bound to this layer (= this instance)
        storageMeterLayer(ctx.storage.sql),
        // Lease unsealing + re-wrapping happen inside the DO (the head
        // of programs-lease.ts: audit atomicity). A separate instance
        // from the worker-side ServerKey, but derives the same keypair
        // from the same Workers Secret. The DO's env-reading boundary
        // for it: the IKM is Redacted from here on (worker-env.ts)
        Layer.sync(ServerKey, () => makeServerKey(readWorkerSecrets(env).serverEncKeyIkm)),
        // Effect logs from DO programs go to console.warn / console.error
        // with the message text only (server-logger.ts)
        ServerLoggerLive,
      ),
    );
  }

  /**
   * Invalidation of instance memory on task failure. DO storage rolls
   * back per task, but instance memory (the parsed chain, the derived
   * state, the audit sequence) remains. If a defect mid-write-phase left
   * only the cache advanced, a phantom state disagreeing with the
   * rolled-back storage would be handed out (worst case, a follow-up
   * append to a phantom head makes a gap permanent in the stored chain
   * and every post-restart operation defects), so on the failure path it
   * is always discarded and the next load / append falls back to a
   * re-read from the stored state. An acceptance rejection
   * (DataRejected) is out of scope because it settles before the write
   * phase (the cache has not advanced).
   */
  #invalidateCachesOnDefect<A, E>(
    program: Effect.Effect<A, E, DoServices>,
  ): Effect.Effect<A, E, DoServices> {
    const cache = this.#stateCache;
    return program.pipe(
      Effect.catchDefect((defect) =>
        Effect.gen(function* () {
          const audit = yield* AuditStore;
          cache.chain = null;
          cache.current = null;
          audit.resetSeqCacheSync();
          return yield* Effect.die(defect);
        }),
      ),
    );
  }

  /**
   * Run a data-plane program folded into an outcome under the permit.
   * Reads take the permit too: it makes the membership check and the
   * data read atomic against chain writes (the TOCTOU fix of the header
   * comment).
   */
  #runData<T>(program: Effect.Effect<T, DataRejectedError, DoServices>): Promise<DataOutcome<T>> {
    return this.#runtime.runPromise(
      this.#opLock.withPermit(this.#invalidateCachesOnDefect(toDataOutcome(program))),
    );
  }

  /**
   * A mirror accepts no write (AUTH_SPEC §11-7 ruling B): refused with
   * `mirror-read-only` after the caller's membership (a non-member gets
   * the uniform 404 of §11-2 — the worker checks only the token's scope,
   * so the membership check must happen here, before the mark is
   * consulted) and before the program's role floor and any state change.
   * Every member may read the mark through the status endpoint, so the
   * refusal reveals nothing a reader could not learn. Reads and leases
   * take `#runData` as before.
   */
  #ensureWritable(): Effect.Effect<void, DataRejectedError> {
    const sql = this.ctx.storage.sql;
    return Effect.suspend(() =>
      readMirrorState(sql) === null ? Effect.void : rejectData({ kind: "mirror-read-only" }),
    );
  }

  /**
   * {@link #runData} for the write entry points: membership → the mirror
   * guard → the program. The mutation counter a paged export binds its
   * cursor to is kept by the schema's triggers (do-schema.ts step 7), not
   * here: any row change by any path moves it.
   */
  #runWrite<T>(
    callerUserId: string,
    program: Effect.Effect<T, DataRejectedError, DoServices>,
  ): Promise<DataOutcome<T>> {
    return this.#runData(
      requireMemberState(callerUserId, "reader", this.#stateCache).pipe(
        Effect.flatMap(() => this.#ensureWritable()),
        Effect.flatMap(() => program),
      ),
    );
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  init(
    expectedProjectId: string,
    entry: ChainEntry,
    admission: InitAdmission,
  ): Promise<InitOutcome> {
    // Rejections (DataRejected) fold into the same rejected shape as
    // toDataOutcome. Only init-specific branches — "already initialized"
    // (not a rejection: the decision input of idempotent repair), "fresh
    // initialization not admitted" (the worker's project-count limit —
    // §11-3), and the worker-bug detector project-id-mismatch — have
    // dedicated branches
    return this.#runtime.runPromise(
      this.#opLock.withPermit(
        this.#invalidateCachesOnDefect(
          initProgram(expectedProjectId, entry, admission, this.#stateCache).pipe(
            Effect.map((head): InitOutcome => ({
              kind: "initialized",
              headSeq: head.headSeq,
              headHashHex: head.headHashHex,
            })),
            Effect.catchTags({
              AlreadyInitialized: (error): Effect.Effect<InitOutcome> =>
                Effect.succeed({
                  kind: "already-initialized",
                  genesisActorUserId: error.genesisActorUserId,
                  headSeq: error.headSeq,
                  headHashHex: error.headHashHex,
                }),
              FreshInitNotAdmitted: (): Effect.Effect<InitOutcome> =>
                Effect.succeed({ kind: "fresh-not-admitted" }),
              ProjectIdMismatch: (): Effect.Effect<InitOutcome> =>
                Effect.succeed({ kind: "project-id-mismatch" }),
              DataRejected: (error): Effect.Effect<InitOutcome> =>
                Effect.succeed({ kind: "rejected", rejection: error.rejection }),
            }),
          ),
        ),
      ),
    );
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  append(
    parentHeadHashHex: string,
    entry: ChainEntry,
    callerUserId: string,
  ): Promise<AppendOutcome> {
    return this.#runWrite(
      callerUserId,
      appendProgram(parentHeadHashHex, entry, callerUserId, this.#stateCache),
    );
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  snapshotFor(callerUserId: string): Promise<SnapshotOutcome> {
    return this.#runData(snapshotProgram(callerUserId, this.#stateCache));
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  putHeadAttestation(
    callerUserId: string,
    input: HeadAttestationSubmissionInput,
  ): Promise<DataOutcome<void>> {
    return this.#runWrite(
      callerUserId,
      putHeadAttestationProgram(callerUserId, input, this.#stateCache),
    );
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  memberRoleFor(callerUserId: string): Promise<DataOutcome<Role>> {
    return this.#runData(memberRoleProgram(callerUserId, this.#stateCache));
  }

  // --- Data-plane RPC (AUTH_SPEC §12) ---------------------------------

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  createEnvironment(
    actor: DataActor,
    input: {
      readonly parentHeadHashHex: string;
      readonly entry: ChainEntry & { readonly op: "create_environment" };
      readonly statement: MetaStatementInput;
      readonly deks: readonly DekWrapInput[];
      readonly manifest: EnvManifestInput;
      readonly checkpoint: ChainEntry & { readonly op: "checkpoint" };
    },
  ): Promise<DataOutcome<EnvironmentChainResultValue>> {
    // Composite acceptance (§12-4): the chain append (CAS + verifyChain)
    // and the data registration are made atomic in the same permit and
    // the same synchronous block (the §6.4 composite acceptance)
    return this.#runWrite(
      actor.userId,
      createEnvironmentCompositeProgram(actor, input, this.#stateCache),
    );
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  rotateEpoch(
    actor: DataActor,
    environmentId: string,
    input: {
      readonly parentHeadHashHex: string;
      readonly entry: ChainEntry & { readonly op: "rotate_epoch" };
      readonly deks: readonly DekWrapInput[];
      readonly manifest: EnvManifestInput;
      readonly checkpoint: ChainEntry & { readonly op: "checkpoint" };
    },
  ): Promise<DataOutcome<EnvironmentChainResultValue>> {
    return this.#runWrite(
      actor.userId,
      rotateEpochCompositeProgram(actor, environmentId, input, this.#stateCache),
    );
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  renameEnvironment(
    actor: DataActor,
    environmentId: string,
    statement: MetaStatementInput,
    manifest: EnvManifestInput,
  ): Promise<DataOutcome<void>> {
    return this.#runWrite(
      actor.userId,
      renameEnvironmentProgram(actor, environmentId, statement, manifest, this.#stateCache),
    );
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  deleteEnvironment(
    actor: DataActor,
    environmentId: string,
    statement: MetaStatementInput,
  ): Promise<DataOutcome<void>> {
    return this.#runWrite(
      actor.userId,
      deleteEnvironmentProgram(actor, environmentId, statement, this.#stateCache),
    );
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  listEnvironments(actor: DataActor): Promise<DataOutcome<EnvironmentListValue>> {
    return this.#runData(listEnvironmentsProgram(actor, this.#stateCache));
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  createVariable(
    actor: DataActor,
    environmentId: string,
    input: {
      readonly variableId: string;
      readonly statement: MetaStatementInput;
      /** The version-1 value of an active creation. Omitted for a declared creation (§12-5). */
      readonly value?: ValueInput;
      readonly manifest: EnvManifestInput;
    },
  ): Promise<DataOutcome<VariableVersionValue>> {
    return this.#runWrite(
      actor.userId,
      createVariableProgram(actor, environmentId, input, this.#stateCache),
    );
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  activateVariable(
    actor: DataActor,
    environmentId: string,
    variableId: string,
    input: {
      readonly value: ValueInput;
      readonly statement: MetaStatementInput;
      readonly manifest: EnvManifestInput;
    },
  ): Promise<DataOutcome<VariableVersionValue>> {
    // The activation composite (§12-5): declared → active as the atomic
    // acceptance of value version 1 + the statement + the manifest
    return this.#runWrite(
      actor.userId,
      activateVariableProgram(actor, environmentId, variableId, input, this.#stateCache),
    );
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  pushVersion(
    actor: DataActor,
    environmentId: string,
    variableId: string,
    value: ValueInput,
    sameValueAs: number | undefined,
  ): Promise<DataOutcome<VariableVersionValue>> {
    return this.#runWrite(
      actor.userId,
      pushVersionProgram(actor, environmentId, variableId, value, sameValueAs, this.#stateCache),
    );
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  variableHistory(
    actor: DataActor,
    environmentId: string,
    variableId: string,
  ): Promise<DataOutcome<VariableVersionHistoryValue>> {
    // The version history (§12-7 — VH): metadata only, no var.read
    return this.#runData(
      variableHistoryProgram(actor, environmentId, variableId, this.#stateCache),
    );
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  variableVersionValues(
    actor: DataActor,
    environmentId: string,
    variableId: string,
    fromVersion: number,
  ): Promise<DataOutcome<VariableVersionValuesValue>> {
    // The version value range (§12-7 — VH): records var.read
    return this.#runData(
      variableVersionValuesProgram(actor, environmentId, variableId, fromVersion, this.#stateCache),
    );
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  renameVariable(
    actor: DataActor,
    environmentId: string,
    variableId: string,
    statement: MetaStatementInput,
    manifest: EnvManifestInput,
  ): Promise<DataOutcome<void>> {
    return this.#runWrite(
      actor.userId,
      renameVariableProgram(
        actor,
        environmentId,
        variableId,
        statement,
        manifest,
        this.#stateCache,
      ),
    );
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  deleteVariable(
    actor: DataActor,
    environmentId: string,
    variableId: string,
    statement: MetaStatementInput,
    manifest: EnvManifestInput,
  ): Promise<DataOutcome<void>> {
    return this.#runWrite(
      actor.userId,
      deleteVariableProgram(
        actor,
        environmentId,
        variableId,
        statement,
        manifest,
        this.#stateCache,
      ),
    );
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  pullEnvironment(
    actor: DataActor,
    environmentId: string,
  ): Promise<DataOutcome<EnvironmentPullValue>> {
    return this.#runData(pullEnvironmentProgram(actor, environmentId, this.#stateCache));
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  pullEnvironmentMetadata(
    actor: DataActor,
    environmentId: string,
  ): Promise<DataOutcome<EnvironmentMetadataPullValue>> {
    return this.#runData(pullEnvironmentMetadataProgram(actor, environmentId, this.#stateCache));
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  registerDekWraps(
    actor: DataActor,
    environmentId: string,
    wraps: readonly DekWrapInput[],
  ): Promise<DataOutcome<void>> {
    return this.#runWrite(
      actor.userId,
      registerDekWrapsProgram(actor, environmentId, wraps, this.#stateCache),
    );
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  listMyDekWraps(
    actor: DataActor,
    environmentId: string,
  ): Promise<DataOutcome<readonly RecipientDekValue[]>> {
    return this.#runData(listMyDekWrapsProgram(actor, environmentId, this.#stateCache));
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  deleteDekWraps(
    actor: DataActor,
    environmentId: string,
    refs: readonly DekWrapRefInput[],
  ): Promise<DataOutcome<void>> {
    return this.#runWrite(
      actor.userId,
      deleteDekWrapsProgram(actor, environmentId, refs, this.#stateCache),
    );
  }

  // --- schemaPolicy configuration RPC (AUTH_SPEC §12-11) ----------------

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  schemaPolicyFor(actor: DataActor): Promise<DataOutcome<{ readonly schemaPolicy: SchemaPolicy }>> {
    return this.#runData(getSchemaPolicyProgram(actor, this.#stateCache));
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  setSchemaPolicy(actor: DataActor, schemaPolicy: SchemaPolicy): Promise<DataOutcome<void>> {
    return this.#runWrite(
      actor.userId,
      setSchemaPolicyProgram(actor, schemaPolicy, this.#stateCache),
    );
  }

  // --- Rotation-needed flag RPC (AUDIT_SPEC §4.1 / §7) ------------------

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  rotationFlags(actor: DataActor): Promise<DataOutcome<readonly EffectiveRotationFlag[]>> {
    return this.#runData(rotationFlagsProgram(actor, this.#stateCache));
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  dismissRotationFlags(
    actor: DataActor,
    targets: readonly RotationDismissTargetInput[],
  ): Promise<DataOutcome<void>> {
    return this.#runWrite(
      actor.userId,
      dismissRotationFlagsProgram(actor, targets, this.#stateCache),
    );
  }

  // --- Sealed value proposals RPC (CRYPTO_SPEC §5.3 / AUTH_SPEC §14-5) --

  /**
   * The workload mint (programs-proposal.ts). Like issueLease, the OIDC
   * verification is already done on the worker side and the result is a
   * ProposalOutcome (the lease rejection vocabulary plus the §14-5
   * acceptance reasons), not a DataOutcome.
   */
  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  proposeRotation(
    environmentId: string,
    ephemeralPubHex: string,
    facts: LeaseTokenFacts,
    proposal: RotationProposalInput,
  ): Promise<ProposalOutcome> {
    return this.#runtime.runPromise(
      this.#opLock.withPermit(
        this.#invalidateCachesOnDefect(
          proposeRotationProgram(
            environmentId,
            ephemeralPubHex,
            facts,
            proposal,
            this.#stateCache,
          ).pipe(
            Effect.match({
              onSuccess: (value: ProposalReceipt): ProposalOutcome => ({ kind: "ok", value }),
              onFailure: (rejection): ProposalOutcome => ({ kind: "rejected", rejection }),
            }),
          ),
        ),
      ),
    );
  }

  /** The mint's pre-flight (AUTH_SPEC §14-5 O-4 — programs-proposal.ts): the same split as proposeRotation, no value. */
  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  preflightRotation(
    environmentId: string,
    ephemeralPubHex: string,
    facts: LeaseTokenFacts,
    variables: readonly PreflightVariableInput[],
    recipients?: readonly PreflightRecipientInput[],
  ): Promise<PreflightOutcome> {
    return this.#runtime.runPromise(
      this.#opLock.withPermit(
        this.#invalidateCachesOnDefect(
          preflightRotationProgram(
            environmentId,
            ephemeralPubHex,
            facts,
            variables,
            this.#stateCache,
            recipients,
          ).pipe(
            Effect.match({
              onSuccess: (): PreflightOutcome => ({ kind: "ok" }),
              onFailure: (rejection): PreflightOutcome => ({ kind: "rejected", rejection }),
            }),
          ),
        ),
      ),
    );
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  listRotationProposals(actor: DataActor): Promise<DataOutcome<readonly MemberProposalValue[]>> {
    return this.#runData(listRotationProposalsProgram(actor, this.#stateCache));
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  resolveRotationProposal(
    actor: DataActor,
    proposalId: string,
    resolution: ProposalResolutionInput,
  ): Promise<DataOutcome<void>> {
    return this.#runWrite(
      actor.userId,
      resolveRotationProposalProgram(actor, proposalId, resolution, this.#stateCache),
    );
  }

  // --- Project export RPCs (AUTH_SPEC §11-6 — PF3) ----------------------

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  exportPage(actor: DataActor, cursor: string | null): Promise<DataOutcome<ExportPageValue>> {
    return this.#runData(
      exportPageProgram(
        actor,
        cursor,
        this.ctx.storage.sql,
        this.ctx.id.toString(),
        this.#stateCache,
      ),
    );
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  exportMembers(actor: DataActor): Promise<DataOutcome<ExportMembersValue>> {
    return this.#runData(exportMembersProgram(actor, this.#stateCache));
  }

  // --- Mirrors (AUTH_SPEC §11-7 — PF2; programs-mirror.ts) ------------------

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  mirrorStatus(actor: DataActor): Promise<DataOutcome<MirrorStatusValue>> {
    return this.#runData(mirrorStatusProgram(actor, this.ctx.storage.sql, this.#stateCache));
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  markMirror(actor: DataActor, sourceOrigin: string): Promise<DataOutcome<MirrorStatusValue>> {
    return this.#runData(
      markMirrorProgram(actor, sourceOrigin, this.ctx.storage, this.#stateCache),
    );
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  unmarkMirror(actor: DataActor): Promise<DataOutcome<MirrorStatusValue>> {
    return this.#runData(unmarkMirrorProgram(actor, this.ctx.storage, this.#stateCache));
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  mirrorPage(actor: DataActor, page: MirrorPageRequest): Promise<DataOutcome<MirrorPageValue>> {
    return this.#runData(mirrorPageProgram(actor, page, this.ctx.storage, this.#stateCache));
  }

  // --- Audit-event read RPC (AUDIT_SPEC §6 / §7) -----------------------

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  auditEvents(
    actor: DataActor,
    query: AuditEventsQueryInput,
  ): Promise<DataOutcome<readonly AuditEventValue[]>> {
    return this.#runData(auditEventsProgram(actor, query, this.#stateCache));
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  auditHeadFor(actor: DataActor): Promise<DataOutcome<{ readonly auditHeadHashHex: string }>> {
    return this.#runData(auditHeadProgram(actor, this.#stateCache));
  }

  // --- Workload-lease RPC (AUTH_SPEC §14) ------------------------------

  /**
   * Lease authorization, unsealing, re-wrap, and audit
   * (programs-lease.ts). The OIDC verification is already complete on
   * the worker side; what arrives here is only the facts of a verified
   * token (authentication and authorization separated — §14-3's "only an
   * authentication failure is a 401" is kept structurally).
   *
   * Unlike the other RPCs it returns LeaseOutcome, not DataOutcome: the
   * lease rejection vocabulary (404 / 429 / 503) does not overlap the
   * data plane's DataRejection, and folding them would make the
   * worker-side mapping table carry both meanings.
   */
  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  issueLease(
    environmentId: string,
    ephemeralPubHex: string,
    facts: LeaseTokenFacts,
  ): Promise<LeaseOutcome> {
    return this.#runtime.runPromise(
      this.#opLock.withPermit(
        this.#invalidateCachesOnDefect(
          leaseProgram(environmentId, ephemeralPubHex, facts, this.#stateCache).pipe(
            Effect.match({
              onSuccess: (value: LeaseValue): LeaseOutcome => ({ kind: "ok", value }),
              onFailure: (rejection): LeaseOutcome => ({ kind: "rejected", rejection }),
            }),
          ),
        ),
      ),
    );
  }

  // --- Ops RPC (hosted-ops.md §2-D / §2-E; not callable over HTTP) -----

  /**
   * The DO → R2 evacuation (under the permit = all tables consistent).
   * Reading and writing is do-snapshot.ts. The census (the AUTH_SPEC
   * §12-8 judgment) shares the existing meter and pure function (feeding
   * into the §12-8 warning line — hosted-ops.md §2-C; the warning line's
   * wording and once-only discipline are unchanged).
   * An evacuation failure is returned as a static code (retried on the
   * next sweep).
   */
  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the cron sweep calls it via the stub)
  opsBackup(input: OpsBackupInput): Promise<OpsBackupOutcome> {
    const bucket = this.env.OPS_BACKUP_BUCKET;
    if (bucket === undefined) {
      return Promise.resolve({ kind: "no-bucket" });
    }
    const sql = this.ctx.storage.sql;
    const doIdHex = this.ctx.id.toString();
    return this.#runtime.runPromise(
      this.#opLock.withPermit(
        Effect.gen(function* () {
          const meter = yield* StorageMeter;
          const databaseSizeBytes = meter.databaseSizeBytes();
          const storageLevel = storageGuardDecision(databaseSizeBytes);
          const marks = readWatermarks(sql);
          if (
            input.skipIfUnchanged !== null &&
            input.skipIfUnchanged.auditSeq === marks.auditMaxSeq &&
            input.skipIfUnchanged.chainSeq === marks.chainHeadSeq &&
            input.skipIfUnchanged.attestationMark === marks.attestationMark
          ) {
            return {
              kind: "skipped",
              auditSeq: marks.auditMaxSeq,
              chainSeq: marks.chainHeadSeq,
              attestationMark: marks.attestationMark,
              storageLevel,
              databaseSizeBytes,
            } satisfies OpsBackupOutcome;
          }
          if (databaseSizeBytes > input.maxBytes) {
            return { kind: "oversize", storageLevel, databaseSizeBytes } satisfies OpsBackupOutcome;
          }
          const objectKey = snapshotObjectKey(input.keyPrefix, doIdHex, input.nowMs);
          return yield* writeSnapshot({
            sql,
            tables: PROJECT_DO_TABLES,
            schemaVersion: readProjectDoSchemaVersion(sql),
            doIdHex,
            takenAtMs: input.nowMs,
            bucket,
            key: objectKey,
            ...(input.partBytes === undefined ? {} : { partBytes: input.partBytes }),
          }).pipe(
            Effect.map((result): OpsBackupOutcome => ({
              kind: "uploaded",
              objectKey,
              bytes: result.bytes,
              auditSeq: result.trailer.auditMaxSeq,
              chainSeq: result.trailer.chainHeadSeq,
              attestationMark: marks.attestationMark,
              storageLevel,
              databaseSizeBytes,
              trailer: result.trailer,
            })),
            // Every evacuation failure is a defect (do-snapshot.ts); it is
            // answered with the static code and retried on the next sweep
            Effect.catchDefect((defect) =>
              // A static message only (up to the class name). The
              // record lives in the worker-side D1
              Effect.logWarning(
                "project snapshot upload failed; retried on the next sweep",
                defect instanceof Error ? defect.name : "unknown",
              ).pipe(
                Effect.as<OpsBackupOutcome>({
                  kind: "upload-failed",
                  storageLevel,
                  databaseSizeBytes,
                }),
              ),
            ),
          );
        }),
      ),
    );
  }

  /**
   * Restore from an evacuation (under the permit). Writes **only into an
   * empty DO** (do-snapshot.ts — no overwrite path exists). After the
   * restore, instance memory (the derived state, the audit sequence) is
   * discarded, the cumulative hash row is extended to MAX(seq), and the
   * audit head is returned (for cross-checking).
   */
  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the restore worker calls it via the stub)
  opsRestore(objectKey: string, etag?: string): Promise<OpsRestoreOutcome> {
    const bucket = this.env.OPS_BACKUP_BUCKET;
    if (bucket === undefined) {
      return Promise.resolve({ kind: "no-bucket" });
    }
    const storage = this.ctx.storage;
    const sql = storage.sql;
    const cache = this.#stateCache;
    return this.#runtime.runPromise(
      this.#opLock.withPermit(
        Effect.gen(function* () {
          const audit = yield* AuditStore;
          const restored = yield* Effect.gen(function* () {
            // An import restores the body its pre-check verified, by its
            // etag (ruling H revision, round 4): a re-put between the two
            // reads is refused, never restored unchecked
            const object = yield* Effect.promise(() =>
              etag === undefined
                ? bucket.get(objectKey)
                : bucket.get(objectKey, { onlyIf: { etagMatches: etag } }),
            );
            if (object === null) {
              return yield* new RestoreRefusedError({ code: "object-missing" });
            }
            // A precondition failure answers the object without a body
            const verified = "body" in object ? (object as R2ObjectBody) : null;
            if (verified === null) {
              return yield* new RestoreRefusedError({ code: "object-changed" });
            }
            return yield* restoreSnapshot({
              storage,
              tables: PROJECT_DO_TABLES,
              schemaVersion: readProjectDoSchemaVersion(sql),
              body: verified.body,
            }).pipe(
              // Discard the memory regardless of success or failure (no
              // residue of a partial restore is handed out either)
              Effect.ensuring(
                Effect.sync(() => {
                  cache.chain = null;
                  cache.current = null;
                  audit.resetSeqCacheSync();
                }),
              ),
            );
          }).pipe(
            // A refusal is answered, never thrown past the permit
            Effect.catchTag("RestoreRefused", (error) =>
              Effect.succeed({
                kind: "refused",
                code: error.code,
              } satisfies OpsRestoreOutcome),
            ),
          );
          if ("code" in restored) {
            return restored;
          }
          // Extend the audit-head row to the end (bounded extension — a
          // one-time operation at restore, so run it to convergence)
          while ((yield* audit.ensureHeadCurrent) === "more-remains") {
            // Always terminates because each call makes progress (the
            // bounded contract of audit-store.ts)
          }
          const marks = readWatermarks(sql);
          return {
            kind: "restored",
            rows: restored.rows,
            chainHeadSeq: marks.chainHeadSeq,
            chainHeadHashHex: marks.chainHeadHashHex,
            auditMaxSeq: marks.auditMaxSeq,
            auditHeadHashHex: audit.currentHeadHexSync(),
          } satisfies OpsRestoreOutcome;
        }),
      ),
    );
  }
}
