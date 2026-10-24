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
//   DataStore / AuditStore). The DDL lives in do-schema.ts and is applied at
//   genesis acceptance (init) — a never-initialized DO holds no tables so a
//   probe of an arbitrary project ID leaves no storage (Sc-7 / A-4). The
//   constructor only applies pending migration steps to an already-materialized
//   DO; opsRestore materializes a fresh destination
//
// The RPC methods are thin: each runs one program under the permit — the
// chain API's (programs-chain.ts), the head attestation's
// (attestation-accept.ts), the data plane's (programs/programs-*.ts and
// composite-programs.ts) or the ops RPC's (do-ops.ts). What stays in the
// class is what runs around the programs: the runtime and the permit,
// the instance state (the chain-state cache, dropped on a defect, and
// the materialization flag), the guards (#runData's not-initialized
// gate, #runWrite's membership and mirror checks, the lease's single-use
// chain tokens, the ops RPCs' bucket and materialization checks) and the
// folding of each program's result into its RPC outcome (toDataOutcome,
// init's tag mapping, the lease and rotation-proposal matches).

import type { EnvironmentId, UserId, VariableId } from "@maruhi/core";
import type { ChainEntry, Role } from "@maruhi/crypto";
import { DurableObject } from "cloudflare:workers";
import { Clock, Effect, Layer, ManagedRuntime, Semaphore } from "effect";

import type { HeadAttestationSubmissionInput } from "../attestation-accept.ts";
import { putHeadAttestationProgram } from "../attestation-accept.ts";
import { AuditStore, auditStoreLayer } from "../audit-store.ts";
import { requireMemberState } from "../data/data-guards.ts";
import type {
  DataActor,
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
import type { DataOutcome, DataRejectedError } from "../data/data-rejection.ts";
import { rejectData } from "../data/data-rejection.ts";
import type { DataStore } from "../data/data-store.ts";
import { dataStoreLayer } from "../data/data-store.ts";
import type { EnvironmentChainResultValue } from "../programs/composite-programs.ts";
import {
  createEnvironmentCompositeProgram,
  deleteEnvironmentCompositeProgram,
  rotateEpochCompositeProgram,
} from "../programs/composite-programs.ts";
import type { AuditEventsQueryInput, AuditEventValue } from "../programs/programs-audit.ts";
import { auditEventsProgram, auditHeadProgram } from "../programs/programs-audit.ts";
import type {
  AppendOutcome,
  InitAdmission,
  InitOutcome,
  SnapshotOutcome,
} from "../programs/programs-chain.ts";
import {
  appendProgram,
  initProgram,
  memberRoleProgram,
  snapshotProgram,
} from "../programs/programs-chain.ts";
import {
  deleteDekWrapsProgram,
  listMyDekWrapsProgram,
  registerDekWrapsProgram,
} from "../programs/programs-dek.ts";
import {
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
import { leaseChainProgram, leaseProgram } from "../programs/programs-lease.ts";
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
import type { EffectiveRotationFlag } from "../rotation-detect.ts";
import { makeServerKey, ServerKey } from "../server-key.ts";
import { ServerLoggerLive } from "../server-logger.ts";
import type { StorageMeter } from "../storage-guard.ts";
import { storageGuardDecision, storageMeterLayer } from "../storage-guard.ts";
import { readWorkerSecrets } from "../worker-env.ts";
import type { ChainStore, StateCache } from "./chain-store.ts";
import { chainStoreLayer } from "./chain-store.ts";
import { readMirrorState } from "./do-mirror.ts";
import type { OpsBackupInput, OpsBackupOutcome, OpsRestoreOutcome } from "./do-ops.ts";
import { backupProgram, restoreBody, restoreProgram } from "./do-ops.ts";
import { ensureProjectDoTables, projectDoInitialized } from "./do-schema.ts";
import { LeaseChainGrants } from "./lease-chain-grants.ts";

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
  // The five *_RATE_LIMIT bindings below are required here because both
  // serving modes declare them (test/cf-env.test.ts), but a deployment
  // whose config lacks one has it undefined at runtime. They are read only
  // through worker-env.ts's ipRateLimitAllowed, which answers a missing
  // binding with 503 SetupIncomplete (AUTH_SPEC §4-1 (1)).
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
   * The source-IP rate limit of lease issuance. A DO is addressable by
   * name, so a valid OIDC token alone could aim requests at arbitrary
   * project IDs; a never-materialized DO no longer stores anything on reach
   * (Sc-7 / A-4), so this request-level limit before projectStub is reached
   * bounds the CPU of such probing rather than any storage growth.
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
// The Durable Object (the ManagedRuntime pattern)
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
  // Issued leases' heads awaiting their chain read (lease-chain-grants.ts)
  readonly #leaseChainGrants = new LeaseChainGrants();
  // Whether this DO's tables exist. A fresh DO holds no storage until a
  // genesis is accepted (Sc-7 / A-4, owner approval 2026-10-11 — AUTH_SPEC
  // §14-3 / §11-3): materialized by init (genesis) or opsRestore. Reads and
  // writes to an unmaterialized DO fold to the uniform 404 (§11-2) without
  // touching storage (#runData), so a probe of an arbitrary project ID — the
  // unauthenticated lease, an authenticated GET — leaves nothing behind.
  //
  // A performance cache, not the source of truth: it is `true` only when the
  // tables are known to exist, and a `false` value is re-checked against
  // storage before it is trusted (#latchInitialized). So a path that
  // materialized the tables without returning through a flag-setting branch
  // (an opsRestore whose post-commit extension defects after the tables
  // committed) cannot strand the DO reporting not-initialized — which would
  // 404 every read, skip evacuation, and make `GET /projects` prune live
  // members as phantoms (handlers-membership.ts).
  #initialized: boolean;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    // Read-only detection (creates nothing). A materialized DO applies any
    // pending migration steps and re-asserts its triggers (the catch-up that
    // used to run unconditionally); a fresh DO is left untouched until a
    // genesis is accepted.
    this.#initialized = projectDoInitialized(ctx.storage.sql);
    if (this.#initialized) {
      ensureProjectDoTables(ctx.storage);
    }
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
   * Whether this DO's tables exist, re-checking storage when the cached flag
   * is `false` and latching it `true` on the way (read-only — creates
   * nothing). The re-check keeps a never-materialized DO cheap (one
   * `sqlite_master` lookup per probe, no storage) while never stranding a DO
   * whose tables were materialized outside a flag-setting branch.
   */
  #latchInitialized(): boolean {
    if (this.#initialized) {
      return true;
    }
    if (projectDoInitialized(this.ctx.storage.sql)) {
      this.#initialized = true;
      return true;
    }
    return false;
  }

  /**
   * Run a data-plane program folded into an outcome under the permit.
   * Reads take the permit too: it makes the membership check and the
   * data read atomic against chain writes (the TOCTOU fix of the header
   * comment).
   */
  #runData<T>(program: Effect.Effect<T, DataRejectedError, DoServices>): Promise<DataOutcome<T>> {
    // An unmaterialized DO holds no tables (Sc-7 / A-4): every read / write
    // folds to not-initialized (the uniform 404 of §11-2) before any storage
    // is touched. The lease / proposal family does not take this gate — their
    // server-key-unconfigured 503 must precede the existence check (§14-3), so
    // they reach uninitialized through the chain load instead (loadInitializedChain).
    if (!this.#latchInitialized()) {
      return Promise.resolve({ kind: "rejected", rejection: { kind: "not-initialized" } });
    }
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
   * cursor to is kept by the schema's triggers (the mutation triggers the
   * do-schema.ts base step creates), not here: any row change by any path
   * moves it.
   */
  #runWrite<T>(
    callerUserId: UserId,
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
          initProgram(expectedProjectId, entry, admission, this.ctx.storage, this.#stateCache).pipe(
            Effect.map((head): InitOutcome => {
              // The genesis committed and the tables were materialized
              // (initProgram): record it so later reads / writes run instead
              // of folding to not-initialized.
              this.#initialized = true;
              return {
                kind: "initialized",
                headSeq: head.headSeq,
                headHashHex: head.headHashHex,
              };
            }),
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
    callerUserId: UserId,
  ): Promise<AppendOutcome> {
    return this.#runWrite(
      callerUserId,
      appendProgram(parentHeadHashHex, entry, callerUserId, this.#stateCache),
    );
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  snapshotFor(callerUserId: UserId): Promise<SnapshotOutcome> {
    return this.#runData(snapshotProgram(callerUserId, this.#stateCache));
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  putHeadAttestation(
    callerUserId: UserId,
    input: HeadAttestationSubmissionInput,
  ): Promise<DataOutcome<void>> {
    return this.#runWrite(
      callerUserId,
      putHeadAttestationProgram(callerUserId, input, this.#stateCache),
    );
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  memberRoleFor(callerUserId: UserId): Promise<DataOutcome<Role>> {
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
    environmentId: EnvironmentId,
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
    environmentId: EnvironmentId,
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
    environmentId: EnvironmentId,
    input: {
      readonly parentHeadHashHex: string;
      readonly entry: ChainEntry & { readonly op: "delete_environment" };
    },
  ): Promise<DataOutcome<void>> {
    // Composite acceptance (§12-4 — 2026-10-07): the delete_environment
    // append (CAS + verifyChain) and the data deletion in the same permit
    // and the same synchronous block
    return this.#runWrite(
      actor.userId,
      deleteEnvironmentCompositeProgram(actor, environmentId, input, this.#stateCache),
    );
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  listEnvironments(actor: DataActor): Promise<DataOutcome<EnvironmentListValue>> {
    return this.#runData(listEnvironmentsProgram(actor, this.#stateCache));
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  createVariable(
    actor: DataActor,
    environmentId: EnvironmentId,
    input: {
      readonly variableId: VariableId;
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
    environmentId: EnvironmentId,
    variableId: VariableId,
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
    environmentId: EnvironmentId,
    variableId: VariableId,
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
    environmentId: EnvironmentId,
    variableId: VariableId,
  ): Promise<DataOutcome<VariableVersionHistoryValue>> {
    // The version history (§12-7 — VH): metadata only, no var.read
    return this.#runData(
      variableHistoryProgram(actor, environmentId, variableId, this.#stateCache),
    );
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  variableVersionValues(
    actor: DataActor,
    environmentId: EnvironmentId,
    variableId: VariableId,
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
    environmentId: EnvironmentId,
    variableId: VariableId,
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
    environmentId: EnvironmentId,
    variableId: VariableId,
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
    environmentId: EnvironmentId,
  ): Promise<DataOutcome<EnvironmentPullValue>> {
    return this.#runData(pullEnvironmentProgram(actor, environmentId, this.#stateCache));
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  pullEnvironmentMetadata(
    actor: DataActor,
    environmentId: EnvironmentId,
  ): Promise<DataOutcome<EnvironmentMetadataPullValue>> {
    return this.#runData(pullEnvironmentMetadataProgram(actor, environmentId, this.#stateCache));
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  registerDekWraps(
    actor: DataActor,
    environmentId: EnvironmentId,
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
    environmentId: EnvironmentId,
  ): Promise<DataOutcome<readonly RecipientDekValue[]>> {
    return this.#runData(listMyDekWrapsProgram(actor, environmentId, this.#stateCache));
  }

  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  deleteDekWraps(
    actor: DataActor,
    environmentId: EnvironmentId,
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
    environmentId: EnvironmentId,
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
    environmentId: EnvironmentId,
    ephemeralPubHex: string,
    facts: LeaseTokenFacts,
    variables: readonly PreflightVariableInput[],
    recipients: readonly PreflightRecipientInput[],
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
    environmentId: EnvironmentId,
    ephemeralPubHex: string,
    facts: LeaseTokenFacts,
  ): Promise<LeaseOutcome> {
    return this.#runtime.runPromise(
      this.#opLock.withPermit(
        this.#invalidateCachesOnDefect(
          leaseProgram(environmentId, ephemeralPubHex, facts, this.#stateCache).pipe(
            Effect.matchEffect({
              onSuccess: (value: LeaseValue) =>
                Effect.map(Clock.currentTimeMillis, (nowMs): LeaseOutcome => ({
                  kind: "ok",
                  value,
                  chainToken: this.#leaseChainGrants.grant(
                    { seq: value.headSeq, hashHex: value.headHashHex },
                    nowMs,
                  ),
                })),
              onFailure: (rejection) =>
                Effect.succeed<LeaseOutcome>({ kind: "rejected", rejection }),
            }),
          ),
        ),
      ),
    );
  }

  /**
   * The chain half of a lease (programs-lease.ts — §14-2), so the chain and
   * the values each get their own RPC result. It takes the single-use token
   * issueLease returned with an ok outcome — the authorization stays in the
   * DO (a stub holder cannot read a chain without an authorized issuance) —
   * and returns the chain up to the head that issuance was judged against.
   * An unknown, spent or expired token is a defect (500).
   */
  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the worker calls it via the stub)
  leaseChain(chainToken: string): Promise<readonly ChainEntry[]> {
    return this.#runtime.runPromise(
      this.#opLock.withPermit(
        Effect.flatMap(Clock.currentTimeMillis, (nowMs) => {
          // A token miss is checked before the defect guard: it touches no
          // state, so it must not drop the caches
          const head = this.#leaseChainGrants.take(chainToken, nowMs);
          return head === undefined
            ? Effect.die(new Error("unknown, spent or expired lease chain token"))
            : this.#invalidateCachesOnDefect(leaseChainProgram(head, this.#stateCache));
        }),
      ),
    );
  }

  // --- Ops RPC (hosted-ops.md §2-D / §2-E; not callable over HTTP) -----

  /**
   * The DO → R2 evacuation (hosted-ops.md §2-D): do-ops.ts's backupProgram
   * under the permit (= all tables consistent).
   */
  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the cron sweep calls it via the stub)
  opsBackup(input: OpsBackupInput): Promise<OpsBackupOutcome> {
    const bucket = this.env.OPS_BACKUP_BUCKET;
    if (bucket === undefined) {
      return Promise.resolve({ kind: "no-bucket" });
    }
    // A never-materialized DO has nothing to evacuate (Sc-7 / A-4). The sweep
    // enumerates D1 `projects`, which only an accepted genesis writes, so this
    // is a defensive guard — reading the watermarks would fault without tables.
    if (!this.#latchInitialized()) {
      const databaseSizeBytes = this.ctx.storage.sql.databaseSize;
      return Promise.resolve({
        kind: "skipped",
        auditSeq: 0,
        chainSeq: 0,
        attestationMark: 0,
        storageLevel: storageGuardDecision(databaseSizeBytes),
        databaseSizeBytes,
      });
    }
    return this.#runtime.runPromise(
      this.#opLock.withPermit(
        backupProgram(input, this.ctx.storage.sql, this.ctx.id.toString(), bucket),
      ),
    );
  }

  /**
   * Restore from an evacuation (under the permit). Writes **only into an
   * empty DO** (do-snapshot-restore.ts — no overwrite path exists). After
   * the restore, instance memory (the derived state, the audit sequence) is
   * discarded, the cumulative hash row is extended to MAX(seq) below the
   * storage guard's line, and the audit head is returned (for
   * cross-checking — do-ops.ts's restoreProgram).
   */
  // fallow-ignore-next-line unused-class-member -- a DO RPC method (the restore worker calls it via the stub)
  opsRestore(objectKey: string, etag?: string): Promise<OpsRestoreOutcome> {
    const bucket = this.env.OPS_BACKUP_BUCKET;
    if (bucket === undefined) {
      return Promise.resolve({ kind: "no-bucket" });
    }
    return this.#runtime
      .runPromise(
        this.#opLock.withPermit(
          restoreProgram(this.ctx.storage, restoreBody(bucket, objectKey, etag), this.#stateCache),
        ),
      )
      .finally(() => {
        // restoreProgram may have materialized the tables (Sc-7 / A-4) before
        // the outcome resolved — a committed restore whose post-commit head
        // extension then defects still leaves them. Re-check storage and latch
        // the flag either way, so a defect cannot strand the DO reporting
        // not-initialized. A refusal before any table was created (object
        // missing / changed — do-ops.ts) leaves none, and the flag stays false.
        this.#latchInitialized();
      });
  }
}
