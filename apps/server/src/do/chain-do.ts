import type { EnvironmentId, UserId, VariableId } from "@maruhi/core";
import type { ChainEntry, Role } from "@maruhi/crypto";
import { DurableObject } from "cloudflare:workers";
import { Clock, Effect, Layer, ManagedRuntime, Semaphore } from "effect";

import type { HeadAttestationSubmissionInput } from "../attestation-accept.ts";
import { putHeadAttestationProgram } from "../attestation-accept.ts";
import { AuditStore, auditStoreLayer } from "../audit-store.ts";
import type {
  DataActor,
  DataOutcome,
  DataRejectedError,
  DataStore,
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
} from "../data.package/index.ts";
import { dataStoreLayer, rejectData, requireMemberState } from "../data.package/index.ts";
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
import { makeServerKeyFromEnv, ServerKey } from "../server-key.ts";
import { ServerLoggerLive } from "../server-logger.ts";
import type { StorageMeter } from "../storage-guard.ts";
import { storageGuardDecision, storageMeterLayer } from "../storage-guard.ts";
import type { ChainStore, StateCache } from "./chain-store.ts";
import { chainStoreLayer } from "./chain-store.ts";
import { readMirrorState } from "./do-mirror-state.ts";
import type { OpsBackupInput, OpsBackupOutcome, OpsRestoreOutcome } from "./do-ops.ts";
import { backupProgram, restoreBody, restoreProgram } from "./do-ops.ts";
import { ensureProjectDoTables, projectDoInitialized } from "./do-schema.ts";
import { LeaseChainGrants } from "./lease-chain-grants.ts";

export interface Env {
  readonly PROJECT_CHAIN: DurableObjectNamespace<ProjectChainDO>;
  readonly DB: D1Database;
  readonly GITHUB_CLIENT_ID: string | SecretsStoreSecret;
  readonly GITHUB_CLIENT_SECRET: string | SecretsStoreSecret;
  readonly SERVER_ENC_KEY_IKM?: string | SecretsStoreSecret;
  readonly CLI_START_RATE_LIMIT: RateLimit;
  readonly CLI_POLL_RATE_LIMIT: RateLimit;
  readonly OAUTH_CALLBACK_RATE_LIMIT: RateLimit;
  readonly LEASE_RATE_LIMIT: RateLimit;
  readonly SIGNUP_START_RATE_LIMIT: RateLimit;
  readonly CLI_VERIFY_RATE_LIMIT: RateLimit;
  readonly CLI_APPROVE_RATE_LIMIT: RateLimit;
  readonly OPS_BACKUP_BUCKET?: R2Bucket;
  readonly OPS_ALERT_WEBHOOK_URL?: string | SecretsStoreSecret;
}

type DoServices = ChainStore | DataStore | AuditStore | ServerKey | StorageMeter;

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
  readonly #opLock = Semaphore.makeUnsafe(1);
  readonly #stateCache: StateCache = { current: null, chain: null };
  readonly #leaseChainGrants = new LeaseChainGrants();
  #initialized: boolean;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.#initialized = projectDoInitialized(ctx.storage.sql);
    if (this.#initialized) {
      ensureProjectDoTables(ctx.storage);
    }
    this.#runtime = ManagedRuntime.make(
      Layer.mergeAll(
        chainStoreLayer(ctx.storage.sql, this.#stateCache),
        dataStoreLayer(ctx.storage.sql),
        auditStoreLayer(ctx.storage.sql),
        storageMeterLayer(ctx.storage.sql),
        Layer.effect(ServerKey, makeServerKeyFromEnv(env.SERVER_ENC_KEY_IKM)),
        ServerLoggerLive,
      ),
    );
  }

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

  #runData<T>(program: Effect.Effect<T, DataRejectedError, DoServices>): Promise<DataOutcome<T>> {
    if (!this.#latchInitialized()) {
      return Promise.resolve({ kind: "rejected", rejection: { kind: "not-initialized" } });
    }
    return this.#runtime.runPromise(
      this.#opLock.withPermit(this.#invalidateCachesOnDefect(toDataOutcome(program))),
    );
  }

  #ensureWritable(): Effect.Effect<void, DataRejectedError> {
    const sql = this.ctx.storage.sql;
    return Effect.suspend(() =>
      readMirrorState(sql) === null ? Effect.void : rejectData({ kind: "mirror-read-only" }),
    );
  }

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

  init(
    expectedProjectId: string,
    entry: ChainEntry,
    admission: InitAdmission,
  ): Promise<InitOutcome> {
    return this.#runtime.runPromise(
      this.#opLock.withPermit(
        this.#invalidateCachesOnDefect(
          initProgram(expectedProjectId, entry, admission, this.ctx.storage, this.#stateCache).pipe(
            Effect.map((head): InitOutcome => {
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

  snapshotFor(callerUserId: UserId): Promise<SnapshotOutcome> {
    return this.#runData(snapshotProgram(callerUserId, this.#stateCache));
  }

  putHeadAttestation(
    callerUserId: UserId,
    input: HeadAttestationSubmissionInput,
  ): Promise<DataOutcome<void>> {
    return this.#runWrite(
      callerUserId,
      putHeadAttestationProgram(callerUserId, input, this.#stateCache),
    );
  }

  memberRoleFor(callerUserId: UserId): Promise<DataOutcome<Role>> {
    return this.#runData(memberRoleProgram(callerUserId, this.#stateCache));
  }

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
    return this.#runWrite(
      actor.userId,
      createEnvironmentCompositeProgram(actor, input, this.#stateCache),
    );
  }

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

  deleteEnvironment(
    actor: DataActor,
    environmentId: EnvironmentId,
    input: {
      readonly parentHeadHashHex: string;
      readonly entry: ChainEntry & { readonly op: "delete_environment" };
    },
  ): Promise<DataOutcome<void>> {
    return this.#runWrite(
      actor.userId,
      deleteEnvironmentCompositeProgram(actor, environmentId, input, this.#stateCache),
    );
  }

  listEnvironments(actor: DataActor): Promise<DataOutcome<EnvironmentListValue>> {
    return this.#runData(listEnvironmentsProgram(actor, this.#stateCache));
  }

  createVariable(
    actor: DataActor,
    environmentId: EnvironmentId,
    input: {
      readonly variableId: VariableId;
      readonly statement: MetaStatementInput;
      readonly value?: ValueInput;
      readonly manifest: EnvManifestInput;
    },
  ): Promise<DataOutcome<VariableVersionValue>> {
    return this.#runWrite(
      actor.userId,
      createVariableProgram(actor, environmentId, input, this.#stateCache),
    );
  }

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
    return this.#runWrite(
      actor.userId,
      activateVariableProgram(actor, environmentId, variableId, input, this.#stateCache),
    );
  }

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

  variableHistory(
    actor: DataActor,
    environmentId: EnvironmentId,
    variableId: VariableId,
  ): Promise<DataOutcome<VariableVersionHistoryValue>> {
    return this.#runData(
      variableHistoryProgram(actor, environmentId, variableId, this.#stateCache),
    );
  }

  variableVersionValues(
    actor: DataActor,
    environmentId: EnvironmentId,
    variableId: VariableId,
    fromVersion: number,
  ): Promise<DataOutcome<VariableVersionValuesValue>> {
    return this.#runData(
      variableVersionValuesProgram(actor, environmentId, variableId, fromVersion, this.#stateCache),
    );
  }

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

  pullEnvironment(
    actor: DataActor,
    environmentId: EnvironmentId,
  ): Promise<DataOutcome<EnvironmentPullValue>> {
    return this.#runData(pullEnvironmentProgram(actor, environmentId, this.#stateCache));
  }

  pullEnvironmentMetadata(
    actor: DataActor,
    environmentId: EnvironmentId,
  ): Promise<DataOutcome<EnvironmentMetadataPullValue>> {
    return this.#runData(pullEnvironmentMetadataProgram(actor, environmentId, this.#stateCache));
  }

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

  listMyDekWraps(
    actor: DataActor,
    environmentId: EnvironmentId,
  ): Promise<DataOutcome<readonly RecipientDekValue[]>> {
    return this.#runData(listMyDekWrapsProgram(actor, environmentId, this.#stateCache));
  }

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

  schemaPolicyFor(actor: DataActor): Promise<DataOutcome<{ readonly schemaPolicy: SchemaPolicy }>> {
    return this.#runData(getSchemaPolicyProgram(actor, this.#stateCache));
  }

  setSchemaPolicy(actor: DataActor, schemaPolicy: SchemaPolicy): Promise<DataOutcome<void>> {
    return this.#runWrite(
      actor.userId,
      setSchemaPolicyProgram(actor, schemaPolicy, this.#stateCache),
    );
  }

  rotationFlags(actor: DataActor): Promise<DataOutcome<readonly EffectiveRotationFlag[]>> {
    return this.#runData(rotationFlagsProgram(actor, this.#stateCache));
  }

  dismissRotationFlags(
    actor: DataActor,
    targets: readonly RotationDismissTargetInput[],
  ): Promise<DataOutcome<void>> {
    return this.#runWrite(
      actor.userId,
      dismissRotationFlagsProgram(actor, targets, this.#stateCache),
    );
  }

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

  listRotationProposals(actor: DataActor): Promise<DataOutcome<readonly MemberProposalValue[]>> {
    return this.#runData(listRotationProposalsProgram(actor, this.#stateCache));
  }

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

  exportMembers(actor: DataActor): Promise<DataOutcome<ExportMembersValue>> {
    return this.#runData(exportMembersProgram(actor, this.#stateCache));
  }

  mirrorStatus(actor: DataActor): Promise<DataOutcome<MirrorStatusValue>> {
    return this.#runData(mirrorStatusProgram(actor, this.ctx.storage.sql, this.#stateCache));
  }

  markMirror(actor: DataActor, sourceOrigin: string): Promise<DataOutcome<MirrorStatusValue>> {
    return this.#runData(
      markMirrorProgram(actor, sourceOrigin, this.ctx.storage, this.#stateCache),
    );
  }

  unmarkMirror(actor: DataActor): Promise<DataOutcome<MirrorStatusValue>> {
    return this.#runData(unmarkMirrorProgram(actor, this.ctx.storage, this.#stateCache));
  }

  mirrorPage(actor: DataActor, page: MirrorPageRequest): Promise<DataOutcome<MirrorPageValue>> {
    return this.#runData(mirrorPageProgram(actor, page, this.ctx.storage, this.#stateCache));
  }

  auditEvents(
    actor: DataActor,
    query: AuditEventsQueryInput,
  ): Promise<DataOutcome<readonly AuditEventValue[]>> {
    return this.#runData(auditEventsProgram(actor, query, this.#stateCache));
  }

  auditHeadFor(actor: DataActor): Promise<DataOutcome<{ readonly auditHeadHashHex: string }>> {
    return this.#runData(auditHeadProgram(actor, this.#stateCache));
  }

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

  leaseChain(chainToken: string): Promise<readonly ChainEntry[]> {
    return this.#runtime.runPromise(
      this.#opLock.withPermit(
        Effect.flatMap(Clock.currentTimeMillis, (nowMs) => {
          const head = this.#leaseChainGrants.take(chainToken, nowMs);
          return head === undefined
            ? Effect.die(new Error("unknown, spent or expired lease chain token"))
            : this.#invalidateCachesOnDefect(leaseChainProgram(head, this.#stateCache));
        }),
      ),
    );
  }

  opsBackup(input: OpsBackupInput): Promise<OpsBackupOutcome> {
    const bucket = this.env.OPS_BACKUP_BUCKET;
    if (bucket === undefined) {
      return Promise.resolve({ kind: "no-bucket" });
    }
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
        this.#latchInitialized();
      });
  }
}
