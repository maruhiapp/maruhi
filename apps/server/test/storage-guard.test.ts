import {
  auditGroup,
  DataLimitExceededError,
  deksGroup,
  environmentsGroup,
  membershipGroup,
  schemaPolicyGroup,
  variablesGroup,
} from "@maruhi/api-schema";
import type { ChainEntry } from "@maruhi/crypto";
import { testKeyFingerprintHex, testUserId, testVariableId } from "@maruhi/crypto/test-support";
import { addMemberOp, signEntryAt, testEnvironmentId, testProjectId } from "@maruhi/test-kit";
import { env, runInDurableObject } from "cloudflare:test";
import { Cause, Effect, Exit, Layer, Redacted } from "effect";
import type { HttpApiEndpoint } from "effect/http-api";
import { describe, expect, it, vi } from "vite-plus/test";

import { putHeadAttestationProgram } from "../src/attestation-accept.ts";
import {
  AuditStore,
  auditStoreLayer,
  deriveAuditHeads,
  makeAuditStore,
} from "../src/audit-store.ts";
import type { DataActor, DataRejection, DataStore } from "../src/data.package/index.ts";
import {
  dataStoreLayer,
  toManifestInput,
  toMetaStatementInput,
  toValueInput,
  unwrapDataOutcome,
} from "../src/data.package/index.ts";
import type { ChainStore, StateCache } from "../src/do/chain-store.ts";
import { chainStoreLayer } from "../src/do/chain-store.ts";
import { restoreProgram } from "../src/do/do-ops.ts";
import { DO_STORAGE_REJECT_BYTES, DO_STORAGE_WARN_BYTES } from "../src/policy.ts";
import {
  createEnvironmentCompositeProgram,
  deleteEnvironmentCompositeProgram,
  rotateEpochCompositeProgram,
} from "../src/programs/composite-programs.ts";
import { auditHeadProgram } from "../src/programs/programs-audit.ts";
import { appendProgram, snapshotProgram } from "../src/programs/programs-chain.ts";
import {
  deleteDekWrapsProgram,
  listMyDekWrapsProgram,
  registerDekWrapsProgram,
} from "../src/programs/programs-dek.ts";
import {
  listEnvironmentsProgram,
  pullEnvironmentMetadataProgram,
  pullEnvironmentProgram,
  renameEnvironmentProgram,
} from "../src/programs/programs-environment.ts";
import { exportPageProgram } from "../src/programs/programs-export.ts";
import { variableVersionValuesProgram } from "../src/programs/programs-history.ts";
import type { LeaseTokenFacts } from "../src/programs/programs-lease.ts";
import { leaseProgram } from "../src/programs/programs-lease.ts";
import type { RotationProposalInput } from "../src/programs/programs-proposal.ts";
import {
  listRotationProposalsProgram,
  preflightRotationProgram,
  proposeRotationProgram,
  resolveRotationProposalProgram,
} from "../src/programs/programs-proposal.ts";
import { dismissRotationFlagsProgram } from "../src/programs/programs-rotation.ts";
import {
  getSchemaPolicyProgram,
  setSchemaPolicyProgram,
} from "../src/programs/programs-schema-policy.ts";
import {
  activateVariableProgram,
  createVariableProgram,
  deleteVariableProgram,
  pushVersionProgram,
  renameVariableProgram,
} from "../src/programs/programs-variable.ts";
import { makeServerKey, ServerKey } from "../src/server-key.ts";
import { ServerLoggerLive } from "../src/server-logger.ts";
import { makeStorageMeter, StorageMeter, storageGuardDecision } from "../src/storage-guard.ts";
import { identityOf, vectorKeyOf } from "./support/data-crypto.ts";
import {
  appendOperation,
  createEnvironmentOk,
  MEMBER,
  OWNER,
  projectId,
  READER,
  seedMemberToken,
  STRANGER,
} from "./support/data-fixture.ts";
import {
  aadFor,
  createVariableOk,
  ENV,
  fixture,
  registerDataScenario,
  unsignedManifest,
  unsignedPayload,
  unsignedVariableStatement,
  VAR,
} from "./support/data-scenario.ts";
import {
  backfillServerWrap,
  grantServer as grantLeases,
  workloadKeyPair,
} from "./support/lease-scenario.ts";
import { LEASE_AUDIENCE, LEASE_SUBJECT } from "./support/lease.ts";
import { OIDC_ISSUER } from "./support/oidc-issuer.ts";
import { evictProjectDo, readAuditEvents, resetProjectDo } from "./support/project-do.ts";

registerDataScenario();

const actor = (userId: string): DataActor => ({ userId: testUserId(userId) });

type DoProgram<A, E> = Effect.Effect<
  A,
  E,
  ChainStore | DataStore | AuditStore | ServerKey | StorageMeter
>;
type Runner = <A, E>(program: DoProgram<A, E>) => Promise<Exit.Exit<A, E>>;

async function runInProject<A>(
  databaseSizeBytes: number | (() => number),
  body: (run: Runner, state: DurableObjectState) => Promise<A>,
  options: { readonly atFloor?: boolean; readonly headChunks?: number } = {},
): Promise<A> {
  const meter = makeStorageMeter(
    typeof databaseSizeBytes === "number" ? () => databaseSizeBytes : databaseSizeBytes,
  );
  const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));
  return await runInDurableObject(stub, async (_instance, state) => {
    const cache: StateCache = { current: null, chain: null };
    const full = () => {
      throw new Error(SQLITE_FULL);
    };
    const { headChunks } = options;
    const layers = Layer.mergeAll(
      chainStoreLayer(state.storage.sql, cache),
      dataStoreLayer(state.storage.sql),
      options.atFloor === true
        ? Layer.sync(AuditStore, () => ({
            ...makeAuditStore(state.storage.sql),
            appendSync: full,
            appendManySync: full,
          }))
        : headChunks === undefined
          ? auditStoreLayer(state.storage.sql)
          : Layer.sync(AuditStore, () =>
              makeAuditStore(state.storage.sql, { maxHeadExtensionChunks: headChunks }),
            ),
      Layer.succeed(StorageMeter, meter),
      Layer.sync(ServerKey, () => makeServerKey(Redacted.make(env.SERVER_ENC_KEY_IKM ?? ""))),
      ServerLoggerLive,
    );
    const run: Runner = (program) => Effect.runPromiseExit(program.pipe(Effect.provide(layers)));
    return await body(run, state);
  });
}

const SQLITE_FULL = "SQLITE_FULL: database or disk is full";

const workloadFacts = (): LeaseTokenFacts => ({
  issuer: OIDC_ISSUER,
  subject: LEASE_SUBJECT,
  audiences: [LEASE_AUDIENCE],
  claims: { sub: LEASE_SUBJECT },
  claimsDigestHex: "00".repeat(32),
  bindingKeyHex: "11".repeat(32),
  bindingExpiresAtMs: Date.now() + 300_000,
});

function rejectionOf(exit: Exit.Exit<unknown, unknown>): DataRejection | null {
  if (Exit.isSuccess(exit)) {
    return null;
  }
  const error = Cause.squash(exit.cause) as { rejection?: DataRejection };
  return error.rejection ?? null;
}

const STORAGE_REJECTION: DataRejection = {
  kind: "limit-exceeded",
  resource: "project-storage-bytes",
  limit: DO_STORAGE_REJECT_BYTES,
};

const dummyValueInput = (version: number) =>
  toValueInput({ ...unsignedPayload(aadFor(1, version)), suite: "maruhi/v1" });
const dummyVariableStatement = (variableId: string, name: string) =>
  toMetaStatementInput({ ...unsignedVariableStatement(variableId, name), suite: "maruhi/v1" });
const dummyManifest = () =>
  toManifestInput({ ...unsignedManifest(), environmentId: testEnvironmentId(ENV) });
const dummyEnvStatement = (name: string, status: "active" = "active") =>
  toMetaStatementInput({
    suite: "maruhi/v1",
    name,
    status,
    metaVersion: 2,
    prevMetaSigHashHex: "ab".repeat(32),
    chainHeadHashHex: fixture.head.hashHex,
    chainHeadSeq: fixture.head.seq,
    signatureHex: "00".repeat(64),
  });
const dummyWrap = {
  suite: "maruhi/v1" as const,
  epoch: 1,
  recipientClass: "member" as const,
  recipientUserId: STRANGER,
  recipientEncPubHex: "ab".repeat(32),
  encHex: "cd".repeat(32),
  ciphertextHex: "ef".repeat(48),
  signatureHex: "00".repeat(64),
};

const signedEntry = (operation: Parameters<typeof signEntryAt>[0]["operation"]) =>
  signEntryAt({
    seq: fixture.head.seq + 1,
    prevHashHex: fixture.head.hashHex,
    actor: identityOf(OWNER),
    operation,
  });

describe("storageGuardDecision (pure function — §12-8's two thresholds)", () => {
  it("admits below the warning threshold, warns from it, rejects from the rejection threshold", () => {
    expect(storageGuardDecision(0)).toBe("admit");
    expect(storageGuardDecision(DO_STORAGE_WARN_BYTES - 1)).toBe("admit");
    expect(storageGuardDecision(DO_STORAGE_WARN_BYTES)).toBe("warn");
    expect(storageGuardDecision(DO_STORAGE_REJECT_BYTES - 1)).toBe("warn");
    expect(storageGuardDecision(DO_STORAGE_REJECT_BYTES)).toBe("reject");
    expect(storageGuardDecision(10_000_000_000)).toBe("reject");
  });

  it("keeps the rejection threshold under the 10 GB platform floor in either unit", () => {
    expect(DO_STORAGE_REJECT_BYTES).toBeLessThan(10_000_000_000);
    expect(DO_STORAGE_REJECT_BYTES).toBeLessThan(10 * 1024 ** 3);
    expect(DO_STORAGE_WARN_BYTES).toBeLessThan(DO_STORAGE_REJECT_BYTES);
  });

  it("takes thresholds as parameters (self-hosted adjustment surface)", () => {
    expect(storageGuardDecision(50, { warnBytes: 40, rejectBytes: 60 })).toBe("warn");
    expect(storageGuardDecision(60, { warnBytes: 40, rejectBytes: 60 })).toBe("reject");
  });
});

describe("error contract — every endpoint on a rejection-effective surface declares 422 DataLimitExceeded", () => {
  it("maps project-storage-bytes within the contract (never a 500) on every guarded surface", () => {
    const guarded = {
      "variables.create": variablesGroup.endpoints.create,
      "variables.push": variablesGroup.endpoints.push,
      "variables.activate": variablesGroup.endpoints.activate,
      "variables.rename": variablesGroup.endpoints.rename,
      "environments.create": environmentsGroup.endpoints.create,
      "environments.rename": environmentsGroup.endpoints.rename,
      "deks.register": deksGroup.endpoints.register,
      "membership.append": membershipGroup.endpoints.append,
      "schemaPolicy.set": schemaPolicyGroup.endpoints.set,
      "audit.auditHead": auditGroup.endpoints.auditHead,
      "environments.rotate": environmentsGroup.endpoints.rotate,
    };
    for (const [label, endpoint] of Object.entries(guarded)) {
      const error = Effect.runSync(
        Effect.flip(
          unwrapDataOutcome(
            { kind: "rejected", rejection: STORAGE_REJECTION },
            testProjectId(projectId),
            endpoint as HttpApiEndpoint.Top,
          ),
        ),
      );
      expect(error, label).toBeInstanceOf(DataLimitExceededError);
      expect(error, label).toMatchObject({
        resource: "project-storage-bytes",
        limit: DO_STORAGE_REJECT_BYTES,
      });
    }
  });
});

describe("acceptance-path wiring — a DO at or above the rejection threshold (§12-8)", () => {
  it("rejects every content-growth surface with limit-exceeded project-storage-bytes", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const addMember = await signedEntry({
      op: "add_member",
      payload: {
        targetUserId: STRANGER,
        encPubHex: "ab".repeat(32),
        sigPubHex: "cd".repeat(32),
        role: "member",
        scopeKind: "all",
        scopeEnvironmentIds: [],
      },
    });
    const grantServer = await signedEntry({
      op: "grant_server",
      payload: {
        serverEncPubHex: "ab".repeat(32),
        serverKeyFingerprintHex: testKeyFingerprintHex("cd".repeat(16)),
        scopeEnvironmentIds: [testEnvironmentId(ENV)],
        leasePolicy: [],
      },
    });
    const createEnv = await signedEntry({
      op: "create_environment",
      payload: { environmentId: testEnvironmentId("env-new"), dekCommitmentHex: "ab".repeat(32) },
    });
    const checkpoint = await signedEntry({
      op: "checkpoint",
      payload: { environments: [], auditHeadHashHex: "" },
    });
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await runInProject(DO_STORAGE_REJECT_BYTES, async (run) => {
        const cache: StateCache = { current: null, chain: null };
        const outcomes = {
          push: rejectionOf(
            await run(
              pushVersionProgram(
                actor(OWNER),
                testEnvironmentId(ENV),
                VAR,
                dummyValueInput(2),
                undefined,
                cache,
              ),
            ),
          ),
          lineagePush: rejectionOf(
            await run(
              pushVersionProgram(
                actor(OWNER),
                testEnvironmentId(ENV),
                VAR,
                dummyValueInput(2),
                1,
                cache,
              ),
            ),
          ),
          createVariable: rejectionOf(
            await run(
              createVariableProgram(
                actor(OWNER),
                testEnvironmentId(ENV),
                {
                  variableId: testVariableId("var-new"),
                  statement: dummyVariableStatement("var-new", "NEW"),
                  value: dummyValueInput(1),
                  manifest: dummyManifest(),
                },
                cache,
              ),
            ),
          ),
          declareVariable: rejectionOf(
            await run(
              createVariableProgram(
                actor(OWNER),
                testEnvironmentId(ENV),
                {
                  variableId: testVariableId("var-declared"),
                  statement: dummyVariableStatement("var-declared", "DECLARED"),
                  manifest: dummyManifest(),
                },
                cache,
              ),
            ),
          ),
          activate: rejectionOf(
            await run(
              activateVariableProgram(
                actor(OWNER),
                testEnvironmentId(ENV),
                VAR,
                {
                  value: dummyValueInput(1),
                  statement: dummyVariableStatement(VAR, "DATABASE_URL"),
                  manifest: dummyManifest(),
                },
                cache,
              ),
            ),
          ),
          renameVariable: rejectionOf(
            await run(
              renameVariableProgram(
                actor(OWNER),
                testEnvironmentId(ENV),
                VAR,
                dummyVariableStatement(VAR, "RENAMED"),
                dummyManifest(),
                cache,
              ),
            ),
          ),
          renameEnvironment: rejectionOf(
            await run(
              renameEnvironmentProgram(
                actor(OWNER),
                testEnvironmentId(ENV),
                dummyEnvStatement("Renamed"),
                dummyManifest(),
                cache,
              ),
            ),
          ),
          registerWraps: rejectionOf(
            await run(
              registerDekWrapsProgram(actor(OWNER), testEnvironmentId(ENV), [dummyWrap], cache),
            ),
          ),
          createEnvironment: rejectionOf(
            await run(
              createEnvironmentCompositeProgram(
                actor(OWNER),
                {
                  parentHeadHashHex: fixture.head.hashHex,
                  entry: createEnv.entry as ChainEntry & { readonly op: "create_environment" },
                  statement: dummyEnvStatement("New"),
                  deks: [],
                  manifest: dummyManifest(),
                  checkpoint: checkpoint.entry as ChainEntry & { readonly op: "checkpoint" },
                },
                cache,
              ),
            ),
          ),
          addMember: rejectionOf(
            await run(appendProgram(fixture.head.hashHex, addMember.entry, OWNER, cache)),
          ),
          grantServer: rejectionOf(
            await run(appendProgram(fixture.head.hashHex, grantServer.entry, OWNER, cache)),
          ),
          setSchemaPolicy: rejectionOf(
            await run(setSchemaPolicyProgram(actor(OWNER), "enabled", cache)),
          ),
        };
        for (const [surface, rejection] of Object.entries(outcomes)) {
          expect(rejection, surface).toEqual(STORAGE_REJECTION);
        }
      });
      expect(errorSpy).toHaveBeenCalledTimes(1);
      const [message] = errorSpy.mock.calls[0] ?? [];
      expect(typeof message).toBe("string");
      expect(message).not.toContain(projectId);
      expect(message).not.toContain(OWNER);
    } finally {
      errorSpy.mockRestore();
    }
    const versions = await runInProject(0, async (run) => {
      const pulled = await run(
        pullEnvironmentProgram(actor(READER), testEnvironmentId(ENV), {
          current: null,
          chain: null,
        }),
      );
      return Exit.isSuccess(pulled) ? pulled.value.variables.map((v) => v.version) : null;
    });
    expect(versions).toEqual([1]);
  });

  it("guards the four-eyes path at the entry that first carries the growth intent (propose / approve of add_member or grant_server) and leaves remove / withdraw open", async () => {
    await seedMemberToken(fixture, "user-owner-0014", 9014);
    await appendOperation(fixture, OWNER, addMemberOp(identityOf("user-owner-0014"), "owner"));
    await appendOperation(fixture, OWNER, {
      op: "set_approval_policy",
      payload: { ops: ["add_member", "grant_server", "remove_member"], requiredApprovals: 2 },
    });
    const addStranger = {
      op: "add_member" as const,
      payload: {
        targetUserId: STRANGER,
        encPubHex: "ab".repeat(32),
        sigPubHex: "cd".repeat(32),
        role: "member" as const,
        scopeKind: "all" as const,
        scopeEnvironmentIds: [],
      },
    };
    const expiresAtMs = Date.now() + 7 * 24 * 60 * 60 * 1000;
    await appendOperation(fixture, OWNER, {
      op: "propose",
      payload: { inner: addStranger, expiresAtMs },
    });
    const pendingAddHash = fixture.head.hashHex;

    const proposeAdd = await signedEntry({
      op: "propose",
      payload: { inner: addStranger, expiresAtMs },
    });
    const proposeGrant = await signedEntry({
      op: "propose",
      payload: {
        inner: {
          op: "grant_server",
          payload: {
            serverEncPubHex: "ab".repeat(32),
            serverKeyFingerprintHex: testKeyFingerprintHex("cd".repeat(16)),
            scopeEnvironmentIds: [],
            leasePolicy: [],
          },
        },
        expiresAtMs,
      },
    });
    const approveAdd = await signedEntry({
      op: "approve",
      payload: { proposalHashHex: pendingAddHash },
    });
    const proposeRemove = await signedEntry({
      op: "propose",
      payload: { inner: { op: "remove_member", payload: { targetUserId: READER } }, expiresAtMs },
    });
    const withdrawAdd = await signedEntry({
      op: "withdraw",
      payload: { proposalHashHex: pendingAddHash },
    });
    await runInProject(DO_STORAGE_REJECT_BYTES, async (run) => {
      const cache: StateCache = { current: null, chain: null };
      const rejected = {
        proposeAddMember: rejectionOf(
          await run(appendProgram(fixture.head.hashHex, proposeAdd.entry, OWNER, cache)),
        ),
        proposeGrantServer: rejectionOf(
          await run(appendProgram(fixture.head.hashHex, proposeGrant.entry, OWNER, cache)),
        ),
        approveOfPendingAddMember: rejectionOf(
          await run(appendProgram(fixture.head.hashHex, approveAdd.entry, OWNER, cache)),
        ),
      };
      for (const [surface, rejection] of Object.entries(rejected)) {
        expect(rejection, surface).toEqual(STORAGE_REJECTION);
      }
      const removeProposed = await run(
        appendProgram(fixture.head.hashHex, proposeRemove.entry, OWNER, cache),
      );
      expect(rejectionOf(removeProposed)).toBeNull();
      if (!Exit.isSuccess(removeProposed)) throw new Error("unreachable");
      const resigned = await signEntryAt({
        seq: removeProposed.value.headSeq + 1,
        prevHashHex: removeProposed.value.headHashHex,
        actor: identityOf(OWNER),
        operation: withdrawAdd.entry,
      });
      expect(
        rejectionOf(
          await run(appendProgram(removeProposed.value.headHashHex, resigned.entry, OWNER, cache)),
        ),
      ).toBeNull();
    });
  });

  it("keeps reads, deletions, revocations, rotation, attestation, checkpoint and settings open", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const staleParent = "00".repeat(32);
    const removeMember = await signedEntry({
      op: "remove_member",
      payload: { targetUserId: READER },
    });
    const changeRole = await signedEntry({
      op: "change_role",
      payload: {
        targetUserId: READER,
        newRole: "member",
        scopeKind: "all",
        scopeEnvironmentIds: [],
      },
    });
    const revokeServer = await signedEntry({
      op: "revoke_server",
      payload: { serverKeyFingerprintHex: testKeyFingerprintHex("cd".repeat(16)) },
    });
    const checkpoint = await signedEntry({
      op: "checkpoint",
      payload: { environments: [], auditHeadHashHex: "" },
    });
    const deleteEnv = await signEntryAt({
      seq: fixture.head.seq + 1,
      prevHashHex: staleParent,
      actor: identityOf(OWNER),
      operation: {
        op: "delete_environment",
        payload: { environmentId: testEnvironmentId(ENV) },
      },
    });
    const rotate = await signedEntry({
      op: "rotate_epoch",
      payload: {
        environmentId: testEnvironmentId("env-other"),
        newEpoch: 2,
        reason: "scheduled",
        dekCommitmentHex: "ab".repeat(32),
      },
    });
    await runInProject(DO_STORAGE_REJECT_BYTES, async (run) => {
      const cache: StateCache = { current: null, chain: null };
      const pulled = await run(
        pullEnvironmentProgram(actor(READER), testEnvironmentId(ENV), cache),
      );
      expect(Exit.isSuccess(pulled)).toBe(true);
      expect(
        Exit.isSuccess(
          await run(pullEnvironmentMetadataProgram(actor(READER), testEnvironmentId(ENV), cache)),
        ),
      ).toBe(true);
      expect(Exit.isSuccess(await run(listEnvironmentsProgram(actor(READER), cache)))).toBe(true);
      expect(Exit.isSuccess(await run(snapshotProgram(READER, cache)))).toBe(true);
      expect(
        Exit.isSuccess(
          await run(listMyDekWrapsProgram(actor(READER), testEnvironmentId(ENV), cache)),
        ),
      ).toBe(true);
      expect(
        rejectionOf(
          await run(
            deleteVariableProgram(
              actor(OWNER),
              testEnvironmentId(ENV),
              VAR,
              dummyVariableStatement(VAR, "WRONG_NAME"),
              dummyManifest(),
              cache,
            ),
          ),
        ),
      ).toEqual({ kind: "meta-version-conflict", currentMetaVersion: 1 });
      expect(
        rejectionOf(
          await run(
            deleteEnvironmentCompositeProgram(
              actor(OWNER),
              testEnvironmentId(ENV),
              {
                parentHeadHashHex: staleParent,
                entry: deleteEnv.entry as ChainEntry & { readonly op: "delete_environment" },
              },
              cache,
            ),
          ),
        )?.kind,
      ).toBe("chain-head-conflict");
      expect(
        rejectionOf(
          await run(
            deleteDekWrapsProgram(
              actor(OWNER),
              testEnvironmentId(ENV),
              [
                {
                  epoch: 7,
                  recipientClass: "member",
                  recipientUserId: STRANGER,
                  recipientEncPubHex: "ab".repeat(32),
                },
              ],
              cache,
            ),
          ),
        ),
      ).toEqual({ kind: "dek-wrap-not-found", epoch: 7, recipientUserId: STRANGER });
      for (const entry of [
        removeMember.entry,
        changeRole.entry,
        revokeServer.entry,
        checkpoint.entry,
      ]) {
        const rejection = rejectionOf(await run(appendProgram(staleParent, entry, OWNER, cache)));
        expect(rejection?.kind, entry.op).toBe("chain-head-conflict");
      }
      expect(
        rejectionOf(
          await run(
            rotateEpochCompositeProgram(
              actor(OWNER),
              testEnvironmentId(ENV),
              {
                parentHeadHashHex: fixture.head.hashHex,
                entry: rotate.entry as ChainEntry & { readonly op: "rotate_epoch" },
                deks: [],
                manifest: dummyManifest(),
                checkpoint: checkpoint.entry as ChainEntry & { readonly op: "checkpoint" },
              },
              cache,
            ),
          ),
        ),
      ).toEqual({ kind: "payload-mismatch", field: "environmentId" });
      expect(
        rejectionOf(
          await run(
            putHeadAttestationProgram(
              OWNER,
              {
                suite: "maruhi/v1",
                chainHeadHashHex: fixture.head.hashHex,
                chainHeadSeq: fixture.head.seq,
                signatureHex: "00".repeat(64),
              },
              cache,
            ),
          ),
        )?.kind,
      ).toBe("attestation-rejected");
      expect(Exit.isSuccess(await run(dismissRotationFlagsProgram(actor(OWNER), [], cache)))).toBe(
        true,
      );
      expect(Exit.isSuccess(await run(getSchemaPolicyProgram(actor(READER), cache)))).toBe(true);
      const removed = await run(
        appendProgram(fixture.head.hashHex, removeMember.entry, OWNER, cache),
      );
      expect(Exit.isSuccess(removed)).toBe(true);
      const snapshot = await run(snapshotProgram(OWNER, cache));
      expect(Exit.isSuccess(snapshot) && snapshot.value.headSeq).toBe(fixture.head.seq + 1);
    });
  });
});

describe("sealed value proposals (§12-8 / §14-5 — the mint is a growth surface, the closing paths are bounded)", () => {
  const ephemeralPubHex = "ab".repeat(32);
  const writers = [OWNER, MEMBER].map((userId) => ({
    userId,
    encPubHex: vectorKeyOf(userId).enc_pub_hex,
  }));
  const proposal: RotationProposalInput = {
    proposalId: "00112233445566778899aabbccddeeff",
    connector: "exec",
    facts: [],
    expiresInDays: 7,
    variables: [
      {
        variableId: VAR,
        baseVersion: 1,
        wraps: writers.map((writer) => ({
          recipientUserId: writer.userId,
          recipientEncPubHex: writer.encPubHex,
          encHex: "cd".repeat(32),
          ciphertextHex: "ef".repeat(48),
        })),
      },
    ],
  };
  const preflight = (baseVersion: number, cache: StateCache, facts = workloadFacts()) =>
    preflightRotationProgram(
      testEnvironmentId(ENV),
      ephemeralPubHex,
      facts,
      [{ variableId: VAR, baseVersion }],
      cache,
      writers,
    );
  const mint = (cache: StateCache, facts = workloadFacts()) =>
    proposeRotationProgram(testEnvironmentId(ENV), ephemeralPubHex, facts, proposal, cache);
  const failureOf = (exit: Exit.Exit<unknown, unknown>) =>
    Exit.isSuccess(exit) ? null : Cause.squash(exit.cause);
  const STORAGE_LIMIT = { kind: "proposal-rejected", reason: "storage-limit" };

  it("refuses the mint and its pre-flight with storage-limit before every other check, and keeps the stored proposals' list and resolution open", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await grantLeases({ scope: [ENV] });
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      await runInProject(DO_STORAGE_REJECT_BYTES, async (run) => {
        const cache: StateCache = { current: null, chain: null };
        expect(failureOf(await run(preflight(1, cache)))).toEqual(STORAGE_LIMIT);
        expect(failureOf(await run(preflight(5, cache)))).toEqual(STORAGE_LIMIT);
        expect(failureOf(await run(mint(cache)))).toEqual(STORAGE_LIMIT);
      });
      const events = (await readAuditEvents(projectId)).map((event) => event["event"]);
      expect(events).not.toContain("rotation.proposed");
      await runInProject(DO_STORAGE_WARN_BYTES, async (run) => {
        const cache: StateCache = { current: null, chain: null };
        expect(Exit.isSuccess(await run(preflight(1, cache)))).toBe(true);
        expect(Exit.isSuccess(await run(mint(cache)))).toBe(true);
      });
      expect(warnSpy).toHaveBeenCalledTimes(1);
      await runInProject(DO_STORAGE_REJECT_BYTES, async (run) => {
        const cache: StateCache = { current: null, chain: null };
        const listed = await run(listRotationProposalsProgram(actor(OWNER), cache));
        expect(Exit.isSuccess(listed) && listed.value.map((p) => p.proposalId)).toEqual([
          proposal.proposalId,
        ]);
        expect(
          Exit.isSuccess(
            await run(
              resolveRotationProposalProgram(
                actor(OWNER),
                proposal.proposalId,
                { outcome: "rejected", versions: [] },
                cache,
              ),
            ),
          ),
        ).toBe(true);
      });
    } finally {
      errorSpy.mockRestore();
      warnSpy.mockRestore();
    }
  });

  it("answers a caller no lease policy matches with the uniform 404 even in the refusal band, and a refused mint does not sweep", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await grantLeases({ scope: [ENV] });
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await runInProject(0, async (run, state) => {
        expect(Exit.isSuccess(await run(mint({ current: null, chain: null })))).toBe(true);
        state.storage.sql.exec("UPDATE rotation_proposals SET expires_at = 1");
      });
      const stranger = { ...workloadFacts(), claims: { sub: "repo:someone-else/app:ref:main" } };
      await runInProject(DO_STORAGE_REJECT_BYTES, async (run, state) => {
        const cache: StateCache = { current: null, chain: null };
        expect(failureOf(await run(preflight(1, cache, stranger)))).toEqual({ kind: "not-found" });
        expect(failureOf(await run(mint(cache, stranger)))).toEqual({ kind: "not-found" });
        expect(failureOf(await run(preflight(1, cache)))).toEqual(STORAGE_LIMIT);
        expect(failureOf(await run(mint(cache)))).toEqual(STORAGE_LIMIT);
        expect(
          state.storage.sql.exec("SELECT COUNT(*) AS n FROM rotation_proposals").one()["n"],
        ).toBe(1);
      });
      const events = (await readAuditEvents(projectId)).map((event) => event["event"]);
      expect(events).not.toContain("rotation.proposal_expired");
    } finally {
      errorSpy.mockRestore();
    }
  });
});

describe("the audit-writing reads (§12-8 (a)(e) — open in the rejection band, refused at the floor)", () => {
  it("serves the with-values pull, the version value range, the lease and the export under rejection, and fails each with its audit append at the floor", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await grantLeases({ scope: [ENV] });
    await backfillServerWrap(1, dek);
    const workload = await workloadKeyPair();
    const reads = async (atFloor: boolean) =>
      await runInProject(
        DO_STORAGE_REJECT_BYTES,
        async (run, state) => {
          const cache: StateCache = { current: null, chain: null };
          return {
            pull: await run(pullEnvironmentProgram(actor(READER), testEnvironmentId(ENV), cache)),
            versionValues: await run(
              variableVersionValuesProgram(actor(READER), testEnvironmentId(ENV), VAR, 1, cache),
            ),
            lease: await run(
              leaseProgram(testEnvironmentId(ENV), workload.publicKeyHex, workloadFacts(), cache),
            ),
            export: await run(
              exportPageProgram(actor(OWNER), null, state.storage.sql, state.id.toString(), cache),
            ),
          };
        },
        { atFloor },
      );
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      for (const [read, exit] of Object.entries<Exit.Exit<unknown, unknown>>(await reads(false))) {
        expect(Exit.isSuccess(exit), read).toBe(true);
      }
      for (const [read, exit] of Object.entries<Exit.Exit<unknown, unknown>>(await reads(true))) {
        expect(Exit.isSuccess(exit), read).toBe(false);
        if (Exit.isFailure(exit)) {
          expect(String(Cause.squash(exit.cause)), read).toContain(SQLITE_FULL);
        }
      }
    } finally {
      errorSpy.mockRestore();
    }
  });
});

describe("materializing the audit-head derived column (the §12-8 (a) exception — AUDIT_SPEC §5.1's lazy materialization)", () => {
  it("rejects the audit-head read only while the derived column lags behind the audit log", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await runInProject(DO_STORAGE_REJECT_BYTES, async (run) => {
        const cache: StateCache = { current: null, chain: null };
        expect(rejectionOf(await run(auditHeadProgram(actor(OWNER), cache)))).toEqual(
          STORAGE_REJECTION,
        );
        const notarizing = await signedEntry({
          op: "checkpoint",
          payload: { environments: [], auditHeadHashHex: "ab".repeat(32) },
        });
        expect(
          rejectionOf(
            await run(appendProgram(fixture.head.hashHex, notarizing.entry, OWNER, cache)),
          ),
        ).toEqual(STORAGE_REJECTION);
      });
      const materialized = await runInProject(0, async (run) =>
        Exit.isSuccess(await run(auditHeadProgram(actor(OWNER), { current: null, chain: null }))),
      );
      expect(materialized).toBe(true);
      const current = await runInProject(DO_STORAGE_REJECT_BYTES, async (run) =>
        Exit.isSuccess(await run(auditHeadProgram(actor(OWNER), { current: null, chain: null }))),
      );
      expect(current).toBe(true);
      await runInProject(DO_STORAGE_REJECT_BYTES, async (run) => {
        const cache: StateCache = { current: null, chain: null };
        expect(
          Exit.isSuccess(
            await run(pullEnvironmentProgram(actor(READER), testEnvironmentId(ENV), cache)),
          ),
        ).toBe(true);
        expect(rejectionOf(await run(auditHeadProgram(actor(OWNER), cache)))).toEqual(
          STORAGE_REJECTION,
        );
      });
    } finally {
      errorSpy.mockRestore();
    }
  });
});

describe("no audit-head materialization at or above the rejection threshold (§12-8 — the export §11-6, the restore §11-7)", () => {
  const count = (state: DurableObjectState, table: string) =>
    Number(state.storage.sql.exec(`SELECT COUNT(*) AS n FROM ${table}`).one()["n"]);
  const trailerOf = (lines: readonly string[]) =>
    JSON.parse(lines.at(-1) ?? "{}") as {
      readonly kind: string;
      readonly auditMaxSeq: number;
      readonly auditHeadHashHex: string | null;
    };
  const seedReads = (n: number) =>
    runInProject(0, async (run) => {
      for (let i = 0; i < n; i += 1) {
        await run(
          pullEnvironmentProgram(actor(READER), testEnvironmentId(ENV), {
            current: null,
            chain: null,
          }),
        );
      }
    });
  const exportLines = async (run: Runner, state: DurableObjectState) => {
    const exit = await run(
      exportPageProgram(actor(OWNER), null, state.storage.sql, state.id.toString(), {
        current: null,
        chain: null,
      }),
    );
    if (!Exit.isSuccess(exit)) throw new Error("export failed");
    expect(exit.value.next).toBeNull();
    return exit.value.lines;
  };

  it("the export's first page materializes nothing at the line and serves a null trailer head; below it, it converges", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await seedReads(3);
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await runInProject(DO_STORAGE_REJECT_BYTES, async (run, state) => {
        const before = count(state, "audit_head_hashes");
        const trailer = trailerOf(await exportLines(run, state));
        expect(trailer.kind).toBe("trailer");
        expect(trailer.auditHeadHashHex).toBeNull();
        expect(count(state, "audit_head_hashes")).toBe(before);
      });
    } finally {
      errorSpy.mockRestore();
    }
    await runInProject(0, async (run, state) => {
      const trailer = trailerOf(await exportLines(run, state));
      expect(trailer.auditHeadHashHex).toMatch(/^[0-9a-f]{64}$/u);
      expect(count(state, "audit_head_hashes")).toBe(trailer.auditMaxSeq);
    });
  });

  it("the export overshoots the line by at most one bounded extension call", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await seedReads(120);
    let measured = 0;
    const crossing = () => (measured++ === 0 ? 0 : DO_STORAGE_REJECT_BYTES);
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await runInProject(
        crossing,
        async (run, state) => {
          const before = count(state, "audit_head_hashes");
          const trailer = trailerOf(await exportLines(run, state));
          expect(count(state, "audit_head_hashes") - before).toBe(50);
          expect(trailer.auditHeadHashHex).toBeNull();
        },
        { headChunks: 1 },
      );
    } finally {
      errorSpy.mockRestore();
    }
  });

  it("a restore at the line hashes and checks every row but stores no further head, and reports the same head as one below it", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await seedReads(120);
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const { lines, carried } = await runInProject(
        DO_STORAGE_REJECT_BYTES,
        async (run, state) => ({
          lines: await exportLines(run, state),
          carried: count(state, "audit_head_hashes"),
        }),
      );
      const text = `${lines.join("\n")}\n`;
      const restoreAt = async (size: number | (() => number)) => {
        await resetProjectDo(projectId);
        const outcome = await runInProject(size, async (run, state) => {
          const exit = await run(
            restoreProgram(
              state.storage,
              Effect.succeed(new Blob([text]).stream().pipeThrough(new CompressionStream("gzip"))),
              { current: null, chain: null },
            ),
          );
          if (!Exit.isSuccess(exit) || exit.value.kind !== "restored") {
            throw new Error("restore failed");
          }
          const column = state.storage.sql
            .exec(
              "SELECT COUNT(*) AS n, COALESCE(MIN(seq), 1) AS mn, COALESCE(MAX(seq), 0) AS mx FROM audit_head_hashes",
            )
            .one();
          return {
            head: exit.value.auditHeadHashHex,
            heads: Number(column["n"]),
            prefix: Number(column["mn"]) === 1 && Number(column["n"]) === Number(column["mx"]),
            rows: count(state, "audit_events"),
          };
        });
        await evictProjectDo(projectId);
        return outcome;
      };
      const atLine = await restoreAt(DO_STORAGE_REJECT_BYTES);
      const below = await restoreAt(0);
      let measured = 0;
      const flipping = await restoreAt(() => (measured++ === 0 ? DO_STORAGE_REJECT_BYTES : 0));
      expect(below.heads).toBe(below.rows);
      expect(below.head).toMatch(/^[0-9a-f]{64}$/u);
      expect(atLine.heads).toBe(carried);
      expect(atLine.heads).toBeLessThan(atLine.rows);
      expect(atLine.head).toBe(below.head);
      for (const restored of [atLine, below, flipping]) {
        expect(restored.prefix).toBe(true);
      }
      expect(flipping.heads).toBe(flipping.rows);
      expect(flipping.head).toBe(below.head);
    } finally {
      errorSpy.mockRestore();
    }
  });
});

describe("deriveAuditHeads past the store line (§11-7 — every row is still checked)", () => {
  it("refuses a gap or a row the canonical form refuses in a chunk it does not store, and stores only the prefix before the line", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await runInProject(0, async (run, state) => {
      for (let i = 0; i < 120; i += 1) {
        await run(
          pullEnvironmentProgram(actor(READER), testEnvironmentId(ENV), {
            current: null,
            chain: null,
          }),
        );
      }
      const sql = state.storage.sql;
      const derive = async (tamper: string | null) => {
        sql.exec("DROP TABLE IF EXISTS derive_source");
        sql.exec("DROP TABLE IF EXISTS derive_heads");
        sql.exec("CREATE TABLE derive_source AS SELECT * FROM audit_events");
        sql.exec("CREATE TABLE derive_heads (seq INTEGER, head_hash_hex TEXT)");
        if (tamper !== null) {
          sql.exec(tamper);
        }
        let asked = 0;
        const head = await deriveAuditHeads(sql, "derive_source", "derive_heads", 0, "", () => {
          asked += 1;
          return asked !== 2;
        });
        const stored = sql
          .exec("SELECT COUNT(*) AS n, COALESCE(MAX(seq), 0) AS mx FROM derive_heads")
          .one();
        return { head, stored: Number(stored["n"]), max: Number(stored["mx"]) };
      };
      const clean = await derive(null);
      expect(clean.head).toMatch(/^[0-9a-f]{64}$/u);
      expect(clean).toMatchObject({ stored: 50, max: 50 });
      expect(await derive("DELETE FROM derive_source WHERE seq = 100")).toMatchObject({
        head: null,
      });
      expect(await derive("UPDATE derive_source SET server_ts = -1 WHERE seq = 100")).toMatchObject(
        { head: null },
      );
      sql.exec("DROP TABLE derive_source");
      sql.exec("DROP TABLE derive_heads");
    });
  });
});

describe("the warning threshold (§12-8 — operations log)", () => {
  it("admits growth writes in the warning band and logs one static line per meter", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await runInProject(DO_STORAGE_WARN_BYTES, async (run) => {
        const cache: StateCache = { current: null, chain: null };
        for (let i = 0; i < 3; i += 1) {
          const rejection = rejectionOf(
            await run(
              pushVersionProgram(
                actor(OWNER),
                testEnvironmentId(ENV),
                VAR,
                dummyValueInput(2),
                undefined,
                cache,
              ),
            ),
          );
          expect(rejection?.kind).toBe("value-rejected");
        }
      });
      expect(warnSpy).toHaveBeenCalledTimes(1);
      const [message] = warnSpy.mock.calls[0] ?? [];
      expect(typeof message).toBe("string");
      expect(message).not.toContain(projectId);
      expect(errorSpy).not.toHaveBeenCalled();
    } finally {
      warnSpy.mockRestore();
      errorSpy.mockRestore();
    }
  });

  it("warns from the value pull path too (pull-only projects cross the band without growth writes)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await runInProject(DO_STORAGE_WARN_BYTES, async (run) => {
        const cache: StateCache = { current: null, chain: null };
        for (let i = 0; i < 3; i += 1) {
          expect(
            Exit.isSuccess(
              await run(pullEnvironmentProgram(actor(READER), testEnvironmentId(ENV), cache)),
            ),
          ).toBe(true);
        }
        expect(
          Exit.isSuccess(
            await run(pullEnvironmentMetadataProgram(actor(READER), testEnvironmentId(ENV), cache)),
          ),
        ).toBe(true);
      });
      expect(warnSpy).toHaveBeenCalledTimes(1);
      expect(errorSpy).not.toHaveBeenCalled();
      await runInProject(DO_STORAGE_REJECT_BYTES, async (run) => {
        const cache: StateCache = { current: null, chain: null };
        expect(
          Exit.isSuccess(
            await run(pullEnvironmentProgram(actor(READER), testEnvironmentId(ENV), cache)),
          ),
        ).toBe(true);
        expect(
          Exit.isSuccess(
            await run(pullEnvironmentProgram(actor(READER), testEnvironmentId(ENV), cache)),
          ),
        ).toBe(true);
      });
      expect(errorSpy).toHaveBeenCalledTimes(1);
    } finally {
      warnSpy.mockRestore();
      errorSpy.mockRestore();
    }
  });

  it("stays silent below the warning threshold", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      await runInProject(DO_STORAGE_WARN_BYTES - 1, async (run) => {
        const rejection = rejectionOf(
          await run(
            pushVersionProgram(
              actor(OWNER),
              testEnvironmentId(ENV),
              VAR,
              dummyValueInput(2),
              undefined,
              {
                current: null,
                chain: null,
              },
            ),
          ),
        );
        expect(rejection?.kind).toBe("value-rejected");
      });
      expect(warnSpy).not.toHaveBeenCalled();
    } finally {
      warnSpy.mockRestore();
    }
  });
});
