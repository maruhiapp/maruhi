// Tests for the DO total-storage guard (AUTH_SPEC §12-8).
//
// Generating a real 8-9 GB is impractical, so this is pinned in two
// layers:
// 1. the decision's pure function (storageGuardDecision — the
//    threshold boundaries)
// 2. the acceptance paths' wiring: against a real project DO's
//    SqlStorage (chains, environments, variables the fixture created
//    via the API), run the **real programs** under a StorageMeter
//    whose measured size alone is swapped for a fixed value, and pin
//    that the "surfaces rejection must stop" halt with
//    limit-exceeded (project-storage-bytes) while the "surfaces that
//    must stay open under rejection" (reads, deletes, revocations,
//    rotation, attestation, checkpoint, settings) pass the guard (=
//    are rejected for another reason or succeed). Since the guard
//    sits at each program's head (right after membership, before
//    semantic checks), any result other than limit-exceeded is
//    evidence the guard was not called (or admitted). The sealed
//    value proposal mint and pre-flight refuse in the workload
//    vocabulary (`storage-limit`)
// 3. the 10 GB floor: the reads that append an audit row run under an
//    audit store whose appends fail like SQLITE_FULL, and pin that they
//    fail rather than being served unrecorded
//
// The warning (8 GB) operations log is a static message, once per DO
// instance (= per meter).

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
import { env, runInDurableObject } from "cloudflare:test";
import { Cause, Effect, Exit, Layer, Redacted } from "effect";
import type { HttpApiEndpoint } from "effect/http-api";
import { describe, expect, it, vi } from "vitest";

import { putHeadAttestationProgram } from "../src/attestation-accept.ts";
import { AuditStore, auditStoreLayer, makeAuditStore } from "../src/audit-store.ts";
import {
  toManifestInput,
  toMetaStatementInput,
  toValueInput,
  unwrapDataOutcome,
} from "../src/data/data-http.ts";
import type { DataActor, DataRejection } from "../src/data/data-plane.ts";
import type { DataStore } from "../src/data/data-store.ts";
import { dataStoreLayer } from "../src/data/data-store.ts";
import { appendProgram, snapshotProgram } from "../src/do/chain-do.ts";
import type { ChainStore, StateCache } from "../src/do/chain-store.ts";
import { chainStoreLayer } from "../src/do/chain-store.ts";
import { DO_STORAGE_REJECT_BYTES, DO_STORAGE_WARN_BYTES } from "../src/policy.ts";
import {
  createEnvironmentCompositeProgram,
  deleteEnvironmentCompositeProgram,
  rotateEpochCompositeProgram,
} from "../src/programs/composite-programs.ts";
import { auditHeadProgram } from "../src/programs/programs-audit.ts";
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
import { addMemberOperation, signEntryAt, vectorKeyOf } from "./support/data-crypto.ts";
import { testEnvironmentId } from "./support/data-crypto.ts";
import { testProjectId } from "./support/data-crypto.ts";
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
import { readAuditEvents } from "./support/project-do.ts";

registerDataScenario();

const actor = (userId: string): DataActor => ({ userId: testUserId(userId) });

/** The services in-DO programs require (chain-do.ts's DoServices). */
type DoProgram<A, E> = Effect.Effect<
  A,
  E,
  ChainStore | DataStore | AuditStore | ServerKey | StorageMeter
>;
type Runner = <A, E>(program: DoProgram<A, E>) => Promise<Exit.Exit<A, E>>;

/**
 * Under a meter with a fixed measured size, run programs against the
 * real project DO's SqlStorage (the same layer composition as
 * chain-do.ts's constructor, with the meter swapped). StateCache is
 * empty per call = a full load from the stored rows. `atFloor` swaps the
 * audit store's appends for the 10 GB floor's SQLITE_FULL (the platform
 * limit cannot be reached for real either).
 */
async function runInProject<A>(
  databaseSizeBytes: number,
  body: (run: Runner, state: DurableObjectState) => Promise<A>,
  options: { readonly atFloor?: boolean } = {},
): Promise<A> {
  const meter = makeStorageMeter(() => databaseSizeBytes);
  const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));
  return await runInDurableObject(stub, async (_instance, state) => {
    const cache: StateCache = { current: null, chain: null };
    const full = () => {
      throw new Error(SQLITE_FULL);
    };
    const layers = Layer.mergeAll(
      chainStoreLayer(state.storage.sql, cache),
      dataStoreLayer(state.storage.sql),
      options.atFloor === true
        ? Layer.sync(AuditStore, () => ({
            ...makeAuditStore(state.storage.sql),
            appendSync: full,
            appendManySync: full,
          }))
        : auditStoreLayer(state.storage.sql),
      Layer.succeed(StorageMeter, meter),
      // The deployment key the DO derives (the workload paths authorize against its grant)
      Layer.sync(ServerKey, () => makeServerKey(Redacted.make(env.SERVER_ENC_KEY_IKM ?? ""))),
      // The DO runtime's logger (chain-do.ts) — without it the
      // converted Effect.logWarning / logError lines do not reach
      // the console spies
      ServerLoggerLive,
    );
    const run: Runner = (program) => Effect.runPromiseExit(program.pipe(Effect.provide(layers)));
    return await body(run, state);
  });
}

const SQLITE_FULL = "SQLITE_FULL: database or disk is full";

/** The verified token facts the worker hands the DO, matching the lease scenario's default policy. */
const workloadFacts = (): LeaseTokenFacts => ({
  issuer: OIDC_ISSUER,
  subject: LEASE_SUBJECT,
  audiences: [LEASE_AUDIENCE],
  claims: { sub: LEASE_SUBJECT },
  claimsDigestHex: "00".repeat(32),
  bindingKeyHex: "11".repeat(32),
  bindingExpiresAtMs: Date.now() + 300_000,
});

/** Exit → rejection reason (success / defect is null). */
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

// Wire-shape dummies (the support wire types carry suite as string) →
// DO inputs. Since the guard stands before signature verification,
// zero-signature dummies suffice
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
    actorUserId: OWNER,
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
    // Under either interpretation — 10 GB (decimal) / 10 GiB (binary) —
    // the rejection threshold sits below the floor (§12-8)
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
      // the add_member / grant_server rejection surface
      "membership.append": membershipGroup.endpoints.append,
      // schemaPolicy change
      "schemaPolicy.set": schemaPolicyGroup.endpoints.set,
      // reads that require materializing the audit-head derived
      // column, and rotate, which can bundle a non-empty notarizing
      // boundary checkpoint
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
    // The target keys may be dummies (the guard stands before verifyChain)
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
          // not a growth surface, but a settings change that piles up audit rows without helping exit / release / remediation
          setSchemaPolicy: rejectionOf(
            await run(setSchemaPolicyProgram(actor(OWNER), "enabled", cache)),
          ),
        };
        for (const [surface, rejection] of Object.entries(outcomes)) {
          expect(rejection, surface).toEqual(STORAGE_REJECTION);
        }
      });
      // The rejection-band operations log is a static message once per meter (1 line for 12 rejections)
      expect(errorSpy).toHaveBeenCalledTimes(1);
      const [message] = errorSpy.mock.calls[0] ?? [];
      expect(typeof message).toBe("string");
      expect(message).not.toContain(projectId);
      expect(message).not.toContain(OWNER);
    } finally {
      errorSpy.mockRestore();
    }
    // Nothing was written: still 1 variable, version still 1, the chain unchanged
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
    // Four-eyes enablement (2 owners + the policy) and a pending
    // add_member proposal are created over HTTP under the normal
    // meter (design record es-design.md §11 K5-D)
    await seedMemberToken(fixture, "user-owner-0014", 9014);
    await appendOperation(fixture, OWNER, addMemberOperation("user-owner-0014", "owner"));
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
      // Surfaces that are rejected (the head does not move)
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
      // Surfaces that are accepted (a remediation proposal / releasing a proposal)
      const removeProposed = await run(
        appendProgram(fixture.head.hashHex, proposeRemove.entry, OWNER, cache),
      );
      expect(rejectionOf(removeProposed)).toBeNull();
      if (!Exit.isSuccess(removeProposed)) throw new Error("unreachable");
      const resigned = await signEntryAt({
        seq: removeProposed.value.headSeq + 1,
        prevHashHex: removeProposed.value.headHashHex,
        actorUserId: OWNER,
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
    // Revocation-kind entries with a mismatched parent head:
    // limit-exceeded if the guard was called, chain-head-conflict if
    // not (the guard precedes ensureParentHead)
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
    // The deletion composite checks the declared parent against the entry's
    // own prev before the CAS (§12-4), so its entry chains onto the stale
    // parent to reach the CAS
    const deleteEnv = await signEntryAt({
      seq: fixture.head.seq + 1,
      prevHashHex: staleParent,
      actorUserId: OWNER,
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
      // (a) reads — succeed (a value pull carries a var.read audit append but is accepted)
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
      // (b) deletions — pass the guard and are rejected for another reason (dummy input:
      // the variable statement's metaVersion 1 fails the CAS; the environment
      // deletion composite's stale parent fails the chain-head CAS)
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
      // (c) revocations / permission narrowing + (g) checkpoint — do not pass the guard (chain-head-conflict)
      for (const entry of [
        removeMember.entry,
        changeRole.entry,
        revokeServer.entry,
        checkpoint.entry,
      ]) {
        const rejection = rejectionOf(await run(appendProgram(staleParent, entry, OWNER, cache)));
        expect(rejection?.kind, entry.op).toBe("chain-head-conflict");
      }
      // (d) the rotation composite — proceeds to the in-composite consistency check (environmentId mismatch)
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
      // (f) head attestation — proceeds to signature verification (the dummy signature is attestation-rejected)
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
      // (h) dismissal — succeeds (audit rows bounded by the flag
      // count). Changing schemaPolicy is a rejection target (the
      // growth-surface test above); reading it is a read and passes
      expect(Exit.isSuccess(await run(dismissRotationFlagsProgram(actor(OWNER), [], cache)))).toBe(
        true,
      );
      expect(Exit.isSuccess(await run(getSchemaPolicyProgram(actor(READER), cache)))).toBe(true);
      // Actual acceptance of (c): a remove_member with the correct parent head is accepted even at/above the rejection threshold
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
  // Sealed to W(E) (owner + member devices); the server verifies nothing inside a wrap
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
  const preflight = (baseVersion: number, cache: StateCache) =>
    preflightRotationProgram(
      testEnvironmentId(ENV),
      ephemeralPubHex,
      workloadFacts(),
      [{ variableId: VAR, baseVersion }],
      cache,
      writers,
    );
  const mint = (cache: StateCache) =>
    proposeRotationProgram(
      testEnvironmentId(ENV),
      ephemeralPubHex,
      workloadFacts(),
      proposal,
      cache,
    );
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
        // A stale base version would be base-version-stale: the guard precedes the semantic checks
        expect(failureOf(await run(preflight(5, cache)))).toEqual(STORAGE_LIMIT);
        expect(failureOf(await run(mint(cache)))).toEqual(STORAGE_LIMIT);
      });
      const events = (await readAuditEvents(projectId)).map((event) => event["event"]);
      expect(events).not.toContain("rotation.proposed");
      // In the warning band the same requests are admitted (observation only)
      await runInProject(DO_STORAGE_WARN_BYTES, async (run) => {
        const cache: StateCache = { current: null, chain: null };
        expect(Exit.isSuccess(await run(preflight(1, cache)))).toBe(true);
        expect(Exit.isSuccess(await run(mint(cache)))).toBe(true);
      });
      expect(warnSpy).toHaveBeenCalledTimes(1);
      // The closing paths of a stored proposal stay open under rejection (§12-8 (h))
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
      // No read is served without its audit row (an unrecorded read of a
      // member nobody can remove at the floor)
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
      // Audit rows exist but the derived column is not yet
      // materialized (nobody has read the audit head yet) →
      // materialization requires a write proportional to the audit
      // row count, so it is rejected at/above the rejection
      // threshold
      await runInProject(DO_STORAGE_REJECT_BYTES, async (run) => {
        const cache: StateCache = { current: null, chain: null };
        expect(rejectionOf(await run(auditHeadProgram(actor(OWNER), cache)))).toEqual(
          STORAGE_REJECTION,
        );
        // A standalone checkpoint of a non-empty attestation stops on
        // the same input (placed before the parent-head check = after
        // requireRole(admin)). An empty attestation (the CLI default)
        // passes — that is the chain-head-conflict in the test
        // above
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
      // One read below the threshold = it is materialized
      const materialized = await runInProject(0, async (run) =>
        Exit.isSuccess(await run(auditHeadProgram(actor(OWNER), { current: null, chain: null }))),
      );
      expect(materialized).toBe(true);
      // With the column current, it passes as a read-only call even at/above the rejection threshold
      const current = await runInProject(DO_STORAGE_REJECT_BYTES, async (run) =>
        Exit.isSuccess(await run(auditHeadProgram(actor(OWNER), { current: null, chain: null }))),
      );
      expect(current).toBe(true);
      // When audit rows grow (a value pull's var.read — a read that is
      // accepted even under rejection) the column lags again, and the
      // next audit-head read requires materialization and is rejected
      // again
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

describe("the warning threshold (§12-8 — operations log)", () => {
  it("admits growth writes in the warning band and logs one static line per meter", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await runInProject(DO_STORAGE_WARN_BYTES, async (run) => {
        const cache: StateCache = { current: null, chain: null };
        // The guard passes with an admit verdict; the dummies fall later (at value-signature verification)
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
    // A project whose dominant growth term is var.read crosses
    // 8 GB → 9 GB with no growth-surface writes. If the observation
    // points covered only the growth surface, the warning band's
    // design of "buying the operators response time" would not hold
    // for pull-dominant projects
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await runInProject(DO_STORAGE_WARN_BYTES, async (run) => {
        const cache: StateCache = { current: null, chain: null };
        // Observation only — the pull is accepted (a var.read is also recorded)
        for (let i = 0; i < 3; i += 1) {
          expect(
            Exit.isSuccess(
              await run(pullEnvironmentProgram(actor(READER), testEnvironmentId(ENV), cache)),
            ),
          ).toBe(true);
        }
        // A metadata-only pull is a read that writes no audit row = it has no observation point
        expect(
          Exit.isSuccess(
            await run(pullEnvironmentMetadataProgram(actor(READER), testEnvironmentId(ENV), cache)),
          ),
        ).toBe(true);
      });
      expect(warnSpy).toHaveBeenCalledTimes(1);
      expect(errorSpy).not.toHaveBeenCalled();
      // Pulls also pass in the rejection band; the rejection-band log fires once (no rejection actually happens)
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
