import type { ProjectId } from "@maruhi/core";
import {
  addMemberOp,
  buildChain,
  type BuiltChain,
  changeRoleOp,
  createEnvironmentOp,
  deleteEnvironmentOp,
  type GeneratedIdentity,
  generateIdentity,
  genesisOp,
  removeMemberOp,
  testEnvironmentId,
} from "@maruhi/test-kit";
import { Effect, Exit } from "effect";
import { beforeAll, describe, expect, it } from "vite-plus/test";

import type { MaruhiClient } from "../src/api.ts";
import { type VerifiedProject, verifyChainSnapshot } from "../src/chain-sync.ts";
import { requireWritingMember } from "../src/dek-wrap.ts";
import { environmentKeysFor } from "../src/deks.ts";
import { scopeChangesOf } from "../src/member.package/member-change-role.ts";
import {
  environmentsOfScopeAt,
  requireEnvironmentInScope,
  sameScope,
  scopeChangeAt,
  scopeContains,
} from "../src/scope.ts";

let owner: GeneratedIdentity;
let dev: GeneratedIdentity;
let built: BuiltChain;
let verified: VerifiedProject;

async function verify(chain: BuiltChain): Promise<VerifiedProject> {
  return Effect.runPromise(
    verifyChainSnapshot({
      projectId: chain.projectId as ProjectId,
      entries: chain.entries,
      claimedHeadSeq: chain.entries.length,
      claimedHeadHashHex: chain.hashes[chain.hashes.length - 1] ?? "",
    }),
  );
}

beforeAll(async () => {
  owner = await generateIdentity("user-owner-1111");
  dev = await generateIdentity("user-dev-2222");
  const dek = crypto.getRandomValues(new Uint8Array(32));
  built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp("env-dev", dek) },
    { actor: owner, operation: createEnvironmentOp("env-prod", dek) },
    { actor: owner, operation: addMemberOp(dev, "member", ["env-dev"]) },
    { actor: owner, operation: removeMemberOp(dev) },
    { actor: owner, operation: createEnvironmentOp("env-later", dek) },
  ]);
  verified = await verify(built);
});

describe("receiving-side scope rules (CRYPTO_SPEC §6.3 — K4-F)", () => {
  it("when the environment is outside your scope it fetches no DEK and stops with a typed error (zero server requests)", async () => {
    const chain = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp("env-dev", new Uint8Array(32)) },
      { actor: owner, operation: createEnvironmentOp("env-prod", new Uint8Array(32)) },
      { actor: owner, operation: addMemberOp(dev, "member", ["env-dev"]) },
    ]);
    const view = await verify(chain);
    let listMineCalls = 0;
    const client = {
      deks: {
        listMine: () => {
          listMineCalls += 1;
          return Effect.die(new Error("must not be called"));
        },
      },
    } as unknown as MaruhiClient;
    const failure = await Effect.runPromise(
      Effect.flip(
        environmentKeysFor({
          client,
          verified: view,
          environmentId: testEnvironmentId("env-prod"),
          recipient: { userId: dev.userId, encPubHex: dev.encPubHex, encKeyPair: dev.encKeyPair },
        }),
      ),
    );
    expect(failure.message).toContain("is outside your environment scope");
    expect(failure.message).toContain("is not used (CRYPTO_SPEC §6.3");
    expect(failure.message).toContain("your scope: env-dev");
    expect(listMineCalls).toBe(0);
  });
});

describe("concretizing a mandate's environment set (K4-J)", () => {
  it("all covers only environments that existed at the mandate's seq (later-created environments are excluded)", () => {
    expect(environmentsOfScopeAt(verified, { kind: "all" }, 5)).toEqual(["env-dev", "env-prod"]);
    expect(environmentsOfScopeAt(verified, { kind: "all" }, 6)).toEqual([
      "env-dev",
      "env-later",
      "env-prod",
    ]);
    expect(
      environmentsOfScopeAt(
        verified,
        { kind: "listed", environmentIds: [testEnvironmentId("env-prod")] },
        5,
      ),
    ).toEqual(["env-prod"]);
  });

  it("an all → listed narrowing concretizes U \\ X into that point's environment set", () => {
    const change = scopeChangeAt(
      verified,
      { kind: "all" },
      { kind: "listed", environmentIds: [testEnvironmentId("env-dev")] },
      5,
    );
    expect(change.narrowed).toEqual(["env-prod"]);
    expect(change.widened).toEqual([]);
  });
});

describe("containment predicates (CRYPTO_SPEC §6.2's set algebra — K4-I)", () => {
  const all = { kind: "all" } as const;
  const devOnly = { kind: "listed", environmentIds: [testEnvironmentId("env-dev")] } as const;
  const both = {
    kind: "listed",
    environmentIds: [testEnvironmentId("env-dev"), testEnvironmentId("env-prod")],
  } as const;
  const none = { kind: "listed", environmentIds: [] } as const;

  it("all ⊇ anything, listed ⊉ all, listed-to-listed is subset, and an empty listed is contained in everything", () => {
    expect(scopeContains(all, all)).toBe(true);
    expect(scopeContains(all, both)).toBe(true);
    expect(scopeContains(devOnly, all)).toBe(false);
    expect(scopeContains(both, devOnly)).toBe(true);
    expect(scopeContains(devOnly, both)).toBe(false);
    expect(scopeContains(none, none)).toBe(true);
    expect(scopeContains(devOnly, none)).toBe(true);
    expect(scopeContains(none, devOnly)).toBe(false);
  });

  it("sameScope compares as sets (order-insensitive; all and listed{} differ)", () => {
    expect(
      sameScope(both, {
        kind: "listed",
        environmentIds: [testEnvironmentId("env-prod"), testEnvironmentId("env-dev")],
      }),
    ).toBe(true);
    expect(sameScope(all, none)).toBe(false);
    expect(sameScope({ scopeKind: "all", scopeEnvironmentIds: [] }, all)).toBe(true);
  });
});

describe("re-deriving the widened / narrowed portions from the change_role history (K4-N supplement (2))", () => {
  const dek = new Uint8Array(32);

  function targetOf(view: VerifiedProject) {
    const member = view.state.members.get(dev.userId);
    if (member === undefined) throw new Error("dev is not a member");
    return member;
  }

  it("widen then narrow: the widened portion is the history's union ∩ current scope (environments lost in the narrowing excluded); the narrowed portion is the last difference", async () => {
    const chain = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp("env-dev", dek) },
      { actor: owner, operation: createEnvironmentOp("env-prod", dek) },
      { actor: owner, operation: createEnvironmentOp("env-stg", dek) },
      { actor: owner, operation: addMemberOp(dev, "member", ["env-dev"]) },
      { actor: owner, operation: changeRoleOp(dev, "member", ["env-dev", "env-prod", "env-stg"]) },
      { actor: owner, operation: changeRoleOp(dev, "member", ["env-dev", "env-prod"]) },
    ]);
    const view = await verify(chain);
    const change = scopeChangesOf(view, targetOf(view));
    expect(change.widened).toEqual(["env-prod"]);
    expect(change.narrowed).toEqual(["env-stg"]);
  });

  it("re-widening: even with a third party's change_role in between, a history-wide widened portion still inside the current scope is a resumption target", async () => {
    const chain = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp("env-dev", dek) },
      { actor: owner, operation: createEnvironmentOp("env-prod", dek) },
      { actor: owner, operation: addMemberOp(dev, "member", ["env-dev"]) },
      { actor: owner, operation: changeRoleOp(dev, "member", ["env-dev", "env-prod"]) },
      { actor: owner, operation: changeRoleOp(dev, "admin", ["env-dev", "env-prod"]) },
    ]);
    const view = await verify(chain);
    const change = scopeChangesOf(view, targetOf(view));
    expect(change.widened).toEqual(["env-prod"]);
    expect(change.narrowed).toEqual([]);
  });

  it("all → listed → all: an environment lost in the narrowing returns to the widened portion on re-widening, and the narrowed portion is empty", async () => {
    const chain = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp("env-dev", dek) },
      { actor: owner, operation: createEnvironmentOp("env-prod", dek) },
      { actor: owner, operation: addMemberOp(dev, "member", ["env-dev", "env-prod"]) },
      { actor: owner, operation: changeRoleOp(dev, "member") },
      { actor: owner, operation: changeRoleOp(dev, "member", ["env-dev"]) },
      { actor: owner, operation: changeRoleOp(dev, "member") },
    ]);
    const view = await verify(chain);
    const change = scopeChangesOf(view, targetOf(view));
    expect(change.widened).toEqual(["env-prod"]);
    expect(change.narrowed).toEqual([]);
  });
});

describe("the scope gates refuse a chain-deleted environment first (§6.2)", () => {
  let view: VerifiedProject;
  beforeAll(async () => {
    const dek = new Uint8Array(32);
    view = await verify(
      await buildChain([
        { actor: owner, operation: genesisOp(owner) },
        { actor: owner, operation: createEnvironmentOp("env-dev", dek) },
        { actor: owner, operation: addMemberOp(dev, "member", ["env-dev"]) },
        { actor: owner, operation: deleteEnvironmentOp("env-dev") },
      ]),
    );
  });

  for (const who of ["listed member", "all-scope owner"] as const) {
    it(`requireEnvironmentInScope reports the deletion (${who})`, async () => {
      const user = who === "listed member" ? dev : owner;
      const exit = await Effect.runPromiseExit(
        requireEnvironmentInScope({
          verified: view,
          userId: user.userId,
          environmentId: testEnvironmentId("env-dev"),
          operation: "pull values from",
        }),
      );
      expect(JSON.stringify(exit)).toContain("is deleted (delete_environment at chain seq 4)");
      expect(JSON.stringify(exit)).not.toContain("outside your environment scope");
    });

    it(`requireWritingMember reports the deletion (${who})`, async () => {
      const user = who === "listed member" ? dev : owner;
      const exit = await Effect.runPromiseExit(
        requireWritingMember({
          verified: view,
          environmentId: testEnvironmentId("env-dev"),
          target: "existing",
          signerUserId: user.userId,
          signingKeyPair: user.sigKeyPair,
          operation: "rotate the epoch",
          forbidden: "forbidden",
        }),
      );
      expect(JSON.stringify(exit)).toContain("is deleted (delete_environment at chain seq 4)");
      expect(JSON.stringify(exit)).not.toContain("outside your environment scope");
    });
  }

  it("requireWritingMember leaves a new-environment target to the creation check (a burned ID is duplicate-environment, not a deletion refusal)", async () => {
    const exit = await Effect.runPromiseExit(
      requireWritingMember({
        verified: view,
        environmentId: testEnvironmentId("env-dev"),
        target: "new",
        signerUserId: owner.userId,
        signingKeyPair: owner.sigKeyPair,
        operation: "create an environment",
        forbidden: "forbidden",
      }),
    );
    expect(Exit.isSuccess(exit)).toBe(true);
  });
});
