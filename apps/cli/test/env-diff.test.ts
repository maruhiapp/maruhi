// Tests for the cross-environment parity check (`maruhi env diff`).
//
// Invariants pinned:
//  1. **Never fetch values**: it only ever touches the §12-7 metadata-only
//     pull — the value pull (`/pull`) and DEK distribution (`/deks`) are never
//     touched (the server records no `var.read` — AUDIT_SPEC §3.3)
//  2. The diff contents and count, plus **a stable output order sorted by
//     name** (the output is unchanged even if the wire order changes)
//  3. Variable names are plaintext metadata written by other members, so
//     ANSI / BEL / newlines are neutralized, and visually identical names
//     are reported as distinct when their normalization forms differ (NFC / NFD)
//  4. Warnings for both environments are labeled by environment ID (warnings
//     with identical wording must not fold away one side's fact)
//  5. **The prelude runs only once** (one chain sync), and the view the first
//     pull advanced via bounded resync is handed to the second pull
//  6. The environment-level floor (meta · manifest · coordinate (ii)) is
//     committed, but the value floor and the rule (c) pull criterion are
//     never fabricated (M1-A3 — the chain floor's head advances per pull)
//  7. The sampling skew from sequential reads is disclosed on stderr
//     **regardless of whether a diff exists** (a zero-diff conclusion is
//     exactly the one a skew can cover)
//  8. **Never require the device key** (it does not decrypt; it also works
//     under a MARUHI_TOKEN session)
//  9. Usage mistakes (one environment · the same environment ID twice ·
//     options exclusive to other operations) fall with a usage error (2)
//     **before any communication**

import type { EnvironmentId } from "@maruhi/core";
import { Effect } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { reportEnvironmentDiff, reportEnvironmentWarnings } from "../src/env-diff.ts";
import { makeFileFloorStore } from "../src/floor-log.ts";
import type { ProjectFloor } from "../src/floor.ts";
import { masterKeyEntryName } from "../src/keychain.ts";
import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  environmentStatementFor,
  genesisOp,
  headOf,
  makeTestUser,
  manifestFor,
  statementFor,
  type TestUser,
  type WireDistributedEnvironmentStatement,
  type WireDistributedVariableStatement,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

const DEV = "dev";
const PROD = "prod";

let owner: TestUser;
let chain: BuiltChain;
let devStatement: WireDistributedEnvironmentStatement;
let prodStatement: WireDistributedEnvironmentStatement;
let servers: MockServer[] = [];

/** Reads the floor (the fold of the observation log) — floor-log.ts's append-only JSONL. */
async function loadFloor(env: TestEnv): Promise<ProjectFloor> {
  const loaded = await Effect.runPromise(makeFileFloorStore(env.floorDir).load(chain.projectId));
  expect(loaded.floor).not.toBeNull();
  return loaded.floor as ProjectFloor;
}

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  chain = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    {
      actor: owner,
      operation: createEnvironmentOp(DEV, crypto.getRandomValues(new Uint8Array(32))),
    },
    {
      actor: owner,
      operation: createEnvironmentOp(PROD, crypto.getRandomValues(new Uint8Array(32))),
    },
    // The 4th: an extra entry that exists only to build the shape where the
    // two pulls each trigger a bounded resync (seq 2 → 3 → 4). Not a diff target
    {
      actor: owner,
      operation: createEnvironmentOp("staging", crypto.getRandomValues(new Uint8Array(32))),
    },
  ]);
  devStatement = await environmentStatementOf(DEV);
  prodStatement = await environmentStatementOf(PROD);
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

function environmentStatementOf(
  environmentId: string,
): Promise<WireDistributedEnvironmentStatement> {
  return environmentStatementFor({
    projectId: chain.projectId,
    environmentId,
    name: environmentId,
    author: owner,
    head: headOf(chain, 1),
  });
}

/** One verified statement (declared head defaults to genesis). */
function variableOf(
  environmentId: string,
  variableId: string,
  name: string,
  headSeq = 1,
): Promise<WireDistributedVariableStatement> {
  return statementFor({
    projectId: chain.projectId,
    environmentId,
    variableId,
    name,
    author: owner,
    head: headOf(chain, headSeq),
  });
}

/**
 * Chain distribution. Because `heads` advances on each call (stopping at the
 * last), it can build the shape "a short chain at sync time → grows via
 * bounded resync". Prefixes are cut from the same build, so the prev_hash chain stays correct.
 */
function chainHandlerOf(heads: readonly number[]): MockHandler {
  let call = 0;
  return onRequest("GET", `/projects/${chain.projectId}/chain`, () => {
    const headSeq = heads[Math.min(call, heads.length - 1)] ?? chain.entries.length;
    call += 1;
    return {
      status: 200,
      json: {
        projectId: chain.projectId,
        entries: chain.entries.slice(0, headSeq),
        headSeq,
        headHashHex: chain.hashes[headSeq - 1],
      },
    };
  });
}

/** The position (seq) of create_environment. The manifest's declared head must be at or after it. */
const CREATED_AT_SEQ: Readonly<Record<string, number>> = { [DEV]: 2, [PROD]: 3 };

/** The response of a metadata-only pull (§12-7). Carries neither values nor DEKs (the manifest is bundled). */
function pullMetadataHandlerOf(
  environmentId: string,
  statement: WireDistributedEnvironmentStatement,
  variables: readonly WireDistributedVariableStatement[],
): MockHandler {
  // The declared head is the larger of "the environment creation's seq" and
  // "the distributed statements' max declared seq": the bounded-resync tests
  // (short chain → extension) only advance the view up to a statement's
  // declared seq, so declaring beyond it still fails as future after resync
  const headSeq = Math.max(
    CREATED_AT_SEQ[environmentId] ?? chain.entries.length,
    ...variables.map((variable) => variable.chainHeadSeq),
  );
  return onRequest(
    "GET",
    `/projects/${chain.projectId}/environments/${environmentId}/pull/metadata`,
    async () => ({
      status: 200,
      json: {
        environmentId,
        currentEpoch: 1,
        statement,
        variables,
        deletedVariables: [],
        manifest: await manifestFor({
          projectId: chain.projectId,
          environmentId,
          epoch: 1,
          issuer: owner,
          head: headOf(chain, headSeq),
          envStatement: statement,
          statements: variables,
        }),
      },
    }),
  );
}

async function startEnv(
  handlers: readonly MockHandler[],
  /** The length of the chain distributed per sync (default is always full length). */
  chainHeads: readonly number[] = [chain.entries.length],
): Promise<TestEnv & { origin: string }> {
  const server = await MockServer.start([chainHandlerOf(chainHeads), ...handlers]);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, { server: server.origin, defaultProject: chain.projectId });
  return Object.assign(env, { origin: server.origin });
}

/** The most recently started mock server (for assertions). */
function lastServer(): MockServer {
  const server = servers[servers.length - 1];
  if (server === undefined) {
    throw new Error("no mock server started");
  }
  return server;
}

/**
 * That no value-carrying path was ever touched. `/pull/metadata` returns
 * neither values nor DEKs, so a suffix match distinguishes it from the value pull (`/pull`).
 */
function expectNoValueFetches(): void {
  const valuePaths = lastServer()
    .requests.map((request) => request.path)
    .filter((path) => path.endsWith("/pull") || path.endsWith("/deks"));
  expect(valuePaths).toEqual([]);
}

/** Builds metadata-pull handlers for the two environments, given only names. */
async function handlersFor(
  devNames: readonly string[],
  prodNames: readonly string[],
): Promise<readonly MockHandler[]> {
  const dev = await Promise.all(
    devNames.map((name, index) => variableOf(DEV, `var-dev-${index}`, name)),
  );
  const prod = await Promise.all(
    prodNames.map((name, index) => variableOf(PROD, `var-prod-${index}`, name)),
  );
  return [
    pullMetadataHandlerOf(DEV, devStatement, dev),
    pullMetadataHandlerOf(PROD, prodStatement, prod),
  ];
}

describe("maruhi env diff", () => {
  it("reports variable names present on only one side, and never touches the value-fetch path", async () => {
    const env = await startEnv(
      await handlersFor(["ZULU", "SHARED_ONE", "ALPHA", "MIKE"], ["PROD_ONLY", "SHARED_ONE"]),
    );

    expect(await runCli(["env", "diff", DEV, PROD], env.layer)).toBe(0);
    // The diff contents / count and the name-sorted order
    expect(env.logs).toEqual([
      `Synced and verified: environment ${DEV} = 4 variables / environment ${PROD} = 2 variables`,
      `Variables only in environment ${DEV}: 3`,
      "  ALPHA",
      "  MIKE",
      "  ZULU",
      `Variables only in environment ${PROD}: 1`,
      "  PROD_ONLY",
      "Variables in both with a differing schema contract: 0",
      "Variables in both: 1 (names match, nothing more — values were neither fetched nor decrypted, so whether the values match was not compared)",
    ]);
    // The value pull / DEK distribution are never touched (pullMetadata only)
    expectNoValueFetches();
    expect(
      lastServer().requests.filter((request) => request.path.endsWith("/pull/metadata")),
    ).toHaveLength(2);
    // The prelude runs only once = the chain sync runs only once (syncing per
    // environment would run the §6.3 verification twice and could end up
    // comparing two disagreeing verified views)
    expect(lastServer().requests.filter((request) => request.path.endsWith("/chain"))).toHaveLength(
      1,
    );
  });

  it("notes the sampling skew regardless of whether a diff exists (stderr; only the advice follows the conclusion)", async () => {
    // The two environments are read in order, so a push landing mid-run is
    // briefly visible on only one side = a fake diff. A "fix" that believes it
    // is an un-undoable push, so prompt a re-check before filling it
    const drifted = await startEnv(await handlersFor(["ONLY_DEV"], []));
    expect(await runCli(["env", "diff", DEV, PROD], drifted.layer)).toBe(0);
    const driftNotices = drifted.errors.filter((line) =>
      line.includes("read sequentially, not atomically"),
    );
    expect(driftNotices).toHaveLength(1);
    expect(driftNotices[0]).toContain(
      "run this again to confirm before filling them in with a push",
    );
    // The advice is not mixed into stdout (the diff list)
    expect(drifted.logs.some((line) => line.includes("read sequentially, not atomically"))).toBe(
      false,
    );

    // **Never stay silent at zero diff**: a deletion landing after the first
    // read is reported as "present on both" and ends with zero diff = a real
    // diff is missed — that conclusion is exactly the one that can be overturned
    const clean = await startEnv(await handlersFor(["SAME"], ["SAME"]));
    expect(await runCli(["env", "diff", DEV, PROD], clean.layer)).toBe(0);
    const cleanNotices = clean.errors.filter((line) =>
      line.includes("read sequentially, not atomically"),
    );
    expect(cleanNotices).toHaveLength(1);
    expect(cleanNotices[0]).toContain(
      "Before treating zero differences as proof the environments are in sync",
    );
    expect(cleanNotices[0]).not.toContain("before filling them in with a push");
  });

  it("terminal-neutralizes the environment ID too (EnvironmentId is not branded)", async () => {
    // `EnvironmentId` is an alias of Schema.String.check, so an unverified
    // string can be assigned as-is (the type does not enforce validation). The
    // CLI side goes through requireEnvironmentId, but this directly pins that
    // the display side does not lean on that invariant
    const env = await makeTestEnv();
    await Effect.runPromise(
      reportEnvironmentDiff({
        firstEnvironmentId: "\u001b[2Kdev" as EnvironmentId,
        secondEnvironmentId: "prod\u0007" as EnvironmentId,
        onlyInFirst: [{ name: "ONLY_DEV", declared: false, required: "none" }],
        onlyInSecond: [],
        contractMismatches: [],
        shared: 0,
      }).pipe(Effect.provide(env.layer)),
    );
    const output = [...env.logs, ...env.errors].join("\n");
    expect(output).not.toContain("\u001b");
    expect(output).not.toContain("\u0007");
    expect(env.logs).toContain("Variables only in environment \uFFFD[2Kdev: 1");
    expect(env.logs).toContain(
      "Synced and verified: environment \uFFFD[2Kdev = 1 variable / environment prod\uFFFD = 0 variables",
    );
  });

  it("a warning terminal-neutralizes both the environment-ID label and the body", async () => {
    const env = await makeTestEnv();
    await Effect.runPromise(
      // The environment ID is not necessarily verified even as EnvironmentId,
      // and the warning body is not necessarily neutralized by its future
      // producers either — the assembled line goes through as a whole
      reportEnvironmentWarnings("\u001b[2Kprod" as EnvironmentId, [
        "変数 v1\u0007 の名前が not NFC-normalized", // english-exempt: non-ASCII fixture data exercising warning-text neutralization
      ]).pipe(Effect.provide(env.layer)),
    );
    expect(env.errors).toEqual([
      "Warning: environment \uFFFD[2Kprod: 変数 v1\uFFFD の名前が not NFC-normalized", // english-exempt: non-ASCII fixture asserting warning-text neutralization
    ]);
  });

  it("commits the environment-level floor but never fabricates the value floor / rule (c) pull criterion (M1-A3)", async () => {
    const env = await startEnv(await handlersFor(["ONLY_DEV"], ["ONLY_PROD"]));

    expect(await runCli(["env", "diff", DEV, PROD], env.layer)).toBe(0);
    const floor = await loadFloor(env);
    expect(floor.chainHead).toEqual({
      seq: chain.entries.length,
      hashHex: chain.hashes[chain.entries.length - 1],
    });
    // The verified environment-level observation (meta · manifest ·
    // coordinate (ii)) is joined (§6.3's recording rule — a fact that verified
    // successfully is always joined)
    const dev = floor.environments[DEV];
    expect(dev?.metaVersion).toBe(1);
    expect(dev?.manifest).toMatchObject({ manifestVersion: 1 });
    expect(dev?.observedEpoch).toBe(1);
    // Since no value was read, the value floor and pull criterion are never fabricated (the rule (c) norm)
    expect(dev?.pullEpoch).toBe(0);
    expect(dev?.variables).toEqual({});
  });

  it("the output is unchanged when the wire order changes (stabilized by name sort)", async () => {
    const forward = await startEnv(await handlersFor(["ALPHA", "MIKE", "ZULU"], ["SHARED"]));
    expect(await runCli(["env", "diff", DEV, PROD], forward.layer)).toBe(0);

    const reversed = await startEnv(await handlersFor(["ZULU", "MIKE", "ALPHA"], ["SHARED"]));
    expect(await runCli(["env", "diff", DEV, PROD], reversed.layer)).toBe(0);

    expect(reversed.logs).toEqual(forward.logs);
    expect(forward.logs).toContain("  ALPHA");
  });

  it("reports 0 items even between environments with no diff (exit code stays 0)", async () => {
    const env = await startEnv(await handlersFor(["A", "B"], ["B", "A"]));

    expect(await runCli(["env", "diff", DEV, PROD], env.layer)).toBe(0);
    expect(env.logs).toEqual([
      `Synced and verified: environment ${DEV} = 2 variables / environment ${PROD} = 2 variables`,
      `Variables only in environment ${DEV}: 0`,
      `Variables only in environment ${PROD}: 0`,
      "Variables in both with a differing schema contract: 0",
      "Variables in both: 2 (names match, nothing more — values were neither fetched nor decrypted, so whether the values match was not compared)",
    ]);
  });

  it("variable-name letter case is distinguished (byte-exact matching — AUTH_SPEC §12-1)", async () => {
    const env = await startEnv(await handlersFor(["API_KEY"], ["api_key"]));

    expect(await runCli(["env", "diff", DEV, PROD], env.layer)).toBe(0);
    expect(env.logs).toContain("  API_KEY");
    expect(env.logs).toContain("  api_key");
    expect(env.logs).toContain(
      "Variables in both: 0 (names match, nothing more — values were neither fetched nor decrypted, so whether the values match was not compared)",
    );
  });

  it("displays variable names with ANSI / BEL / newlines neutralized", async () => {
    const env = await startEnv(
      await handlersFor(["\u001b[31mEVIL\u0007", "LINE\nBREAK"], ["KEEP"]),
    );

    expect(await runCli(["env", "diff", DEV, PROD], env.layer)).toBe(0);
    expect(env.logs).toContain("  \uFFFD[31mEVIL\uFFFD");
    expect(env.logs).toContain("  LINE\uFFFDBREAK");
    // No raw control character remains on any output line
    expect(env.logs.some((line) => /\p{Cc}/u.test(line))).toBe(false);
  });

  it("names that look identical but differ in normalization form are reported as distinct variables (NFC / NFD)", async () => {
    // On the terminal both look like "CAFÉ", but byte-exact they are
    // different. A parity check is exactly where this misunderstanding is
    // likely, so instead of treating them as equal, report them as a diff on
    // both sides, and attach the §12-1 SHOULD warning to the non-NFC side (detection stays in values.ts)
    const nfc = "CAF\u00C9";
    const nfd = "CAFE\u0301";
    expect(nfd.normalize("NFC")).toBe(nfc);
    const env = await startEnv([
      pullMetadataHandlerOf(DEV, devStatement, [await variableOf(DEV, "var-dev-0", nfc)]),
      pullMetadataHandlerOf(PROD, prodStatement, [await variableOf(PROD, "var-prod-0", nfd)]),
    ]);

    expect(await runCli(["env", "diff", DEV, PROD], env.layer)).toBe(0);
    expect(env.logs).toContain(`  ${nfc}`);
    expect(env.logs).toContain(`  ${nfd}`);
    expect(env.logs).toContain(
      "Variables in both: 0 (names match, nothing more — values were neither fetched nor decrypted, so whether the values match was not compared)",
    );
    // The warning fires only on the side that distributed the non-NFC name
    const warnings = env.errors.filter((line) => line.includes("not NFC-normalized"));
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain(`Warning: environment ${PROD}: `);
  });

  it("warnings for both environments are labeled by environment ID (identical wording must not fold away)", async () => {
    // A non-NFC name (E + combining acute). Place the same variableId and same
    // name in both environments and the warning wording matches exactly —
    // folding by set would silently erase one side's fact
    const nonNfc = "CAFE\u0301";
    const dev = [await variableOf(DEV, "var-nfc", nonNfc)];
    const prod = [await variableOf(PROD, "var-nfc", nonNfc)];
    const env = await startEnv([
      pullMetadataHandlerOf(DEV, devStatement, dev),
      pullMetadataHandlerOf(PROD, prodStatement, prod),
    ]);

    expect(await runCli(["env", "diff", DEV, PROD], env.layer)).toBe(0);
    const warnings = env.errors.filter((line) => line.includes("not NFC-normalized"));
    expect(warnings).toHaveLength(2);
    expect(warnings[0]).toContain(`Warning: environment ${DEV}: `);
    expect(warnings[1]).toContain(`Warning: environment ${PROD}: `);
  });

  it("hands the view the first pull advanced to the second pull", async () => {
    // The chain is genesis (1) → create dev (2) → create prod (3). At sync
    // time only 2 entries are distributed, so prod does not yet exist in our view
    const dev = [await variableOf(DEV, "var-dev-0", "ONLY_DEV", 3)];
    const prod = [await variableOf(PROD, "var-prod-0", "ONLY_PROD")];
    const env = await startEnv(
      [
        pullMetadataHandlerOf(DEV, devStatement, dev),
        pullMetadataHandlerOf(PROD, prodStatement, prod),
      ],
      [2, 3],
    );

    // dev's statement is bound to a head beyond our view (seq 3), so the first
    // pull advances the view to 3 entries via the §6.3-2b bounded resync.
    // Without handing that view to the second pull, prod would be compared as
    // an environment "that does not exist on the chain" and the comparison would be against different histories
    expect(await runCli(["env", "diff", DEV, PROD], env.layer)).toBe(0);
    expect(env.errors.some((line) => line.includes("does not exist on the chain"))).toBe(false);
    expect(env.logs).toContain("  ONLY_DEV");
    expect(env.logs).toContain("  ONLY_PROD");
    // The advanced head is kept in the floor. Staying at the openProject-time
    // head (seq 2) would leave rollbacks into that gap undetectable on later
    // runs (pull / push write the same head)
    const floor = await loadFloor(env);
    expect(floor.chainHead).toEqual({ seq: 3, hashHex: chain.hashes[2] });
    // No value was read, so no value floor is built (environment-level observation only — M1-A3)
    expect(floor.environments[DEV]?.pullEpoch).toBe(0);
    expect(floor.environments[DEV]?.variables).toEqual({});
  });

  it("what stays in the floor is the head of the final view including the second pull", async () => {
    // The two pulls each trigger a bounded resync: seq 2 →(dev)→ 3 →(prod)→ 4.
    // Stopping at the first view would fail to leave the second's established advance in the floor
    const dev = [await variableOf(DEV, "var-dev-0", "ONLY_DEV", 3)];
    const prod = [await variableOf(PROD, "var-prod-0", "ONLY_PROD", 4)];
    const env = await startEnv(
      [
        pullMetadataHandlerOf(DEV, devStatement, dev),
        pullMetadataHandlerOf(PROD, prodStatement, prod),
      ],
      [2, 3, 4],
    );

    expect(await runCli(["env", "diff", DEV, PROD], env.layer)).toBe(0);
    const floor = await loadFloor(env);
    expect(floor.chainHead).toEqual({ seq: 4, hashHex: chain.hashes[3] });
  });

  it("even when the second pull fails, the advance the first established stays in the floor", async () => {
    // pull / push write the head to the floor per response. Writing it lumped
    // at the end would throw away the first pull's bounded-resync result on a run where the second fails
    const dev = [await variableOf(DEV, "var-dev-0", "ONLY_DEV", 3)];
    const env = await startEnv(
      [
        pullMetadataHandlerOf(DEV, devStatement, dev),
        // The second environment cannot be fetched (standing in for network failure / authorization failure)
        onRequest("GET", `/projects/${chain.projectId}/environments/${PROD}/pull/metadata`, () => ({
          status: 503,
          json: { error: "unavailable" },
        })),
      ],
      [2, 3],
    );

    // The run itself fails (1)
    expect(await runCli(["env", "diff", DEV, PROD], env.layer)).toBe(1);
    const floor = await loadFloor(env);
    // The record shows the first pull advanced to seq 3 (never left at the
    // openProject-time seq 2)
    expect(floor.chainHead).toEqual({ seq: 3, hashHex: chain.hashes[2] });
  });

  it("even when the second pull fails, the warnings collected by the first are always emitted", async () => {
    // Carrying warnings in the return value and emitting them lumped at the
    // end would silently lose them on the failure path (env-rotate explicitly avoids the same shape)
    const dev = [await variableOf(DEV, "var-dev-0", "CAFE\u0301")];
    const env = await startEnv([
      pullMetadataHandlerOf(DEV, devStatement, dev),
      onRequest("GET", `/projects/${chain.projectId}/environments/${PROD}/pull/metadata`, () => ({
        status: 503,
        json: { error: "unavailable" },
      })),
    ]);

    expect(await runCli(["env", "diff", DEV, PROD], env.layer)).toBe(1);
    const warnings = env.errors.filter((line) => line.includes("not NFC-normalized"));
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain(`Warning: environment ${DEV}: `);
  });

  it("runnable on a terminal without a device key (it never decrypts, so it is not required)", async () => {
    const env = await startEnv(await handlersFor(["ONLY_DEV"], []));
    // A state where a session exists but no device key is in the keychain
    // (a run via MARUHI_TOKEN, or a terminal that has not yet recovered its key)
    env.keychain.delete(masterKeyEntryName(env.origin, owner.userId));

    expect(await runCli(["env", "diff", DEV, PROD], env.layer)).toBe(0);
    expect(env.logs).toContain("  ONLY_DEV");
    expect(env.errors.some((line) => line.includes("No device key"))).toBe(false);
  });

  describe("schema awareness (S4 — the required axis of design doc §1-5)", () => {
    /** A layout-v2 statement (status / schema specified form). */
    function schemaVariableOf(
      environmentId: string,
      variableId: string,
      name: string,
      status: "active" | "declared",
      schema: { varType: "" | "string" | "number" | "boolean" | "url"; required: boolean },
      description = "",
    ): Promise<WireDistributedVariableStatement> {
      return statementFor({
        projectId: chain.projectId,
        environmentId,
        variableId,
        name,
        author: owner,
        head: headOf(chain, 1),
        status,
        schema: { varType: schema.varType, required: schema.required, description },
      });
    }

    const SECRET_HINT = "Primary endpoint of the shop";

    it("annotates a variable present on only one side with required and declared notes (never shows description)", async () => {
      const dev = [
        await schemaVariableOf(
          DEV,
          "var-req-decl",
          "REQ_DECL",
          "declared",
          { varType: "url", required: true },
          SECRET_HINT,
        ),
        await schemaVariableOf(DEV, "var-opt-decl", "OPT_DECL", "declared", {
          varType: "",
          required: false,
        }),
        await variableOf(DEV, "var-v1", "V1_ONLY"),
      ];
      const env = await startEnv([
        pullMetadataHandlerOf(DEV, devStatement, dev),
        pullMetadataHandlerOf(PROD, prodStatement, []),
      ]);
      expect(await runCli(["env", "diff", DEV, PROD], env.layer)).toBe(0);
      expect(env.logs).toContain("  REQ_DECL (required, declared — no value set)");
      expect(env.logs).toContain("  OPT_DECL (optional, declared — no value set)");
      // v1 (no schema column) stays name-only as before (never fabricate required)
      expect(env.logs).toContain("  V1_ONLY");
      // description is never shown in diff output (the §2 consumption-point
      // discipline), and the word "verified" is not used either (the §14.3 display discipline)
      const output = [...env.logs, ...env.errors].join("\n");
      expect(output).not.toContain(SECRET_HINT);
      expect(output.toLowerCase()).not.toContain("verified from");
    });

    it("reports required-contract / state disagreements even for names present on both sides (exit code stays 0)", async () => {
      const dev = [
        // A state disagreement (dev = set / prod = declared)
        await schemaVariableOf(DEV, "var-a", "SHARED_STATUS", "active", {
          varType: "url",
          required: true,
        }),
        // A required disagreement (dev = required / prod = optional)
        await schemaVariableOf(DEV, "var-b", "SHARED_REQ", "active", {
          varType: "",
          required: true,
        }),
        // v2 × v1 (prod has no schema column)
        await schemaVariableOf(DEV, "var-c", "SHARED_V1", "active", {
          varType: "",
          required: true,
        }),
        // Full agreement (not reported)
        await schemaVariableOf(DEV, "var-d", "SHARED_SAME", "active", {
          varType: "",
          required: true,
        }),
      ];
      const prod = [
        await schemaVariableOf(
          PROD,
          "var-a2",
          "SHARED_STATUS",
          "declared",
          { varType: "url", required: true },
          SECRET_HINT,
        ),
        await schemaVariableOf(PROD, "var-b2", "SHARED_REQ", "active", {
          varType: "",
          required: false,
        }),
        await variableOf(PROD, "var-c2", "SHARED_V1"),
        await schemaVariableOf(PROD, "var-d2", "SHARED_SAME", "active", {
          varType: "",
          required: true,
        }),
      ];
      const env = await startEnv([
        pullMetadataHandlerOf(DEV, devStatement, dev),
        pullMetadataHandlerOf(PROD, prodStatement, prod),
      ]);
      expect(await runCli(["env", "diff", DEV, PROD], env.layer)).toBe(0);
      expect(env.logs).toContain("Variables in both with a differing schema contract: 3");
      expect(env.logs).toContain(
        `  SHARED_STATUS — ${DEV}: required / ${PROD}: required, declared — no value set`,
      );
      expect(env.logs).toContain(`  SHARED_REQ — ${DEV}: required / ${PROD}: optional`);
      expect(env.logs).toContain(`  SHARED_V1 — ${DEV}: required / ${PROD}: no schema (layout v1)`);
      expect(env.logs.some((line) => line.includes("SHARED_SAME —"))).toBe(false);
      // The present-on-both count stays as before (contract disagreements are a subset of shared names)
      expect(env.logs).toContain(
        "Variables in both: 4 (names match, nothing more — values were neither fetched nor decrypted, so whether the values match was not compared)",
      );
      expect([...env.logs, ...env.errors].join("\n")).not.toContain(SECRET_HINT);
    });
  });

  describe("usage mistakes (usage error = 2)", () => {
    it("rejects a run that names only one environment (before any communication)", async () => {
      const env = await startEnv([]);

      expect(await runCli(["env", "diff", DEV], env.layer)).toBe(2);
      expect(env.errors).toEqual([
        "Usage: maruhi env diff [flags] <environment-id> <other-environment-id>",
        "maruhi: Missing positional argument other-environment-id",
      ]);
      expect(lastServer().requests).toEqual([]);
    });

    it("rejects a run that writes the same environment ID twice (never shows the given value)", async () => {
      const env = await startEnv([]);

      expect(await runCli(["env", "diff", DEV, DEV], env.layer)).toBe(2);
      expect(env.errors).toEqual([
        "maruhi: The same environment ID was written twice. Specify two different environments to compare",
      ]);
      expect(lastServer().requests).toEqual([]);
    });

    it("applies the format check to the second environment ID too (never shows the given value)", async () => {
      const env = await startEnv([]);

      expect(await runCli(["env", "diff", DEV, "not a valid id"], env.layer)).toBe(2);
      expect(env.errors).toEqual([
        "maruhi: Invalid environment ID (must start with an alphanumeric character, followed by up to 63 alphanumerics, _ or -. Example: `maruhi env diff dev prod`)",
      ]);
      expect(env.errors[0]).not.toContain("not a valid id");
      expect(lastServer().requests).toEqual([]);
    });

    it("refuses create-only --name on diff", async () => {
      const env = await startEnv([]);

      expect(await runCli(["env", "diff", DEV, PROD, "--name", "x"], env.layer)).toBe(2);
      expect(env.errors).toEqual([
        "Usage: maruhi env diff [flags] <environment-id> <other-environment-id>",
        "maruhi: Unknown flag (flags this command accepts: --server --project --help --version)",
      ]);
      expect(lastServer().requests).toEqual([]);
    });

    it("refuses rotate-only --reason / --new-epoch on diff", async () => {
      const withReason = await startEnv([]);
      expect(await runCli(["env", "diff", DEV, PROD, "--reason", "x"], withReason.layer)).toBe(2);
      expect(withReason.errors).toEqual([
        "Usage: maruhi env diff [flags] <environment-id> <other-environment-id>",
        "maruhi: Unknown flag (flags this command accepts: --server --project --help --version)",
      ]);

      const withEpoch = await startEnv([]);
      expect(await runCli(["env", "diff", DEV, PROD, "--new-epoch"], withEpoch.layer)).toBe(2);
      expect(withEpoch.errors).toEqual([
        "Usage: maruhi env diff [flags] <environment-id> <other-environment-id>",
        "maruhi: Unknown flag (flags this command accepts: --server --project --help --version)",
      ]);
      // The negated form (`--no-new-epoch`) is also refused as a spelling of the same option
      const negated = await startEnv([]);
      expect(await runCli(["env", "diff", DEV, PROD, "--no-new-epoch"], negated.layer)).toBe(2);
      expect(negated.errors).toEqual([
        "Usage: maruhi env diff [flags] <environment-id> <other-environment-id>",
        "maruhi: Unknown flag (flags this command accepts: --server --project --help --version)",
      ]);
    });

    it("the diff-only third positional arg is an extra argument on create / rotate", async () => {
      // create is a nested subcommand, so we can say "the only positional it
      // takes is environment-id"
      const created = await startEnv([]);
      expect(await runCli(["env", "create", DEV, PROD], created.layer)).toBe(2);
      expect(created.errors.join("\n")).toContain("Unexpected extra arguments (1");
      expect(created.errors.join("\n")).toContain(
        "maruhi env create only takes these positional arguments: environment-id",
      );

      // On rotate too, the third is an extra argument
      const rotated = await startEnv([]);
      expect(await runCli(["env", "rotate", DEV, PROD], rotated.layer)).toBe(2);
      expect(rotated.errors.join("\n")).toContain("Unexpected extra arguments (1");
    });

    it("does not drop the third arg on an unknown operation (reports the operation-name mistake first)", async () => {
      const env = await startEnv([]);

      expect(await runCli(["env", "bogus", DEV, PROD], env.layer)).toBe(2);
      expect(env.errors).toEqual([
        "Usage: maruhi env <subcommand> [flags]",
        "maruhi: Unknown subcommand (expected one of: create | rotate | diff)",
      ]);
      expect(lastServer().requests).toEqual([]);
    });

    it("unknown operation + an empty positional arg reports the operation-name mistake first (usage error = 2)", async () => {
      const env = await startEnv([]);

      // Because subcommand resolution runs before positional-arg checking,
      // the unknown operation is reported first (fixing it and re-running
      // then shows the empty-positional mistake). The exit code is the same 2
      expect(await runCli(["env", "bogus", DEV, " "], env.layer)).toBe(2);
      expect(env.errors).toEqual([
        "Usage: maruhi env <subcommand> [flags]",
        "maruhi: Unknown subcommand (expected one of: create | rotate | diff)",
      ]);
      expect(lastServer().requests).toEqual([]);
    });
  });
});
