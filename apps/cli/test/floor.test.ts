// Tests for the local floor (CRYPTO_SPEC §6.3 — append-only observation log
// + fold).
//
// First half: the floor store (floor-log.ts) in isolation — append + fold's
// monotone join, typed conflicts (both pieces of evidence for same-coordinate
// differing-hash observations are preserved), self-recovery from a torn tail
// record, snapshot-record compaction, intents / resolutions, and migration
// from the legacy storage form. Concurrent appends are pinned as: "two store
// instances appending concurrently leave both observations in the log, a
// same-version differing-hash pair becomes a both-evidence typed conflict,
// and concurrent commits of different variables union". The second half
// (wiring tests) lives in floor-detection.test.ts.

import { appendFile, mkdir, mkdtemp, readdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Effect } from "effect";
import { beforeEach, describe, expect, it } from "vitest";

import { cliError } from "../src/errors.ts";
import { makeFloorHandle } from "../src/floor-check.ts";
import { makeFileFloorStore } from "../src/floor-log.ts";
import type { EnvironmentFloor, FloorStoreShape } from "../src/floor.ts";

const PROJECT_ID = "ab".repeat(32);
const HASH_A = "11".repeat(32);
const HASH_B = "22".repeat(32);
const HASH_C = "33".repeat(32);
const HASH_D = "44".repeat(32);

function envFloor(overrides?: Partial<EnvironmentFloor>): EnvironmentFloor {
  return {
    pullEpoch: 2,
    observedEpoch: 2,
    metaVersion: 1,
    metaSigHashHex: HASH_A,
    variables: {
      va: {
        status: "active",
        version: 3,
        epoch: 2,
        valueSigHashHex: HASH_B,
        metaVersion: 1,
        metaSigHashHex: HASH_C,
      },
      vb: { status: "deleted", metaVersion: 2, metaSigHashHex: HASH_C },
    },
    ...overrides,
  };
}

describe("makeFileFloorStore (append-only log + fold)", () => {
  let dir: string;
  let store: FloorStoreShape;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "maruhi-floor-test-"));
    store = makeFileFloorStore(dir);
  });

  const load = () => Effect.runPromise(store.load(PROJECT_ID));
  const logPath = () => join(dir, `${PROJECT_ID}.jsonl`);

  it("distinguishes missing file = missing (first run) from a non-empty file with zero readable records = corrupt", async () => {
    expect(await load()).toEqual({ floor: null, state: "missing", droppedRecords: 0 });
    await Effect.runPromise(store.commitHead(PROJECT_ID, { seq: 1, hashHex: HASH_A }));
    expect((await load()).state).toBe("loaded");
    await writeFile(logPath(), "{broken\nnot-json-either\n");
    expect(await load()).toEqual({ floor: null, state: "corrupt", droppedRecords: 2 });
  });

  it("counts partially unreadable lines as droppedRecords (the caller's warning material)", async () => {
    await Effect.runPromise(store.commitHead(PROJECT_ID, { seq: 1, hashHex: HASH_A }));
    await appendFile(logPath(), "\n{torn-line-without-newline");
    const result = await load();
    expect(result.state).toBe("loaded");
    expect(result.droppedRecords).toBe(1);
    expect(result.floor?.chainHead).toEqual({ seq: 1, hashHex: HASH_A });
  });

  it("retires droppedRecords on compaction (doesn't warn forever about an old torn line)", async () => {
    const compacting = makeFileFloorStore(dir, { compactionThreshold: 2 });
    await Effect.runPromise(compacting.commitHead(PROJECT_ID, { seq: 1, hashHex: HASH_A }));
    await appendFile(logPath(), "\n{torn-line-without-newline");
    expect((await load()).droppedRecords).toBe(1);
    // Once enough snapshots accumulate past the threshold, the torn line
    // enters the folded prefix and is no longer counted (only records past
    // the fold point are warned about)
    for (let index = 0; index < 4; index += 1) {
      await Effect.runPromise(
        compacting.commitHead(PROJECT_ID, { seq: 2 + index, hashHex: HASH_B }),
      );
    }
    const result = await load();
    expect(result.state).toBe("loaded");
    expect(result.droppedRecords).toBe(0);
  });

  it("commitHead only advances the head (a seq-regressing observation loses the join)", async () => {
    await Effect.runPromise(store.commitHead(PROJECT_ID, { seq: 5, hashHex: HASH_A }));
    await Effect.runPromise(store.commitHead(PROJECT_ID, { seq: 3, hashHex: HASH_B }));
    const result = await load();
    expect(result.floor?.chainHead).toEqual({ seq: 5, hashHex: HASH_A });
  });

  it("commitPull performs the environment-floor join and head advance in a single appended record", async () => {
    await Effect.runPromise(
      store.commitPull(PROJECT_ID, {
        chainHead: { seq: 3, hashHex: HASH_A },
        environmentId: "prod",
        environment: envFloor(),
      }),
    );
    await Effect.runPromise(
      store.commitPull(PROJECT_ID, {
        chainHead: { seq: 4, hashHex: HASH_B },
        environmentId: "dev",
        environment: envFloor({ pullEpoch: 1, observedEpoch: 1, variables: {} }),
      }),
    );
    const result = await load();
    expect(result.floor?.chainHead).toEqual({ seq: 4, hashHex: HASH_B });
    // The other environment's floor is preserved (the join is per-
    // environment)
    expect(Object.keys(result.floor?.environments ?? {}).toSorted()).toEqual(["dev", "prod"]);
    expect(result.floor?.environments["prod"]?.variables["va"]).toMatchObject({ version: 3 });
  });

  it("commitPush advances the variable floor and does not move pullEpoch (rule (c)'s baseline)", async () => {
    await Effect.runPromise(
      store.commitPull(PROJECT_ID, {
        chainHead: { seq: 3, hashHex: HASH_A },
        environmentId: "prod",
        environment: envFloor({ pullEpoch: 2 }),
      }),
    );
    await Effect.runPromise(
      store.commitPush(PROJECT_ID, {
        chainHead: { seq: 3, hashHex: HASH_A },
        environmentId: "prod",
        variableId: "va",
        variable: {
          status: "active",
          version: 4,
          epoch: 3,
          valueSigHashHex: HASH_C,
          metaVersion: 1,
          metaSigHashHex: HASH_C,
        },
      }),
    );
    const result = await load();
    const environment = result.floor?.environments["prod"];
    expect(environment?.pullEpoch).toBe(2);
    expect(environment?.variables["va"]).toMatchObject({ version: 4, epoch: 3 });
    // Other variable floors are preserved
    expect(environment?.variables["vb"]).toMatchObject({ status: "deleted" });
  });

  it("commitPush without an environment floor does not fabricate the rule (c) baseline (a partial observation of the variable floor only)", async () => {
    await Effect.runPromise(
      store.commitPush(PROJECT_ID, {
        chainHead: { seq: 2, hashHex: HASH_A },
        environmentId: "prod",
        variableId: "va",
        variable: { status: "deleted", metaVersion: 1, metaSigHashHex: HASH_A },
      }),
    );
    const result = await load();
    const environment = result.floor?.environments["prod"];
    expect(result.floor?.chainHead?.seq).toBe(2);
    // Each coordinate is an independent semilattice: the pull baseline and
    // environment meta stay bottom while only the variable floor stands
    expect(environment?.pullEpoch).toBe(0);
    expect(environment?.metaVersion).toBe(0);
    expect(environment?.variables["va"]).toMatchObject({ status: "deleted" });
  });

  it("commitMetadata joins only the environment level (fabricates no value floor, doesn't move the pull baseline)", async () => {
    await Effect.runPromise(
      store.commitMetadata(PROJECT_ID, {
        chainHead: { seq: 3, hashHex: HASH_A },
        environmentId: "prod",
        observedEpoch: 4,
        metaVersion: 2,
        metaSigHashHex: HASH_B,
        manifest: { manifestVersion: 3, epoch: 4, manifestSigHashHex: HASH_C },
      }),
    );
    const result = await load();
    const environment = result.floor?.environments["prod"];
    expect(environment?.pullEpoch).toBe(0);
    expect(environment?.observedEpoch).toBe(4);
    expect(environment?.metaVersion).toBe(2);
    expect(environment?.manifest).toEqual({
      manifestVersion: 3,
      epoch: 4,
      manifestSigHashHex: HASH_C,
    });
    expect(environment?.variables).toEqual({});
  });

  it("commitManifest advances only the manifest floor and the environment-level epoch observation (coordinate (ii))", async () => {
    await Effect.runPromise(
      store.commitPull(PROJECT_ID, {
        chainHead: { seq: 3, hashHex: HASH_A },
        environmentId: "prod",
        environment: envFloor({
          pullEpoch: 2,
          observedEpoch: 2,
          manifest: { manifestVersion: 1, epoch: 2, manifestSigHashHex: HASH_A },
        }),
      }),
    );
    await Effect.runPromise(
      store.commitManifest(PROJECT_ID, {
        chainHead: { seq: 4, hashHex: HASH_B },
        environmentId: "prod",
        manifest: { manifestVersion: 2, epoch: 3, manifestSigHashHex: HASH_B },
      }),
    );
    const result = await load();
    const environment = result.floor?.environments["prod"];
    expect(environment?.manifest).toMatchObject({ manifestVersion: 2, epoch: 3 });
    // The manifest's epoch also joins into coordinate (ii)
    // (observedEpoch)
    expect(environment?.observedEpoch).toBe(3);
    // Rule (c)'s pull baseline does not move (a chain sync or acceptance
    // check alone never advances it)
    expect(environment?.pullEpoch).toBe(2);
    // The variable floor is unchanged
    expect(environment?.variables["va"]).toMatchObject({ version: 3 });
  });

  describe("concurrent appends from 2 store instances (= 2 processes)", () => {
    it("concurrent commits of different variables union and neither observation is lost", async () => {
      // The shape where 2 processes depart from the same old floor and
      // commit independently
      const storeA = makeFileFloorStore(dir);
      const storeB = makeFileFloorStore(dir);
      await Effect.runPromise(
        storeA.commitPush(PROJECT_ID, {
          chainHead: { seq: 3, hashHex: HASH_A },
          environmentId: "prod",
          variableId: "va",
          variable: {
            status: "active",
            version: 1,
            epoch: 1,
            valueSigHashHex: HASH_A,
            metaVersion: 1,
            metaSigHashHex: HASH_A,
          },
        }),
      );
      await Effect.runPromise(
        storeB.commitPush(PROJECT_ID, {
          chainHead: { seq: 3, hashHex: HASH_A },
          environmentId: "prod",
          variableId: "vb",
          variable: {
            status: "active",
            version: 2,
            epoch: 1,
            valueSigHashHex: HASH_B,
            metaVersion: 1,
            metaSigHashHex: HASH_B,
          },
        }),
      );
      const result = await load();
      const environment = result.floor?.environments["prod"];
      expect(environment?.variables["va"]).toMatchObject({ version: 1 });
      expect(environment?.variables["vb"]).toMatchObject({ version: 2 });
      expect(result.floor?.conflicts).toEqual([]);
    });

    it("concurrent commits of same-version differing-hash leave both observations in the log and become a both-evidence typed conflict", async () => {
      const storeA = makeFileFloorStore(dir);
      const storeB = makeFileFloorStore(dir);
      const variable = (hash: string) =>
        ({
          status: "active",
          version: 3,
          epoch: 1,
          valueSigHashHex: hash,
          metaVersion: 1,
          metaSigHashHex: HASH_A,
        }) as const;
      await Effect.runPromise(
        storeA.commitPush(PROJECT_ID, {
          chainHead: { seq: 3, hashHex: HASH_A },
          environmentId: "prod",
          variableId: "va",
          variable: variable(HASH_C),
        }),
      );
      // A later-landing same-version differing-hash does not "win last" — it
      // fails as a typed conflict (overwriting evidence is not expressible
      // in the storage form — append only)
      await expect(
        Effect.runPromise(
          storeB.commitPush(PROJECT_ID, {
            chainHead: { seq: 3, hashHex: HASH_A },
            environmentId: "prod",
            variableId: "va",
            variable: variable(HASH_D),
          }),
        ),
      ).rejects.toThrow("contradict each other");
      // Both observations remain in the log (append-only — the earlier
      // evidence doesn't disappear)
      const raw = await readFile(logPath(), "utf8");
      expect(raw).toContain(HASH_C);
      expect(raw).toContain(HASH_D);
      // fold surfaces the both-evidence typed conflict
      const result = await load();
      expect(result.floor?.conflicts).toHaveLength(1);
      const conflict = result.floor?.conflicts[0];
      expect(conflict).toMatchObject({ kind: "value", environmentId: "prod", variableId: "va" });
      expect([conflict?.firstHashHex, conflict?.secondHashHex].toSorted()).toEqual(
        [HASH_C, HASH_D].toSorted(),
      );
    });

    it("different hashes at the same manifestVersion are a typed conflict too (rule (b)'s merge semantics)", async () => {
      await Effect.runPromise(
        store.commitManifest(PROJECT_ID, {
          chainHead: { seq: 3, hashHex: HASH_A },
          environmentId: "prod",
          manifest: { manifestVersion: 2, epoch: 1, manifestSigHashHex: HASH_C },
        }),
      );
      await expect(
        Effect.runPromise(
          store.commitManifest(PROJECT_ID, {
            chainHead: { seq: 3, hashHex: HASH_A },
            environmentId: "prod",
            manifest: { manifestVersion: 2, epoch: 1, manifestSigHashHex: HASH_D },
          }),
        ),
      ).rejects.toThrow("manifestVersion");
      const result = await load();
      expect(result.floor?.conflicts[0]).toMatchObject({ kind: "manifest" });
    });

    it("different chain-head hashes at the same seq are a fork typed conflict", async () => {
      await Effect.runPromise(store.commitHead(PROJECT_ID, { seq: 5, hashHex: HASH_A }));
      await expect(
        Effect.runPromise(store.commitHead(PROJECT_ID, { seq: 5, hashHex: HASH_B })),
      ).rejects.toThrow("fork");
      const result = await load();
      expect(result.floor?.conflicts[0]).toMatchObject({ kind: "chain-head" });
    });

    it("an active observation with a metaVersion beyond deleted (terminal) is an undeletion typed conflict", async () => {
      await Effect.runPromise(
        store.commitPush(PROJECT_ID, {
          chainHead: { seq: 3, hashHex: HASH_A },
          environmentId: "prod",
          variableId: "va",
          variable: { status: "deleted", metaVersion: 2, metaSigHashHex: HASH_A },
        }),
      );
      await expect(
        Effect.runPromise(
          store.commitPush(PROJECT_ID, {
            chainHead: { seq: 3, hashHex: HASH_A },
            environmentId: "prod",
            variableId: "va",
            variable: {
              status: "active",
              version: 1,
              epoch: 1,
              valueSigHashHex: HASH_B,
              metaVersion: 3,
              metaSigHashHex: HASH_B,
            },
          }),
        ),
      ).rejects.toThrow("undeletion");
      // The representative stays deleted (the terminal state isn't
      // overwritten by active)
      const result = await load();
      expect(result.floor?.environments["prod"]?.variables["va"]).toMatchObject({
        status: "deleted",
      });
    });

    it("a delayed landing of an older pull merely loses the monotone join — no evidence is lost", async () => {
      // Process B has already committed a newer generation (pullEpoch 3,
      // va v5)
      await Effect.runPromise(
        store.commitPull(PROJECT_ID, {
          chainHead: { seq: 5, hashHex: HASH_B },
          environmentId: "prod",
          environment: envFloor({
            pullEpoch: 3,
            observedEpoch: 3,
            metaVersion: 2,
            variables: {
              va: {
                status: "active",
                version: 5,
                epoch: 3,
                valueSigHashHex: HASH_B,
                metaVersion: 2,
                metaSigHashHex: HASH_B,
              },
            },
          }),
        }),
      );
      // Process A's older pull (pullEpoch 2, va v3, with vb's tombstone)
      // lands later
      await Effect.runPromise(
        store.commitPull(PROJECT_ID, {
          chainHead: { seq: 3, hashHex: HASH_A },
          environmentId: "prod",
          environment: envFloor(),
        }),
      );
      const result = await load();
      const environment = result.floor?.environments["prod"];
      expect(result.floor?.chainHead).toEqual({ seq: 5, hashHex: HASH_B });
      expect(environment?.pullEpoch).toBe(3);
      expect(environment?.metaVersion).toBe(2);
      expect(environment?.variables["va"]).toMatchObject({ version: 5, epoch: 3 });
      // A variable present on only one side (vb) is kept by the union
      expect(environment?.variables["vb"]).toMatchObject({ status: "deleted" });
      expect(result.floor?.conflicts).toEqual([]);
    });
  });

  describe("self-recovery from a torn tail record", () => {
    it("a torn line (a crashed partial write) is ignored by fold and doesn't corrupt later appends", async () => {
      await Effect.runPromise(
        store.commitPull(PROJECT_ID, {
          chainHead: { seq: 3, hashHex: HASH_A },
          environmentId: "prod",
          environment: envFloor(),
        }),
      );
      // The shape of a concurrent process crashing mid-write (a partial
      // line with no trailing newline)
      await appendFile(logPath(), '{"r":"pull","head":{"seq":9');
      const afterTear = await load();
      expect(afterTear.state).toBe("loaded");
      expect(afterTear.floor?.environments["prod"]?.variables["va"]).toMatchObject({ version: 3 });
      // The next append prepends a newline to isolate the torn line — the
      // new observation lands correctly
      await Effect.runPromise(
        store.commitPush(PROJECT_ID, {
          chainHead: { seq: 4, hashHex: HASH_B },
          environmentId: "prod",
          variableId: "va",
          variable: {
            status: "active",
            version: 4,
            epoch: 2,
            valueSigHashHex: HASH_D,
            metaVersion: 1,
            metaSigHashHex: HASH_C,
          },
        }),
      );
      const result = await load();
      expect(result.floor?.environments["prod"]?.variables["va"]).toMatchObject({ version: 4 });
      expect(result.floor?.chainHead).toEqual({ seq: 4, hashHex: HASH_B });
    });
  });

  describe("intent / resolution(journal-before-send)", () => {
    const intentInput = {
      op: "rotate_epoch" as const,
      environmentId: "prod",
      epoch: 2,
      dekCommitmentHex: HASH_C,
      variableId: null,
      manifestVersion: 2,
      manifestSigHashHex: HASH_D,
      declaredHead: { seq: 3, hashHex: HASH_A },
    };

    it("an unresolved intent is surfaced by fold as 'needs reconciliation' and a resolution closes it", async () => {
      const id = await Effect.runPromise(store.appendIntent(PROJECT_ID, intentInput));
      let result = await load();
      expect(result.floor?.intents).toHaveLength(1);
      expect(result.floor?.intents[0]).toMatchObject({
        id,
        op: "rotate_epoch",
        environmentId: "prod",
        epoch: 2,
        dekCommitmentHex: HASH_C,
      });
      await Effect.runPromise(store.resolveIntent(PROJECT_ID, id, "accepted"));
      result = await load();
      expect(result.floor?.intents).toEqual([]);
    });

    it("an intent does not enter the join lattice (moves no floor observation coordinate)", async () => {
      await Effect.runPromise(store.appendIntent(PROJECT_ID, intentInput));
      const result = await load();
      expect(result.floor?.chainHead).toBeNull();
      expect(result.floor?.environments).toEqual({});
    });
  });

  describe("compaction (appending snapshot records — never rewriting)", () => {
    it("past the threshold a snapshot is appended; the fold result is unchanged and folded conflict evidence isn't lost", async () => {
      const compacting = makeFileFloorStore(dir, { compactionThreshold: 4 });
      // Create one conflict (pins that the evidence survives across the
      // snapshot)
      await Effect.runPromise(compacting.commitHead(PROJECT_ID, { seq: 5, hashHex: HASH_A }));
      await expect(
        Effect.runPromise(compacting.commitHead(PROJECT_ID, { seq: 5, hashHex: HASH_B })),
      ).rejects.toThrow("fork");
      // Stack observations past the threshold (4 records) — commits onto a
      // conflicted floor keep failing, but the appends themselves still
      // happen (evidence only ever grows)
      for (let index = 0; index < 5; index += 1) {
        await Effect.runPromise(
          Effect.ignore(compacting.commitHead(PROJECT_ID, { seq: 6 + index, hashHex: HASH_C })),
        );
      }
      const raw = await readFile(logPath(), "utf8");
      expect(raw).toContain('"r":"snapshot"');
      // After the snapshot lands, fold's semantics are unchanged (the
      // conflict doesn't disappear)
      const result = await load();
      expect(result.floor?.conflicts.some((conflict) => conflict.kind === "chain-head")).toBe(true);
      // No physical collection happens (append-only): as a stand-in check
      // that no torn rewrite occurred, verify all records still remain in
      // the log after the snapshot
      expect(raw).toContain(HASH_B);
    });

    it("folding only the records after the snapshot yields the same state (positional baseline + idempotent join)", async () => {
      const compacting = makeFileFloorStore(dir, { compactionThreshold: 2 });
      for (let index = 0; index < 4; index += 1) {
        await Effect.runPromise(
          compacting.commitPush(PROJECT_ID, {
            chainHead: { seq: index + 1, hashHex: HASH_A },
            environmentId: "prod",
            variableId: "va",
            variable: {
              status: "active",
              version: index + 1,
              epoch: 1,
              valueSigHashHex: HASH_B,
              metaVersion: 1,
              metaSigHashHex: HASH_C,
            },
          }),
        );
      }
      const result = await load();
      expect(result.floor?.environments["prod"]?.variables["va"]).toMatchObject({ version: 4 });
      expect(result.floor?.chainHead?.seq).toBe(4);
    });
  });

  describe("migration from the legacy storage form (a single JSON snapshot)", () => {
    const legacy = {
      v: 1,
      chainHead: { seq: 3, hashHex: HASH_A },
      environments: {
        prod: {
          pullEpoch: 2,
          metaVersion: 1,
          metaSigHashHex: HASH_A,
          manifest: { manifestVersion: 1, epoch: 2, manifestSigHashHex: HASH_B },
          variables: {
            va: {
              status: "active",
              version: 3,
              epoch: 2,
              valueSigHashHex: HASH_B,
              metaVersion: 1,
              metaSigHashHex: HASH_C,
            },
          },
        },
      },
    };

    it("compat-reads the legacy file (observedEpoch derived from known verified facts) and migrates to the log on the first append", async () => {
      await mkdir(dir, { recursive: true });
      await writeFile(join(dir, `${PROJECT_ID}.json`), JSON.stringify(legacy));
      const loaded = await load();
      expect(loaded.state).toBe("loaded");
      expect(loaded.floor?.environments["prod"]).toMatchObject({
        pullEpoch: 2,
        observedEpoch: 2,
        metaVersion: 1,
      });
      // The first append migrates the legacy state into the log as a
      // snapshot record
      await Effect.runPromise(store.commitHead(PROJECT_ID, { seq: 4, hashHex: HASH_B }));
      const raw = await readFile(logPath(), "utf8");
      expect(raw).toContain('"r":"snapshot"');
      const result = await load();
      expect(result.floor?.chainHead).toEqual({ seq: 4, hashHex: HASH_B });
      expect(result.floor?.environments["prod"]?.variables["va"]).toMatchObject({ version: 3 });
      // The legacy file remains as forensic material (append-only
      // discipline — don't delete it)
      const entries = await readdir(dir);
      expect(entries).toContain(`${PROJECT_ID}.json`);
    });

    it("distinguishes a corrupt legacy file as corrupt", async () => {
      await mkdir(dir, { recursive: true });
      await writeFile(join(dir, `${PROJECT_ID}.json`), "{broken");
      expect(await load()).toEqual({ floor: null, state: "corrupt", droppedRecords: 0 });
    });

    it("an empty .jsonl (a remnant crashed between open and write) does not hide a valid legacy form", async () => {
      // open("a") creates the file immediately, so a crash right after can
      // leave a 0-byte log. Collapsing that into missing (first run) would
      // let a run that does have a valid legacy floor run floorless
      // (fail-open) and emit a factually wrong first-sync notice
      await mkdir(dir, { recursive: true });
      await writeFile(join(dir, `${PROJECT_ID}.json`), JSON.stringify(legacy));
      await writeFile(join(dir, `${PROJECT_ID}.jsonl`), "");
      const loaded = await load();
      expect(loaded.state).toBe("loaded");
      expect(loaded.floor?.environments["prod"]?.variables["va"]).toMatchObject({ version: 3 });
    });
  });

  it("missing means ENOENT only: other read errors are not conflated with first-run", async () => {
    // Place a directory at the floor log's path (readFile → EISDIR)
    await mkdir(logPath(), { recursive: true });
    await expect(Effect.runPromise(store.load(PROJECT_ID))).rejects.toThrow(
      "Cannot read the local floor log",
    );
    // The write path also aborts (don't create a silently dead floor)
    await expect(
      Effect.runPromise(store.commitHead(PROJECT_ID, { seq: 1, hashHex: HASH_A })),
    ).rejects.toThrow("Cannot write the local floor log");
  });

  it("enforces the project ID format (hex 64) before assembling the path", async () => {
    await expect(Effect.runPromise(store.load("../escape"))).rejects.toThrow();
  });
});

describe("FloorHandle (in-process cache and the intent front door)", () => {
  let dir: string;
  let store: FloorStoreShape;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "maruhi-floor-handle-test-"));
    store = makeFileFloorStore(dir);
  });

  it("syncs to the folded floor on every commit (never misses a concurrent process's detection material)", async () => {
    // The sibling process has already established vb's tombstone (after this
    // process's openProject)
    await Effect.runPromise(
      store.commitPull(PROJECT_ID, {
        chainHead: { seq: 3, hashHex: HASH_A },
        environmentId: "prod",
        environment: envFloor({ pullEpoch: 3, observedEpoch: 3 }),
      }),
    );
    // This process's handle starts from the stale snapshot (no floor)
    const handle = makeFloorHandle({
      store,
      projectId: PROJECT_ID,
      environmentId: "prod",
      initial: null,
    });
    await Effect.runPromise(
      handle.commitPull(
        envFloor({
          pullEpoch: 2,
          observedEpoch: 2,
          variables: {
            va: {
              status: "active",
              version: 1,
              epoch: 2,
              valueSigHashHex: HASH_B,
              metaVersion: 1,
              metaSigHashHex: HASH_C,
            },
          },
        }),
        { seq: 3, hashHex: HASH_A },
      ),
    );
    // The folded floor — not the sent snapshot (va v1, pullEpoch 2) — is
    // adopted: the sibling's tombstone (vb), the newer va (v3), and the
    // higher baseline (pullEpoch 3) carry over to later checks in the same
    // command
    const current = handle.current();
    expect(current?.pullEpoch).toBe(3);
    expect(current?.variables["vb"]).toMatchObject({ status: "deleted" });
    expect(current?.variables["va"]).toMatchObject({ version: 3 });
  });

  it("commitManifest advances the in-process baseline with the same join even when the disk write fails", async () => {
    const failing: FloorStoreShape = {
      ...store,
      commitManifest: () => Effect.fail(cliError("injected floor write failure")),
    };
    const handle = makeFloorHandle({
      store: failing,
      projectId: PROJECT_ID,
      environmentId: "prod",
      initial: envFloor({ manifest: { manifestVersion: 1, epoch: 1, manifestSigHashHex: HASH_A } }),
    });
    await expect(
      Effect.runPromise(
        handle.commitManifest(
          { manifestVersion: 2, epoch: 2, manifestSigHashHex: HASH_B },
          { seq: 4, hashHex: HASH_B },
        ),
      ),
    ).rejects.toThrow();
    expect(handle.current()?.manifest).toMatchObject({ manifestVersion: 2 });
    // Coordinate (ii) advances under the same join too
    expect(handle.current()?.observedEpoch).toBe(2);
  });

  it("intents are held per environment scope and resolveIntent closes idempotently", async () => {
    const handle = makeFloorHandle({
      store,
      projectId: PROJECT_ID,
      environmentId: "prod",
      initial: null,
    });
    const id = await Effect.runPromise(
      handle.appendIntent({
        op: "meta-op",
        environmentId: "prod",
        epoch: 1,
        dekCommitmentHex: null,
        variableId: "va",
        manifestVersion: 2,
        manifestSigHashHex: HASH_A,
        declaredHead: { seq: 3, hashHex: HASH_B },
      }),
    );
    expect(handle.unresolvedIntents()).toHaveLength(1);
    await Effect.runPromise(handle.resolveIntent(id, "accepted"));
    expect(handle.unresolvedIntents()).toEqual([]);
    // A double resolution is a no-op (no extra resolution is logged)
    await Effect.runPromise(handle.resolveIntent(id, "accepted"));
    const loaded = await Effect.runPromise(store.load(PROJECT_ID));
    expect(loaded.floor?.intents).toEqual([]);
  });
});

describe("the floor log's non-sensitivity (the diskless invariant)", () => {
  it("ProjectFloor's shape contains no plaintext-value or name fields (the type-level pin is a value check here)", async () => {
    const dir = await mkdtemp(join(tmpdir(), "maruhi-floor-shape-test-"));
    const store = makeFileFloorStore(dir);
    await Effect.runPromise(
      store.commitPull(PROJECT_ID, {
        chainHead: { seq: 1, hashHex: HASH_A },
        environmentId: "prod",
        environment: envFloor(),
      }),
    );
    const raw = await readFile(join(dir, `${PROJECT_ID}.jsonl`), "utf8");
    // An append prepends an isolating newline — the first non-empty line is
    // the record
    const line = raw.split("\n").find((candidate) => candidate.trim() !== "") as string;
    const record: unknown = JSON.parse(line);
    // Only hashes, counters, and op kinds are stored (§6.3)
    expect(JSON.stringify(record)).not.toContain("name");
  });
});
