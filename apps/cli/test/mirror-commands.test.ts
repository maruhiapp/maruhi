// Tests for mirrors on the client side (AUTH_SPEC §11-7 — PF2,
// docs/notes/pf2-design.md): `maruhi mirror sync | status | mark | promote`,
// the mirror's own credential (MARUHI_MIRROR_TOKEN).
//
// Properties pinned down:
//  1. sync pages the export from the server and uploads the pages to the
//     mirror in sequence (restarting at 0 when the project changed), under
//     the mirror's own session; the report names heads and counts only
//  2. a mirror that is not marked, or that refuses the replica, fails with
//     the server's reason; status compares the two heads
//  5. MARUHI_MIRROR_TOKEN opens the mirror's session (sent to the mirror only)

import { Effect } from "effect";
import { beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { FloorStore } from "../src/floor.ts";
import { servedChainResponse } from "./support/chain-handler.ts";
import {
  addMemberOp,
  buildChain,
  type BuiltChain,
  genesisOp,
  makeTestUser,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import {
  built,
  deadOrigin,
  headOfChain,
  mirrorHandlers,
  mirrorState,
  type MirrorState,
  owner,
  start,
} from "./support/mirror.ts";
import { type MockHandler, type MockRequest, MockServer, onRequest } from "./support/server.ts";

/** The same genesis, another second entry: a fork of `built` (entries are deterministic). */
let forked: BuiltChain;

beforeAll(async () => {
  const other = await makeTestUser("user-other-4444");
  forked = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: addMemberOp(other, "reader") },
  ]);
  if (forked.projectId !== built.projectId) {
    throw new Error("the fork fixture must share the genesis");
  }
});

/** The evacuation lines the server pages (two pages: 3 + 2 lines). */
function snapshotLines(): string[] {
  return [
    JSON.stringify({
      kind: "header",
      format: "maruhi-do-snapshot",
      version: 1,
      schemaVersion: 4,
      takenAtMs: 1_700_000_000_000,
      doIdHex: "ab".repeat(32),
    }),
    JSON.stringify({ kind: "table", table: "audit_events", columns: ["seq", "event"] }),
    JSON.stringify({ kind: "row", table: "audit_events", values: [1, "chain.genesis"] }),
    JSON.stringify({ kind: "table", table: "chain_entries", columns: ["seq", "entry_hash_hex"] }),
    JSON.stringify({
      kind: "trailer",
      rows: { audit_events: 1, chain_entries: 0 },
      ...headOfChain(),
      auditHeadHashHex: "cd".repeat(32),
      databaseSizeBytes: 4096,
    }),
  ];
}

interface SourceOptions {
  /** How many times the continuation page answers 409 before succeeding. */
  changedPages?: number;
  /** The chain the server serves (default: `built`); a prefix of it with `chainEntries`. */
  chain?: BuiltChain;
  chainEntries?: number;
  /** An HTTP status the chain read answers instead of the chain. */
  chainStatus?: number;
}

/** The server's own `GET /projects/:id/mirror` answer (null = a writable primary with no marks); a test sets it and resets it. */
let sourceStatus: Record<string, unknown> | "refused" | null = null;

/** The server: the chain and the export's pages. */
function sourceHandlers(options: SourceOptions = {}): MockHandler[] {
  const lines = snapshotLines();
  const state = { changedPages: options.changedPages ?? 0 };
  const chain = options.chain ?? built;
  const entries = options.chainEntries ?? chain.entries.length;
  return [
    (request: MockRequest) =>
      request.method === "GET" && request.path === `/projects/${built.projectId}/chain`
        ? options.chainStatus === undefined
          ? servedChainResponse(
              built.projectId,
              chain.entries.slice(0, entries),
              chain.hashes.slice(0, entries),
            )
          : { status: options.chainStatus, json: { message: "no chain" } }
        : null,
    (request: MockRequest) =>
      request.method === "GET" && request.path === `/projects/${built.projectId}/mirror`
        ? sourceStatus === "refused"
          ? { status: 403, json: { _tag: "InsufficientScope" } }
          : {
              status: 200,
              json: sourceStatus ?? {
                mirror: false,
                head: { chainHeadSeq: 2, chainHeadHashHex: built.hashes[1] ?? "" },
              },
            }
        : null,
    (request: MockRequest) => {
      if (request.method !== "GET" || request.path !== `/projects/${built.projectId}/export`) {
        return null;
      }
      if (request.query["cursor"] === undefined) {
        return {
          status: 200,
          json: { lines: lines.slice(0, 3), next: "Y3Vyc29y", head: headOfChain() },
        };
      }
      if (state.changedPages > 0) {
        state.changedPages -= 1;
        return { status: 409, json: { _tag: "ExportChanged", reason: "project-changed" } };
      }
      return { status: 200, json: { lines: lines.slice(3), head: headOfChain() } };
    },
  ];
}

interface Pair {
  readonly env: TestEnv;
  readonly source: MockServer;
  readonly mirror: MockServer;
  readonly state: MirrorState;
}

async function startPair(
  options: { source?: SourceOptions; marked?: boolean } = {},
): Promise<Pair> {
  const source = await start(sourceHandlers(options.source));
  // The mirror's recorded source is the pair's server (a sync refuses any other — H-15)
  const state = mirrorState(options.marked, source.origin);
  const mirror = await start(mirrorHandlers(state));
  const env = await makeTestEnv();
  seedSession(env, source.origin, owner);
  seedSession(env, mirror.origin, owner);
  await seedConfig(env, { server: source.origin, defaultProject: built.projectId });
  return { env, source, mirror, state };
}

describe("maruhi mirror sync / status / mark / promote (PF2)", () => {
  it("pages the export from the server and uploads the pages in sequence under the mirror's session", async () => {
    const pair = await startPair();
    expect(await runCli(["mirror", "sync", "--mirror", pair.mirror.origin], pair.env.layer)).toBe(
      0,
    );
    const lines = snapshotLines();
    expect(pair.state.pages).toEqual([
      { sequence: 0, lines: lines.slice(0, 3) },
      { sequence: 1, lines: lines.slice(3) },
    ]);
    const logs = pair.env.logs.join("\n");
    expect(logs).toContain(
      `Replicated project ${built.projectId} to ${pair.mirror.origin}: chain head seq=2 (in sync with the verified view); audit seq=4; 2 pages, 5 lines`,
    );
    expect(logs).toContain("Before this run: No replication recorded since the mark");
    expect(logs).not.toContain("chain.genesis");
    // The export came from the server, the pages went to the mirror
    expect(pair.source.requests.filter((r) => r.path.endsWith("/export"))).toHaveLength(2);
    expect(pair.mirror.requests.filter((r) => r.path.endsWith("/export"))).toHaveLength(0);
  });

  it("restarts at sequence 0 when the project changed between pages, and reads the mirror from the `mirror` setting", async () => {
    const pair = await startPair({ source: { changedPages: 1 } });
    await seedConfig(pair.env, {
      server: pair.source.origin,
      defaultProject: built.projectId,
      mirror: pair.mirror.origin,
    });
    expect(await runCli(["mirror", "sync"], pair.env.layer)).toBe(0);
    expect(pair.state.pages.map((page) => page.sequence)).toEqual([0, 0, 1]);
    expect(pair.env.logs.join("\n")).toContain("restarted 1 time because the project changed");
    // The verified view is rebuilt before the restarted pass (H-13): the
    // report compares the committed head with the view it was exported from
    expect(pair.source.requests.filter((r) => r.path.endsWith("/chain"))).toHaveLength(2);
    expect(pair.env.logs.join("\n")).toContain("in sync with the verified view");
  });

  it("refuses to replicate from a server that is not the mirror's recorded source, unless forced (ruling H revision, round 6)", async () => {
    const source = await start(sourceHandlers());
    const state = mirrorState(true, "https://elsewhere.maruhi.app");
    const mirror = await start(mirrorHandlers(state));
    const env = await makeTestEnv();
    seedSession(env, source.origin, owner);
    seedSession(env, mirror.origin, owner);
    await seedConfig(env, { server: source.origin, defaultProject: built.projectId });
    expect(await runCli(["mirror", "sync", "--mirror", mirror.origin], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      `The mirror holds this project as a mirror of https://elsewhere.maruhi.app, not of ${source.origin}`,
    );
    expect(state.pages).toHaveLength(0);
    // Nothing was exported before the refusal
    expect(source.requests.filter((r) => r.path.endsWith("/export"))).toHaveLength(0);
    expect(await runCli(["mirror", "sync", "--mirror", mirror.origin, "--force"], env.layer)).toBe(
      0,
    );
    expect(state.pages).toHaveLength(2);
  });

  it("a deployment under another hostname is the same deployment: the mark refuses it as the source of itself (ruling C revision, round 5)", async () => {
    const fingerprint = "ab".repeat(16);
    const config = () => ({
      status: 200,
      json: {
        githubClientId: "dummy",
        signupPolicy: "open",
        serverKeyFingerprintHex: fingerprint,
        serverEncPubHex: "11".repeat(32),
      },
    });
    const state = mirrorState(false);
    const mirror = await start([
      onRequest("GET", "/auth/config", config),
      ...mirrorHandlers(state),
    ]);
    const alias = await start([onRequest("GET", "/auth/config", config)]);
    const env = await makeTestEnv();
    seedSession(env, mirror.origin, owner);
    await seedConfig(env, { server: mirror.origin, defaultProject: built.projectId });
    expect(
      await runCli(
        ["mirror", "mark", "--server", mirror.origin, "--source", alias.origin],
        env.layer,
      ),
    ).toBe(2);
    expect(env.errors.join("\n")).toContain(
      "--source publishes this server's key fingerprint: it is this deployment under another hostname",
    );
    expect(state.status).toMatchObject({ mirror: false });
  });

  it("uploads nothing — and fetches no chain — when the server's chain head, audit seq and mutation counter are the last replication's", async () => {
    const pair = await startPair();
    const head = headOfChain();
    // The mirror holds the head the last replication recorded, with the
    // source's mutation counter of that export
    pair.state.status = {
      ...pair.state.status,
      head,
      lastSync: { atMs: 5, ...head, attestationMark: 0, mutationSeq: 5 },
    };
    // The server's own status (the owner sees the three marks)
    sourceStatus = { mirror: false, head: { ...head, mutationSeq: 5 } };
    try {
      expect(await runCli(["mirror", "sync", "--mirror", pair.mirror.origin], pair.env.layer)).toBe(
        0,
      );
      expect(pair.env.logs.join("\n")).toContain(
        `Mirror ${pair.mirror.origin} is current for project ${built.projectId}`,
      );
      expect(pair.state.pages).toHaveLength(0);
      // A "current" tick is the status reads: no chain download, no
      // export (ruling H revision, round 4)
      expect(pair.source.requests.map((r) => r.path)).toEqual([
        `/projects/${built.projectId}/mirror`,
      ]);
      expect(pair.mirror.requests.map((r) => r.path)).toEqual([
        `/projects/${built.projectId}/mirror`,
      ]);
      // A floor below the source's head is proved on the chain by the view
      // once (H-14), which advances the floor (H-16): the next tick is the
      // status reads again
      await Effect.runPromise(
        Effect.gen(function* () {
          yield* (yield* FloorStore).commitHead(built.projectId, {
            seq: 1,
            hashHex: built.hashes[0] ?? "",
          });
        }).pipe(Effect.provide(pair.env.layer)),
      );
      const requestsBefore = pair.source.requests.length;
      expect(await runCli(["mirror", "sync", "--mirror", pair.mirror.origin], pair.env.layer)).toBe(
        0,
      );
      expect(pair.env.logs.at(-2)).toContain("is current for project");
      expect(
        pair.source.requests.slice(requestsBefore).filter((r) => r.path.endsWith("/chain")),
      ).toHaveLength(1);
      const requestsAfter = pair.source.requests.length;
      expect(await runCli(["mirror", "sync", "--mirror", pair.mirror.origin], pair.env.layer)).toBe(
        0,
      );
      expect(
        pair.source.requests.slice(requestsAfter).filter((r) => r.path.endsWith("/chain")),
      ).toHaveLength(0);
      expect(pair.state.pages).toHaveLength(0);
      // A moved attestation mark alone brings a replica
      // A moved mutation counter alone (a write that appends no audit row
      // and no chain entry — an attestation) brings a replica
      sourceStatus = { mirror: false, head: { ...head, mutationSeq: 6 } };
      expect(await runCli(["mirror", "sync", "--mirror", pair.mirror.origin], pair.env.layer)).toBe(
        0,
      );
      expect(pair.state.pages).toHaveLength(2);
      expect(pair.env.logs.join("\n")).toContain("Replicated project");
      // A source whose reported head is behind this machine's floor is not
      // "current" — the replicating path's floor check decides (H-11)
      sourceStatus = { mirror: false, head: { ...head, mutationSeq: 5 } };
      pair.state.pages.length = 0;
      await Effect.runPromise(
        Effect.gen(function* () {
          yield* (yield* FloorStore).commitHead(built.projectId, {
            seq: head.chainHeadSeq + 1,
            hashHex: "cd".repeat(32),
          });
        }).pipe(Effect.provide(pair.env.layer)),
      );
      const logged = pair.env.logs.length;
      expect(await runCli(["mirror", "sync", "--mirror", pair.mirror.origin], pair.env.layer)).toBe(
        1,
      );
      expect(pair.state.pages).toHaveLength(0);
      expect(pair.env.logs.slice(logged).join("\n")).not.toContain("is current for project");
    } finally {
      sourceStatus = null;
    }
  });

  it("fails with the mirror's reason: not marked, a refused replica, and the mirror URL being the server", async () => {
    const unmarked = await startPair({ marked: false });
    expect(
      await runCli(["mirror", "sync", "--mirror", unmarked.mirror.origin], unmarked.env.layer),
    ).toBe(1);
    expect(unmarked.env.errors.join("\n")).toContain("not marked as a mirror on that server");
    expect(unmarked.state.pages).toHaveLength(0);

    const refused = await startPair();
    refused.state.lastPage = {
      status: 422,
      json: { _tag: "MirrorSyncRejected", reason: "chain-not-extension" },
    };
    expect(
      await runCli(["mirror", "sync", "--mirror", refused.mirror.origin], refused.env.layer),
    ).toBe(1);
    expect(refused.env.errors.join("\n")).toContain(
      "its chain does not extend the chain the mirror holds (chain-not-extension)",
    );

    const same = await startPair();
    expect(await runCli(["mirror", "sync", "--mirror", same.source.origin], same.env.layer)).toBe(
      2,
    );
    expect(await runCli(["mirror", "sync"], same.env.layer)).toBe(1);
    expect(same.env.errors.join("\n")).toContain("No mirror URL");
  });

  it("status compares the two heads; mark and promote address the mirror deployment as --server", async () => {
    const pair = await startPair();
    expect(await runCli(["mirror", "status", "--mirror", pair.mirror.origin], pair.env.layer)).toBe(
      0,
    );
    const logs = pair.env.logs.join("\n");
    expect(logs).toContain(`Mirror ${pair.mirror.origin} of ${pair.source.origin}`);
    expect(logs).toContain("Server: chain head seq=2 (the verified view)");
    expect(logs).toContain(
      "Mirror: chain head seq=1 — behind the verified view by 1 chain entry (seq 1 of 2); audit seq=4",
    );
    expect(logs).toContain("No replication recorded since the mark");

    const fresh = await startPair({ marked: false });
    // The source still answers here (the pair's server) but refuses the
    // read of its mark: a promotion may leave two writable copies, so it is
    // refused unless forced, naming what could not be read (ruling C
    // revision, round 5)
    sourceStatus = "refused";
    expect(
      await runCli(
        ["mirror", "mark", "--server", fresh.mirror.origin, "--source", fresh.source.origin],
        fresh.env.layer,
      ),
    ).toBe(0);
    expect(fresh.state.status).toMatchObject({
      mirror: true,
      sourceOrigin: fresh.source.origin,
    });
    expect(fresh.env.logs.join("\n")).toContain(
      `Marked project ${built.projectId} on ${fresh.mirror.origin} as a mirror of ${fresh.source.origin}`,
    );
    expect(
      await runCli(["mirror", "promote", "--server", fresh.mirror.origin], fresh.env.layer),
    ).toBe(1);
    expect(fresh.env.errors.join("\n")).toContain(
      `The source ${fresh.source.origin} still answers, and its mark could not be read from this machine (no session for it here, or it refused the read): promoting ${fresh.mirror.origin} now may leave two writable copies`,
    );
    sourceStatus = null;
    // … and one whose mark says it holds the project writable is refused
    // with the planned order
    const live = await startPair({ marked: false });
    expect(
      await runCli(
        ["mirror", "mark", "--server", live.mirror.origin, "--source", live.source.origin],
        live.env.layer,
      ),
    ).toBe(0);
    sourceStatus = { mirror: false, head: headOfChain() };
    try {
      expect(
        await runCli(["mirror", "promote", "--server", live.mirror.origin], live.env.layer),
      ).toBe(1);
    } finally {
      sourceStatus = null;
    }
    expect(live.env.errors.join("\n")).toContain(
      `The source ${live.source.origin} still answers and holds this project writable: promoting ${live.mirror.origin} now leaves two writable copies`,
    );
    expect(fresh.state.status).toMatchObject({ mirror: true });
    expect(
      await runCli(
        ["mirror", "promote", "--server", fresh.mirror.origin, "--force"],
        fresh.env.layer,
      ),
    ).toBe(0);
    expect(fresh.state.status).toMatchObject({ mirror: false });
    expect(fresh.env.logs.join("\n")).toContain(
      `Promoted project ${built.projectId} on ${fresh.mirror.origin}`,
    );
    // --force still reads the source and says what it overrides (ruling C
    // revision, round 9) — as the consequence, not the dead remedy (round 12)
    expect(fresh.env.errors.join("\n")).toContain(
      `Warning: promoting with --force. The source ${fresh.source.origin} still answers and holds this project writable: two writable copies from now on (a split brain) until one is marked as a mirror of the other — the source as a mirror of ${fresh.mirror.origin}`,
    );
    expect(fresh.env.errors.join("\n")).not.toContain("Pass --force to promote anyway");
    expect(fresh.env.errors.join("\n")).not.toContain("bring its last writes over");
    // A source already frozen as a mirror of this deployment (the planned
    // order): the promotion goes through without a probe
    const frozen = await startPair({ marked: false });
    expect(
      await runCli(
        ["mirror", "mark", "--server", frozen.mirror.origin, "--source", frozen.source.origin],
        frozen.env.layer,
      ),
    ).toBe(0);
    sourceStatus = { mirror: true, sourceOrigin: frozen.mirror.origin, head: headOfChain() };
    try {
      // … unless the mirror lacks the frozen source's last writes (the
      // planned order's last sync was skipped — ruling C revision, round 7)
      frozen.state.status = {
        ...frozen.state.status,
        head: { ...headOfChain(), chainHeadSeq: 1, chainHeadHashHex: built.projectId },
      };
      expect(
        await runCli(["mirror", "promote", "--server", frozen.mirror.origin], frozen.env.layer),
      ).toBe(1);
      expect(frozen.env.errors.join("\n")).toContain(
        `is frozen at chain seq ${headOfChain().chainHeadSeq} (head ${headOfChain().chainHeadHashHex}) but this mirror holds seq 1`,
      );
      expect(frozen.state.status).toMatchObject({ mirror: true });
      // Forced past it: the entries the source holds past the mirror are
      // named as what becomes unreachable (round 12) — on a fresh pair, so
      // the planned promotion below still runs
      const abandoned = await startPair({ marked: false });
      sourceStatus = { mirror: true, sourceOrigin: abandoned.mirror.origin, head: headOfChain() };
      expect(
        await runCli(
          [
            "mirror",
            "mark",
            "--server",
            abandoned.mirror.origin,
            "--source",
            abandoned.source.origin,
          ],
          abandoned.env.layer,
        ),
      ).toBe(0);
      abandoned.state.status = {
        ...abandoned.state.status,
        head: { ...headOfChain(), chainHeadSeq: 1, chainHeadHashHex: built.projectId },
      };
      expect(
        await runCli(
          ["mirror", "promote", "--server", abandoned.mirror.origin, "--force"],
          abandoned.env.layer,
        ),
      ).toBe(0);
      expect(abandoned.env.errors.join("\n")).toContain(
        `Warning: promoting with --force. promoting without the chain entries ${abandoned.source.origin} holds past seq 1 (its head is seq 2): a promoted copy takes no page, so they are unreachable from ${abandoned.mirror.origin} from now on — keep them with \`maruhi project export --server ${abandoned.source.origin}\``,
      );
      expect(abandoned.env.errors.join("\n")).not.toContain("Run `maruhi mirror sync");
      sourceStatus = { mirror: true, sourceOrigin: frozen.mirror.origin, head: headOfChain() };
      frozen.state.status = { ...frozen.state.status, head: headOfChain() };
      expect(
        await runCli(["mirror", "promote", "--server", frozen.mirror.origin], frozen.env.layer),
      ).toBe(0);
    } finally {
      sourceStatus = null;
    }
    expect(frozen.state.status).toMatchObject({ mirror: false });
    // A source that is a mirror of ANOTHER deployment: the primary moved
    // there, so promoting this copy is the split brain (ruling C revision,
    // round 4) — refused with the re-point, unless forced
    const moved = await startPair({ marked: false });
    expect(
      await runCli(
        ["mirror", "mark", "--server", moved.mirror.origin, "--source", moved.source.origin],
        moved.env.layer,
      ),
    ).toBe(0);
    const elsewhere = await deadOrigin();
    sourceStatus = { mirror: true, sourceOrigin: elsewhere, head: headOfChain() };
    try {
      expect(
        await runCli(["mirror", "promote", "--server", moved.mirror.origin], moved.env.layer),
      ).toBe(1);
      expect(moved.env.errors.join("\n")).toContain(
        `The source ${moved.source.origin} holds this project as a mirror of ${elsewhere}, not of ${moved.mirror.origin}: the project's primary moved there`,
      );
      expect(moved.env.errors.join("\n")).toContain(
        `maruhi mirror mark --server ${moved.mirror.origin} --source ${elsewhere}`,
      );
      expect(moved.state.status).toMatchObject({ mirror: true });
      const movedErrorsBefore = moved.env.errors.length;
      expect(
        await runCli(
          ["mirror", "promote", "--server", moved.mirror.origin, "--force"],
          moved.env.layer,
        ),
      ).toBe(0);
      // The forced consequence names the two copies and the mark that
      // stops the split while this one has taken no write (round 13)
      const forcedOutput = moved.env.errors.slice(movedErrorsBefore).join("\n");
      expect(forcedOutput).toContain(
        `Warning: promoting with --force. The source ${moved.source.origin} holds this project as a mirror of ${elsewhere}: two writable copies from now on, this one and the primary at ${elsewhere}`,
      );
      expect(forcedOutput).not.toContain("would leave two writable copies");
    } finally {
      sourceStatus = null;
    }
    expect(moved.state.status).toMatchObject({ mirror: false });
    // A source nothing answers at: the mark proceeds with a warning (the
    // chain check needs the source), and the promotion goes through
    const gone = await startPair({ marked: false });
    const dead = await deadOrigin();
    expect(
      await runCli(
        ["mirror", "mark", "--server", gone.mirror.origin, "--source", dead],
        gone.env.layer,
      ),
    ).toBe(0);
    expect(gone.env.errors.join("\n")).toContain("the source's chain and mark could not be read");
    expect(
      await runCli(["mirror", "promote", "--server", gone.mirror.origin], gone.env.layer),
    ).toBe(0);
    expect(gone.state.status).toMatchObject({ mirror: false });
    // --source is required, and must not be the server itself
    expect(await runCli(["mirror", "mark", "--server", fresh.mirror.origin], fresh.env.layer)).toBe(
      2,
    );
    expect(
      await runCli(
        ["mirror", "mark", "--server", fresh.mirror.origin, "--source", fresh.mirror.origin],
        fresh.env.layer,
      ),
    ).toBe(2);
  });

  it("the mark accepts a project ahead of the source on one chain (the planned freeze) and refuses only a fork (ruling C revision, round 8)", async () => {
    // The primary P (the project being marked, holding the full chain)
    // against a mirror M whose chain is a prefix: the freeze of the planned
    // failover, with the last sync named as the next step
    const ahead = await startPair({ marked: false, source: { chainEntries: 1 } });
    // The source M is a mirror of P (the project being marked): the freeze
    sourceStatus = {
      mirror: true,
      sourceOrigin: ahead.mirror.origin,
      head: { chainHeadSeq: 1, chainHeadHashHex: built.hashes[0] ?? "" },
    };
    try {
      expect(
        await runCli(
          ["mirror", "mark", "--server", ahead.mirror.origin, "--source", ahead.source.origin],
          ahead.env.layer,
        ),
      ).toBe(0);
    } finally {
      sourceStatus = null;
    }
    expect(ahead.state.status).toMatchObject({ mirror: true, sourceOrigin: ahead.source.origin });
    expect(ahead.env.errors.join("\n")).toContain(
      `this project holds 1 chain entry that ${ahead.source.origin} lacks (seq 2 against 1): after the mark, bring them over with \`maruhi mirror sync --server ${ahead.mirror.origin} --mirror ${ahead.source.origin}\` before promoting ${ahead.source.origin}`,
    );
    // The same chains, but the source holds the project writable: no sync
    // can bring the entries into it, so the mark is refused and says which
    // way round the mark goes (ruling C revision, round 9)
    const writable = await startPair({ marked: false, source: { chainEntries: 1 } });
    expect(
      await runCli(
        ["mirror", "mark", "--server", writable.mirror.origin, "--source", writable.source.origin],
        writable.env.layer,
      ),
    ).toBe(1);
    expect(writable.env.errors.join("\n")).toContain(
      `${writable.source.origin} holds this project writable, and this project holds 1 chain entry it lacks (seq 2 against 1): no sync brings them into a writable deployment`,
    );
    expect(writable.env.errors.join("\n")).toContain(
      `maruhi mirror mark --server ${writable.source.origin} --source ${writable.mirror.origin}`,
    );
    expect(writable.state.status).toMatchObject({ mirror: false });
    expect(
      await runCli(
        [
          "mirror",
          "mark",
          "--server",
          writable.mirror.origin,
          "--source",
          writable.source.origin,
          "--force",
        ],
        writable.env.layer,
      ),
    ).toBe(0);
    // A source that is itself a mirror of a third origin: the mark goes
    // against that origin (the star), unless forced
    const third = await startPair({ marked: false });
    const primary = await deadOrigin();
    sourceStatus = { mirror: true, sourceOrigin: primary, head: headOfChain() };
    try {
      expect(
        await runCli(
          ["mirror", "mark", "--server", third.mirror.origin, "--source", third.source.origin],
          third.env.layer,
        ),
      ).toBe(1);
      expect(third.env.errors.join("\n")).toContain(
        `${third.source.origin} holds this project as a mirror of ${primary}: mirrors sync from the primary, so this project is marked against it (\`maruhi mirror mark --server ${third.mirror.origin} --source ${primary}\`)`,
      );
      expect(third.state.status).toMatchObject({ mirror: false });
      expect(
        await runCli(
          [
            "mirror",
            "mark",
            "--server",
            third.mirror.origin,
            "--source",
            third.source.origin,
            "--force",
          ],
          third.env.layer,
        ),
      ).toBe(0);
    } finally {
      sourceStatus = null;
    }
    expect(third.state.status).toMatchObject({ mirror: true, sourceOrigin: third.source.origin });
    // Two chains sharing the genesis and nothing after it: neither head is
    // an entry of the other — refused, unless forced
    const fork = await startPair({ marked: false, source: { chain: forked } });
    expect(
      await runCli(
        ["mirror", "mark", "--server", fork.mirror.origin, "--source", fork.source.origin],
        fork.env.layer,
      ),
    ).toBe(1);
    expect(fork.env.errors.join("\n")).toContain(
      "are not one chain: neither head is an entry of the other",
    );
    expect(fork.state.status).toMatchObject({ mirror: false });
    const forkErrorsBefore = fork.env.errors.length;
    expect(
      await runCli(
        [
          "mirror",
          "mark",
          "--server",
          fork.mirror.origin,
          "--source",
          fork.source.origin,
          "--force",
        ],
        fork.env.layer,
      ),
    ).toBe(0);
    expect(fork.state.status).toMatchObject({ mirror: true });
    // --force still reads the source and says what it overrides (round 10)
    expect(fork.env.errors.slice(forkErrorsBefore).join("\n")).toContain(
      "Warning: marking with --force. This project's chain",
    );
    // … without the refusal's own escape clause (round 11)
    expect(fork.env.errors.slice(forkErrorsBefore).join("\n")).not.toContain("pass --force");
    expect(third.env.errors.join("\n")).not.toContain(
      "Warning: marking with --force. " +
        third.source.origin +
        " holds this project as a mirror of " +
        primary +
        ": mirrors sync from the primary, so this project is marked against it (`maruhi mirror mark --server " +
        third.mirror.origin +
        " --source " +
        primary +
        "`), or pass --force",
    );
    // Equal to a source frozen for this project: both copies frozen after
    // the mark — the note names the promotion to run (round 10)
    const undo = await startPair({ marked: false });
    sourceStatus = { mirror: true, sourceOrigin: undo.mirror.origin, head: headOfChain() };
    try {
      expect(
        await runCli(
          ["mirror", "mark", "--server", undo.mirror.origin, "--source", undo.source.origin],
          undo.env.layer,
        ),
      ).toBe(0);
    } finally {
      sourceStatus = null;
    }
    expect(undo.env.errors.join("\n")).toContain(
      `${undo.source.origin} is frozen as a mirror of this deployment, so after this mark neither copy accepts writes: promote one`,
    );
    // The mark's read fails alone: the chain check still runs (round 10)
    const halfRead = await startPair({ marked: false, source: { chain: forked } });
    sourceStatus = "refused";
    try {
      expect(
        await runCli(
          [
            "mirror",
            "mark",
            "--server",
            halfRead.mirror.origin,
            "--source",
            halfRead.source.origin,
          ],
          halfRead.env.layer,
        ),
      ).toBe(1);
    } finally {
      sourceStatus = null;
    }
    expect(halfRead.env.errors.join("\n")).toContain("the source's mark could not be read");
    expect(halfRead.env.errors.join("\n")).toContain("are not one chain");
    // The chain's read fails alone while the mark says frozen for this
    // deployment: the undo note stands on the mark (round 11)
    const chainless = await startPair({ marked: false, source: { chainStatus: 500 } });
    sourceStatus = { mirror: true, sourceOrigin: chainless.mirror.origin, head: headOfChain() };
    try {
      expect(
        await runCli(
          [
            "mirror",
            "mark",
            "--server",
            chainless.mirror.origin,
            "--source",
            chainless.source.origin,
          ],
          chainless.env.layer,
        ),
      ).toBe(0);
    } finally {
      sourceStatus = null;
    }
    expect(chainless.env.errors.join("\n")).toContain("the source's chain could not be read");
    expect(chainless.env.errors.join("\n")).toContain(
      "so after this mark neither copy accepts writes: promote one of them",
    );
    // The mark's read fails while this project is ahead: the note hedges
    // the sync on what the source holds (round 11)
    const hedged = await startPair({ marked: false, source: { chainEntries: 1 } });
    sourceStatus = "refused";
    try {
      expect(
        await runCli(
          ["mirror", "mark", "--server", hedged.mirror.origin, "--source", hedged.source.origin],
          hedged.env.layer,
        ),
      ).toBe(0);
    } finally {
      sourceStatus = null;
    }
    expect(hedged.env.errors.join("\n")).toContain(
      `if ${hedged.source.origin} is frozen for this project; if it holds the project writable, the mark goes the other way round`,
    );
    // A source frozen for this deployment under another hostname: the star
    // instruction would be a self-mark, so the way out is the mark under
    // that name (round 11)
    const fingerprint = "ab".repeat(16);
    const config = () => ({
      status: 200,
      json: {
        githubClientId: "dummy",
        signupPolicy: "open",
        serverKeyFingerprintHex: fingerprint,
        serverEncPubHex: "11".repeat(32),
      },
    });
    const aliasState = mirrorState(false);
    const aliased = await start([
      onRequest("GET", "/auth/config", config),
      ...mirrorHandlers(aliasState),
    ]);
    const alias = await start([onRequest("GET", "/auth/config", config)]);
    const aliasSource = await start(sourceHandlers());
    const aliasEnv = await makeTestEnv();
    seedSession(aliasEnv, aliased.origin, owner);
    seedSession(aliasEnv, aliasSource.origin, owner);
    await seedConfig(aliasEnv, { server: aliasSource.origin, defaultProject: built.projectId });
    sourceStatus = { mirror: true, sourceOrigin: alias.origin, head: headOfChain() };
    try {
      expect(
        await runCli(
          ["mirror", "mark", "--server", aliased.origin, "--source", aliasSource.origin],
          aliasEnv.layer,
        ),
      ).toBe(1);
    } finally {
      sourceStatus = null;
    }
    expect(aliasEnv.errors.join("\n")).toContain(
      `${aliasSource.origin} holds this project as a mirror of ${alias.origin}, which publishes this server's key fingerprint: that is this deployment under the name the freeze used — run the mark with \`--server ${alias.origin}\``,
    );
  });

  it("a frozen source behind the mirror promotes when its head is on the mirror's chain, is refused as a fork otherwise, and the rows left behind are counted (ruling C revision, round 8)", async () => {
    const pair = await startPair({ marked: false });
    expect(
      await runCli(
        ["mirror", "mark", "--server", pair.mirror.origin, "--source", pair.source.origin],
        pair.env.layer,
      ),
    ).toBe(0);
    pair.state.status = {
      ...pair.state.status,
      head: headOfChain(),
      lastSync: { atMs: 5, ...headOfChain(), attestationMark: 0 },
    };
    // Frozen at seq 1 with an entry that is not the mirror's: a fork, no
    // sync can repair it, and the refusal says so (no sync is suggested)
    sourceStatus = {
      mirror: true,
      sourceOrigin: pair.mirror.origin,
      head: { chainHeadSeq: 1, chainHeadHashHex: "ab".repeat(32), auditMaxSeq: 9 },
    };
    try {
      expect(
        await runCli(["mirror", "promote", "--server", pair.mirror.origin], pair.env.layer),
      ).toBe(1);
      const errors = pair.env.errors.join("\n");
      expect(errors).toContain(
        `is frozen at chain seq 1 (head ${"ab".repeat(32)}), which is not an entry of this mirror's chain (seq 2`,
      );
      expect(errors).toContain("the two copies forked, and a promotion would bury the fork");
      expect(errors).not.toContain("maruhi mirror sync");
      expect(pair.state.status).toMatchObject({ mirror: true });
      // At the mirror's height with another hash: the same fork, no chain
      // fetch needed (round 10)
      sourceStatus = {
        mirror: true,
        sourceOrigin: pair.mirror.origin,
        head: { chainHeadSeq: 2, chainHeadHashHex: "cd".repeat(32), auditMaxSeq: 9 },
      };
      const chainReads = pair.mirror.requests.filter((r) => r.path.endsWith("/chain")).length;
      expect(
        await runCli(["mirror", "promote", "--server", pair.mirror.origin], pair.env.layer),
      ).toBe(1);
      expect(pair.env.errors.join("\n")).toContain(
        `is frozen at chain seq 2 (head ${"cd".repeat(32)}), which is not an entry of this mirror's chain (seq 2`,
      );
      expect(pair.mirror.requests.filter((r) => r.path.endsWith("/chain")).length).toBe(chainReads);
      // Frozen at seq 1 with the mirror's own genesis (restored from an
      // older backup, then frozen): a strict prefix holds nothing the
      // mirror lacks — promoted; its audit rows since the last replication
      // are positions of another log, so they are said to be uncountable
      // from here (ruling C revision, round 9)
      sourceStatus = {
        mirror: true,
        sourceOrigin: pair.mirror.origin,
        head: { chainHeadSeq: 1, chainHeadHashHex: built.hashes[0] ?? "", auditMaxSeq: 9 },
      };
      expect(
        await runCli(["mirror", "promote", "--server", pair.mirror.origin], pair.env.layer),
      ).toBe(0);
    } finally {
      sourceStatus = null;
    }
    expect(pair.state.status).toMatchObject({ mirror: false });
    const logs = pair.env.logs.join("\n");
    expect(logs).toContain(`Promoted project ${built.projectId} on ${pair.mirror.origin}`);
    expect(logs).toContain(
      `The audit rows the frozen source ${pair.source.origin} wrote since the last replication (the reads and leases it served) cannot be counted from here: a promoted copy takes no page, so they can never be brought over — keep them with \`maruhi project export --server ${pair.source.origin}\``,
    );
    // The planned failover (the frozen head is the mirror's, a replication
    // from it recorded): the rows are counted
    const planned = await startPair({ marked: false });
    expect(
      await runCli(
        ["mirror", "mark", "--server", planned.mirror.origin, "--source", planned.source.origin],
        planned.env.layer,
      ),
    ).toBe(0);
    planned.state.status = {
      ...planned.state.status,
      head: headOfChain(),
      lastSync: { atMs: 5, ...headOfChain(), attestationMark: 0 },
    };
    sourceStatus = {
      mirror: true,
      sourceOrigin: planned.mirror.origin,
      head: { ...headOfChain(), auditMaxSeq: 9 },
    };
    try {
      expect(
        await runCli(["mirror", "promote", "--server", planned.mirror.origin], planned.env.layer),
      ).toBe(0);
    } finally {
      sourceStatus = null;
    }
    expect(planned.env.logs.join("\n")).toContain(
      `5 audit rows stay on the frozen source ${planned.source.origin} (the reads and leases it served since the last replication): a promoted copy takes no page`,
    );
    // A source that synced back from this mirror holds the mirror's log
    // followed by its own rows: its own record counts exactly, whatever
    // the mirror's record says (round 10)
    const syncedBack = await startPair({ marked: false });
    expect(
      await runCli(
        [
          "mirror",
          "mark",
          "--server",
          syncedBack.mirror.origin,
          "--source",
          syncedBack.source.origin,
        ],
        syncedBack.env.layer,
      ),
    ).toBe(0);
    syncedBack.state.status = {
      ...syncedBack.state.status,
      head: headOfChain(),
      lastSync: { atMs: 5, ...headOfChain(), attestationMark: 0 },
    };
    sourceStatus = {
      mirror: true,
      sourceOrigin: syncedBack.mirror.origin,
      head: { ...headOfChain(), auditMaxSeq: 12 },
      lastSync: { atMs: 6, ...headOfChain(), auditMaxSeq: 10, attestationMark: 0 },
    };
    try {
      expect(
        await runCli(
          ["mirror", "promote", "--server", syncedBack.mirror.origin],
          syncedBack.env.layer,
        ),
      ).toBe(0);
    } finally {
      sourceStatus = null;
    }
    expect(syncedBack.env.logs.join("\n")).toContain(
      `2 audit rows stay on the frozen source ${syncedBack.source.origin}`,
    );
  });

  it("a server that is itself a mirror of another origin is no source — refused before any page, unless forced; a server frozen for this mirror is one whatever it replicated before (ruling H revision, rounds 8 and 9)", async () => {
    const pair = await startPair();
    const elsewhere = await deadOrigin();
    sourceStatus = { mirror: true, sourceOrigin: elsewhere, head: headOfChain() };
    try {
      expect(await runCli(["mirror", "sync", "--mirror", pair.mirror.origin], pair.env.layer)).toBe(
        1,
      );
      expect(pair.env.errors.join("\n")).toContain(
        `The server ${pair.source.origin} holds this project as a mirror of ${elsewhere}: mirrors sync from the primary`,
      );
      expect(pair.env.errors.join("\n")).toContain(
        `maruhi mirror mark --server ${pair.mirror.origin} --source ${elsewhere}`,
      );
      expect(pair.state.pages).toHaveLength(0);
      expect(pair.source.requests.some((r) => r.path.endsWith("/export"))).toBe(false);
      // A server frozen for this mirror with a replication record (a
      // sibling re-pointed here, or the former primary that synced back):
      // a source all the same — the pair stays consistent (round 9)
      sourceStatus = {
        mirror: true,
        sourceOrigin: pair.mirror.origin,
        head: headOfChain(),
        lastSync: { atMs: 5, ...headOfChain(), attestationMark: 0 },
      };
      expect(await runCli(["mirror", "sync", "--mirror", pair.mirror.origin], pair.env.layer)).toBe(
        0,
      );
      expect(pair.state.pages).toHaveLength(2);
      // … and the planned failover's last sync (frozen, nothing replicated
      // into it yet) goes through; --force overrides the star rule
      sourceStatus = { mirror: true, sourceOrigin: pair.mirror.origin, head: headOfChain() };
      expect(await runCli(["mirror", "sync", "--mirror", pair.mirror.origin], pair.env.layer)).toBe(
        0,
      );
      expect(pair.state.pages).toHaveLength(4);
      sourceStatus = { mirror: true, sourceOrigin: elsewhere, head: headOfChain() };
      expect(
        await runCli(["mirror", "sync", "--mirror", pair.mirror.origin, "--force"], pair.env.layer),
      ).toBe(0);
      expect(pair.state.pages).toHaveLength(6);
    } finally {
      sourceStatus = null;
    }
  });

  it("a replica on another chain than the verified view is reported and fails the sync (ruling H revision, round 8)", async () => {
    const pair = await startPair();
    pair.state.lastPage = {
      status: 200,
      json: {
        nextSequence: 0,
        committed: { atMs: 5, ...headOfChain(), chainHeadHashHex: "ab".repeat(32) },
      },
    };
    expect(await runCli(["mirror", "sync", "--mirror", pair.mirror.origin], pair.env.layer)).toBe(
      1,
    );
    expect(pair.env.logs.join("\n")).toContain(
      "a different chain at the same height as the verified view",
    );
    expect(pair.env.errors.join("\n")).toContain(
      `The replica ${pair.mirror.origin} now holds is a different chain at the same height as the verified view`,
    );
    expect(pair.env.errors.join("\n")).toContain(
      "do not promote it and run `maruhi project verify`",
    );
  });

  it("a replica behind the view taken before the export, or past the view taken after the commit, fails the sync as a rollback at the server (ruling H revision, round 9)", async () => {
    // Behind: the server exported a chain shorter than the one it served
    const behind = await startPair();
    behind.state.lastPage = {
      status: 200,
      json: {
        nextSequence: 0,
        committed: {
          atMs: 5,
          ...headOfChain(),
          chainHeadSeq: 1,
          chainHeadHashHex: built.hashes[0] ?? "",
        },
      },
    };
    expect(
      await runCli(["mirror", "sync", "--mirror", behind.mirror.origin], behind.env.layer),
    ).toBe(1);
    expect(behind.env.errors.join("\n")).toContain(
      `The replica ${behind.mirror.origin} now holds is behind the verified view taken before the export (seq 1 of 2): the server exported a chain shorter than the one it served — a rollback at the server, not a race`,
    );
    // Ahead: the view is taken again after the commit (the honest race is a
    // write that landed in between), and the server still serves seq 2 —
    // it exported entries it no longer serves
    const past = await startPair();
    past.state.lastPage = {
      status: 200,
      json: {
        nextSequence: 0,
        committed: {
          atMs: 5,
          ...headOfChain(),
          chainHeadSeq: 3,
          chainHeadHashHex: "ab".repeat(32),
        },
      },
    };
    const chainReadsBefore = past.source.requests.filter((r) => r.path.endsWith("/chain")).length;
    expect(await runCli(["mirror", "sync", "--mirror", past.mirror.origin], past.env.layer)).toBe(
      1,
    );
    expect(
      past.source.requests.filter((r) => r.path.endsWith("/chain")).length - chainReadsBefore,
    ).toBe(2);
    expect(past.env.errors.join("\n")).toContain(
      `The replica ${past.mirror.origin} now holds is ahead of the verified view taken after the commit (seq 3 > 2): the server exported entries it no longer serves — a rollback at the server, not a race`,
    );
    // The report never calls it a write that landed (round 10), and on the
    // sync path names the sync's own causes only (round 11)
    expect(past.env.logs.join("\n")).toContain(
      "ahead of the verified view taken after the commit (seq 3 > 2) — the server exported entries it no longer serves (a rollback at the server))",
    );
    expect(past.env.logs.join("\n")).not.toContain("a write landed");
    expect(past.env.logs.join("\n")).not.toContain("the mirror was promoted and written to");
    // The view taken after the commit fails (the server now serves a chain
    // the local floor refuses): the failure names the replica the mirror
    // holds and the no-promotion advice (round 10)
    const failing = await startPair();
    failing.state.lastPage = past.state.lastPage;
    let chainServed = 0;
    const flaky = await start([
      (request: MockRequest) => {
        if (request.method !== "GET" || request.path !== `/projects/${built.projectId}/chain`) {
          return null;
        }
        chainServed += 1;
        return chainServed === 1
          ? servedChainResponse(built.projectId, built.entries, built.hashes)
          : servedChainResponse(
              built.projectId,
              built.entries.slice(0, 1),
              built.hashes.slice(0, 1),
            );
      },
      ...sourceHandlers(),
    ]);
    seedSession(failing.env, flaky.origin, owner);
    expect(
      await runCli(
        ["mirror", "sync", "--server", flaky.origin, "--mirror", failing.mirror.origin, "--force"],
        failing.env.layer,
      ),
    ).toBe(1);
    expect(failing.env.errors.join("\n")).toContain(
      `The mirror now holds a replica at chain seq 3 (head ${"ab".repeat(32)}), past the view taken before the export (seq 2), and the server failed verification right after exporting it:`,
    );
    expect(failing.env.errors.join("\n")).toContain("Do not promote the mirror");
    expect(failing.env.errors.join("\n")).not.toContain("stopped answering");
    // A server that stops answering after the commit did not fail
    // verification: the replica is unchecked, not condemned (round 11)
    const gone = await startPair();
    gone.state.lastPage = past.state.lastPage;
    let chainAnswers = 0;
    const dying = await start([
      (request: MockRequest) => {
        if (request.method !== "GET" || request.path !== `/projects/${built.projectId}/chain`) {
          return null;
        }
        chainAnswers += 1;
        return chainAnswers === 1
          ? servedChainResponse(built.projectId, built.entries, built.hashes)
          : { status: 503, json: { message: "gateway" } };
      },
      ...sourceHandlers(),
    ]);
    seedSession(gone.env, dying.origin, owner);
    expect(
      await runCli(
        ["mirror", "sync", "--server", dying.origin, "--mirror", gone.mirror.origin, "--force"],
        gone.env.layer,
      ),
    ).toBe(1);
    const goneErrors = gone.env.errors.join("\n");
    expect(goneErrors).toContain("The server stopped answering after the commit (");
    expect(goneErrors).toContain(
      `the replica the mirror now holds (chain seq 3, head ${"ab".repeat(32)}) is past the view taken before the export (seq 2) and could not be checked against a second view`,
    );
    expect(goneErrors).not.toContain("failed verification");
    // A session refused on the re-read: neither condemned nor unreachable (round 12)
    const refused = await startPair();
    refused.state.lastPage = past.state.lastPage;
    let chainAsked = 0;
    const expiring = await start([
      (request: MockRequest) => {
        if (request.method !== "GET" || request.path !== `/projects/${built.projectId}/chain`) {
          return null;
        }
        chainAsked += 1;
        return chainAsked === 1
          ? servedChainResponse(built.projectId, built.entries, built.hashes)
          : { status: 401, json: { _tag: "Unauthorized" } };
      },
      ...sourceHandlers(),
    ]);
    seedSession(refused.env, expiring.origin, owner);
    expect(
      await runCli(
        [
          "mirror",
          "sync",
          "--server",
          expiring.origin,
          "--mirror",
          refused.mirror.origin,
          "--force",
        ],
        refused.env.layer,
      ),
    ).toBe(1);
    const refusedErrors = refused.env.errors.join("\n");
    expect(refusedErrors).toContain("The server could not be verified again after the commit (");
    expect(refusedErrors).toContain(
      "was not checked against a second view. Re-run `maruhi mirror sync`",
    );
    expect(refusedErrors).not.toContain("failed verification");
    expect(refusedErrors).not.toContain("stopped answering");
  });

  it("an export that keeps changing fails the sync naming the sync, not the export (ruling H revision, round 11)", async () => {
    const pair = await startPair({ source: { changedPages: 4 } });
    expect(await runCli(["mirror", "sync", "--mirror", pair.mirror.origin], pair.env.layer)).toBe(
      1,
    );
    expect(pair.env.errors.join("\n")).toContain(
      `The project changed on ${pair.source.origin} while it was being exported, 4 times in a row: re-run \`maruhi mirror sync\` when the writes settle`,
    );
    expect(pair.env.errors.join("\n")).not.toContain("maruhi project export");
  });

  it("mirror status fails on fork evidence as the sync does (ruling H revision, round 11)", async () => {
    const pair = await startPair();
    pair.state.status = {
      ...pair.state.status,
      head: { ...headOfChain(), chainHeadHashHex: "ab".repeat(32) },
    };
    expect(await runCli(["mirror", "status", "--mirror", pair.mirror.origin], pair.env.layer)).toBe(
      1,
    );
    expect(pair.env.logs.join("\n")).toContain(
      "a different chain at the same height as the verified view",
    );
    expect(pair.env.errors.join("\n")).toContain(
      `The mirror ${pair.mirror.origin} holds a chain head that is a different chain at the same height as the verified view`,
    );
    expect(pair.env.errors.join("\n")).toContain(
      `— against ${pair.source.origin} and against the mirror`,
    );
    // A promoted copy (not marked) diverging from the server: two writable
    // copies, not a mirror to "not promote" (round 12)
    const promoted = await startPair({ marked: false });
    promoted.state.status = {
      mirror: false,
      head: { ...headOfChain(), chainHeadHashHex: "ab".repeat(32) },
    };
    expect(
      await runCli(["mirror", "status", "--mirror", promoted.mirror.origin], promoted.env.layer),
    ).toBe(1);
    expect(promoted.env.errors.join("\n")).toContain(
      `${promoted.mirror.origin} is not marked as a mirror (promoted, or never marked) and holds a chain head that is a different chain at the same height as the verified view`,
    );
    expect(promoted.env.errors.join("\n")).toContain(
      "two writable copies have diverged (a split brain)",
    );
    // A mirror of another source: judged against the wrong server
    const other = await startPair();
    const elsewhere = await deadOrigin();
    other.state.status = {
      ...other.state.status,
      sourceOrigin: elsewhere,
      head: { ...headOfChain(), chainHeadHashHex: "ab".repeat(32) },
    };
    expect(
      await runCli(["mirror", "status", "--mirror", other.mirror.origin], other.env.layer),
    ).toBe(1);
    expect(other.env.errors.join("\n")).toContain(
      `${other.mirror.origin} is a mirror of ${elsewhere}, not of ${other.source.origin}, and holds a chain head that is`,
    );
    expect(other.env.errors.join("\n")).toContain(
      `maruhi mirror status --server ${elsewhere} --mirror ${other.mirror.origin}`,
    );
  });

  it("MARUHI_MIRROR_TOKEN opens the mirror's session without a keychain entry, and is never sent to the server", async () => {
    const source = await start(sourceHandlers());
    const state = mirrorState(true, source.origin);
    const mirror = await start(mirrorHandlers(state));
    const env = await makeTestEnv();
    seedSession(env, source.origin, owner);
    await seedConfig(env, { server: source.origin, defaultProject: built.projectId });
    // No session for the mirror: refused with the mirror-specific guidance
    expect(await runCli(["mirror", "sync", "--mirror", mirror.origin], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(`Not logged in to the mirror ${mirror.origin}`);
    expect(env.errors.join("\n")).toContain("MARUHI_MIRROR_TOKEN");
    env.setEnvVar("MARUHI_MIRROR_TOKEN", "maruhi_pat_MirrorTokenValue0000000000000000000000");
    expect(await runCli(["mirror", "sync", "--mirror", mirror.origin], env.layer)).toBe(0);
    expect(state.pages).toHaveLength(2);
    expect(
      state.bearers.every((b) => b === "Bearer maruhi_pat_MirrorTokenValue0000000000000000000000"),
    ).toBe(true);
    expect(
      source.requests.some(
        (r) =>
          r.headers["authorization"] === "Bearer maruhi_pat_MirrorTokenValue0000000000000000000000",
      ),
    ).toBe(false);
  });
});
