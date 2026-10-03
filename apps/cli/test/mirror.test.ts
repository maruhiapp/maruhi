// Tests for mirrors on the client side (AUTH_SPEC §11-7 — PF2,
// docs/notes/pf2-design.md): `maruhi mirror sync | status | mark | promote`,
// the read-only fallback of `pull` / `run` / `ci run` to a configured mirror,
// the mirror's own credential (MARUHI_MIRROR_TOKEN), and
// `server grant --key-from`.
//
// Properties pinned down:
//  1. sync pages the export from the server and uploads the pages to the
//     mirror in sequence (restarting at 0 when the project changed), under
//     the mirror's own session; the report names heads and counts only
//  2. a mirror that is not marked, or that refuses the replica, fails with
//     the server's reason; status compares the two heads
//  3. pull / run retry against the mirror only when the server does not
//     answer (a connection failure, a gateway 503), never on an answer
//     (a 403), and say so on stderr; the command runs once
//  4. ci run requests the lease from the mirror with a token for the
//     mirror's audience
//  5. MARUHI_MIRROR_TOKEN opens the mirror's session (sent to the mirror only)
//  6. server grant --key-from reads the key from the named deployment and
//     appends the grant on the server

import { createServer } from "node:http";

import { type ChainEntry, computeServerKeyFingerprint, encodeHex } from "@maruhi/crypto";
import { Duration, Effect } from "effect";
import { FetchHttpClient } from "effect/http";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { makeApiClient } from "../src/api.ts";
import { runCli } from "../src/cli.ts";
import { toCliError } from "../src/failure.ts";
import { FloorStore } from "../src/floor.ts";
import { masterKeyEntryName, tokenEntryName } from "../src/keychain.ts";
import { OIDC_REQUEST_TOKEN_ENV, OIDC_REQUEST_URL_ENV } from "../src/oidc-github.ts";
import { acceptAppendedEntry, chainHandlerOf } from "./support/chain-handler.ts";
import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  encryptValueFor,
  environmentStatementFor,
  genesisOp,
  headOf,
  makeTestUser,
  statementFor,
  type TestUser,
  type WireDistributedEnvironmentStatement,
  type WireRecipientDek,
  wrapDekFor,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, type MockRequest, MockServer, onRequest } from "./support/server.ts";
import { makeValueEnvironmentServer, type StoredVariable } from "./support/value-env.ts";

const ENV_ID = "prod";
const ALPHA_VALUE = "alpha-value";

let owner: TestUser;
let built: BuiltChain;
let dek: Uint8Array;
let wrap: WireRecipientDek;
let envStatement: WireDistributedEnvironmentStatement;
let alpha: StoredVariable;
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  dek = crypto.getRandomValues(new Uint8Array(32));
  built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek) },
  ]);
  const common = { projectId: built.projectId, environmentId: ENV_ID };
  wrap = await wrapDekFor({ ...common, epoch: 1, dek, recipient: owner, signer: owner });
  const head = { seq: 1, hashHex: built.projectId };
  envStatement = await environmentStatementFor({
    ...common,
    name: ENV_ID,
    author: owner,
    head,
  });
  alpha = {
    variableId: "va",
    statement: await statementFor({
      ...common,
      variableId: "va",
      name: "ALPHA",
      author: owner,
      head,
    }),
    value: await encryptValueFor({
      dek,
      ...common,
      epoch: 1,
      variableId: "va",
      version: 1,
      plaintext: ALPHA_VALUE,
      writer: owner,
      head: headOf(built, 2),
    }),
  };
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

async function start(handlers: readonly MockHandler[]): Promise<MockServer> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  return server;
}

/** An origin nothing listens on (the connection is refused at once). */
async function deadOrigin(): Promise<string> {
  const server = await MockServer.start([]);
  const origin = server.origin;
  await server.close();
  return origin;
}

const headOfChain = () => ({
  chainHeadSeq: built.entries.length,
  chainHeadHashHex: built.hashes[built.hashes.length - 1] ?? "",
  auditMaxSeq: 4,
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
}

/** The server's own `GET /projects/:id/mirror` answer (null = not served); a test sets it and resets it. */
let sourceStatus: Record<string, unknown> | null = null;

/** The server: the chain and the export's pages. */
function sourceHandlers(options: SourceOptions = {}): MockHandler[] {
  const lines = snapshotLines();
  const state = { changedPages: options.changedPages ?? 0 };
  return [
    chainHandlerOf(built),
    (request: MockRequest) =>
      request.method === "GET" &&
      request.path === `/projects/${built.projectId}/mirror` &&
      sourceStatus !== null
        ? { status: 200, json: sourceStatus }
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

interface MirrorState {
  readonly pages: { readonly sequence: number; readonly lines: readonly string[] }[];
  readonly bearers: string[];
  status: Record<string, unknown>;
  /** An injected answer for the page carrying the trailer. */
  lastPage: { readonly status: number; readonly json: unknown } | null;
}

/** The mirror: the status, the pages (committing when the trailer arrives), the mark and the promotion. */
function mirrorHandlers(state: MirrorState): MockHandler[] {
  const path = `/projects/${built.projectId}/mirror`;
  return [
    (request: MockRequest) => {
      state.bearers.push(String(request.headers["authorization"] ?? ""));
      return null;
    },
    // The mirror serves the chain like any server (the mark's check reads it)
    chainHandlerOf(built),
    onRequest("GET", path, () => ({ status: 200, json: state.status })),
    onRequest("PUT", path, (request) => {
      const body = request.body as { readonly sourceOrigin: string };
      state.status = {
        ...state.status,
        mirror: true,
        sourceOrigin: body.sourceOrigin,
        markedAtMs: 1,
      };
      return { status: 200, json: state.status };
    }),
    onRequest("DELETE", path, () => {
      state.status = { mirror: false, head: state.status["head"] };
      return { status: 200, json: state.status };
    }),
    onRequest("PUT", `${path}/pages`, (request) => {
      const body = request.body as { readonly sequence: number; readonly lines: readonly string[] };
      state.pages.push(body);
      const trailer = body.lines.some((line) => line.includes('"kind":"trailer"'));
      if (trailer && state.lastPage !== null) {
        return state.lastPage;
      }
      return trailer
        ? { status: 200, json: { nextSequence: 0, committed: { atMs: 5, ...headOfChain() } } }
        : { status: 200, json: { nextSequence: body.sequence + 1 } };
    }),
    onRequest("GET", "/auth/me", () => ({
      status: 200,
      json: { userId: owner.userId, orgs: [] },
    })),
  ];
}

function mirrorState(marked = true): MirrorState {
  return {
    pages: [],
    bearers: [],
    status: marked
      ? {
          mirror: true,
          sourceOrigin: "https://my.maruhi.app",
          markedAtMs: 1,
          head: { ...headOfChain(), chainHeadSeq: 1, chainHeadHashHex: built.projectId },
        }
      : { mirror: false, head: headOfChain() },
    lastPage: null,
  };
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
  const state = mirrorState(options.marked);
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
      "--source is the server itself (the same deployment, possibly under another hostname)",
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
      // A "current" tick is the two status reads: no chain download, no
      // export (ruling H revision, round 4)
      expect(pair.source.requests.map((r) => r.path)).toEqual([
        `/projects/${built.projectId}/mirror`,
      ]);
      expect(pair.mirror.requests.map((r) => r.path)).toEqual([
        `/projects/${built.projectId}/mirror`,
      ]);
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
    expect(logs).toContain(`Mirror ${pair.mirror.origin} of https://my.maruhi.app`);
    expect(logs).toContain("Server: chain head seq=2 (the verified view)");
    expect(logs).toContain(
      "Mirror: chain head seq=1 — behind the verified view by 1 chain entry (seq 1 of 2); audit seq=4",
    );
    expect(logs).toContain("No replication recorded since the mark");

    const fresh = await startPair({ marked: false });
    // The source still answers here (the pair's server) but serves no mark
    // to read: a promotion may leave two writable copies, so it is refused
    // unless forced, naming what could not be read (ruling C revision, round 5)
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
      expect(
        await runCli(
          ["mirror", "promote", "--server", moved.mirror.origin, "--force"],
          moved.env.layer,
        ),
      ).toBe(0);
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
    expect(gone.env.errors.join("\n")).toContain("the source's chain could not be read");
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

  it("MARUHI_MIRROR_TOKEN opens the mirror's session without a keychain entry, and is never sent to the server", async () => {
    const source = await start(sourceHandlers());
    const state = mirrorState();
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

/** A session on the mirror without a device key there (the key is the person's — stored for the server origin only). */
function seedMirrorSession(env: TestEnv, mirrorOrigin: string): void {
  seedSession(env, mirrorOrigin, owner);
  env.keychain.delete(masterKeyEntryName(mirrorOrigin, owner.userId));
}

/** The mirror as a full read server (chain + pull), plus the status it reports (a mirror of `sourceOrigin`). */
function readMirrorHandlers(sourceOrigin: string, status?: Record<string, unknown>): MockHandler[] {
  const value = makeValueEnvironmentServer({
    chain: built,
    owner,
    environmentId: ENV_ID,
    envStatement,
    wrap,
    initialVariables: [alpha],
  });
  const state = mirrorState();
  state.status = status ?? { ...state.status, sourceOrigin };
  return [...value.handlers, ...mirrorHandlers(state)];
}

describe("the read-only fallback to a mirror (PF2)", () => {
  it("pull retries against the mirror when the server does not answer, and says so", async () => {
    const dead = await deadOrigin();
    const mirror = await start(readMirrorHandlers(dead));
    const env = await makeTestEnv();
    seedSession(env, dead, owner);
    seedMirrorSession(env, mirror.origin);
    await seedConfig(env, {
      server: dead,
      defaultProject: built.projectId,
      defaultEnvironment: ENV_ID,
      mirror: mirror.origin,
    });
    expect(await runCli(["pull"], env.layer)).toBe(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Failed to connect to the server");
    expect(errors).toContain(`Retrying this read against the mirror ${mirror.origin}`);
    expect(env.logs.join("\n")).toContain("Sync and verification OK: 1 variable");
    expect(mirror.requests.some((r) => r.path.endsWith("/pull"))).toBe(true);
    // The mark was checked first, with the mirror's own session
    expect(mirror.requests[0]?.path).toBe(`/projects/${built.projectId}/mirror`);
  });

  it("a promoted copy, or a mirror of another deployment, is not read as a fallback", async () => {
    const dead = await deadOrigin();
    const promoted = await start(readMirrorHandlers(dead, { mirror: false, head: headOfChain() }));
    const env = await makeTestEnv();
    seedSession(env, dead, owner);
    seedMirrorSession(env, promoted.origin);
    await seedConfig(env, {
      server: dead,
      defaultProject: built.projectId,
      defaultEnvironment: ENV_ID,
      mirror: promoted.origin,
    });
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `${promoted.origin} does not hold this project as a mirror (it was promoted, or never marked), so the read is not retried there`,
    );
    // The mirror's own word never moves a member's writes
    expect(errors).toContain("Confirm with an owner whether the project was promoted");
    expect(errors).not.toContain(`config set server ${promoted.origin}`);
    expect(promoted.requests.some((r) => r.path.endsWith("/pull"))).toBe(false);

    const foreign = await start(readMirrorHandlers("https://elsewhere.example"));
    const other = await makeTestEnv();
    seedSession(other, dead, owner);
    seedMirrorSession(other, foreign.origin);
    await seedConfig(other, {
      server: dead,
      defaultProject: built.projectId,
      defaultEnvironment: ENV_ID,
      mirror: foreign.origin,
    });
    expect(await runCli(["pull"], other.layer)).toBe(1);
    expect(other.errors.join("\n")).toContain(
      `holds this project as a mirror of https://elsewhere.example, not of ${dead}`,
    );
    expect(foreign.requests.some((r) => r.path.endsWith("/pull"))).toBe(false);
  });

  it("a 500 from the server is retried (a crashed handler is not an answer about the read)", async () => {
    const crashed = await start([
      () => ({ status: 500, bodyText: "internal error", contentType: "text/plain" }),
    ]);
    const mirror = await start(readMirrorHandlers(crashed.origin));
    const env = await makeTestEnv();
    seedSession(env, crashed.origin, owner);
    seedMirrorSession(env, mirror.origin);
    await seedConfig(env, {
      server: crashed.origin,
      defaultProject: built.projectId,
      defaultEnvironment: ENV_ID,
      mirror: mirror.origin,
    });
    expect(await runCli(["pull"], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain("Retrying this read against the mirror");
  });

  it("a server that accepts the connection and never answers is unreachable after the request bound", async () => {
    const silent = await start([
      () =>
        new Promise((resolve) => {
          setTimeout(() => resolve({ status: 200, json: {} }), 1500);
        }),
    ]);
    const failure = await Effect.runPromise(
      makeApiClient({ baseUrl: silent.origin, timeout: Duration.millis(200) }).pipe(
        Effect.flatMap((client) => client.auth.authConfig({})),
        Effect.map(() => null),
        Effect.catch((error) => Effect.succeed(toCliError(error))),
        Effect.provide(FetchHttpClient.layer),
      ),
    );
    expect(failure?.unreachable).toBe(true);
    expect(failure?.message).toContain("The server did not answer (no answer within 0.2 s");
  });

  it("a server that sends headers and stalls the body is unreachable after the body bound", async () => {
    const stalled = createServer((_request, response) => {
      response.writeHead(200, { "content-type": "application/json" });
      response.write("{");
      // never ended
    });
    await new Promise<void>((resolve) => {
      stalled.listen(0, "127.0.0.1", resolve);
    });
    const address = stalled.address();
    const port = typeof address === "object" && address !== null ? address.port : 0;
    try {
      const failure = await Effect.runPromise(
        makeApiClient({
          baseUrl: `http://127.0.0.1:${port}`,
          bodyTimeout: Duration.millis(300),
        }).pipe(
          Effect.flatMap((client) => client.auth.authConfig({})),
          Effect.map(() => null),
          Effect.catch((error) => Effect.succeed(toCliError(error))),
          Effect.provide(FetchHttpClient.layer),
        ),
      );
      expect(failure?.unreachable).toBe(true);
      expect(failure?.message).toContain("no complete answer within 0.3 s");
    } finally {
      stalled.closeAllConnections();
      await new Promise<void>((resolve) => {
        stalled.close(() => resolve());
      });
    }
  });

  it("config set mirror warns when no session for the mirror is stored", async () => {
    const env = await makeTestEnv();
    await seedConfig(env, { server: "https://my.maruhi.app" });
    expect(await runCli(["config", "set", "mirror", "https://mirror.example.com"], env.layer)).toBe(
      0,
    );
    expect(env.errors.join("\n")).toContain(
      "no session for https://mirror.example.com is stored: run `maruhi login --server https://mirror.example.com` now, while the server is up",
    );
    const ready = await makeTestEnv();
    seedSession(ready, "https://mirror.example.com", owner);
    await seedConfig(ready, { server: "https://my.maruhi.app" });
    expect(
      await runCli(["config", "set", "mirror", "https://mirror.example.com"], ready.layer),
    ).toBe(0);
    expect(ready.errors.join("\n")).not.toContain("no session for");
  });

  it("a gateway 503 from the server is retried; an answer of the server (403) is not", async () => {
    const gateway = await start([
      () => ({ status: 503, bodyText: "upstream connect error", contentType: "text/plain" }),
    ]);
    const mirror = await start(readMirrorHandlers(gateway.origin));
    const env = await makeTestEnv();
    seedSession(env, gateway.origin, owner);
    seedMirrorSession(env, mirror.origin);
    await seedConfig(env, {
      server: gateway.origin,
      defaultProject: built.projectId,
      defaultEnvironment: ENV_ID,
    });
    expect(await runCli(["pull", "--mirror", mirror.origin], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain("Retrying this read against the mirror");

    const refusing = await start([
      () => ({ status: 403, json: { _tag: "Forbidden", reason: "insufficient-role" } }),
    ]);
    const other = await makeTestEnv();
    seedSession(other, refusing.origin, owner);
    seedMirrorSession(other, mirror.origin);
    await seedConfig(other, {
      server: refusing.origin,
      defaultProject: built.projectId,
      defaultEnvironment: ENV_ID,
    });
    const before = mirror.requests.length;
    expect(await runCli(["pull", "--mirror", mirror.origin], other.layer)).toBe(1);
    expect(other.errors.join("\n")).not.toContain("Retrying");
    expect(mirror.requests).toHaveLength(before);
  });

  it("run reads from the mirror and runs the command once with the values; the mirror equal to the server is no fallback", async () => {
    const dead = await deadOrigin();
    const mirror = await start(readMirrorHandlers(dead));
    const env = await makeTestEnv();
    seedSession(env, dead, owner);
    seedMirrorSession(env, mirror.origin);
    await seedConfig(env, {
      server: dead,
      defaultProject: built.projectId,
      defaultEnvironment: ENV_ID,
    });
    expect(
      await runCli(["run", "--mirror", mirror.origin, "--", "printenv", "ALPHA"], env.layer),
    ).toBe(0);
    expect(env.runnerCalls).toHaveLength(1);
    expect(env.runnerCalls[0]?.extraEnv["ALPHA"]).toBe(ALPHA_VALUE);
    expect(env.logs.join("\n")).not.toContain(ALPHA_VALUE);
    // Nothing was written to the mirror (no attestation, no device registration, no wrap fill)
    expect(
      mirror.requests.filter((r) => r.method !== "GET").map((r) => `${r.method} ${r.path}`),
    ).toEqual([]);

    const same = await makeTestEnv();
    seedSession(same, dead, owner);
    await seedConfig(same, {
      server: dead,
      defaultProject: built.projectId,
      defaultEnvironment: ENV_ID,
      mirror: dead,
    });
    expect(await runCli(["run", "--", "printenv", "ALPHA"], same.layer)).toBe(1);
    expect(same.errors.join("\n")).toContain("no fallback is possible");
  });

  it("a MARUHI_TOKEN run falls back too (the token path keeps the transport failure), through MARUHI_MIRROR_TOKEN", async () => {
    const dead = await deadOrigin();
    const mirror = await start(readMirrorHandlers(dead));
    const env = await makeTestEnv();
    // Only the device key is in the keychain (stored for the server origin); the credentials are env vars
    seedSession(env, dead, owner);
    env.keychain.delete(tokenEntryName(dead));
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_ServerTokenValue00000000000000000000000");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", dead);
    env.setEnvVar("MARUHI_MIRROR_TOKEN", "maruhi_pat_MirrorTokenValue0000000000000000000000");
    await seedConfig(env, {
      server: dead,
      defaultProject: built.projectId,
      defaultEnvironment: ENV_ID,
      mirror: mirror.origin,
    });
    expect(await runCli(["run", "--", "printenv", "ALPHA"], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain(
      `Retrying this read against the mirror ${mirror.origin}`,
    );
    expect(env.runnerCalls[0]?.extraEnv["ALPHA"]).toBe(ALPHA_VALUE);
    const bearers = new Set(mirror.requests.map((r) => String(r.headers["authorization"])));
    expect(bearers).toEqual(new Set(["Bearer maruhi_pat_MirrorTokenValue0000000000000000000000"]));
  });

  it("mirror status reports the mirror's head alone when the server does not answer", async () => {
    const dead = await deadOrigin();
    const mirror = await start(readMirrorHandlers(dead));
    const env = await makeTestEnv();
    seedSession(env, dead, owner);
    seedMirrorSession(env, mirror.origin);
    await seedConfig(env, { server: dead, defaultProject: built.projectId });
    expect(await runCli(["mirror", "status", "--mirror", mirror.origin], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain("Reporting the mirror's head alone");
    const logs = env.logs.join("\n");
    expect(logs).toContain("Server: unreachable (no verified view)");
    expect(logs).toContain("Mirror: chain head seq=1 (head ");
    expect(logs).toContain("the server did not answer, so it is not compared with a verified view");
  });

  it("ci run requests the lease from the mirror with a token for the mirror's audience", async () => {
    const audiences: string[] = [];
    const leased: string[] = [];
    const mirror = await start([
      (request: MockRequest) => {
        if (request.method !== "GET" || request.path !== "/oidc/token") {
          return null;
        }
        audiences.push(request.query["audience"] ?? "");
        const payload = Buffer.from(
          JSON.stringify({
            iss: "https://issuer.example",
            sub: "repo:acme/app",
            aud: request.query["audience"],
          }),
        ).toString("base64url");
        return { status: 200, json: { value: `eyJhbGciOiJSUzI1NiJ9.${payload}.c2ln` } };
      },
      (request: MockRequest) => {
        if (request.method !== "POST" || !request.path.endsWith("/lease")) {
          return null;
        }
        leased.push(request.path);
        return { status: 404, json: { _tag: "ProjectNotFound", projectId: built.projectId } };
      },
    ]);
    const dead = await deadOrigin();
    const env = await makeTestEnv();
    env.setEnvVar(OIDC_REQUEST_URL_ENV, `${mirror.origin}/oidc/token`);
    env.setEnvVar(OIDC_REQUEST_TOKEN_ENV, "runner-token");
    const args = [
      "ci",
      "run",
      "--server",
      dead,
      "--project",
      built.projectId,
      "--env",
      ENV_ID,
      "--mirror",
      mirror.origin,
      "--",
      "printenv",
      "ALPHA",
    ];
    // The mirror answers (a 404 here): the fallback fired, with a second token for the mirror's audience
    expect(await runCli(args, env.layer)).toBe(1);
    expect(audiences).toEqual([dead, mirror.origin]);
    expect(leased).toEqual([`/projects/${built.projectId}/environments/${ENV_ID}/lease`]);
    expect(env.errors.join("\n")).toContain(`Retrying against the mirror ${mirror.origin}`);
    expect(env.runnerCalls).toHaveLength(0);
    // An explicit --audience is kept on the retry (a flag goes before `--`)
    audiences.length = 0;
    const terminator = args.indexOf("--");
    const withAudience = [
      ...args.slice(0, terminator),
      "--audience",
      "https://aud.example",
      ...args.slice(terminator),
    ];
    expect(await runCli(withAudience, env.layer)).toBe(1);
    expect(audiences).toEqual(["https://aud.example", "https://aud.example"]);
  });
});

describe("maruhi server grant --key-from (PF2)", () => {
  it("reads the server key from the named deployment and appends the grant on the server", async () => {
    const keyPub = Uint8Array.from({ length: 32 }, () => 0x6b);
    const fp = await computeServerKeyFingerprint(keyPub);
    if (!fp.ok) throw new Error("fingerprint failed");
    const mirrorFp = encodeHex(fp.value);
    const appended: unknown[] = [];
    const entries = [...built.entries];
    const hashes = [...built.hashes];
    const source = await start([
      onRequest("GET", "/auth/config", () => ({
        status: 200,
        json: {
          githubClientId: "dummy",
          signupPolicy: "open",
          serverKeyFingerprintHex: "00".repeat(16),
          serverEncPubHex: "11".repeat(32),
        },
      })),
      onRequest("GET", `/projects/${built.projectId}/chain`, () => ({
        status: 200,
        json: {
          projectId: built.projectId,
          entries,
          headSeq: entries.length,
          headHashHex: hashes[hashes.length - 1],
          attestations: [],
        },
      })),
      onRequest("POST", `/projects/${built.projectId}/chain/entries`, (request) => {
        const body = request.body as { readonly entry: ChainEntry };
        appended.push(body.entry.payload);
        // The served chain reflects the append (the grant's resync reads it back)
        return acceptAppendedEntry(built.projectId, entries, hashes, body.entry);
      }),
      (request: MockRequest) =>
        /\/environments\/[^/]+\/deks$/.test(request.path)
          ? request.method === "GET"
            ? { status: 200, json: { deks: [wrap] } }
            : { status: 204, json: undefined }
          : null,
    ]);
    const keyServer = await start([
      onRequest("GET", "/auth/config", () => ({
        status: 200,
        json: {
          githubClientId: "dummy",
          signupPolicy: "open",
          serverKeyFingerprintHex: mirrorFp,
          serverEncPubHex: encodeHex(keyPub),
        },
      })),
    ]);
    const env = await makeTestEnv();
    seedSession(env, source.origin, owner);
    await seedConfig(env, { server: source.origin, defaultProject: built.projectId });
    const code = await runCli(
      [
        "server",
        "grant",
        "--environments",
        ENV_ID,
        "--key-from",
        keyServer.origin,
        "--expect-fingerprint",
        mirrorFp,
      ],
      env.layer,
    );
    expect(env.errors.join("\n"), env.errors.join("\n")).not.toContain("maruhi:");
    expect(code).toBe(0);
    expect(appended).toHaveLength(1);
    expect(appended[0]).toMatchObject({
      serverKeyFingerprintHex: mirrorFp,
      serverEncPubHex: encodeHex(keyPub),
      scopeEnvironmentIds: [ENV_ID],
    });
    // The key server was asked for its config only; the grant went to the server
    expect(keyServer.requests.map((r) => r.path)).toEqual(["/auth/config"]);
    expect(env.logs.join("\n")).toContain(`(the key of ${keyServer.origin})`);
    expect(env.errors.join("\n")).toContain("reach " + keyServer.origin);
  });
});
