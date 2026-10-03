// Tests for `maruhi project export` (AUTH_SPEC §11-6 — PF3), driven through
// runCli against a MockServer that pages an export.
//
// Properties pinned down:
//  1. the pages are concatenated and gzipped to the file exactly (one line
//     per NDJSON line, a trailing newline), the identities companion is
//     written next to it, and the report names the heads and counts only
//  2. a 409 ExportChanged restarts the export from the first page (the
//     partial file is removed first)
//  3. the trailer's chain head is cross-checked against the verified view
//  4. an existing file is never overwritten; --out is required (usage)

import { mkdtemp, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";

import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { chainHandlerOf } from "./support/chain-handler.ts";
import {
  buildChain,
  type BuiltChain,
  genesisOp,
  makeTestUser,
  type TestUser,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, type MockRequest, MockServer, onRequest } from "./support/server.ts";

let owner: TestUser;
let built: BuiltChain;
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

/** The evacuation lines the mock serves (two pages). */
function snapshotLines(): string[] {
  const head = built.hashes[built.hashes.length - 1] ?? "";
  return [
    JSON.stringify({
      kind: "header",
      format: "maruhi-do-snapshot",
      version: 1,
      schemaVersion: 3,
      takenAtMs: 1_700_000_000_000,
      doIdHex: "ab".repeat(32),
    }),
    JSON.stringify({ kind: "table", table: "audit_events", columns: ["seq", "event"] }),
    JSON.stringify({ kind: "row", table: "audit_events", values: [1, "chain.genesis"] }),
    JSON.stringify({ kind: "row", table: "audit_events", values: [2, "project.exported"] }),
    JSON.stringify({
      kind: "table",
      table: "chain_entries",
      columns: ["seq", "entry_hash_hex"],
    }),
    JSON.stringify({ kind: "row", table: "chain_entries", values: [1, head] }),
    JSON.stringify({
      kind: "trailer",
      rows: { audit_events: 2, chain_entries: 1 },
      chainHeadSeq: built.entries.length,
      chainHeadHashHex: head,
      auditMaxSeq: 2,
      auditHeadHashHex: "cd".repeat(32),
      databaseSizeBytes: 4096,
    }),
  ];
}

/** The companion as the server answers it (read at the chain head the file's trailer names). */
const identitiesAt = (chainHeadHashHex: string) => ({
  exportedBy: "user-owner-1111",
  chainHeadSeq: built.entries.length,
  chainHeadHashHex,
  identities: [
    {
      userId: "user-owner-1111",
      provider: "github",
      providerUserId: "9001",
      providerLogin: "octocat",
    },
  ],
  unlinked: [],
});

interface Fixture {
  readonly env: TestEnv;
  readonly server: MockServer;
  readonly dir: string;
  /** How many times the continuation page answers 409 before succeeding. */
  changedPages: number;
}

interface StartOptions {
  readonly changedPages?: number;
  /** An injected answer for the first page (undefined = the normal page). */
  readonly firstPage?: { readonly status: number; readonly json: unknown };
  /** An injected answer for the identities companion (undefined = normal). */
  readonly identities?: { readonly status: number; readonly json: unknown };
  /** How many times the companion answers with another chain head before the file's (a mismatched pair). */
  readonly staleCompanions?: number;
  /** Further endpoints of the mock (the mark's status, for the report's mark line). */
  readonly extraHandlers?: readonly MockHandler[];
}

async function startEnv(options: StartOptions = {}): Promise<Fixture> {
  const lines = snapshotLines();
  const head = {
    chainHeadSeq: built.entries.length,
    chainHeadHashHex: built.hashes[built.hashes.length - 1] ?? "",
    auditMaxSeq: 2,
  };
  const fixture: { changedPages: number; staleCompanions: number } = {
    changedPages: options.changedPages ?? 0,
    staleCompanions: options.staleCompanions ?? 0,
  };
  const handlers: MockHandler[] = [
    ...(options.extraHandlers ?? []),
    chainHandlerOf(built),
    (request: MockRequest) => {
      if (request.method !== "GET" || request.path !== `/projects/${built.projectId}/export`) {
        return null;
      }
      const cursor = request.query["cursor"];
      if (cursor === undefined) {
        return (
          options.firstPage ?? {
            status: 200,
            json: { lines: lines.slice(0, 3), next: "Y3Vyc29y", head },
          }
        );
      }
      if (cursor !== "Y3Vyc29y") {
        return { status: 409, json: { _tag: "ExportChanged", reason: "project-changed" } };
      }
      if (fixture.changedPages > 0) {
        fixture.changedPages -= 1;
        return { status: 409, json: { _tag: "ExportChanged", reason: "project-changed" } };
      }
      return { status: 200, json: { lines: lines.slice(3), head } };
    },
    onRequest("GET", `/projects/${built.projectId}/export/identities`, () => {
      if (options.identities !== undefined) {
        return options.identities;
      }
      if (fixture.staleCompanions > 0) {
        fixture.staleCompanions -= 1;
        return { status: 200, json: identitiesAt("00".repeat(32)) };
      }
      return { status: 200, json: identitiesAt(head.chainHeadHashHex) };
    }),
  ];
  const server = await MockServer.start(handlers);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
  const dir = await mkdtemp(join(tmpdir(), "maruhi-export-test-"));
  return {
    env,
    server,
    dir,
    get changedPages() {
      return fixture.changedPages;
    },
    set changedPages(value: number) {
      fixture.changedPages = value;
    },
  };
}

function pageRequests(server: MockServer): number {
  return server.requests.filter((request) => request.path === `/projects/${built.projectId}/export`)
    .length;
}

describe("maruhi project export (PF3)", () => {
  it("writes the gzipped evacuation lines and the identities companion, and reports heads and counts only", async () => {
    const fixture = await startEnv();
    const out = join(fixture.dir, "project.ndjson.gz");
    expect(await runCli(["project", "export", "--out", out], fixture.env.layer)).toBe(0);
    const text = gunzipSync(await readFile(out)).toString("utf8");
    expect(text).toBe(`${snapshotLines().join("\n")}\n`);
    const companion = JSON.parse(await readFile(`${out}.identities.json`, "utf8")) as unknown;
    expect(companion).toEqual(identitiesAt(built.hashes[built.hashes.length - 1] ?? ""));
    const logs = fixture.env.logs.join("\n");
    expect(logs).toContain(`Exported project ${out} (`);
    expect(logs).toContain("7 lines): chain head seq=1 matches the verified view; audit seq=2");
    expect(logs).toContain("rows: audit_events=2, chain_entries=1");
    expect(logs).toContain(
      `Identities companion: ${out}.identities.json (1 member identity, exported by user-owner-1111)`,
    );
    expect(logs).toContain("submit a restore job with `identitiesKey`");
    // The mark could not be read here (the mock has no status endpoint):
    // the next steps say to mark before relying on the file
    expect(logs).toContain("The project's mark could not be read (");
    expect(logs).toContain("mark it now (`maruhi mirror mark --source <destination url>`)");
    // No row content in the report
    expect(logs).not.toContain("chain.genesis");
    expect(pageRequests(fixture.server)).toBe(2);
  });

  it("reports whether the project is frozen here or still writable (ruling J revision, round 4)", async () => {
    const head = { chainHeadSeq: 1, chainHeadHashHex: built.hashes[0] ?? "" };
    const writable = await startEnv({
      extraHandlers: [
        onRequest("GET", `/projects/${built.projectId}/mirror`, () => ({
          status: 200,
          json: { mirror: false, head },
        })),
      ],
    });
    const out = join(writable.dir, "writable.ndjson.gz");
    expect(await runCli(["project", "export", "--out", out], writable.env.layer)).toBe(0);
    expect(writable.env.logs.join("\n")).toContain(
      "Warning: this project is still writable here — a write after this export does not reach the destination. For a migration, freeze it first with `maruhi mirror mark --source <destination url>`",
    );
    const frozen = await startEnv({
      extraHandlers: [
        onRequest("GET", `/projects/${built.projectId}/mirror`, () => ({
          status: 200,
          json: { mirror: true, sourceOrigin: "https://new.maruhi.app", markedAtMs: 1, head },
        })),
      ],
    });
    const frozenOut = join(frozen.dir, "frozen.ndjson.gz");
    expect(await runCli(["project", "export", "--out", frozenOut], frozen.env.layer)).toBe(0);
    expect(frozen.env.logs.join("\n")).toContain(
      "This project is frozen here (a mirror of https://new.maruhi.app): nothing can land on this server after the export",
    );
  });

  it("restarts from the first page when the project changed between pages, removing the partial file", async () => {
    const fixture = await startEnv({ changedPages: 1 });
    const out = join(fixture.dir, "restart.ndjson.gz");
    expect(await runCli(["project", "export", "--out", out], fixture.env.layer)).toBe(0);
    expect(gunzipSync(await readFile(out)).toString("utf8")).toBe(
      `${snapshotLines().join("\n")}\n`,
    );
    // first attempt: page 1 + the 409; second attempt: page 1 + page 2
    expect(pageRequests(fixture.server)).toBe(4);
    // A project that never settles gives up with the server rejection's wording
    const restless = await startEnv({ changedPages: 10 });
    const never = join(restless.dir, "never.ndjson.gz");
    expect(await runCli(["project", "export", "--out", never], restless.env.layer)).toBe(1);
    expect(restless.env.errors.join("\n")).toContain(
      "The project changed while it was being exported",
    );
    await expect(stat(never)).rejects.toThrow();
    await expect(stat(`${never}.identities.json`)).rejects.toThrow();
  });

  it("starts over when the companion was read at another chain head than the file's, and gives up when it never matches", async () => {
    const once = await startEnv({ staleCompanions: 1 });
    const out = join(once.dir, "stale-once.ndjson.gz");
    expect(await runCli(["project", "export", "--out", out], once.env.layer)).toBe(0);
    const companion = JSON.parse(await readFile(`${out}.identities.json`, "utf8")) as {
      chainHeadHashHex: string;
    };
    expect(companion.chainHeadHashHex).toBe(built.hashes[built.hashes.length - 1]);
    // two attempts: 2 pages each
    expect(pageRequests(once.server)).toBe(4);
    const always = await startEnv({ staleCompanions: 10 });
    const never = join(always.dir, "stale-always.ndjson.gz");
    expect(await runCli(["project", "export", "--out", never], always.env.layer)).toBe(1);
    expect(always.env.errors.join("\n")).toContain(
      "The project changed while it was being exported",
    );
    await expect(stat(never)).rejects.toThrow();
    await expect(stat(`${never}.identities.json`)).rejects.toThrow();
  });

  it("leaves no file behind when the server refuses a page or the companion cannot be fetched", async () => {
    const refused = await startEnv({
      firstPage: {
        status: 429,
        json: { _tag: "ExportRateLimited", retryAfterSeconds: 120 },
      },
    });
    const out = join(refused.dir, "refused.ndjson.gz");
    expect(await runCli(["project", "export", "--out", out], refused.env.layer)).toBe(1);
    expect(refused.env.errors.join("\n")).toContain(
      "Too many exports of this project in the last hour (HTTP 429). Retry after 120 seconds",
    );
    await expect(stat(out)).rejects.toThrow();
    await expect(stat(`${out}.identities.json`)).rejects.toThrow();
    // The next run is not refused as an overwrite
    const again = await startEnv();
    const second = join(again.dir, "second.ndjson.gz");
    expect(await runCli(["project", "export", "--out", second], again.env.layer)).toBe(0);
    // The companion failing removes the data file too (a migration needs both)
    const half = await startEnv({
      identities: { status: 500, json: { message: "injected identities failure" } },
    });
    const data = join(half.dir, "half.ndjson.gz");
    expect(await runCli(["project", "export", "--out", data], half.env.layer)).toBe(1);
    await expect(stat(data)).rejects.toThrow();
    await expect(stat(`${data}.identities.json`)).rejects.toThrow();
  });

  it("never overwrites an existing file, and --out is required", async () => {
    const fixture = await startEnv();
    const out = join(fixture.dir, "existing.ndjson.gz");
    expect(await runCli(["project", "export", "--out", out], fixture.env.layer)).toBe(0);
    expect(await runCli(["project", "export", "--out", out], fixture.env.layer)).toBe(1);
    expect(fixture.env.errors.join("\n")).toContain(`Refusing to overwrite ${out}`);
    expect(await runCli(["project", "export"], fixture.env.layer)).toBe(2);
    expect(fixture.env.errors.join("\n")).toContain("project export requires --out <file>");
  });
});
