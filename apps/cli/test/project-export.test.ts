import { mkdtemp, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";

import type { ProjectId } from "@maruhi/core";
import {
  buildChain,
  type BuiltChain,
  type GeneratedIdentity,
  generateIdentity,
  genesisOp,
  testProjectId,
} from "@maruhi/test-kit";
import type { ApiSuccess } from "@maruhi/test-kit/api";
import { Cause, Effect, Exit, Fiber } from "effect";
import { afterEach, beforeAll, describe, expect, it, vi } from "vite-plus/test";

import type { MaruhiClient } from "../src/api.ts";
import { verifyChainSnapshot } from "../src/chain-sync.ts";
import { runCli } from "../src/cli.ts";
import { projectExportOp } from "../src/project.package/project-export.ts";
import { chainHandlerOf } from "./support/chain-handler.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import {
  type EndpointAnswer,
  type MockHandler,
  type MockRequest,
  MockServer,
  offSpec,
  onEndpoint,
} from "./support/server.ts";

const refusedOpens = vi.hoisted(() => new Set<string>());

vi.mock("node:fs", async (importOriginal) => {
  const mod = await importOriginal<typeof import("node:fs")>();
  const { Writable } = await import("node:stream");
  return {
    ...mod,
    createWriteStream: (
      path: Parameters<typeof mod.createWriteStream>[0],
      options?: Parameters<typeof mod.createWriteStream>[1],
    ) => {
      if (!refusedOpens.has(String(path))) {
        return mod.createWriteStream(path, options as never);
      }
      const stream = new Writable({
        write: (_chunk, _encoding, done) => done(),
      });
      setImmediate(() => {
        mod.writeFileSync(path, "a foreign file — never this run's to remove");
        stream.emit(
          "error",
          Object.assign(new Error(`EEXIST: file already exists, open '${String(path)}'`), {
            code: "EEXIST",
          }),
        );
      });
      return stream as unknown as ReturnType<typeof mod.createWriteStream>;
    },
  };
});

let owner: GeneratedIdentity;
let built: BuiltChain;
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await generateIdentity("user-owner-1111");
  built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

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

const identitiesAt = (chainHeadHashHex: string): ApiSuccess<"export.identities"> => ({
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
  changedPages: number;
}

interface StartOptions {
  readonly changedPages?: number;
  readonly firstPage?: { readonly status: number; readonly json: unknown };
  readonly identities?: EndpointAnswer<"export.identities">;
  readonly staleCompanions?: number;
  readonly mirrorOf?: string;
}

async function startEnv(options: StartOptions = {}): Promise<Fixture> {
  const lines = snapshotLines();
  const head = {
    chainHeadSeq: built.entries.length,
    chainHeadHashHex: built.hashes[built.hashes.length - 1] ?? "",
    auditMaxSeq: 2,
    mutationSeq: 3,
    ...(options.mirrorOf === undefined ? {} : { mirrorOf: options.mirrorOf }),
  };
  const fixture: { changedPages: number; staleCompanions: number } = {
    changedPages: options.changedPages ?? 0,
    staleCompanions: options.staleCompanions ?? 0,
  };
  const handlers: MockHandler[] = [
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
    onEndpoint("export.identities", { projectId: built.projectId }, () => {
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
    expect(logs).toContain("Warning: this project is still writable here");
    expect(logs).not.toContain("chain.genesis");
    expect(pageRequests(fixture.server)).toBe(2);
  });

  it("reports whether the project is frozen here or still writable, from the last page's head (ruling J revision, round 5)", async () => {
    const writable = await startEnv();
    const out = join(writable.dir, "writable.ndjson.gz");
    expect(await runCli(["project", "export", "--out", out], writable.env.layer)).toBe(0);
    expect(writable.env.logs.join("\n")).toContain(
      "Warning: this project is still writable here — a write after this export does not reach the destination. For a migration, freeze it first with `maruhi mirror mark --source <destination url>`",
    );
    const frozen = await startEnv({ mirrorOf: "https://new.maruhi.app" });
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
    expect(pageRequests(fixture.server)).toBe(4);
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
    const again = await startEnv();
    const second = join(again.dir, "second.ndjson.gz");
    expect(await runCli(["project", "export", "--out", second], again.env.layer)).toBe(0);
    const half = await startEnv({
      identities: offSpec({ status: 500, json: { message: "injected identities failure" } }),
    });
    const data = join(half.dir, "half.ndjson.gz");
    expect(await runCli(["project", "export", "--out", data], half.env.layer)).toBe(1);
    await expect(stat(data)).rejects.toThrow();
    await expect(stat(`${data}.identities.json`)).rejects.toThrow();
  });

  it("removes the partial file when the export is interrupted mid-write", async () => {
    const lines = snapshotLines();
    const head = {
      chainHeadSeq: built.entries.length,
      chainHeadHashHex: built.hashes[built.hashes.length - 1] ?? "",
      auditMaxSeq: 2,
    };
    let secondPageRequested: () => void = () => undefined;
    const secondPage = new Promise<void>((resolve) => {
      secondPageRequested = resolve;
    });
    const client = {
      export: {
        page: (args: { readonly query: { readonly cursor?: string } }) =>
          args.query.cursor === undefined
            ? Effect.succeed({ lines: lines.slice(0, 3), next: "Y3Vyc29y", head })
            : Effect.suspend(() => {
                secondPageRequested();
                return Effect.never;
              }),
        identities: () => Effect.succeed(identitiesAt(head.chainHeadHashHex)),
      },
    } as unknown as MaruhiClient;
    const verified = await Effect.runPromise(
      verifyChainSnapshot({
        projectId: built.projectId as ProjectId,
        entries: built.entries,
        claimedHeadSeq: built.entries.length,
        claimedHeadHashHex: head.chainHeadHashHex,
      }),
    );
    const dir = await mkdtemp(join(tmpdir(), "maruhi-export-test-"));
    const out = join(dir, "interrupted.ndjson.gz");
    const fiber = Effect.runFork(
      projectExportOp({
        client,
        projectId: testProjectId(built.projectId),
        verified,
        outPath: out,
      }),
    );
    await secondPage;
    await vi.waitFor(async () => {
      await stat(out);
    });
    await Effect.runPromise(Fiber.interrupt(fiber));
    await expect(stat(out)).rejects.toThrow();
    await expect(stat(`${out}.identities.json`)).rejects.toThrow();
  });

  it("removes the partial file when the export dies with a defect mid-write", async () => {
    const lines = snapshotLines();
    const head = {
      chainHeadSeq: built.entries.length,
      chainHeadHashHex: built.hashes[built.hashes.length - 1] ?? "",
      auditMaxSeq: 2,
    };
    const client = {
      export: {
        page: (args: { readonly query: { readonly cursor?: string } }) =>
          args.query.cursor === undefined
            ? Effect.succeed({ lines: lines.slice(0, 3), next: "Y3Vyc29y", head })
            : Effect.sleep("200 millis").pipe(
                Effect.andThen(Effect.die(new Error("injected defect"))),
              ),
        identities: () => Effect.succeed(identitiesAt(head.chainHeadHashHex)),
      },
    } as unknown as MaruhiClient;
    const verified = await Effect.runPromise(
      verifyChainSnapshot({
        projectId: built.projectId as ProjectId,
        entries: built.entries,
        claimedHeadSeq: built.entries.length,
        claimedHeadHashHex: head.chainHeadHashHex,
      }),
    );
    const dir = await mkdtemp(join(tmpdir(), "maruhi-export-test-"));
    const out = join(dir, "defect.ndjson.gz");
    const fiber = Effect.runFork(
      projectExportOp({
        client,
        projectId: testProjectId(built.projectId),
        verified,
        outPath: out,
      }),
    );
    await vi.waitFor(async () => {
      await stat(out);
    });
    const exit = await Effect.runPromise(Fiber.await(fiber));
    expect(Exit.isFailure(exit) && Cause.hasDies(exit.cause)).toBe(true);
    await expect(stat(out)).rejects.toThrow();
    await expect(stat(`${out}.identities.json`)).rejects.toThrow();
  });

  it("removes the companion too when an interrupt races its write", async () => {
    const lines = snapshotLines();
    const head = {
      chainHeadSeq: built.entries.length,
      chainHeadHashHex: built.hashes[built.hashes.length - 1] ?? "",
      auditMaxSeq: 2,
    };
    const identities = {
      ...identitiesAt(head.chainHeadHashHex),
      unlinked: Array.from({ length: 2_000_000 }, (_, i) => `user-unlinked-${i}`),
    };
    const client = {
      export: {
        page: (args: { readonly query: { readonly cursor?: string } }) =>
          args.query.cursor === undefined
            ? Effect.succeed({ lines: lines.slice(0, 3), next: "Y3Vyc29y", head })
            : Effect.succeed({ lines: lines.slice(3), head }),
        identities: () => Effect.succeed(identities),
      },
    } as unknown as MaruhiClient;
    const verified = await Effect.runPromise(
      verifyChainSnapshot({
        projectId: built.projectId as ProjectId,
        entries: built.entries,
        claimedHeadSeq: built.entries.length,
        claimedHeadHashHex: head.chainHeadHashHex,
      }),
    );
    const dir = await mkdtemp(join(tmpdir(), "maruhi-export-test-"));
    const out = join(dir, "interrupt-companion.ndjson.gz");
    const companion = `${out}.identities.json`;
    const fiber = Effect.runFork(
      projectExportOp({
        client,
        projectId: testProjectId(built.projectId),
        verified,
        outPath: out,
      }),
    );
    await vi.waitFor(
      async () => {
        await stat(companion);
      },
      { interval: 1, timeout: 10_000 },
    );
    await Effect.runPromise(Fiber.interrupt(fiber));
    await expect(stat(out)).rejects.toThrow();
    await expect(stat(companion)).rejects.toThrow();
  });

  it("never removes a foreign file that landed between the check and the wx open", async () => {
    const fixture = await startEnv();
    const out = join(fixture.dir, "raced.ndjson.gz");
    refusedOpens.add(out);
    try {
      expect(await runCli(["project", "export", "--out", out], fixture.env.layer)).toBe(1);
      expect(fixture.env.errors.join("\n")).toContain(`Writing ${out} failed (Error)`);
      expect(await readFile(out, "utf8")).toBe("a foreign file — never this run's to remove");
      await expect(stat(`${out}.identities.json`)).rejects.toThrow();
    } finally {
      refusedOpens.delete(out);
    }
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
