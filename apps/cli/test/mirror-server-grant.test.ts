// Tests for mirrors on the client side (AUTH_SPEC §11-7 — PF2,
// docs/notes/pf2-design.md): `server grant --key-from`.
//
// Properties pinned down:
//  6. server grant --key-from reads the key from the named deployment and
//     appends the grant on the server

import { type ChainEntry, computeServerKeyFingerprint, encodeHex } from "@maruhi/crypto";
import { describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { acceptAppendedEntry } from "./support/chain-handler.ts";
import { makeTestEnv, seedConfig, seedSession } from "./support/env.ts";
import { built, ENV_ID, owner, start, wrap } from "./support/mirror.ts";
import { type MockRequest, onRequest } from "./support/server.ts";

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
