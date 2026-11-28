import { type ChainEntry, computeServerKeyFingerprint, encodeHex } from "@maruhi/crypto";
import { describe, expect, it } from "vite-plus/test";

import { runCli } from "../src/cli.ts";
import { acceptAppendedEntry, servedChain } from "./support/chain-handler.ts";
import { makeTestEnv, seedConfig, seedSession } from "./support/env.ts";
import { built, ENV_ID, owner, start, wrap } from "./support/mirror.ts";
import { onEndpoint } from "./support/server.ts";

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
      onEndpoint("auth.authConfig", () => ({
        status: 200,
        json: {
          githubClientId: "dummy",
          signupPolicy: "open",
          serverKeyFingerprintHex: "00".repeat(16),
          serverEncPubHex: "11".repeat(32),
        },
      })),
      onEndpoint("membership.get", { projectId: built.projectId }, () => ({
        status: 200,
        json: servedChain(built.projectId, entries, hashes),
      })),
      onEndpoint("membership.append", { projectId: built.projectId }, (request) => {
        const entry = request.body.entry as ChainEntry;
        appended.push(entry.payload);
        return acceptAppendedEntry(built.projectId, entries, hashes, entry);
      }),
      onEndpoint("deks.listMine", () => ({ status: 200, json: { deks: [wrap] } })),
      onEndpoint("deks.register", () => ({ status: 204 })),
    ]);
    const keyServer = await start([
      onEndpoint("auth.authConfig", () => ({
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
    expect(keyServer.requests.map((r) => r.path)).toEqual(["/auth/config"]);
    expect(env.logs.join("\n")).toContain(`(the key of ${keyServer.origin})`);
    expect(env.errors.join("\n")).toContain("reach " + keyServer.origin);
  });
});
