// Tests for mirrors on the client side (AUTH_SPEC §11-7 — PF2,
// docs/notes/pf2-design.md): the read-only fallback of `pull` / `run` /
// `ci run` to a configured mirror.
//
// Properties pinned down:
//  3. pull / run retry against the mirror only when the server does not
//     answer (a connection failure, a gateway 503), never on an answer
//     (a 403), and say so on stderr; the command runs once
//  4. ci run requests the lease from the mirror with a token for the
//     mirror's audience

import { createServer } from "node:http";

import { Duration, Effect } from "effect";
import { FetchHttpClient } from "effect/http";
import { describe, expect, it } from "vitest";

import { makeApiClient } from "../src/api.ts";
import { runCli } from "../src/cli.ts";
import { toCliError } from "../src/failure.ts";
import { masterKeyEntryName, tokenEntryName } from "../src/keychain.ts";
import { OIDC_REQUEST_TOKEN_ENV, OIDC_REQUEST_URL_ENV } from "../src/oidc-github.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import {
  alpha,
  ALPHA_VALUE,
  built,
  deadOrigin,
  ENV_ID,
  envStatement,
  headOfChain,
  mirrorHandlers,
  mirrorState,
  owner,
  start,
  wrap,
} from "./support/mirror.ts";
import { type MockHandler, type MockRequest } from "./support/server.ts";
import { makeValueEnvironmentServer } from "./support/value-env.ts";

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
