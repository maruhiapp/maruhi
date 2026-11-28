import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { chdir, cwd } from "node:process";

import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  distributedEnvironmentStatement,
  distributedManifest,
  distributedValue,
  distributedVariableStatement,
  distributedWrap,
  type GeneratedIdentity,
  generateIdentity,
  genesisOp,
  headOf,
  type WireDistributedEnvironmentStatement,
  type WireDistributedVariableStatement,
} from "@maruhi/test-kit";
import { afterEach, beforeAll, describe, expect, it } from "vite-plus/test";

import { runCli } from "../src/cli.ts";
import { acceptedProxyConfigsPathOf } from "../src/proxy.package/proxy-accept.ts";
import { makeEphemeralCa } from "../src/proxy.package/proxy-cert.ts";
import { parseListenAddress } from "../src/proxy.package/proxy-run.ts";
import {
  makeTestEnv,
  type RunnerCall,
  seedConfig,
  seedSession,
  type TestEnv,
} from "./support/env.ts";
import { httpsViaProxy, type Origin, startOrigin } from "./support/proxy-client.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "dev";
const REAL_TOKEN = "ghp_real_token_0123456789abcdefghijklmnop";
const REAL_DB = "postgres://user:hunter2@db.internal:5432/app";
const REAL_OTHER = "other-secret-value-xyz";

interface Fixture {
  readonly owner: GeneratedIdentity;
  readonly built: BuiltChain;
  readonly wraps: readonly unknown[];
  readonly envStatement: WireDistributedEnvironmentStatement;
  readonly entries: readonly {
    readonly variableId: string;
    readonly statement: WireDistributedVariableStatement;
    readonly value: unknown;
  }[];
}

let fixture: Fixture;
let servers: MockServer[] = [];
let originCa: Awaited<ReturnType<typeof makeEphemeralCa>>;
let origin: Origin;

beforeAll(async () => {
  const owner = await generateIdentity("user-owner-1111");
  const dek = crypto.getRandomValues(new Uint8Array(32));
  const built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek) },
  ]);
  const common = { projectId: built.projectId, environmentId: ENV_ID };
  const wraps = [
    await distributedWrap({ ...common, epoch: 1, dek, recipient: owner, signer: owner }),
  ];
  const head = headOf(built, 2);
  const anchor = { seq: 1, hashHex: built.projectId };
  const entry = async (variableId: string, name: string, plaintext: string) => ({
    variableId,
    statement: await distributedVariableStatement({
      ...common,
      variableId,
      name,
      author: owner,
      head: anchor,
    }),
    value: await distributedValue({
      dek,
      ...common,
      epoch: 1,
      variableId,
      version: 1,
      plaintext,
      writer: owner,
      head,
    }),
  });
  fixture = {
    owner,
    built,
    wraps,
    envStatement: await distributedEnvironmentStatement({
      ...common,
      name: ENV_ID,
      author: owner,
      head: anchor,
    }),
    entries: [
      await entry("v-token", "GITHUB_TOKEN", REAL_TOKEN),
      await entry("v-db", "DATABASE_URL", REAL_DB),
      await entry("v-other", "OTHER", REAL_OTHER),
    ],
  };
  originCa = await makeEphemeralCa(Date.now);
  const leaf = await originCa.issue("api.example.test");
  origin = await startOrigin({ tls: { key: leaf.keyPem, cert: leaf.certPem } });
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
  origin.seen.length = 0;
});

function handlers(): MockHandler[] {
  const { built, wraps, envStatement, entries, owner } = fixture;
  return [
    onRequest("GET", `/projects/${built.projectId}/chain`, () => ({
      status: 200,
      json: {
        projectId: built.projectId,
        entries: built.entries,
        headSeq: built.entries.length,
        headHashHex: built.hashes[built.hashes.length - 1],
        attestations: [],
      },
    })),
    onRequest("GET", `/projects/${built.projectId}/environments/${ENV_ID}/pull`, async () => ({
      status: 200,
      json: {
        environmentId: ENV_ID,
        currentEpoch: 1,
        statement: envStatement,
        variables: entries,
        deletedVariables: [],
        deks: wraps,
        manifest: await distributedManifest({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          issuer: owner,
          head: headOf(built, 2),
          envStatement,
          statements: entries.map((e) => e.statement),
        }),
        schemaPolicy: "enabled" as const,
      },
    })),
  ];
}

async function startEnv(
  config: unknown,
  options: { readonly accepted?: boolean } = {},
): Promise<{ env: TestEnv; configPath: string; configDir: string }> {
  const server = await MockServer.start(handlers());
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, fixture.owner);
  await seedConfig(env, {
    server: server.origin,
    defaultProject: fixture.built.projectId,
    defaultEnvironment: ENV_ID,
  });
  const configDir = await mkdtemp(join(tmpdir(), "maruhi-proxy-run-test-"));
  const configPath = join(configDir, "maruhi.proxy.json");
  await writeFile(configPath, typeof config === "string" ? config : JSON.stringify(config));
  env.setEnvVar("XDG_RUNTIME_DIR", configDir);
  if (typeof config !== "string" && options.accepted !== false) {
    expect(await runCli(["proxy", "accept", "--config", configPath], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain("(first use)");
    env.errors.length = 0;
  }
  env.setProxySeams({
    upstream: {
      connect: () => ({ host: "127.0.0.1", port: origin.port }),
      ca: [originCa.certPem],
    },
  });
  return { env, configPath, configDir };
}

const BROKER_CONFIG = {
  version: 1,
  variables: {
    GITHUB_TOKEN: ["api.example.test"],
    DATABASE_URL: "passthrough",
  },
};

function proxyPortOf(call: RunnerCall): number {
  return Number(new URL(call.extraEnv["HTTPS_PROXY"] ?? "").port);
}

function proxyAuthOf(call: RunnerCall): string {
  const url = new URL(call.extraEnv["HTTPS_PROXY"] ?? "");
  return `${decodeURIComponent(url.username)}:${decodeURIComponent(url.password)}`;
}

describe("maruhi proxy run", () => {
  it("hands the child a placeholder for a brokered variable, the real value for a pass-through, nothing for an unlisted one, and brokers a request made through the proxy", async () => {
    const { env, configPath, configDir } = await startEnv(BROKER_CONFIG);
    let caDir = "";
    let brokered: { status: number; authorization: string | null } | null = null;
    env.setRunnerHandler(async (call) => {
      const e = call.extraEnv;
      expect(e["GITHUB_TOKEN"]).toMatch(/^mhp_GITHUB_TOKEN_[A-Za-z0-9]{22}$/);
      expect(e["DATABASE_URL"]).toBe(REAL_DB);
      expect(e["OTHER"]).toBeUndefined();
      expect(e["HTTP_PROXY"]).toBe(e["HTTPS_PROXY"]);
      expect(e["https_proxy"]).toBe(e["HTTPS_PROXY"]);
      expect(e["NO_PROXY"]).toBe("");
      expect(e["NODE_USE_ENV_PROXY"]).toBe("1");
      caDir = dirname(e["SSL_CERT_FILE"] ?? "");
      expect(caDir.startsWith(join(configDir, "maruhi-proxy-"))).toBe(true);
      const bundle = await readFile(e["SSL_CERT_FILE"] ?? "", "utf8");
      const caOnly = await readFile(e["NODE_EXTRA_CA_CERTS"] ?? "", "utf8");
      expect(caOnly).toMatch(/^-----BEGIN CERTIFICATE-----/);
      expect(bundle.endsWith(caOnly)).toBe(true);
      expect(bundle.split("-----BEGIN CERTIFICATE-----").length).toBeGreaterThan(50);
      expect(e["REQUESTS_CA_BUNDLE"]).toBe(e["SSL_CERT_FILE"]);
      expect(e["GIT_SSL_CAINFO"]).toBe(e["SSL_CERT_FILE"]);
      expect(e["DENO_CERT"]).toBe(e["NODE_EXTRA_CA_CERTS"]);
      expect(call.holdSignals).toBe(true);
      expect(Object.values(e).join("\n")).not.toContain(REAL_TOKEN);
      expect(e["HTTPS_PROXY"]).toMatch(/^http:\/\/maruhi:[A-Za-z0-9]{22}@127\.0\.0\.1:\d+$/);
      const response = await httpsViaProxy({
        proxyPort: proxyPortOf(call),
        ca: [caOnly],
        url: "https://api.example.test/echo",
        headers: { authorization: `Bearer ${e["GITHUB_TOKEN"]}` },
        auth: proxyAuthOf(call),
      });
      brokered = {
        status: response.status,
        authorization: (JSON.parse(response.body.toString()) as { authorization: string | null })
          .authorization,
      };
      return 5;
    });
    expect(await runCli(["proxy", "run", "--config", configPath, "--", "claude"], env.layer)).toBe(
      5,
    );
    expect(env.runnerCalls).toHaveLength(1);
    expect(env.runnerCalls[0]?.command).toEqual(["claude"]);
    expect(origin.seen[0]?.headers.authorization).toBe(`Bearer ${REAL_TOKEN}`);
    expect(brokered).toEqual({
      status: 200,
      authorization: `Bearer ${env.runnerCalls[0]?.extraEnv["GITHUB_TOKEN"]}`,
    });
    expect(caDir).not.toBe("");
    expect(existsSync(caDir)).toBe(false);
    const stderr = env.errors.join("\n");
    expect(stderr).toContain("proxy run: brokering GITHUB_TOKEN → api.example.test (header)");
    expect(stderr).toContain("proxy run: passing through with the real value: DATABASE_URL");
    expect(stderr).toContain("proxy run: withheld (not injected): OTHER");
    expect(stderr).toContain("hosts no rule names are tunnelled untouched");
    expect(stderr).toContain(
      "proxy run: 1 requests brokered, 0 plain requests relayed, 0 connections tunnelled, 0 blocked, 0 failed",
    );
    expect(stderr).toMatch(/proxy listening on 127\.0\.0\.1:\d+;/);
    expect(stderr).not.toContain(proxyAuthOf(env.runnerCalls[0] as RunnerCall).split(":")[1]);
    const everything = [...env.logs, ...env.errors].join("\n");
    expect(everything).not.toContain(REAL_TOKEN);
    expect(everything).not.toContain(REAL_DB);
    expect(everything).not.toContain(REAL_OTHER);
    expect(env.logs).toEqual([]);
  });

  it("passes the pass-through values to the run-output redaction when the output is not a terminal", async () => {
    const { env, configPath } = await startEnv(BROKER_CONFIG);
    env.setTerminal({ stdout: false });
    expect(await runCli(["proxy", "run", "--config", configPath, "--", "true"], env.layer)).toBe(0);
    const redact = (env.runnerCalls[0]?.redact ?? []).map((bytes) =>
      new TextDecoder().decode(bytes),
    );
    const proxyUrl = env.runnerCalls[0]?.extraEnv["HTTPS_PROXY"] ?? "";
    const password = new URL(proxyUrl).password;
    expect(password).toMatch(/^[A-Za-z0-9]{22}$/);
    expect(redact.toSorted()).toEqual([REAL_DB, REAL_TOKEN, password].toSorted());
  });

  it("injects unlisted variables when the config says passthrough, and prints each decision with --verbose", async () => {
    const { env, configPath } = await startEnv({
      ...BROKER_CONFIG,
      unlisted: "passthrough",
      unmatched: "block",
    });
    env.setRunnerHandler(async (call) => {
      expect(call.extraEnv["OTHER"]).toBe(REAL_OTHER);
      const blocked = await httpsViaProxy({
        proxyPort: proxyPortOf(call),
        ca: [],
        url: "https://elsewhere.example.test/x",
        auth: proxyAuthOf(call),
      });
      expect(blocked.status).toBe(403);
      return 0;
    });
    expect(
      await runCli(["proxy", "run", "--config", configPath, "--verbose", "--", "true"], env.layer),
    ).toBe(0);
    const stderr = env.errors.join("\n");
    expect(stderr).toContain("proxy run: hosts no rule names are blocked");
    expect(stderr).toContain(
      "Note: proxy: blocked CONNECT elsewhere.example.test:443 — unmatched host (block)",
    );
    expect(stderr).toContain(
      "proxy run: 0 requests brokered, 0 plain requests relayed, 0 connections tunnelled, 1 blocked, 0 failed",
    );
    expect(stderr).not.toContain(REAL_OTHER);
  });

  it("is allowed when an AI agent is detected (the point of the command) and without a terminal", async () => {
    const { env, configPath } = await startEnv(BROKER_CONFIG);
    env.setAgent({ isAgent: true, name: "claude-code" });
    env.setTerminal({ stdin: false, stdout: false, stderr: false });
    expect(await runCli(["proxy", "run", "--config", configPath, "--", "true"], env.layer)).toBe(0);
    expect(env.runnerCalls).toHaveLength(1);
  });

  it("applies a config only once a person accepted it with `proxy accept`; a new or changed file is refused everywhere, and a brokered project stays gated without its config (§21 R-8 / R-13 / R-14)", async () => {
    const { env, configPath, configDir } = await startEnv(BROKER_CONFIG, { accepted: false });
    const server = servers[servers.length - 1];
    const recordPath = acceptedProxyConfigsPathOf(dirname(env.configPath));
    expect(recordPath).toBe(
      join(dirname(env.configPath), ".config", "maruhi", "proxy-accepted.json"),
    );
    env.setAgent({ isAgent: true, name: "cursor" });
    const requestsBefore = server?.requests.length ?? 0;
    expect(await runCli(["proxy", "run", "--config", configPath, "--", "true"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      `Refused to apply the proxy config ${configPath}: it has not been accepted on this machine yet, and an AI agent environment was detected (cursor): a person reviews the file and runs \`maruhi proxy accept\` from a terminal`,
    );
    expect(env.runnerCalls).toHaveLength(0);
    expect(server?.requests.length).toBe(requestsBefore);
    expect(await runCli(["proxy", "accept", "--config", configPath], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "Refused to accept the proxy config: an AI agent environment was detected (cursor)",
    );
    expect(existsSync(recordPath)).toBe(false);
    env.setAgent({ isAgent: false });
    env.setTerminal({ stdout: false });
    expect(await runCli(["proxy", "run", "--config", configPath, "--", "true"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "stdout is not an interactive terminal: review the file and run `maruhi proxy accept` from a terminal",
    );
    expect(await runCli(["proxy", "accept", "--config", configPath], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "Refused to accept the proxy config: stdout is not an interactive terminal",
    );
    env.setTerminal({ stdout: true });
    env.errors.length = 0;
    expect(await runCli(["proxy", "run", "--config", configPath, "--", "true"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "it has not been accepted on this machine yet, and review it, then run `maruhi proxy accept` to accept it",
    );
    expect(env.runnerCalls).toHaveLength(0);
    env.errors.length = 0;
    expect(await runCli(["proxy", "accept", "--config", configPath], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain(
      `${configPath} accepted on this machine for project ${fixture.built.projectId} (first use): brokers GITHUB_TOKEN → api.example.test (header); passes through DATABASE_URL; unlisted variables are withheld; hosts no rule names are tunnelled untouched`,
    );
    expect(existsSync(recordPath)).toBe(true);
    env.setAgent({ isAgent: true, name: "cursor" });
    const acceptedContent = await readFile(configPath, "utf8");
    await rm(configPath);
    const beforeDelete = cwd();
    chdir(configDir);
    try {
      expect(await runCli(["run", "--", "true"], env.layer)).toBe(1);
      expect(env.errors.join("\n")).toContain("this project is brokered on this machine");
      expect(env.runnerCalls).toHaveLength(0);
    } finally {
      chdir(beforeDelete);
    }
    await writeFile(configPath, acceptedContent);
    expect(await runCli(["proxy", "run", "--config", configPath, "--", "true"], env.layer)).toBe(0);
    expect(env.runnerCalls).toHaveLength(1);
    await writeFile(configPath, JSON.stringify({ ...BROKER_CONFIG, unlisted: "passthrough" }));
    expect(await runCli(["proxy", "run", "--config", configPath, "--", "true"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "it has changed since it was accepted on this machine, and an AI agent environment was detected (cursor)",
    );
    env.setAgent({ isAgent: false });
    env.errors.length = 0;
    expect(await runCli(["proxy", "accept", "--config", configPath], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain(
      "(replaces the content accepted before): brokers GITHUB_TOKEN → api.example.test (header); passes through DATABASE_URL; unlisted variables are passed through with their real value",
    );
    env.errors.length = 0;
    expect(await runCli(["proxy", "accept", "--config", configPath], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain(
      "is already accepted on this machine with this content for this project; nothing changed",
    );
    const otherProject = "f".repeat(64);
    const otherConfigDir = await mkdtemp(join(tmpdir(), "maruhi-proxy-other-"));
    const otherConfigPath = join(otherConfigDir, "maruhi.proxy.json");
    await writeFile(otherConfigPath, JSON.stringify({ ...BROKER_CONFIG, unlisted: "passthrough" }));
    expect(
      await runCli(
        ["proxy", "accept", "--config", otherConfigPath, "--project", otherProject],
        env.layer,
      ),
    ).toBe(0);
    env.setAgent({ isAgent: true, name: "cursor" });
    env.errors.length = 0;
    expect(
      await runCli(["proxy", "run", "--config", otherConfigPath, "--", "true"], env.layer),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "it is accepted on this machine for a different project, not for this one; a person reviews it and runs `maruhi proxy accept` with --project for this project",
    );
    env.setAgent({ isAgent: false });
    env.errors.length = 0;
    expect(await runCli(["proxy", "accept", "--config", otherConfigPath], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain(
      "the same content was already accepted for another project",
    );
    env.setAgent({ isAgent: true, name: "cursor" });
    expect(
      await runCli(["proxy", "run", "--config", otherConfigPath, "--", "true"], env.layer),
    ).toBe(0);
    env.setAgent({ isAgent: false });
    env.runnerCalls.pop();
    const originalCwd = cwd();
    chdir(configDir);
    try {
      env.setAgent({ isAgent: true, name: "cursor" });
      expect(await runCli(["run", "--", "true"], env.layer)).toBe(0);
      expect(env.runnerCalls[1]?.extraEnv["GITHUB_TOKEN"]).toMatch(/^mhp_GITHUB_TOKEN_/);
      await rm(configPath);
      env.errors.length = 0;
      expect(await runCli(["run", "--", "true"], env.layer)).toBe(1);
      expect(env.errors.join("\n")).toContain(
        "Refused to run with the real values: an AI agent environment was detected (cursor), and this project is brokered on this machine (its proxy config",
      );
      expect(env.runnerCalls).toHaveLength(2);
      env.setAgent({ isAgent: false });
      env.setTerminal({ stdout: false });
      expect(await runCli(["run", "--", "true"], env.layer)).toBe(1);
      expect(env.errors.join("\n")).toContain(
        "stdout is not an interactive terminal, and this project is brokered on this machine",
      );
      env.setTerminal({ stdout: true });
      env.errors.length = 0;
      expect(await runCli(["run", "--", "true"], env.layer)).toBe(0);
      expect(env.runnerCalls[2]?.extraEnv["GITHUB_TOKEN"]).toBe(REAL_TOKEN);
      expect(env.errors.join("\n")).toContain(
        "no proxy config is in the working directory; injecting the real values",
      );
    } finally {
      chdir(originalCwd);
    }
    env.setAgent({ isAgent: true, name: "cursor" });
    expect(await runCli(["run", "--", "true"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("this project is brokered on this machine");
    await writeFile(configPath, JSON.stringify(BROKER_CONFIG));
    await writeFile(recordPath, "{ nope");
    env.setAgent({ isAgent: false });
    expect(await runCli(["proxy", "run", "--config", configPath, "--", "true"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "The record of accepted proxy configs cannot be read (corrupt or unreadable)",
    );
    expect(await runCli(["proxy", "accept", "--config", configPath], env.layer)).toBe(1);
    expect(await readFile(recordPath, "utf8")).toBe("{ nope");
    env.errors.length = 0;
    expect(await runCli(["run", "--", "true"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "The record of accepted proxy configs cannot be read (corrupt or unreadable)",
    );
    expect(env.runnerCalls).toHaveLength(3);
  });

  it("warns when a rule names a variable the environment does not hold, and when nothing is brokered", async () => {
    const { env, configPath } = await startEnv({
      version: 1,
      variables: { MISSING: ["api.example.test"], DATABASE_URL: "passthrough" },
    });
    expect(await runCli(["proxy", "run", "--config", configPath, "--", "true"], env.layer)).toBe(0);
    const stderr = env.errors.join("\n");
    expect(stderr).toContain(
      "Warning: proxy run: MISSING has a rule but no value in environment dev",
    );
    expect(stderr).toContain("Warning: proxy run: no variable is brokered");
    expect(env.runnerCalls[0]?.extraEnv["MISSING"]).toBeUndefined();
  });

  it("never starts the child when a connector input is missing from the environment", async () => {
    const { env, configPath } = await startEnv({
      version: 1,
      variables: {
        GH_INSTALLATION_TOKEN: {
          mode: "connector",
          connector: "github-app",
          inputs: { appId: "GH_APP_ID", privateKey: "GITHUB_TOKEN", installationId: "OTHER" },
          hosts: ["api.example.test"],
        },
      },
    });
    expect(await runCli(["proxy", "run", "--config", configPath, "--", "true"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "The connector rule for GH_INSTALLATION_TOKEN names variable GH_APP_ID as its appId, but the environment has no value for it",
    );
    expect(env.runnerCalls).toHaveLength(0);
  });

  it("reports a missing or invalid config before any network, and a --project mismatch as a usage error", async () => {
    const { env, configPath, configDir } = await startEnv("{ not json");
    const server = servers[servers.length - 1];
    expect(await runCli(["proxy", "run", "--config", configPath, "--", "true"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("is invalid: not valid JSON");
    expect(server?.requests).toHaveLength(0);
    env.errors.length = 0;
    expect(
      await runCli(
        ["proxy", "run", "--config", join(configDir, "absent.json"), "--", "true"],
        env.layer,
      ),
    ).toBe(1);
    expect(env.errors).toEqual(
      expect.arrayContaining([
        `maruhi: Cannot read the proxy config ${join(configDir, "absent.json")}. Create it (see the Credential brokering page in the docs), or pass --config <file>`,
      ]),
    );
    env.errors.length = 0;
    await writeFile(configPath, JSON.stringify({ ...BROKER_CONFIG, project: "b".repeat(64) }));
    expect(
      await runCli(
        ["proxy", "run", "--config", configPath, "--project", "c".repeat(64), "--", "true"],
        env.layer,
      ),
    ).toBe(2);
    expect(env.errors.join("\n")).toContain(
      "--project does not match the `project` in the proxy config",
    );
    expect(env.runnerCalls).toHaveLength(0);
  });

  it("proxy accept checks --project's format at its declaration, before the config read, and reports a malformed default project as the config's to fix", async () => {
    const { env, configPath, configDir } = await startEnv(
      { ...BROKER_CONFIG, project: "b".repeat(64) },
      { accepted: false },
    );
    for (const config of [configPath, join(configDir, "absent.json")]) {
      env.errors.length = 0;
      expect(
        await runCli(
          ["proxy", "accept", "--config", config, "--project", "not-a-genesis"],
          env.layer,
        ),
        config,
      ).toBe(2);
      expect(env.errors, config).toEqual([
        "Usage: maruhi proxy accept [flags]",
        "maruhi: Unacceptable value for flag --project (expected: project id (lowercase hex SHA-256 of the genesis entry))",
      ]);
    }
    await writeFile(configPath, JSON.stringify(BROKER_CONFIG));
    await seedConfig(env, { defaultProject: "not-a-genesis" });
    env.errors.length = 0;
    expect(await runCli(["proxy", "accept", "--config", configPath], env.layer)).toBe(1);
    expect(env.errors).toEqual([
      "maruhi: Invalid project ID (64 hex digits) — fix defaultProject in your config",
    ]);
  });

  it("`maruhi run` applies maruhi.proxy.json from the working directory, and --plain is allowed only to a person at a terminal (ADR-0016 decision 7 revision 2)", async () => {
    const { env, configDir } = await startEnv(BROKER_CONFIG);
    const originalCwd = cwd();
    chdir(configDir);
    try {
      expect(await runCli(["run", "--", "claude"], env.layer)).toBe(0);
      const brokered = env.runnerCalls[0]?.extraEnv ?? {};
      expect(brokered["GITHUB_TOKEN"]).toMatch(/^mhp_GITHUB_TOKEN_/);
      expect(brokered["DATABASE_URL"]).toBe(REAL_DB);
      expect(brokered["HTTPS_PROXY"]).toMatch(/^http:\/\/maruhi:/);
      expect(env.runnerCalls[0]?.holdSignals).toBe(true);
      expect(env.errors.join("\n")).toContain(
        "proxy run: brokering GITHUB_TOKEN → api.example.test (header)",
      );
      env.errors.length = 0;
      expect(await runCli(["run", "--plain", "--", "true"], env.layer)).toBe(0);
      const plain = env.runnerCalls[1]?.extraEnv ?? {};
      expect(plain["GITHUB_TOKEN"]).toBe(REAL_TOKEN);
      expect(plain["HTTPS_PROXY"]).toBeUndefined();
      expect(env.runnerCalls[1]?.holdSignals).toBe(false);
      expect(env.errors.join("\n")).toContain(
        "--plain: injecting the real values; maruhi.proxy.json is not applied to this run",
      );
      env.errors.length = 0;
      env.setAgent({ isAgent: true, name: "claude-code" });
      const server = servers[servers.length - 1];
      const requestsBefore = server?.requests.length ?? 0;
      expect(await runCli(["run", "--plain", "--", "true"], env.layer)).toBe(1);
      expect(env.errors.join("\n")).toContain(
        "Refused to run with the real values: an AI agent environment was detected (claude-code) and this repository has a proxy config",
      );
      expect(env.runnerCalls).toHaveLength(2);
      expect(server?.requests.length).toBe(requestsBefore);
      env.setAgent({ isAgent: false });
      env.setTerminal({ stdout: false });
      expect(await runCli(["run", "--plain", "--", "true"], env.layer)).toBe(1);
      expect(env.errors.join("\n")).toContain("stdout is not an interactive terminal");
      expect(await runCli(["run", "--", "true"], env.layer)).toBe(0);
      expect(env.runnerCalls[2]?.extraEnv["GITHUB_TOKEN"]).toMatch(/^mhp_GITHUB_TOKEN_/);
    } finally {
      chdir(originalCwd);
    }
  });

  it("--plain without a config is a no-op note; a broken config in the working directory is reported, not skipped", async () => {
    const { env, configPath, configDir } = await startEnv("{ broken");
    const originalCwd = cwd();
    chdir(configDir);
    try {
      expect(await runCli(["run", "--", "true"], env.layer)).toBe(1);
      expect(env.errors.join("\n")).toContain(
        `The proxy config maruhi.proxy.json is invalid: not valid JSON`,
      );
      expect(env.runnerCalls).toHaveLength(0);
    } finally {
      chdir(originalCwd);
    }
    expect(configPath).toContain("maruhi.proxy.json");
    expect(await runCli(["run", "--plain", "--", "true"], env.layer)).toBe(0);
    expect(env.runnerCalls[0]?.extraEnv["GITHUB_TOKEN"]).toBe(REAL_TOKEN);
    expect(env.errors.join("\n")).toContain(
      "--plain has no effect: no maruhi.proxy.json in the working directory",
    );
  });

  it("--listen binds beyond the loopback and --advertise names the address the command is told (sandbox mode)", async () => {
    const { env, configPath } = await startEnv(BROKER_CONFIG);
    env.setRunnerHandler(async (call) => {
      const url = new URL(call.extraEnv["HTTPS_PROXY"] ?? "");
      expect(url.hostname).toBe("host.docker.internal");
      expect(url.port).not.toBe("");
      const response = await httpsViaProxy({
        proxyPort: Number(url.port),
        ca: [],
        url: "https://api.example.test/ok",
      });
      expect(response.status).toBe(407);
      return 0;
    });
    expect(
      await runCli(
        [
          "proxy",
          "run",
          "--config",
          configPath,
          "--listen",
          "127.0.0.1",
          "--advertise",
          "host.docker.internal",
          "--",
          "true",
        ],
        env.layer,
      ),
    ).toBe(0);
    expect(env.errors.join("\n")).toMatch(
      /proxy listening on 127\.0\.0\.1:\d+, told to the command as host\.docker\.internal:\d+/,
    );
    env.setRunnerHandler(async (call) => {
      const url = new URL(call.extraEnv["HTTPS_PROXY"] ?? "");
      expect(url.hostname).toBe("[fd00::2]");
      expect(url.port).toBe("3128");
      return 0;
    });
    expect(
      await runCli(
        ["proxy", "run", "--config", configPath, "--advertise", "[fd00::2]:3128", "--", "true"],
        env.layer,
      ),
    ).toBe(0);
    expect(env.errors.join("\n")).toContain("told to the command as [fd00::2]:3128");
    env.setRunnerHandler(async () => 0);
    expect(
      await runCli(
        ["proxy", "run", "--config", configPath, "--listen", "not a host/x", "--", "true"],
        env.layer,
      ),
    ).toBe(2);
    expect(env.errors.join("\n")).toContain("--listen must be host[:port]");
  });

  it("requires the run target after `--` like run", async () => {
    const { env, configPath } = await startEnv(BROKER_CONFIG);
    expect(await runCli(["proxy", "run", "--config", configPath], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Specify the command to run after `--`");
    expect(env.runnerCalls).toHaveLength(0);
  });
});

describe("parseListenAddress", () => {
  it("reads host[:port] for names, IPv4 and IPv6 literals (§21 R-6)", () => {
    expect(parseListenAddress("0.0.0.0:8080")).toEqual({ host: "0.0.0.0", port: 8080 });
    expect(parseListenAddress("host.docker.internal")).toEqual({
      host: "host.docker.internal",
      port: 0,
    });
    expect(parseListenAddress("[::1]:8080")).toEqual({ host: "::1", port: 8080 });
    expect(parseListenAddress("[::1]")).toEqual({ host: "::1", port: 0 });
    expect(parseListenAddress("::1")).toEqual({ host: "::1", port: 0 });
    expect(parseListenAddress("[fd00::2]:3128")).toEqual({ host: "fd00::2", port: 3128 });
    expect(parseListenAddress("[::1")).toBeNull();
    expect(parseListenAddress("[::1]x")).toBeNull();
    expect(parseListenAddress("[::1]:70000")).toBeNull();
    expect(parseListenAddress("a/b:1")).toBeNull();
    expect(parseListenAddress(":80")).toBeNull();
  });
});
