import { type ChildProcess, execFile, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

import { testUserId } from "@maruhi/test-kit";
import { Redacted } from "effect";
import { afterAll, beforeAll, describe, expect, it } from "vite-plus/test";

import { runCli } from "../src/cli.ts";
import { serializeStoredToken, tokenEntryName } from "../src/keychain.ts";
import { makeTestEnv, seedConfig, type TestEnv } from "./support/env.ts";

const run = promisify(execFile);

const SERVER_DIR = join(import.meta.dirname, "../../server");
const DAY_MS = 24 * 60 * 60 * 1000;
const TOKEN_LIFETIME_MS = 90 * DAY_MS;

const RECOVERY_CODE = /(?:[A-Z2-7]{4}-){12}[A-Z2-7]{4}/g;

const VARIABLE = "DATABASE_URL";
const VALUE = "postgres://dummy.invalid/smoke";

interface Account {
  readonly userId: string;
  readonly orgId: string;
  readonly tokenId: string;
  readonly token: string;
  readonly login: string;
  readonly githubId: number;
}

const ALICE: Account = {
  userId: "01SMOKEUSERALICE0000000000",
  orgId: "01SMOKEORGALICE00000000000",
  tokenId: "01SMOKETOKENALICE000000000",
  token: "maruhi_pat_smokeDummyTokenOfAlice00000000000000000",
  login: "alice",
  githubId: 1001,
};

const BOB: Account = {
  userId: "01SMOKEUSERBOB000000000000",
  orgId: "01SMOKEORGBOB0000000000000",
  tokenId: "01SMOKETOKENBOB00000000000",
  token: "maruhi_pat_smokeDummyTokenOfBob0000000000000000000",
  login: "bob",
  githubId: 1002,
};

function accountSql(account: Account, nowMs: number): string {
  const tokenHash = createHash("sha256").update(account.token).digest("hex");
  const scopes = JSON.stringify([{ project: "*", permission: "admin" }]);
  return [
    `INSERT INTO users (id, email, email_verified, created_at, updated_at) VALUES ('${account.userId}', NULL, 0, ${nowMs}, ${nowMs});`,
    `INSERT INTO linked_identities (user_id, provider, provider_user_id, provider_login, linked_at) VALUES ('${account.userId}', 'github', '${account.githubId}', '${account.login}', ${nowMs});`,
    `INSERT INTO organizations (id, slug, name, created_at) VALUES ('${account.orgId}', 'u-${account.login}', '${account.login}', ${nowMs});`,
    `INSERT INTO memberships (org_id, user_id, role) VALUES ('${account.orgId}', '${account.userId}', 'owner');`,
    `INSERT INTO api_tokens (id, user_id, name, token_hash, token_prefix, scopes, expires_at, created_at) VALUES ('${account.tokenId}', '${account.userId}', 'smoke', '${tokenHash}', '${account.token.slice(0, 15)}', '${scopes}', ${nowMs + TOKEN_LIFETIME_MS}, ${nowMs});`,
  ].join("\n");
}

function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address === null || typeof address === "string") {
        server.close();
        reject(new Error("failed to allocate a free port"));
        return;
      }
      server.close((err) => (err ? reject(err) : resolve(address.port)));
    });
  });
}

let origin: string;
let stateDir: string;
let devServer: ChildProcess | undefined;

const devServerLogs: string[] = [];

function devServerOutput(): string {
  const text = devServerLogs.join("").trim();
  return text === "" ? "(no output captured)" : text;
}

async function waitForServer(proc: ChildProcess, url: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const up = await fetch(url).then(
      (response) => response.ok,
      () => false,
    );
    if (up) return;
    if (proc.exitCode !== null || proc.signalCode !== null) {
      throw new Error(`cf dev exited before the server at ${url} answered`);
    }
    if (Date.now() > deadline) throw new Error(`server at ${url} did not start`);
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
}

async function stopDevServer(proc: ChildProcess | undefined): Promise<void> {
  if (proc === undefined) return;
  try {
    if (proc.exitCode !== null || proc.signalCode !== null) return;
    const exited = new Promise<void>((resolve) => proc.once("exit", () => resolve()));
    proc.kill("SIGTERM");
    const timedOut = await Promise.race([
      exited.then(() => false),
      new Promise<boolean>((resolve) => setTimeout(() => resolve(true), 10_000).unref()),
    ]);
    if (timedOut) {
      console.error(
        `cf dev did not exit within 10s of SIGTERM; sending SIGKILL\n--- cf dev output ---\n${devServerOutput()}`,
      );
      proc.kill("SIGKILL");
      await exited;
    }
  } finally {
    proc.stdout?.destroy();
    proc.stderr?.destroy();
  }
}

async function prepareDatabase(): Promise<void> {
  const env = { ...process.env, CI: "1" };
  await run("bun", ["run", "db:migrate:local", "--persist-to", stateDir], {
    cwd: SERVER_DIR,
    env,
  });
  const databaseId = (
    await run("bun", ["scripts/d1-id.ts"], { cwd: SERVER_DIR, env })
  ).stdout.trim();
  const nowMs = Date.now();
  await run(
    "bunx",
    [
      "cf",
      "d1",
      "raw",
      databaseId,
      "--local",
      "--persist-to",
      stateDir,
      "--sql",
      `${accountSql(ALICE, nowMs)}\n${accountSql(BOB, nowMs)}`,
    ],
    { cwd: SERVER_DIR, env },
  );
}

beforeAll(async () => {
  stateDir = await mkdtemp(join(tmpdir(), "maruhi-cli-e2e-"));
  await prepareDatabase();
  const port = await getFreePort();
  origin = `http://127.0.0.1:${port}`;
  devServer = spawn("bunx", ["cf", "dev", "--port", String(port), "--", "--persist-to", stateDir], {
    cwd: SERVER_DIR,
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, CI: "1" },
  });
  devServer.stdout?.on("data", (chunk: Buffer) => devServerLogs.push(chunk.toString()));
  devServer.stderr?.on("data", (chunk: Buffer) => devServerLogs.push(chunk.toString()));
  try {
    await waitForServer(devServer, origin, 60_000);
  } catch (cause) {
    await stopDevServer(devServer);
    throw new Error(`cf dev did not become ready\n--- cf dev output ---\n${devServerOutput()}`, {
      cause,
    });
  }
});

afterAll(async () => {
  await stopDevServer(devServer);
  await rm(stateDir, { recursive: true, force: true });
});

async function signedIn(account: Account): Promise<TestEnv> {
  const env = await makeTestEnv();
  await seedConfig(env, { server: origin, identityBacking: "none" });
  env.keychain.set(
    tokenEntryName(origin),
    serializeStoredToken({
      token: Redacted.make(account.token),
      userId: testUserId(account.userId),
      tokenId: account.tokenId,
      expiresAtMs: Date.now() + TOKEN_LIFETIME_MS,
    }),
  );
  return env;
}

interface Outcome {
  readonly code: number;
  readonly out: string;
  readonly err: string;
}

async function maruhi(env: TestEnv, ...args: readonly string[]): Promise<Outcome> {
  env.logs.length = 0;
  env.errors.length = 0;
  const code = await runCli(args, env.layer);
  return { code, out: env.logs.join("\n"), err: env.errors.join("\n") };
}

async function maruhiOk(env: TestEnv, ...args: readonly string[]): Promise<string> {
  const outcome = await maruhi(env, ...args);
  if (outcome.code !== 0) {
    throw new Error(
      `maruhi ${args.slice(0, 2).join(" ")} exited with ${outcome.code}\n${outcome.err.replaceAll(RECOVERY_CODE, "<recovery code>")}`,
    );
  }
  return outcome.out;
}

function firstMatch(pattern: RegExp, text: string, what: string): string {
  const found = pattern.exec(text)?.[1];
  if (found === undefined) {
    throw new Error(`${what} not found in the CLI output`);
  }
  return found;
}

function answerSaveConfirmation(env: TestEnv): void {
  env.setPromptResponses([
    () =>
      firstMatch(
        /^ {4}(?:[A-Z2-7]{4}-){12}([A-Z2-7]{4})$/m,
        env.errors.join("\n"),
        "the recovery code",
      ),
  ]);
}

async function generateKey(env: TestEnv): Promise<string> {
  answerSaveConfirmation(env);
  const out = await maruhiOk(env, "key", "generate");
  return firstMatch(/key fingerprint: ([0-9a-f]{32})/, out, "the key fingerprint");
}

function injectedValues(env: TestEnv): Readonly<Record<string, string>> | undefined {
  return env.runnerCalls.at(-1)?.extraEnv;
}

describe("CLI e2e: the CLI against the server under cf dev", () => {
  let alice: TestEnv;
  let bob: TestEnv;
  let projectId: string;

  it("a new account generates its keys and creates a project", async () => {
    alice = await signedIn(ALICE);
    await generateKey(alice);
    const out = await maruhiOk(alice, "project", "init");
    projectId = firstMatch(/Created project ([0-9a-f]{64})/, out, "the project id");
    await maruhiOk(alice, "config", "set", "defaultProject", projectId);
    expect(await maruhiOk(alice, "env", "create", "dev")).toContain("Created environment dev");
    await maruhiOk(alice, "config", "set", "defaultEnvironment", "dev");
  });

  it("a pushed value comes back verified and is handed to the command decrypted", async () => {
    alice.setStdin(new TextEncoder().encode(VALUE));
    expect(await maruhiOk(alice, "push", VARIABLE)).toContain(`Pushed ${VARIABLE} (version=1`);
    const pulled = await maruhiOk(alice, "pull");
    expect(pulled).toContain("Sync and verification OK: 1 variable");
    expect(pulled).toContain(`${VARIABLE}\tversion=1`);
    await maruhiOk(alice, "run", "--", "true");
    expect(injectedValues(alice)).toEqual({ [VARIABLE]: VALUE });
  });

  it("an account outside the project cannot see it", async () => {
    bob = await signedIn(BOB);
    await generateKey(bob);
    const outcome = await maruhi(bob, "pull", "--project", projectId, "--env", "dev");
    expect(outcome.code).toBe(1);
    expect(outcome.err).toContain("Project not found");
  });

  it("an invited account becomes a member and decrypts the value", async () => {
    const link = firstMatch(
      /^(http\S+\/invite#\S+)$/m,
      await maruhiOk(alice, "invite", "create", "--role", "member"),
      "the invite link",
    );
    bob.setPromptResponses([
      () => firstMatch(/ 12\.(\S+)/, bob.logs.join("\n"), "the inviter's last word"),
    ]);
    const accepted = await maruhiOk(bob, "invite", "accept", link);
    const bobFingerprint = firstMatch(
      /Your key fingerprint[^\n]*\n {2}hex: {2}([0-9a-f]{32})/,
      accepted,
      "the acceptor's fingerprint",
    );
    const added = await maruhiOk(alice, "member", "add", "--expect-fingerprint", bobFingerprint);
    expect(added).toContain(`Added member ${BOB.userId} (role=member)`);
    expect(await maruhiOk(alice, "member", "list")).toContain("Members (2)");

    await maruhiOk(bob, "config", "set", "defaultProject", projectId);
    await maruhiOk(bob, "config", "set", "defaultEnvironment", "dev");
    expect(await maruhiOk(bob, "pull")).toContain("Sync and verification OK: 1 variable");
    await maruhiOk(bob, "run", "--", "true");
    expect(injectedValues(bob)).toEqual({ [VARIABLE]: VALUE });
  });
});
