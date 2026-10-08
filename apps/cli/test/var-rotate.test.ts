// Integration tests for `maruhi var rotate` (PF6 — docs/notes/pf6-design.md
// rulings R2–R6), driven through runCli against the honest in-memory value
// environment and fake issuers.
//
// Invariants pinned down:
//  1. a rotation decrypts the current credential in memory, creates the new
//     one at the issuer, and pushes it as an ordinary new version — the
//     previous credential is left valid and the report says how to finalize
//  2. no value is ever printed (not the old one, not the new one, not the
//     admin credential)
//  3. an AWS rule pushes the key id companion and the secret as two versions
//  4. the admin input may live in another environment the member can decrypt
//  5. --finalize reads the previous version as a verified ancestor and
//     invalidates exactly that credential; a non-interactive finalize needs
//     --yes; an in-place rotation (no grace) asks the same way
//  6. a missing rule, a missing value, and a config of another project stop
//     before anything is sent to the issuer

import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { decryptVariable } from "@maruhi/crypto";
import { Layer } from "effect";
import { FetchHttpClient } from "effect/http";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { type CliServices, runCli } from "../src/cli.ts";
import { IssuerEndpoints } from "../src/rotate-connector.ts";
import {
  buildChain,
  createEnvironmentOp,
  encryptValueFor,
  environmentStatementFor,
  genesisOp,
  headOf,
  hexBytes,
  makeTestUser,
  rotateEpochOp,
  statementFor,
  testEnvironmentId,
  testProjectId,
  testVariableId,
  type BuiltChain,
  type TestUser,
  type WireDistributedEnvironmentStatement,
  type WireDistributedValue,
  type WireRecipientDek,
  type WireStatementSchema,
  valueHashOf,
  wrapDekFor,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer } from "./support/server.ts";
import { withTestClock } from "./support/test-clock.ts";
import { makeValueEnvironmentServer, type ValueEnvironmentState } from "./support/value-env.ts";

const ENV_ID = "prod";
const OPS_ID = "ops";

let owner: TestUser;
let built: BuiltChain;
let dekProd: Uint8Array;
let dekOps: Uint8Array;
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  dekProd = crypto.getRandomValues(new Uint8Array(32));
  dekOps = crypto.getRandomValues(new Uint8Array(32));
  built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dekProd) },
    { actor: owner, operation: createEnvironmentOp(OPS_ID, dekOps) },
  ]);
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

interface Seed {
  readonly variableId: string;
  readonly name: string;
  /** Every version's plaintext, ascending. */
  readonly plaintexts: readonly string[];
  /** The variable's declared schema (layout v3 when maxAgeDays is set). */
  readonly schema?: WireStatementSchema;
}

/** One environment's stateful mock with the given variables. */
async function environmentServer(input: {
  readonly environmentId: string;
  readonly dek: Uint8Array;
  readonly seeds: readonly Seed[];
}) {
  const wrap: WireRecipientDek = await wrapDekFor({
    projectId: built.projectId,
    environmentId: input.environmentId,
    recipient: owner,
    signer: owner,
    epoch: 1,
    dek: input.dek,
  });
  const head = { seq: 1, hashHex: built.projectId };
  const envStatement: WireDistributedEnvironmentStatement = await environmentStatementFor({
    projectId: built.projectId,
    environmentId: input.environmentId,
    name: input.environmentId,
    author: owner,
    head,
  });
  const initialVariables = [];
  const initialHistory = new Map<string, WireDistributedValue[]>();
  for (const seed of input.seeds) {
    const statement = await statementFor({
      projectId: built.projectId,
      environmentId: input.environmentId,
      variableId: seed.variableId,
      name: seed.name,
      author: owner,
      head,
      ...(seed.schema === undefined ? {} : { schema: seed.schema }),
    });
    const values: WireDistributedValue[] = [];
    for (const [index, plaintext] of seed.plaintexts.entries()) {
      const previous = values.at(-1);
      values.push(
        await encryptValueFor({
          dek: input.dek,
          projectId: built.projectId,
          environmentId: input.environmentId,
          epoch: 1,
          variableId: seed.variableId,
          version: index + 1,
          plaintext,
          writer: owner,
          head: headOf(built, 3),
          ...(previous === undefined
            ? {}
            : { prevValueSigHashHex: await valueHashOf(previous, owner.userId) }),
        }),
      );
    }
    const latest = values.at(-1);
    if (latest === undefined) {
      throw new Error("a seed needs at least one version");
    }
    initialVariables.push({ variableId: seed.variableId, statement, value: latest });
    initialHistory.set(seed.variableId, values);
  }
  return {
    dek: input.dek,
    ...makeValueEnvironmentServer({
      chain: built,
      owner,
      environmentId: input.environmentId,
      envStatement,
      wrap,
      initialVariables,
      initialHistory,
    }),
  };
}

async function startEnv(input: {
  readonly prod: readonly Seed[];
  readonly ops?: readonly Seed[];
  readonly config: unknown;
  /** Handlers consulted before the environment's own (a failure injected at one endpoint). */
  readonly before?: readonly MockHandler[];
}): Promise<{
  env: TestEnv;
  prod: ValueEnvironmentState;
  ops: ValueEnvironmentState | null;
  configPath: string;
}> {
  const prod = await environmentServer({ environmentId: ENV_ID, dek: dekProd, seeds: input.prod });
  const ops =
    input.ops === undefined
      ? null
      : await environmentServer({ environmentId: OPS_ID, dek: dekOps, seeds: input.ops });
  const handlers: MockHandler[] = [
    ...(input.before ?? []),
    ...prod.handlers,
    ...(ops === null ? [] : ops.handlers),
  ];
  const server = await MockServer.start(handlers);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, {
    server: server.origin,
    defaultProject: built.projectId,
    defaultEnvironment: ENV_ID,
  });
  const dir = await mkdtemp(join(tmpdir(), "maruhi-var-rotate-test-"));
  const configPath = join(dir, "maruhi.rotate.json");
  await writeFile(
    configPath,
    typeof input.config === "string" ? input.config : JSON.stringify(input.config),
  );
  return { env, prod: prod.state, ops: ops === null ? null : ops.state, configPath };
}

/**
 * The CLI layer with a fake AWS behind the connector: the issuer origins
 * point at `https://iam.test` / `https://sts.test`, and the fetch behind the
 * ambient `HttpClient` answers those from `issuer` (the maruhi server's
 * requests still go out through the real fetch).
 */
function withFakeAws(env: TestEnv, issuer: typeof fetch): Layer.Layer<CliServices> {
  const routed = ((input: string | URL | Request, init?: RequestInit) => {
    const url = input instanceof Request ? input.url : String(input);
    return url.startsWith("https://iam.test/") || url.startsWith("https://sts.test/")
      ? issuer(input, init)
      : globalThis.fetch(input, init);
  }) as typeof fetch;
  return Layer.mergeAll(
    env.layer,
    Layer.succeed(FetchHttpClient.Fetch, routed),
    Layer.succeed(IssuerEndpoints, {
      awsIamBase: "https://iam.test",
      awsStsBase: "https://sts.test",
    }),
  );
}

async function decryptLatest(state: ValueEnvironmentState, dek: Uint8Array, variableId: string) {
  const stored = state.variables.find((entry) => entry.variableId === variableId);
  if (stored === undefined) {
    throw new Error(`variable ${variableId} missing`);
  }
  const result = await decryptVariable({
    dek,
    nonce: hexBytes(stored.value.nonceHex),
    ciphertext: hexBytes(stored.value.ciphertextHex),
    context: {
      projectId: testProjectId(built.projectId),
      environmentId: testEnvironmentId(stored.value.aad.environmentId),
      epoch: stored.value.aad.epoch,
      variableId: testVariableId(variableId),
      version: stored.value.aad.version,
    },
  });
  if (!result.ok) {
    throw new Error("decrypt failed");
  }
  return { plaintext: new TextDecoder().decode(result.value), version: stored.value.aad.version };
}

function recordingSql() {
  const executed: { url: string; statements: readonly string[] }[] = [];
  const probed: string[] = [];
  return {
    executed,
    probed,
    runner: {
      execute: (url: string, statements: readonly string[]) => {
        executed.push({ url, statements });
        return Promise.resolve();
      },
      probe: (url: string) => {
        probed.push(url);
        return Promise.resolve();
      },
    },
  };
}

const OLD_URL = "postgres://app_a:oldpassword@db.example:5432/shop";
const ADMIN_URL = "postgres://admin:adminpassword@db.example:5432/shop";

const PG_CONFIG = {
  version: 1,
  variables: {
    DATABASE_URL: {
      connector: "postgres",
      roles: ["app_a", "app_b"],
      inputs: { adminUrl: { environment: OPS_ID, name: "ADMIN_DATABASE_URL" } },
    },
  },
};

describe("maruhi var rotate (postgres, alternated roles)", () => {
  it("creates the new credential on the admin connection from another environment, pushes it, and reports how to finalize", async () => {
    const { env, prod, ops, configPath } = await startEnv({
      prod: [{ variableId: "v-db", name: "DATABASE_URL", plaintexts: [OLD_URL] }],
      ops: [{ variableId: "v-admin", name: "ADMIN_DATABASE_URL", plaintexts: [ADMIN_URL] }],
      config: PG_CONFIG,
    });
    const sql = recordingSql();
    env.setSqlRunner(sql.runner);
    expect(
      await runCli(["var", "rotate", "DATABASE_URL", "--rotate-config", configPath], env.layer),
    ).toBe(0);
    // The statement ran on the admin URL decrypted from the ops environment
    expect(sql.executed).toHaveLength(1);
    expect(sql.executed[0]?.url).toBe(ADMIN_URL);
    expect(sql.executed[0]?.statements[0]).toMatch(
      /^ALTER ROLE "app_b" WITH PASSWORD '[A-Za-z0-9]{32}'$/,
    );
    // The new URL was pushed as version 2 (an ordinary push — no lineage)
    const versions = prod.writes.filter((write) => write.kind === "version");
    expect(versions).toHaveLength(1);
    const body = versions[0]?.request.body as { sameValueAs?: number } | undefined;
    expect(body?.sameValueAs).toBeUndefined();
    const latest = await decryptLatest(prod, dekProd, "v-db");
    expect(latest.version).toBe(2);
    const url = new URL(latest.plaintext);
    expect(url.username).toBe("app_b");
    expect(url.password).toMatch(/^[A-Za-z0-9]{32}$/);
    expect(sql.probed).toEqual([latest.plaintext]);
    // Nothing was written to the ops environment
    expect(ops?.writes).toEqual([]);
    const output = [...env.logs, ...env.errors].join("\n");
    expect(output).toContain(
      "Rotated DATABASE_URL in environment prod with the postgres connector (DATABASE_URL version=2, epoch=1)",
    );
    expect(output).toContain("role app_b now in use");
    expect(output).toContain("role app_a keeps its previous password until you finalize");
    expect(output).toContain("`maruhi var rotate DATABASE_URL --finalize`");
    // No value, old or new, and no admin credential anywhere in the output
    expect(output).not.toContain("oldpassword");
    expect(output).not.toContain("adminpassword");
    expect(output).not.toContain(url.password);
  });

  it("dates the declared max-age due line off the Effect clock", async () => {
    const { env, configPath } = await startEnv({
      prod: [
        {
          variableId: "v-db",
          name: "DATABASE_URL",
          plaintexts: [OLD_URL],
          schema: { varType: "string", required: true, description: "", maxAgeDays: 30 },
        },
      ],
      ops: [{ variableId: "v-admin", name: "ADMIN_DATABASE_URL", plaintexts: [ADMIN_URL] }],
      config: PG_CONFIG,
    });
    const sql = recordingSql();
    env.setSqlRunner(sql.runner);
    // The due date is computed off the command's Effect clock — pinned here
    // so the whole report line can be asserted.
    const { layer } = await withTestClock(env.layer, { at: Date.UTC(2026, 0, 15) });
    expect(
      await runCli(["var", "rotate", "DATABASE_URL", "--rotate-config", configPath], layer),
    ).toBe(0);
    const dueLine = env.logs.find((line) => line.startsWith("Max age "));
    expect(dueLine).toBe(
      "Max age 30d declared: the next rotation is due by 2026-02-14 (`maruhi rotation list` shows it when it comes close)",
    );
  });

  it("--finalize reads the previous version as a verified ancestor and scrambles that role's password (asks without --yes)", async () => {
    const NEW_URL = "postgres://app_b:newpassword@db.example:5432/shop";
    const { env, configPath } = await startEnv({
      prod: [{ variableId: "v-db", name: "DATABASE_URL", plaintexts: [OLD_URL, NEW_URL] }],
      ops: [{ variableId: "v-admin", name: "ADMIN_DATABASE_URL", plaintexts: [ADMIN_URL] }],
      config: PG_CONFIG,
    });
    const sql = recordingSql();
    env.setSqlRunner(sql.runner);
    // Non-interactive without --yes: refused before anything is sent
    env.setTerminal({ stdin: false, stdout: false });
    expect(
      await runCli(
        ["var", "rotate", "DATABASE_URL", "--finalize", "--rotate-config", configPath],
        env.layer,
      ),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "Refusing to finalize the rotation of DATABASE_URL in a non-interactive environment without --yes",
    );
    expect(sql.executed).toEqual([]);
    env.errors.length = 0;
    // Interactive: the question names the versions; answering n aborts
    env.setTerminal({ stdin: true, stdout: true });
    env.setPromptResponses(["n"]);
    expect(
      await runCli(
        ["var", "rotate", "DATABASE_URL", "--finalize", "--rotate-config", configPath],
        env.layer,
      ),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "will replace the previous role's password with a random one nobody holds (the credential of version 1; version 2 is current)",
    );
    expect(env.errors.join("\n")).toContain("Aborted: nothing was sent to the issuer");
    expect(sql.executed).toEqual([]);
    env.errors.length = 0;
    env.logs.length = 0;
    // --yes: the previous role (app_a, from version 1) is scrambled on the admin connection
    expect(
      await runCli(
        ["var", "rotate", "DATABASE_URL", "--finalize", "--yes", "--rotate-config", configPath],
        env.layer,
      ),
    ).toBe(0);
    expect(sql.executed).toHaveLength(1);
    expect(sql.executed[0]?.url).toBe(ADMIN_URL);
    expect(sql.executed[0]?.statements[0]).toMatch(
      /^ALTER ROLE "app_a" WITH PASSWORD '[A-Za-z0-9]{32}'$/,
    );
    const output = [...env.logs, ...env.errors].join("\n");
    expect(output).toContain(
      "Finalized the rotation of DATABASE_URL in environment prod (postgres): the credential of version 1 is invalidated; version 2 stays current",
    );
    expect(output).not.toContain("oldpassword");
    expect(output).not.toContain("newpassword");
    expect(output).not.toContain("adminpassword");
  });

  it("--finalize with a single version has nothing to finalize; --previous outside --finalize is a usage error", async () => {
    const { env, configPath } = await startEnv({
      prod: [{ variableId: "v-db", name: "DATABASE_URL", plaintexts: [OLD_URL] }],
      ops: [{ variableId: "v-admin", name: "ADMIN_DATABASE_URL", plaintexts: [ADMIN_URL] }],
      config: PG_CONFIG,
    });
    env.setSqlRunner(recordingSql().runner);
    expect(
      await runCli(
        ["var", "rotate", "DATABASE_URL", "--finalize", "--yes", "--rotate-config", configPath],
        env.layer,
      ),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "has no previous version (the current version is 1) — nothing to finalize",
    );
    expect(
      await runCli(
        ["var", "rotate", "DATABASE_URL", "--previous", "1", "--rotate-config", configPath],
        env.layer,
      ),
    ).toBe(2);
    expect(env.errors.join("\n")).toContain("--previous applies to --finalize only");
  });

  it("an in-place rule (no grace) asks before the rotation; --yes accepts", async () => {
    const config = { version: 1, variables: { DATABASE_URL: { connector: "postgres" } } };
    const { env, prod, configPath } = await startEnv({
      prod: [{ variableId: "v-db", name: "DATABASE_URL", plaintexts: [OLD_URL] }],
      config,
    });
    const sql = recordingSql();
    env.setSqlRunner(sql.runner);
    env.setTerminal({ stdin: false, stdout: false });
    expect(
      await runCli(["var", "rotate", "DATABASE_URL", "--rotate-config", configPath], env.layer),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "this rule's rotation invalidates the current credential at once",
    );
    expect(sql.executed).toEqual([]);
    env.errors.length = 0;
    expect(
      await runCli(
        ["var", "rotate", "DATABASE_URL", "--yes", "--rotate-config", configPath],
        env.layer,
      ),
    ).toBe(0);
    // Self-rotation: the current URL is the admin connection
    expect(sql.executed[0]?.url).toBe(OLD_URL);
    expect(sql.executed[0]?.statements[0]).toMatch(/^ALTER ROLE "app_a" WITH PASSWORD '/);
    expect((await decryptLatest(prod, dekProd, "v-db")).version).toBe(2);
    const output = [...env.logs, ...env.errors].join("\n");
    expect(output).toContain(
      "Rotating DATABASE_URL will change the password of role app_a in place",
    );
    expect(output).toContain("nothing to finalize");
    expect(output).not.toContain("--finalize`");
  });
});

describe("maruhi var rotate (aws-iam-access-key)", () => {
  const AWS_CONFIG = {
    version: 1,
    variables: {
      AWS_SECRET_ACCESS_KEY: {
        connector: "aws-iam-access-key",
        accessKeyIdVariable: "AWS_ACCESS_KEY_ID",
        user: "deployer",
      },
    },
  };

  function fakeIam() {
    const actions: string[] = [];
    const fetchImpl = (async (_input: string | URL | Request, init?: RequestInit) => {
      const action = new URLSearchParams(String(init?.body ?? "")).get("Action") ?? "";
      actions.push(action);
      switch (action) {
        case "ListAccessKeys":
          return new Response(
            "<ListAccessKeysResponse><ListAccessKeysResult><AccessKeyMetadata><member><AccessKeyId>AKIAOLD0000000000001</AccessKeyId><Status>Active</Status></member></AccessKeyMetadata></ListAccessKeysResult></ListAccessKeysResponse>",
            { status: 200 },
          );
        case "CreateAccessKey":
          return new Response(
            "<CreateAccessKeyResponse><CreateAccessKeyResult><AccessKey><AccessKeyId>AKIANEW0000000000002</AccessKeyId><SecretAccessKey>brand/new+secret</SecretAccessKey></AccessKey></CreateAccessKeyResult></CreateAccessKeyResponse>",
            { status: 200 },
          );
        case "UpdateAccessKey":
          return new Response("<UpdateAccessKeyResponse/>", { status: 200 });
        case "GetCallerIdentity":
          return new Response(
            "<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/deployer</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>",
            { status: 200 },
          );
        default:
          return new Response(
            "<ErrorResponse><Error><Code>Unexpected</Code></Error></ErrorResponse>",
            { status: 500 },
          );
      }
    }) as typeof fetch;
    return { actions, fetch: fetchImpl };
  }

  it("rotates the pair: the key id companion and the secret are pushed as two versions; the companion name resolves the rule", async () => {
    const { env, prod, configPath } = await startEnv({
      prod: [
        { variableId: "v-id", name: "AWS_ACCESS_KEY_ID", plaintexts: ["AKIAOLD0000000000001"] },
        { variableId: "v-secret", name: "AWS_SECRET_ACCESS_KEY", plaintexts: ["old/secret"] },
      ],
      config: AWS_CONFIG,
    });
    const iam = fakeIam();
    const issuerLayer = withFakeAws(env, iam.fetch);
    expect(
      await runCli(
        ["var", "rotate", "AWS_ACCESS_KEY_ID", "--rotate-config", configPath],
        issuerLayer,
      ),
    ).toBe(0);
    expect(iam.actions).toEqual(["ListAccessKeys", "CreateAccessKey"]);
    expect(await decryptLatest(prod, dekProd, "v-id")).toEqual({
      plaintext: "AKIANEW0000000000002",
      version: 2,
    });
    expect(await decryptLatest(prod, dekProd, "v-secret")).toEqual({
      plaintext: "brand/new+secret",
      version: 2,
    });
    const output = [...env.logs, ...env.errors].join("\n");
    expect(output).toContain(
      "Rotated AWS_SECRET_ACCESS_KEY in environment prod with the aws-iam-access-key connector (AWS_ACCESS_KEY_ID version=2, epoch=1; AWS_SECRET_ACCESS_KEY version=2, epoch=1)",
    );
    expect(output).toContain("user deployer: new access key AKIANEW0000000000002 created");
    expect(output).not.toContain("old/secret");
    expect(output).not.toContain("brand/new+secret");

    // Finalize: the previous key id (version 1 of the companion) is deactivated
    env.logs.length = 0;
    expect(
      await runCli(
        [
          "var",
          "rotate",
          "AWS_SECRET_ACCESS_KEY",
          "--finalize",
          "--yes",
          "--rotate-config",
          configPath,
        ],
        issuerLayer,
      ),
    ).toBe(0);
    // The target is decided against the issuer: the other listed key, held by
    // version 1 of the key id variable, authenticates with version 1's secret
    expect(iam.actions.slice(2)).toEqual([
      "ListAccessKeys",
      "GetCallerIdentity",
      "UpdateAccessKey",
    ]);
    expect(env.logs.join("\n")).toContain("access key AKIAOLD0000000000001 deactivated");
  });

  it("--finalize --previous deactivates the key that authenticates with that version's secret, never one the server's history metadata would name", async () => {
    // Three rotations happened (versions 1..3 of both variables); someone
    // finalizes version 2 explicitly. The issuer lists AKIAMID… and the
    // current key; AKIAMID… was held by version 2 of the key id variable and
    // authenticates with version 2's secret, so it is the one deactivated.
    // The history endpoint's versions and times play no part (a server
    // cannot steer the target by backdating rows)
    const { env, configPath } = await startEnv({
      prod: [
        {
          variableId: "v-id",
          name: "AWS_ACCESS_KEY_ID",
          plaintexts: ["AKIAOLD0000000000001", "AKIAMID0000000000002", "AKIANEW0000000000003"],
        },
        {
          variableId: "v-secret",
          name: "AWS_SECRET_ACCESS_KEY",
          plaintexts: ["old/secret", "mid/secret", "new/secret"],
        },
      ],
      config: AWS_CONFIG,
    });
    const bodies: string[] = [];
    const probes: string[] = [];
    const fetchImpl = (async (_input: string | URL | Request, init?: RequestInit) => {
      const body = String(init?.body ?? "");
      bodies.push(body);
      const action = new URLSearchParams(body).get("Action") ?? "";
      if (action === "ListAccessKeys") {
        return new Response(
          "<ListAccessKeysResponse><ListAccessKeysResult><AccessKeyMetadata><member><AccessKeyId>AKIAMID0000000000002</AccessKeyId><Status>Active</Status></member><member><AccessKeyId>AKIANEW0000000000003</AccessKeyId><Status>Active</Status></member></AccessKeyMetadata></ListAccessKeysResult></ListAccessKeysResponse>",
          { status: 200 },
        );
      }
      if (action === "GetCallerIdentity") {
        const authorization = String(new Headers(init?.headers).get("authorization") ?? "");
        probes.push(authorization);
        return authorization.includes("Credential=AKIAMID0000000000002/")
          ? new Response(
              "<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/deployer</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>",
              { status: 200 },
            )
          : new Response(
              "<ErrorResponse><Error><Code>InvalidClientTokenId</Code></Error></ErrorResponse>",
              { status: 403 },
            );
      }
      return new Response("<UpdateAccessKeyResponse/>", { status: 200 });
    }) as typeof fetch;
    const issuerLayer = withFakeAws(env, fetchImpl);
    expect(
      await runCli(
        [
          "var",
          "rotate",
          "AWS_SECRET_ACCESS_KEY",
          "--finalize",
          "--previous",
          "2",
          "--yes",
          "--rotate-config",
          configPath,
        ],
        issuerLayer,
      ),
    ).toBe(0);
    expect(probes).toHaveLength(1);
    const update = bodies
      .map((body) => new URLSearchParams(body))
      .find((params) => params.get("Action") === "UpdateAccessKey");
    expect(update?.get("AccessKeyId")).toBe("AKIAMID0000000000002");
    expect(update?.get("Status")).toBe("Inactive");
    const output = [...env.logs, ...env.errors].join("\n");
    expect(output).toContain("access key AKIAMID0000000000002 deactivated");
    expect(output).toContain("the credential of version 2 is invalidated; version 3 stays current");
    expect(output).not.toContain("/secret");
  });

  it("a push that fails after the issuer accepted the change names what was stored, its rollback, and the issuer-specific recovery", async () => {
    // The companion (key id) lands as version 2, then the secret's push is
    // refused by the server: the message must not promise that a re-run
    // reclaims the key (two active keys refuse) — it names the orphaned key
    const { env, prod, configPath } = await startEnv({
      prod: [
        { variableId: "v-id", name: "AWS_ACCESS_KEY_ID", plaintexts: ["AKIAOLD0000000000001"] },
        { variableId: "v-secret", name: "AWS_SECRET_ACCESS_KEY", plaintexts: ["old/secret"] },
      ],
      config: AWS_CONFIG,
      before: [
        (request) =>
          request.method === "POST" && request.path.endsWith("/variables/v-secret/versions")
            ? { status: 503, json: { _tag: "Unavailable" } }
            : null,
      ],
    });
    const iam = fakeIam();
    const issuerLayer = withFakeAws(env, iam.fetch);
    expect(
      await runCli(
        ["var", "rotate", "AWS_SECRET_ACCESS_KEY", "--rotate-config", configPath],
        issuerLayer,
      ),
    ).toBe(1);
    expect(iam.actions).toEqual(["ListAccessKeys", "CreateAccessKey"]);
    expect(await decryptLatest(prod, dekProd, "v-id")).toEqual({
      plaintext: "AKIANEW0000000000002",
      version: 2,
    });
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      "The issuer accepted the rotation (user deployer: new access key AKIANEW0000000000002 created (the previous key AKIAOLD0000000000001 stays active)) but storing AWS_SECRET_ACCESS_KEY failed:",
    );
    expect(errors).toContain(
      "Stored so far: AWS_ACCESS_KEY_ID (version 2 — roll it back with `maruhi var rollback AWS_ACCESS_KEY_ID --to 1` so it does not stay paired with the previous value)",
    );
    expect(errors).toContain(
      "Recovery: access key AKIANEW0000000000002 exists at the issuer and its secret is held only by this process (it is not shown) — delete AKIANEW0000000000002 for user deployer at the issuer, then re-run the rotation (a re-run refuses while two active keys exist; only an inactive key is reclaimed)",
    );
    expect(errors).not.toContain("brand/new+secret");
    expect(errors).not.toContain("old/secret");
  });

  it("--finalize when the issuer lists only the current key has nothing to deactivate (the key id variable has a single version)", async () => {
    const { env, configPath } = await startEnv({
      prod: [
        { variableId: "v-id", name: "AWS_ACCESS_KEY_ID", plaintexts: ["AKIAOLD0000000000001"] },
        {
          variableId: "v-secret",
          name: "AWS_SECRET_ACCESS_KEY",
          plaintexts: ["old/secret", "new/secret"],
        },
      ],
      config: AWS_CONFIG,
    });
    const iam = fakeIam();
    const issuerLayer = withFakeAws(env, iam.fetch);
    expect(
      await runCli(
        [
          "var",
          "rotate",
          "AWS_SECRET_ACCESS_KEY",
          "--finalize",
          "--yes",
          "--rotate-config",
          configPath,
        ],
        issuerLayer,
      ),
    ).toBe(0);
    expect(iam.actions).toEqual(["ListAccessKeys"]);
    expect([...env.logs, ...env.errors].join("\n")).toContain(
      "access key AKIAOLD0000000000001 is the only key of user deployer (nothing to deactivate)",
    );
  });
});

describe("maruhi var rotate (exec — a script of the repository, PF8)", () => {
  const EXEC_CONFIG = {
    version: 1,
    variables: {
      STRIPE_SECRET_KEY: {
        connector: "exec",
        rotate: ["./rotate.sh"],
        finalize: ["./finalize.sh"],
        inputs: { STRIPE_ADMIN_KEY: { environment: OPS_ID, name: "STRIPE_ADMIN_KEY" } },
      },
    },
  };
  const encode = (text: string) => new TextEncoder().encode(text);

  it("runs the rotate script with the credential and the admin input in its environment, pushes its stdout as the new version, and finalize hands it the previous credential", async () => {
    const { env, prod, ops, configPath } = await startEnv({
      prod: [{ variableId: "v-stripe", name: "STRIPE_SECRET_KEY", plaintexts: ["sk_live_old"] }],
      ops: [{ variableId: "v-admin", name: "STRIPE_ADMIN_KEY", plaintexts: ["rk_admin"] }],
      config: EXEC_CONFIG,
    });
    env.setCaptureHandler((call) => ({
      exitCode: 0,
      stdout: encode(call.extraEnv["MH_ROTATE_PHASE"] === "rotate" ? "sk_live_new\n" : "done\n"),
      stderr: "talking to stripe with rk_admin\n",
    }));
    expect(
      await runCli(
        ["var", "rotate", "STRIPE_SECRET_KEY", "--rotate-config", configPath],
        env.layer,
      ),
    ).toBe(0);
    expect(env.captureCalls).toHaveLength(1);
    const rotate = env.captureCalls[0];
    expect(rotate?.command).toEqual(["./rotate.sh"]);
    // The scripts run from the config's directory (they travel with the repository)
    expect(rotate?.cwd).toBe(configPath.slice(0, configPath.lastIndexOf("/")));
    expect(rotate?.extraEnv).toEqual({
      MH_ROTATE_VARIABLE: "STRIPE_SECRET_KEY",
      MH_ROTATE_ENVIRONMENT: ENV_ID,
      MH_ROTATE_PHASE: "rotate",
      MH_ROTATE_CURRENT: "sk_live_old",
      STRIPE_SECRET_KEY: "sk_live_old",
      STRIPE_ADMIN_KEY: "rk_admin",
    });
    // The script's stdout became version 2 (an ordinary signed push)
    const latest = await decryptLatest(prod, dekProd, "v-stripe");
    expect(latest).toEqual({ plaintext: "sk_live_new", version: 2 });
    expect(ops?.writes).toEqual([]);
    const output = [...env.logs, ...env.errors].join("\n");
    expect(output).toContain(
      "Rotated STRIPE_SECRET_KEY in environment prod with the exec connector (STRIPE_SECRET_KEY version=2, epoch=1)",
    );
    expect(output).toContain("./rotate.sh: new credential produced");
    expect(output).toContain(
      "Previous credential: the previous credential stays valid until you finalize (./finalize.sh runs with it)",
    );
    expect(output).toContain("`maruhi var rotate STRIPE_SECRET_KEY --finalize`");
    // Nothing the script saw or printed on stderr reaches the output on success
    expect(output).not.toContain("sk_live_old");
    expect(output).not.toContain("sk_live_new");
    expect(output).not.toContain("rk_admin");

    env.logs.length = 0;
    env.errors.length = 0;
    expect(
      await runCli(
        [
          "var",
          "rotate",
          "STRIPE_SECRET_KEY",
          "--finalize",
          "--yes",
          "--rotate-config",
          configPath,
        ],
        env.layer,
      ),
    ).toBe(0);
    expect(env.captureCalls).toHaveLength(2);
    const finalize = env.captureCalls[1];
    expect(finalize?.command).toEqual(["./finalize.sh"]);
    expect(finalize?.extraEnv).toEqual({
      MH_ROTATE_VARIABLE: "STRIPE_SECRET_KEY",
      MH_ROTATE_ENVIRONMENT: ENV_ID,
      MH_ROTATE_PHASE: "finalize",
      MH_ROTATE_CURRENT: "sk_live_new",
      MH_ROTATE_PREVIOUS: "sk_live_old",
      STRIPE_SECRET_KEY: "sk_live_new",
      STRIPE_ADMIN_KEY: "rk_admin",
    });
    const finalized = [...env.logs, ...env.errors].join("\n");
    expect(finalized).toContain(
      "Finalized the rotation of STRIPE_SECRET_KEY in environment prod (exec): the credential of version 1 is invalidated; version 2 stays current",
    );
    expect(finalized).toContain("./finalize.sh: previous credential retired (done)");
    expect(finalized).not.toContain("sk_live_old");
  });

  it("a script whose stdout gained a line is warned about before the push, never refused (D-16), naming the script", async () => {
    const { env, prod, configPath } = await startEnv({
      prod: [{ variableId: "v-stripe", name: "STRIPE_SECRET_KEY", plaintexts: ["sk_live_old"] }],
      ops: [{ variableId: "v-admin", name: "STRIPE_ADMIN_KEY", plaintexts: ["rk_admin"] }],
      config: EXEC_CONFIG,
    });
    env.setCaptureHandler(() => ({
      exitCode: 0,
      stdout: encode("junk_line_dummy\nsk_live_new\n"),
      stderr: "",
    }));
    expect(
      await runCli(
        ["var", "rotate", "STRIPE_SECRET_KEY", "--rotate-config", configPath],
        env.layer,
      ),
    ).toBe(0);
    expect(await decryptLatest(prod, dekProd, "v-stripe")).toEqual({
      plaintext: "junk_line_dummy\nsk_live_new",
      version: 2,
    });
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      "Warning: the new value of STRIPE_SECRET_KEY has 2 lines where the current value has 1 line: check that the rotate script printed only the credential",
    );
    expect(env.logs.join("\n")).toContain("value: 27 bytes, 2 lines");
    expect([...env.logs, ...env.errors].join("\n")).not.toContain("sk_live_new");
    expect([...env.logs, ...env.errors].join("\n")).not.toContain("junk_line_dummy");
  });

  it("a failing script stops the rotation before any push, with its stderr scrubbed; a rule without a finalize script asks first", async () => {
    const { env, prod, configPath } = await startEnv({
      prod: [{ variableId: "v-stripe", name: "STRIPE_SECRET_KEY", plaintexts: ["sk_live_old"] }],
      ops: [{ variableId: "v-admin", name: "STRIPE_ADMIN_KEY", plaintexts: ["rk_admin"] }],
      config: EXEC_CONFIG,
    });
    env.setCaptureHandler(() => ({
      exitCode: 2,
      stdout: new Uint8Array(0),
      stderr: "stripe refused rk_admin for sk_live_old\n",
    }));
    expect(
      await runCli(
        ["var", "rotate", "STRIPE_SECRET_KEY", "--rotate-config", configPath],
        env.layer,
      ),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "exec: the rotate script ./rotate.sh exited with code 2 (its stderr, filtered: stripe refused [redacted] for [redacted])",
    );
    expect(prod.writes).toEqual([]);

    const immediate = await startEnv({
      prod: [{ variableId: "v-stripe", name: "STRIPE_SECRET_KEY", plaintexts: ["sk_live_old"] }],
      config: {
        version: 1,
        variables: { STRIPE_SECRET_KEY: { connector: "exec", rotate: ["./rotate.sh"] } },
      },
    });
    immediate.env.setCaptureHandler(() => ({
      exitCode: 0,
      stdout: encode("sk_live_new"),
      stderr: "",
    }));
    immediate.env.setTerminal({ stdin: false, stdout: false });
    expect(
      await runCli(
        ["var", "rotate", "STRIPE_SECRET_KEY", "--rotate-config", immediate.configPath],
        immediate.env.layer,
      ),
    ).toBe(1);
    expect(immediate.env.errors.join("\n")).toContain(
      "this rule's rotation invalidates the current credential at once (run ./rotate.sh — the rule has no finalize script",
    );
    expect(immediate.env.captureCalls).toEqual([]);
    expect(
      await runCli(
        ["var", "rotate", "STRIPE_SECRET_KEY", "--yes", "--rotate-config", immediate.configPath],
        immediate.env.layer,
      ),
    ).toBe(0);
    expect(immediate.env.captureCalls).toHaveLength(1);
    expect((await decryptLatest(immediate.prod, dekProd, "v-stripe")).plaintext).toBe(
      "sk_live_new",
    );
    expect([...immediate.env.logs, ...immediate.env.errors].join("\n")).toContain(
      "Previous credential: the rotate script was expected to retire the previous credential itself (nothing to finalize)",
    );
  });
});

describe("maruhi var rotate refusals (before anything is sent)", () => {
  it("a variable without a rule, a missing value, and a config of another project", async () => {
    const { env, configPath } = await startEnv({
      prod: [{ variableId: "v-db", name: "DATABASE_URL", plaintexts: [OLD_URL] }],
      config: { version: 1, variables: { OTHER_URL: { connector: "postgres" } } },
    });
    const sql = recordingSql();
    env.setSqlRunner(sql.runner);
    expect(
      await runCli(["var", "rotate", "DATABASE_URL", "--rotate-config", configPath], env.layer),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain("No rotation rule for DATABASE_URL in");
    env.errors.length = 0;
    expect(
      await runCli(
        ["var", "rotate", "OTHER_URL", "--yes", "--rotate-config", configPath],
        env.layer,
      ),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain("Variable OTHER_URL has no value in this environment");
    expect(sql.executed).toEqual([]);

    const other = await startEnv({
      prod: [{ variableId: "v-db", name: "DATABASE_URL", plaintexts: [OLD_URL] }],
      config: {
        version: 1,
        project: "f".repeat(64),
        variables: { DATABASE_URL: { connector: "postgres" } },
      },
    });
    other.env.setSqlRunner(sql.runner);
    expect(
      await runCli(
        ["var", "rotate", "DATABASE_URL", "--rotate-config", other.configPath],
        other.env.layer,
      ),
    ).toBe(2);
    expect(other.env.errors.join("\n")).toContain("belongs to a different project");
    expect(sql.executed).toEqual([]);
  });

  it("a missing admin input names the input and the environment it was expected in", async () => {
    const { env, configPath } = await startEnv({
      prod: [{ variableId: "v-db", name: "DATABASE_URL", plaintexts: [OLD_URL] }],
      ops: [],
      config: PG_CONFIG,
    });
    const sql = recordingSql();
    env.setSqlRunner(sql.runner);
    expect(
      await runCli(["var", "rotate", "DATABASE_URL", "--rotate-config", configPath], env.layer),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "names variable ADMIN_DATABASE_URL in environment ops as its adminUrl, but it has no value there",
    );
    expect(sql.executed).toEqual([]);
  });

  it("an issuer failure is reported with the connector's wording and nothing is pushed", async () => {
    const { env, prod, configPath } = await startEnv({
      prod: [{ variableId: "v-db", name: "DATABASE_URL", plaintexts: [OLD_URL] }],
      ops: [{ variableId: "v-admin", name: "ADMIN_DATABASE_URL", plaintexts: [ADMIN_URL] }],
      config: PG_CONFIG,
    });
    env.setSqlRunner({
      execute: () =>
        Promise.reject(new Error("FATAL: password authentication failed for user admin")),
      probe: () => Promise.resolve(),
    });
    expect(
      await runCli(["var", "rotate", "DATABASE_URL", "--rotate-config", configPath], env.layer),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "postgres: setting the password of role app_b failed: FATAL: password authentication failed for user admin",
    );
    expect(prod.writes).toEqual([]);
  });
});

describe("maruhi var rotate --finalize with an ancestor this device cannot decrypt", () => {
  it("skips the undecryptable version with a warning and never treats its key as one maruhi stored", async () => {
    // The environment rotated from epoch 1 to 2 and this device holds only
    // the epoch-2 wrap (an unfilled gap — device-gaps.ts). Version 1 of the
    // key id variable (epoch 1, AKIAOLD…) cannot be decrypted here. The
    // finalize must still run: that version is skipped with a warning, and
    // because its id is then not one of the ids maruhi is known to have
    // stored, the issuer's AKIAOLD… key is left untouched (fail-safe: the
    // skipped version can only shrink what gets deactivated)
    const dek1 = crypto.getRandomValues(new Uint8Array(32));
    const dek2 = crypto.getRandomValues(new Uint8Array(32));
    const chain = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
    ]);
    const projectId = chain.projectId;
    const wrap2 = await wrapDekFor({
      projectId,
      environmentId: ENV_ID,
      recipient: owner,
      signer: owner,
      epoch: 2,
      dek: dek2,
    });
    const head = { seq: 1, hashHex: projectId };
    const envStatement = await environmentStatementFor({
      projectId,
      environmentId: ENV_ID,
      name: ENV_ID,
      author: owner,
      head,
    });
    const seeded = async (
      variableId: string,
      name: string,
      entries: readonly { readonly plaintext: string; readonly epoch: 1 | 2 }[],
    ) => {
      const statement = await statementFor({
        projectId,
        environmentId: ENV_ID,
        variableId,
        name,
        author: owner,
        head,
      });
      const values: WireDistributedValue[] = [];
      for (const [index, entry] of entries.entries()) {
        const previous = values.at(-1);
        values.push(
          await encryptValueFor({
            dek: entry.epoch === 1 ? dek1 : dek2,
            projectId,
            environmentId: ENV_ID,
            epoch: entry.epoch,
            variableId,
            version: index + 1,
            plaintext: entry.plaintext,
            writer: owner,
            // Signed at the head where that epoch is current
            head: headOf(chain, entry.epoch === 1 ? 2 : 3),
            ...(previous === undefined
              ? {}
              : { prevValueSigHashHex: await valueHashOf(previous, owner.userId) }),
          }),
        );
      }
      const latest = values.at(-1);
      if (latest === undefined) {
        throw new Error("a seed needs at least one version");
      }
      return { variableId, statement, value: latest, values };
    };
    const keyId = await seeded("v-id", "AWS_ACCESS_KEY_ID", [
      { plaintext: "AKIAOLD0000000000001", epoch: 1 },
      { plaintext: "AKIAMID0000000000002", epoch: 2 },
      { plaintext: "AKIANEW0000000000003", epoch: 2 },
    ]);
    const secret = await seeded("v-secret", "AWS_SECRET_ACCESS_KEY", [
      { plaintext: "old/secret", epoch: 2 },
      { plaintext: "new/secret", epoch: 2 },
    ]);
    const prod = makeValueEnvironmentServer({
      chain,
      owner,
      environmentId: ENV_ID,
      envStatement,
      wrap: wrap2,
      wraps: [wrap2],
      currentEpoch: 2,
      initialVariables: [keyId, secret].map((entry) => ({
        variableId: entry.variableId,
        statement: entry.statement,
        value: entry.value,
      })),
      initialHistory: new Map([keyId, secret].map((entry) => [entry.variableId, entry.values])),
    });
    const server = await MockServer.start(prod.handlers);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: projectId,
      defaultEnvironment: ENV_ID,
    });
    const dir = await mkdtemp(join(tmpdir(), "maruhi-var-rotate-gap-test-"));
    const configPath = join(dir, "maruhi.rotate.json");
    await writeFile(
      configPath,
      JSON.stringify({
        version: 1,
        variables: {
          AWS_SECRET_ACCESS_KEY: {
            connector: "aws-iam-access-key",
            accessKeyIdVariable: "AWS_ACCESS_KEY_ID",
            user: "deployer",
          },
        },
      }),
    );
    const actions: string[] = [];
    const fetchImpl = (async (_input: string | URL | Request, init?: RequestInit) => {
      const action = new URLSearchParams(String(init?.body ?? "")).get("Action") ?? "";
      actions.push(action);
      if (action === "ListAccessKeys") {
        return new Response(
          "<ListAccessKeysResponse><ListAccessKeysResult><AccessKeyMetadata><member><AccessKeyId>AKIAOLD0000000000001</AccessKeyId><Status>Active</Status></member><member><AccessKeyId>AKIANEW0000000000003</AccessKeyId><Status>Active</Status></member></AccessKeyMetadata></ListAccessKeysResult></ListAccessKeysResponse>",
          { status: 200 },
        );
      }
      return new Response("<UpdateAccessKeyResponse/>", { status: 200 });
    }) as typeof fetch;
    const issuerLayer = withFakeAws(env, fetchImpl);
    expect(
      await runCli(
        [
          "var",
          "rotate",
          "AWS_SECRET_ACCESS_KEY",
          "--finalize",
          "--yes",
          "--rotate-config",
          configPath,
        ],
        issuerLayer,
      ),
    ).toBe(0);
    const output = [...env.logs, ...env.errors].join("\n");
    expect(output).toContain(
      "version 1 of AWS_ACCESS_KEY_ID could not be decrypted on this device",
    );
    expect(output).toContain("the value it held is not considered");
    expect(output).toContain(
      "access key AKIAOLD0000000000001 of user deployer was never a version of AWS_ACCESS_KEY_ID (not created through maruhi) — left untouched",
    );
    // No probe and no deactivation: the skipped version's key is not touched
    expect(actions).toEqual(["ListAccessKeys"]);
    expect(output).not.toContain("old/secret");
    expect(output).not.toContain("new/secret");
  });
});
