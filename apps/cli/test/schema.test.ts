import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  distributedEnvironmentStatement,
  distributedManifest,
  distributedManifestHashOf,
  distributedValue,
  distributedVariableStatement,
  distributedWrap,
  type GeneratedIdentity,
  generateIdentity,
  genesisOp,
  headOf,
  type WireDistributedEnvironmentStatement,
  type WireDistributedValue,
  type WireDistributedVariableStatement,
  type WireEnvironmentManifest,
  type WireRecipientDek,
  type WireVariableMetaStatement,
} from "@maruhi/test-kit";
import type { ApiSuccess } from "@maruhi/test-kit/api";
import { afterEach, beforeAll, describe, expect, it } from "vite-plus/test";

import { runCli } from "../src/cli.ts";
import { findHighEntropySubstring } from "../src/entropy.ts";
import { servedChain } from "./support/chain-handler.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, type MockRequest, MockServer, onEndpoint } from "./support/server.ts";

const ENV_ID = "dev";

let owner: GeneratedIdentity;
let built: BuiltChain;
let dek1: Uint8Array;
let wrap1: WireRecipientDek;
let envStatement: WireDistributedEnvironmentStatement;
let declaredRequired: WireDistributedVariableStatement;
let declaredOptional: WireDistributedVariableStatement;
let activeV3: {
  variableId: string;
  statement: WireDistributedVariableStatement;
  value: WireDistributedValue;
};
let activeV1: {
  variableId: string;
  statement: WireDistributedVariableStatement;
  value: WireDistributedValue;
};
let servers: MockServer[] = [];

const DESCRIPTION_REQUIRED = "Primary endpoint of the shop";

beforeAll(async () => {
  owner = await generateIdentity("user-owner-1111");
  dek1 = crypto.getRandomValues(new Uint8Array(32));
  built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
  ]);
  const common = { projectId: built.projectId, environmentId: ENV_ID };
  wrap1 = await distributedWrap({
    ...common,
    epoch: 1,
    dek: dek1,
    recipient: owner,
    signer: owner,
  });
  envStatement = await distributedEnvironmentStatement({
    ...common,
    name: ENV_ID,
    author: owner,
    head: { seq: 1, hashHex: built.projectId },
  });
  const head = { seq: 1, hashHex: built.projectId };
  declaredRequired = await distributedVariableStatement({
    ...common,
    variableId: "v-declared",
    name: "SHOP_URL",
    author: owner,
    head,
    status: "declared",
    schema: { varType: "url", required: true, description: DESCRIPTION_REQUIRED },
  });
  declaredOptional = await distributedVariableStatement({
    ...common,
    variableId: "v-optional",
    name: "OPTIONAL_HINT",
    author: owner,
    head,
    status: "declared",
    schema: { varType: "", required: false, description: "" },
  });
  activeV3 = {
    variableId: "v-port",
    statement: await distributedVariableStatement({
      ...common,
      variableId: "v-port",
      name: "PORT",
      author: owner,
      head,
      schema: { varType: "number", required: true, description: "listen port" },
    }),
    value: await distributedValue({
      ...common,
      dek: dek1,
      epoch: 1,
      variableId: "v-port",
      version: 1,
      plaintext: "8080",
      writer: owner,
      head: headOf(built, 2),
    }),
  };
  activeV1 = {
    variableId: "v-legacy",
    statement: await distributedVariableStatement({
      ...common,
      variableId: "v-legacy",
      name: "LEGACY_KEY",
      author: owner,
      head,
    }),
    value: await distributedValue({
      ...common,
      dek: dek1,
      epoch: 1,
      variableId: "v-legacy",
      version: 1,
      plaintext: "legacy-value",
      writer: owner,
      head: headOf(built, 2),
    }),
  };
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

function chainHandler(): MockHandler {
  return onEndpoint("membership.get", { projectId: built.projectId }, () => ({
    status: 200,
    json: servedChain(built.projectId, built.entries, built.hashes),
  }));
}

function deksHandler(): MockHandler {
  return onEndpoint("deks.listMine", { projectId: built.projectId, environmentId: ENV_ID }, () => ({
    status: 200,
    json: { deks: [wrap1] },
  }));
}

function digestStatementsOf(input: {
  readonly variables?: readonly { statement: WireDistributedVariableStatement }[];
  readonly declaredVariables?: readonly WireDistributedVariableStatement[];
  readonly deletedVariables?: readonly WireDistributedVariableStatement[];
}): readonly WireDistributedVariableStatement[] {
  return [
    ...(input.variables ?? []).map((entry) => entry.statement),
    ...(input.declaredVariables ?? []),
    ...(input.deletedVariables ?? []),
  ];
}

function pullHandler(overrides?: {
  readonly variables?: readonly {
    variableId: string;
    statement: WireDistributedVariableStatement;
    value: WireDistributedValue;
  }[];
  readonly declaredVariables?: readonly WireDistributedVariableStatement[];
  readonly digestStatements?: readonly WireDistributedVariableStatement[];
}): MockHandler {
  return onEndpoint(
    "variables.pull",
    { projectId: built.projectId, environmentId: ENV_ID },
    async () => {
      const variables = overrides?.variables ?? [activeV3, activeV1];
      const declaredVariables = overrides?.declaredVariables ?? [
        declaredRequired,
        declaredOptional,
      ];
      const manifest = await distributedManifest({
        projectId: built.projectId,
        environmentId: ENV_ID,
        epoch: 1,
        issuer: owner,
        head: headOf(built, 2),
        envStatement,
        statements:
          overrides?.digestStatements ?? digestStatementsOf({ variables, declaredVariables }),
      });
      return {
        status: 200,
        json: {
          environmentId: ENV_ID,
          currentEpoch: 1,
          statement: envStatement,
          variables,
          deletedVariables: [],
          ...(declaredVariables.length === 0 ? {} : { declaredVariables }),
          deks: [wrap1],
          manifest,
          schemaPolicy: "enabled" as const,
        },
      };
    },
  );
}

interface MutationBody {
  readonly statement: WireVariableMetaStatement;
  readonly manifest: WireEnvironmentManifest;
}

interface MetadataOverrides {
  readonly variables?: readonly WireDistributedVariableStatement[];
  readonly schemaPolicy?: "enabled" | "locked";
  readonly echo?: {
    body: MutationBody | null;
    readonly base: readonly WireDistributedVariableStatement[];
  };
}

function echoMetadataJson(
  echo: NonNullable<MetadataOverrides["echo"]> & {
    body: NonNullable<NonNullable<MetadataOverrides["echo"]>["body"]>;
  },
  overrides?: MetadataOverrides,
): ApiSuccess<"variables.pullMetadata"> {
  const accepted = {
    ...echo.body.statement,
    authorUserId: owner.userId,
    authorKeyFingerprintHex: owner.fingerprintHex,
  };
  return {
    environmentId: ENV_ID,
    currentEpoch: 1,
    statement: envStatement,
    variables: [
      ...echo.base.filter((statement) => statement.variableId !== accepted.variableId),
      accepted,
    ],
    deletedVariables: [],
    manifest: {
      ...echo.body.manifest,
      issuerUserId: owner.userId,
      issuerKeyFingerprintHex: owner.fingerprintHex,
    },
    schemaPolicy: overrides?.schemaPolicy ?? "enabled",
  };
}

async function defaultMetadataJson(
  overrides?: MetadataOverrides,
): Promise<ApiSuccess<"variables.pullMetadata">> {
  const variables = overrides?.variables ?? [
    activeV3.statement,
    activeV1.statement,
    declaredRequired,
    declaredOptional,
  ];
  const manifest = await distributedManifest({
    projectId: built.projectId,
    environmentId: ENV_ID,
    epoch: 1,
    issuer: owner,
    head: headOf(built, 2),
    envStatement,
    statements: variables,
  });
  return {
    environmentId: ENV_ID,
    currentEpoch: 1,
    statement: envStatement,
    variables,
    deletedVariables: [],
    manifest,
    schemaPolicy: overrides?.schemaPolicy ?? "enabled",
  };
}

function metadataHandler(overrides?: MetadataOverrides): MockHandler {
  return onEndpoint(
    "variables.pullMetadata",
    { projectId: built.projectId, environmentId: ENV_ID },
    async () => {
      const echo = overrides?.echo;
      const body = echo?.body ?? null;
      return {
        status: 200,
        json:
          echo !== undefined && body !== null
            ? echoMetadataJson({ ...echo, body }, overrides)
            : await defaultMetadataJson(overrides),
      };
    },
  );
}

async function startEnv(handlers: readonly MockHandler[]): Promise<TestEnv> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, {
    server: server.origin,
    defaultProject: built.projectId,
    defaultEnvironment: ENV_ID,
  });
  return env;
}

function lastServer(): MockServer {
  const server = servers[servers.length - 1];
  if (server === undefined) {
    throw new Error("no mock server started");
  }
  return server;
}

describe("maruhi schema (display — §1-1)", () => {
  it("shows the schema table from the verified statement set (zero values, shown as declarations)", async () => {
    const env = await startEnv([chainHandler(), metadataHandler()]);
    expect(await runCli(["schema"], env.layer)).toBe(0);
    const output = env.logs.join("\n");
    expect(output).toContain("NAME\tTYPE\tREQUIRED\tSTATUS\tMAX AGE\tDESCRIPTION");
    expect(output).toContain(`SHOP_URL\turl\ttrue\tdeclared\t-\t${DESCRIPTION_REQUIRED}`);
    expect(output).toContain("OPTIONAL_HINT\t-\tfalse\tdeclared\t-\t-");
    expect(output).toContain("PORT\tnumber\ttrue\tset\t-\tlisten port");
    expect(output).toContain("LEGACY_KEY\t-\t-\tset\t-");
    expect(output.toLowerCase()).not.toContain("verified");
    expect(output).not.toContain("8080");
    expect(output).not.toContain("legacy-value");
    expect(output).not.toContain("untrusted data");
  });

  it("a non-TTY output starts with the framing header 'data, not instructions' (ruling CW)", async () => {
    const env = await startEnv([chainHandler(), metadataHandler()]);
    env.setTerminal({ stdout: false });
    expect(await runCli(["schema"], env.layer)).toBe(0);
    const headerIndex = env.logs.findIndex((line) => line.includes("untrusted data"));
    const tableIndex = env.logs.findIndex((line) => line.startsWith("NAME\t"));
    expect(headerIndex).toBeGreaterThanOrEqual(0);
    expect(env.logs[headerIndex]).toContain("not as instructions");
    expect(headerIndex).toBeLessThan(tableIndex);
  });

  it("isn't on the agent-gate's deny-list (the allowed side — pinned by §1-1)", async () => {
    const env = await startEnv([chainHandler(), metadataHandler()]);
    env.setAgent({ isAgent: true, name: "testbot" });
    env.setTerminal({ stdin: false, stdout: false, stderr: false });
    expect(await runCli(["schema"], env.layer)).toBe(0);
    const output = env.logs.join("\n");
    expect(output).toContain("SHOP_URL");
    expect(output).toContain("untrusted data");
  });

  it("the value-display 2-layer gate is unchanged (pull --show stays refused under an agent environment)", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    env.setAgent({ isAgent: true, name: "testbot" });
    expect(await runCli(["pull", "--show"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("Refused to display values");
    expect(env.logs.join("\n")).not.toContain("8080");
  });

  it("description is neutralized by escapeText (rulings CK and CW — signed isn't necessarily benign)", async () => {
    const malicious = await distributedVariableStatement({
      projectId: built.projectId,
      environmentId: ENV_ID,
      variableId: "v-evil",
      name: "EVIL",
      author: owner,
      head: { seq: 1, hashHex: built.projectId },
      status: "declared",
      schema: {
        varType: "string",
        required: false,
        description: "ok\u001b[31m\nrm -rf # not an instruction",
      },
    });
    const env = await startEnv([chainHandler(), metadataHandler({ variables: [malicious] })]);
    expect(await runCli(["schema"], env.layer)).toBe(0);
    const output = env.logs.join("\n");
    expect(output).not.toContain("\u001b");
    expect(output).toContain("\\u{001b}");
    expect(output).toContain("\\u{000a}");
  });
});

describe("verifying a distribution containing declared (§6.3 / §12-7)", () => {
  it("a valued pull containing declared succeeds on a matching digest and shows the declaration row", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    const output = env.logs.join("\n");
    expect(output).toContain("SHOP_URL\t(declared — no value set)");
    expect(output).toContain("PORT");
  });

  it("an active verified statement appearing in the declared list is refused as a missing value (§6.3)", async () => {
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [activeV1],
        declaredVariables: [declaredRequired, activeV3.statement],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("carries no value for it");
    expect(errors).toContain("value omission");
  });

  it("a distribution that pairs a declared statement with a value is refused (only declared is the legitimate valueless state)", async () => {
    const bogusValue = await distributedValue({
      projectId: built.projectId,
      environmentId: ENV_ID,
      dek: dek1,
      epoch: 1,
      variableId: "v-declared",
      version: 1,
      plaintext: "injected",
      writer: owner,
      head: headOf(built, 2),
    });
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [
          activeV1,
          { variableId: "v-declared", statement: declaredRequired, value: bogusValue },
        ],
        declaredVariables: [],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("declared statement together with a value");
  });

  it("layoutVersion v4 trips the typed error 'unsupported layout (client update)' (session-46 §8 iteration 5; v3 is supported since PF6 R9)", async () => {
    const v4 = { ...activeV3.statement, layoutVersion: 4 };
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [{ ...activeV3, statement: v4 }, activeV1],
        declaredVariables: [],
        digestStatements: [activeV3.statement, activeV1.statement],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("layout version 4");
    expect(errors).toContain("(supported: 1, 3)");
    expect(errors).toContain("update the maruhi CLI");
    expect(errors).toContain("not a tampering indication");
    expect(errors).not.toContain("forged");
    expect(errors).not.toContain("signature");
  });

  it("the retired layoutVersion 2 trips the same typed 'unsupported layout' error (CRYPTO_SPEC §4.2 — 0.15-draft)", async () => {
    const { maxAgeDays: _dropped, ...v2Shape } = activeV3.statement;
    const v2 = { ...v2Shape, layoutVersion: 2 };
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [{ ...activeV3, statement: v2 }, activeV1],
        declaredVariables: [],
        digestStatements: [activeV3.statement, activeV1.statement],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("layout version 2");
    expect(errors).toContain("(supported: 1, 3)");
    expect(errors).toContain("update the maruhi CLI");
    expect(errors).not.toContain("forged");
    expect(errors).not.toContain("signature");
  });

  it("a partial distribution of v3 fields (an all-or-nothing violation) is refused (§12-2)", async () => {
    const partial: Record<string, unknown> = { ...declaredRequired };
    delete partial["description"];
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [activeV1],
        declaredVariables: [partial as unknown as WireDistributedVariableStatement],
        digestStatements: [activeV1.statement, declaredRequired],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("only part of the layout-v3 field set");
  });
});

describe("maruhi run's fail-fast (§1-4 — hard presence / soft type)", () => {
  it("a declared with required = true doesn't launch the child process and fails with a typed error (no description output)", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["run", "--", "printenv"], env.layer)).toBe(1);
    expect(env.runnerCalls).toHaveLength(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Required variables are declared but have no value yet");
    expect(errors).toContain("SHOP_URL");
    expect(errors).toContain("The command was not started");
    expect(errors).not.toContain(DESCRIPTION_REQUIRED);
  });

  it("a declared with required = false runs with an informational note and no injection", async () => {
    const env = await startEnv([
      chainHandler(),
      pullHandler({ declaredVariables: [declaredOptional] }),
    ]);
    expect(await runCli(["run", "--", "printenv"], env.layer)).toBe(0);
    expect(env.runnerCalls).toHaveLength(1);
    expect(env.runnerCalls[0]?.extraEnv).not.toHaveProperty("OPTIONAL_HINT");
    expect(env.errors.join("\n")).toContain("declared variables without values were not injected");
  });

  it("a type mismatch is an advisory warning only and the run proceeds (§14.3-7 — the value stays out of the wording)", async () => {
    const badPort = await distributedValue({
      projectId: built.projectId,
      environmentId: ENV_ID,
      dek: dek1,
      epoch: 1,
      variableId: "v-port",
      version: 1,
      plaintext: "not-a-number",
      writer: owner,
      head: headOf(built, 2),
    });
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [{ ...activeV3, value: badPort }, activeV1],
        declaredVariables: [],
      }),
    ]);
    expect(await runCli(["run", "--", "printenv"], env.layer)).toBe(0);
    expect(env.runnerCalls).toHaveLength(1);
    expect(env.runnerCalls[0]?.extraEnv["PORT"]).toBe("not-a-number");
    const errors = env.errors.join("\n");
    expect(errors).toContain('does not match its declared type "number"');
    expect(errors).not.toContain("not-a-number");
  });

  it("a type match and v1 (no type) don't warn", async () => {
    const env = await startEnv([chainHandler(), pullHandler({ declaredVariables: [] })]);
    expect(await runCli(["run", "--", "printenv"], env.layer)).toBe(0);
    expect(env.errors.join("\n")).not.toContain("declared type");
  });
});

interface MutationEcho {
  body: MutationBody | null;
  readonly base: readonly WireDistributedVariableStatement[];
}

function captureCreate(echo: MutationEcho, calls: MockRequest[]): MockHandler {
  return onEndpoint(
    "variables.create",
    { projectId: built.projectId, environmentId: ENV_ID },
    (request) => {
      calls.push(request);
      echo.body = request.body;
      const body = request.body;
      return {
        status: 200,
        json: {
          variableId: body.statement.variableId,
          version: "value" in body ? 1 : 0,
          epoch: 1,
        },
      };
    },
  );
}

function captureRename(echo: MutationEcho, calls: MockRequest[], variableId: string): MockHandler {
  return onEndpoint(
    "variables.rename",
    { projectId: built.projectId, environmentId: ENV_ID, variableId },
    (request) => {
      calls.push(request);
      echo.body = request.body;
      return { status: 204 };
    },
  );
}

describe("maruhi schema set (§1-2)", () => {
  it("a nonexistent name is created as a declaration (declared, metaVersion 1) (default required = true)", async () => {
    const echo: MutationEcho = { body: null, base: [] };
    const createCalls: MockRequest[] = [];
    const env = await startEnv([
      chainHandler(),
      metadataHandler({ variables: [], echo }),
      captureCreate(echo, createCalls),
    ]);
    expect(await runCli(["schema", "set", "DATABASE_URL", "--type", "url"], env.layer)).toBe(0);
    expect(createCalls).toHaveLength(1);
    const body = createCalls[0]?.body as {
      statement: Record<string, unknown>;
      value?: unknown;
      manifest: Record<string, unknown>;
    };
    expect(body.value).toBeUndefined();
    expect(body.statement["status"]).toBe("declared");
    expect(body.statement["metaVersion"]).toBe(1);
    expect(body.statement["layoutVersion"]).toBe(3);
    expect(body.statement["maxAgeDays"]).toBeNull();
    expect(body.statement["varType"]).toBe("url");
    expect(body.statement["required"]).toBe(true);
    expect(body.statement["description"]).toBe("");
    expect(body.statement["name"]).toBe("DATABASE_URL");
    expect(body.manifest["manifestVersion"]).toBe(2);
    const output = env.logs.join("\n");
    expect(output).toContain("Declared DATABASE_URL (type=url, required=true)");
    expect(output).toContain("maruhi push DATABASE_URL");
  });

  it("re-issuing an existing variable's schema is a partial update (unspecified fields inherit the previous statement)", async () => {
    const echo: MutationEcho = { body: null, base: [declaredRequired] };
    const renameCalls: MockRequest[] = [];
    const env = await startEnv([
      chainHandler(),
      metadataHandler({ variables: [declaredRequired], echo }),
      captureRename(echo, renameCalls, "v-declared"),
    ]);
    expect(
      await runCli(["schema", "set", "SHOP_URL", "--description", "New words"], env.layer),
    ).toBe(0);
    expect(renameCalls).toHaveLength(1);
    const body = renameCalls[0]?.body as { statement: Record<string, unknown> };
    expect(body.statement["varType"]).toBe("url");
    expect(body.statement["required"]).toBe(true);
    expect(body.statement["description"]).toBe("New words");
    expect(body.statement["status"]).toBe("declared");
    expect(body.statement["name"]).toBe("SHOP_URL");
    expect(body.statement["metaVersion"]).toBe(2);
    expect(body.statement["prevMetaSigHashHex"]).not.toBe("");
    expect(env.logs.join("\n")).toContain("Updated the schema of SHOP_URL");
  });

  it("--optional / --type none / --clear-description can explicitly lower a field and reset it to empty", async () => {
    const echo: MutationEcho = { body: null, base: [declaredRequired] };
    const renameCalls: MockRequest[] = [];
    const env = await startEnv([
      chainHandler(),
      metadataHandler({ variables: [declaredRequired], echo }),
      captureRename(echo, renameCalls, "v-declared"),
    ]);
    expect(
      await runCli(
        ["schema", "set", "SHOP_URL", "--optional", "--type", "none", "--clear-description"],
        env.layer,
      ),
    ).toBe(0);
    const body = renameCalls[0]?.body as { statement: Record<string, unknown> };
    expect(body.statement["varType"]).toBe("");
    expect(body.statement["required"]).toBe(false);
    expect(body.statement["description"]).toBe("");
  });

  it("--max-age declares the expiry interval on a layout-v3 statement; `none` clears it; out-of-range is a usage error (PF6 R9)", async () => {
    const echo: MutationEcho = { body: null, base: [declaredRequired] };
    const renameCalls: MockRequest[] = [];
    const env = await startEnv([
      chainHandler(),
      metadataHandler({ variables: [declaredRequired], echo }),
      captureRename(echo, renameCalls, "v-declared"),
    ]);
    expect(await runCli(["schema", "set", "SHOP_URL", "--max-age", "90"], env.layer)).toBe(0);
    const body = renameCalls[0]?.body as { statement: Record<string, unknown> };
    expect(body.statement["layoutVersion"]).toBe(3);
    expect(body.statement["maxAgeDays"]).toBe(90);
    expect(body.statement["varType"]).toBe("url");
    expect(body.statement["required"]).toBe(true);
    expect(env.logs.join("\n")).toContain("max-age=90d");
    env.logs.length = 0;
    expect(await runCli(["schema", "set", "SHOP_URL", "--max-age", "none"], env.layer)).toBe(0);
    const cleared = renameCalls[1]?.body as { statement: Record<string, unknown> };
    expect(cleared.statement["layoutVersion"]).toBe(3);
    expect(cleared.statement["maxAgeDays"]).toBeNull();
    expect(env.logs.join("\n")).not.toContain("max-age=");
    for (const bad of ["0", "3651", "ninety", "090"]) {
      expect(await runCli(["schema", "set", "SHOP_URL", "--max-age", bad], env.layer)).toBe(2);
      expect(env.errors.join("\n")).toContain("--max-age must be a number of days from 1 to 3650");
      expect(env.errors.join("\n")).not.toContain(bad === "ninety" ? "ninety" : "\u0000");
      env.errors.length = 0;
    }
    expect(renameCalls).toHaveLength(2);
  });

  it("the first v3 re-issue onto a v1 variable requires an explicit required (a local refusal before signing/sending)", async () => {
    const env = await startEnv([
      chainHandler(),
      metadataHandler({ variables: [activeV1.statement] }),
    ]);
    expect(await runCli(["schema", "set", "LEGACY_KEY", "--type", "string"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("layout v1");
    expect(errors).toContain("--required or --optional");
    expect(
      lastServer().requests.filter(
        (request) => request.method === "POST" || request.method === "PATCH",
      ),
    ).toHaveLength(0);
  });

  it("a v1 variable's v3 re-issue passes with an explicit required, and varType / description take their unspecified defaults ('')", async () => {
    const echo: MutationEcho = { body: null, base: [activeV1.statement] };
    const renameCalls: MockRequest[] = [];
    const env = await startEnv([
      chainHandler(),
      metadataHandler({ variables: [activeV1.statement], echo }),
      captureRename(echo, renameCalls, "v-legacy"),
    ]);
    expect(
      await runCli(["schema", "set", "LEGACY_KEY", "--type", "string", "--optional"], env.layer),
    ).toBe(0);
    expect(renameCalls).toHaveLength(1);
    const body = renameCalls[0]?.body as { statement: Record<string, unknown> };
    expect(body.statement["layoutVersion"]).toBe(3);
    expect(body.statement["varType"]).toBe("string");
    expect(body.statement["required"]).toBe(false);
    expect(body.statement["description"]).toBe("");
    expect(body.statement["status"]).toBe("active");
    expect(body.statement["metaVersion"]).toBe(2);
  });

  it("under a locked advisory, a creation without --type is refused locally before signing/sending (§1-2)", async () => {
    const env = await startEnv([
      chainHandler(),
      metadataHandler({ variables: [], schemaPolicy: "locked" }),
    ]);
    expect(await runCli(["schema", "set", "NEW_VAR"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("schema policy is locked");
    expect(errors).toContain("--type");
    expect(lastServer().requests.filter((request) => request.method === "POST")).toHaveLength(0);
  });

  it("--required combined with --optional is a usage error (rejected before the handler runs)", async () => {
    const env = await startEnv([chainHandler()]);
    expect(await runCli(["schema", "set", "X", "--required", "--optional"], env.layer)).toBe(2);
    expect(env.errors).toEqual([
      "Usage: maruhi schema set [flags] <name>",
      "maruhi: --required and --optional are mutually exclusive (specify at most one)",
    ]);
    expect(lastServer().requests).toHaveLength(0);
  });

  it("--description combined with --clear-description is a usage error", async () => {
    const env = await startEnv([chainHandler()]);
    expect(
      await runCli(
        ["schema", "set", "X", "--description", "New words", "--clear-description"],
        env.layer,
      ),
    ).toBe(2);
    expect(env.errors).toEqual([
      "Usage: maruhi schema set [flags] <name>",
      "maruhi: --description and --clear-description are mutually exclusive",
    ]);
    expect(lastServer().requests).toHaveLength(0);
  });
});

describe("the entropy warning (ruling CW — fail-closed)", () => {
  const FAKE_SECRET = "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LXNlY3JldA0K11";

  it("detector: detects a secret-looking run and lets ordinary English sentences and identifiers through", () => {
    expect(findHighEntropySubstring(FAKE_SECRET)).not.toBeNull();
    expect(
      findHighEntropySubstring("token is x7Gh2kQ9pLmA3vB8nC4dE5fJ6hK7iL8m here"),
    ).not.toBeNull();
    expect(findHighEntropySubstring(`token is ${"a1B2".repeat(10)}`)).toBeNull();
    expect(
      findHighEntropySubstring("0f8e2d1c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff0"),
    ).not.toBeNull();
    expect(findHighEntropySubstring("Primary endpoint of the shop frontend")).toBeNull();
    expect(findHighEntropySubstring("DATABASE_URL")).toBeNull();
    expect(findHighEntropySubstring("MY_SUPER_LONG_VARIABLE_NAME_2024")).toBeNull();
    expect(findHighEntropySubstring("PostgresConnectionPoolingEndpoint")).toBeNull();
    expect(findHighEntropySubstring("")).toBeNull();
  });

  it("in a non-interactive environment it refuses with a typed error absent the explicit flag (before any communication or signing)", async () => {
    const env = await startEnv([chainHandler(), metadataHandler({ variables: [] })]);
    env.setTerminal({ stdout: false });
    expect(
      await runCli(["schema", "set", "API_HINT", "--description", FAKE_SECRET], env.layer),
    ).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("secret-like high-entropy");
    expect(errors).toContain("--allow-high-entropy");
    expect(errors).not.toContain(FAKE_SECRET);
    expect(lastServer().requests).toHaveLength(0);
  });

  it("in an interactive environment it warns and asks for an explicit confirmation (a refusal aborts)", async () => {
    const env = await startEnv([chainHandler(), metadataHandler({ variables: [] })]);
    env.setPromptResponses(["no"]);
    expect(
      await runCli(["schema", "set", "API_HINT", "--description", FAKE_SECRET], env.layer),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain("secret-like high-entropy");
    expect(env.prompts.join("\n")).toContain("Continue anyway?");
    expect(lastServer().requests).toHaveLength(0);
  });

  it("--allow-high-entropy proceeds with no confirmation (the fact is still surfaced as a warning)", async () => {
    const echo: MutationEcho = { body: null, base: [] };
    const createCalls: MockRequest[] = [];
    const env = await startEnv([
      chainHandler(),
      metadataHandler({ variables: [], echo }),
      captureCreate(echo, createCalls),
    ]);
    env.setTerminal({ stdout: false });
    expect(
      await runCli(
        ["schema", "set", "API_HINT", "--description", FAKE_SECRET, "--allow-high-entropy"],
        env.layer,
      ),
    ).toBe(0);
    expect(env.errors.join("\n")).toContain("--allow-high-entropy was given");
    expect(createCalls).toHaveLength(1);
  });
});

describe("maruhi push's activation (the first value push onto a declared — §12-5)", () => {
  it("a push resolved to declared builds the activation compound (inheriting the schema fields and the name)", async () => {
    const echo: MutationEcho = { body: null, base: [declaredRequired] };
    const activateCalls: MockRequest[] = [];
    const env = await startEnv([
      chainHandler(),
      deksHandler(),
      metadataHandler({ variables: [declaredRequired], echo }),
      onEndpoint(
        "variables.activate",
        { projectId: built.projectId, environmentId: ENV_ID, variableId: "v-declared" },
        (request) => {
          activateCalls.push(request);
          echo.body = request.body;
          return { status: 200, json: { variableId: "v-declared", version: 1, epoch: 1 } };
        },
      ),
    ]);
    env.setStdin(new TextEncoder().encode("https://shop.example"));
    expect(await runCli(["push", "SHOP_URL"], env.layer)).toBe(0);
    expect(activateCalls).toHaveLength(1);
    const body = activateCalls[0]?.body as {
      statement: Record<string, unknown>;
      value: { aad: Record<string, unknown> };
      manifest: Record<string, unknown>;
    };
    expect(body.value.aad["version"]).toBe(1);
    expect(body.statement["status"]).toBe("active");
    expect(body.statement["metaVersion"]).toBe(2);
    expect(body.statement["name"]).toBe("SHOP_URL");
    expect(body.statement["layoutVersion"]).toBe(3);
    expect(body.statement["varType"]).toBe("url");
    expect(body.statement["required"]).toBe(true);
    expect(body.statement["description"]).toBe(DESCRIPTION_REQUIRED);
    expect(body.statement["maxAgeDays"]).toBeNull();
    expect(body.manifest["manifestVersion"]).toBe(2);
    expect(env.logs.join("\n")).toContain("Pushed SHOP_URL (version=1, epoch=1)");
  });

  it("a create that lost to a concurrent declare switches from 409 duplicate-name to activation", async () => {
    const echo: MutationEcho = { body: null, base: [declaredRequired] };
    let metadataCalls = 0;
    const activateCalls: MockRequest[] = [];
    const emptyManifest = await distributedManifest({
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      issuer: owner,
      head: headOf(built, 2),
      envStatement,
      statements: [],
    });
    const declaredManifest = await distributedManifest({
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      issuer: owner,
      head: headOf(built, 2),
      envStatement,
      statements: [declaredRequired],
      manifestVersion: 2,
      prevManifestSigHashHex: await distributedManifestHashOf(built.projectId, emptyManifest),
    });
    const env = await startEnv([
      chainHandler(),
      deksHandler(),
      onEndpoint(
        "variables.pullMetadata",
        { projectId: built.projectId, environmentId: ENV_ID },
        async () => {
          if (echo.body !== null) {
            return {
              status: 200,
              json: {
                environmentId: ENV_ID,
                currentEpoch: 1,
                statement: envStatement,
                variables: [
                  {
                    ...echo.body.statement,
                    authorUserId: owner.userId,
                    authorKeyFingerprintHex: owner.fingerprintHex,
                  },
                ],
                deletedVariables: [],
                manifest: {
                  ...echo.body.manifest,
                  issuerUserId: owner.userId,
                  issuerKeyFingerprintHex: owner.fingerprintHex,
                },
                schemaPolicy: "enabled" as const,
              },
            };
          }
          metadataCalls += 1;
          const first = metadataCalls === 1;
          return {
            status: 200,
            json: {
              environmentId: ENV_ID,
              currentEpoch: 1,
              statement: envStatement,
              variables: first ? [] : [declaredRequired],
              deletedVariables: [],
              manifest: first ? emptyManifest : declaredManifest,
              schemaPolicy: "enabled" as const,
            },
          };
        },
      ),
      onEndpoint("variables.create", { projectId: built.projectId, environmentId: ENV_ID }, () => ({
        status: 409,
        json: { _tag: "VariableConflict", variableId: "v-declared", reason: "duplicate-name" },
      })),
      onEndpoint(
        "variables.activate",
        { projectId: built.projectId, environmentId: ENV_ID, variableId: "v-declared" },
        (request) => {
          activateCalls.push(request);
          echo.body = request.body;
          return { status: 200, json: { variableId: "v-declared", version: 1, epoch: 1 } };
        },
      ),
    ]);
    env.setStdin(new TextEncoder().encode("https://shop.example"));
    expect(await runCli(["push", "SHOP_URL"], env.layer)).toBe(0);
    expect(activateCalls).toHaveLength(1);
  });
});
