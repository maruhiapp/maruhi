// Tests for the valueless schema S3 (design doc §1-1 / §1-2 / §1-4,
// CRYPTO_SPEC §4.2 / §6.3, AUTH_SPEC §12-7): `maruhi schema` (display —
// including the pinned agent-gate allowance), `maruhi schema set`
// (partial updates, declaration creation, locked pre-check, entropy
// fail-closed), verifying a distribution containing declared (digest
// counting, the value-distribution mandate), run's fail-fast (hard
// presence / soft type), push's activation, and the v3 layout's honest
// failure mode (session-46 §8 iteration 5's test requirement).

import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { findHighEntropySubstring } from "../src/entropy.ts";
import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  encryptValueFor,
  environmentStatementFor,
  genesisOp,
  headOf,
  makeTestUser,
  manifestFor,
  manifestHashOf,
  statementFor,
  type TestUser,
  type WireDistributedEnvironmentStatement,
  type WireDistributedManifest,
  type WireDistributedValue,
  type WireDistributedVariableStatement,
  wrapDekFor,
  type WireRecipientDek,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, type MockRequest, MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "dev";

let owner: TestUser;
let built: BuiltChain;
let dek1: Uint8Array;
let wrap1: WireRecipientDek;
let envStatement: WireDistributedEnvironmentStatement;
/** declared (required, url type, with a description — §4.2 layout v2). */
let declaredRequired: WireDistributedVariableStatement;
/** declared (required = false, no type). */
let declaredOptional: WireDistributedVariableStatement;
/** The v2 active statement (number type) and its value. */
let activeV2: {
  variableId: string;
  statement: WireDistributedVariableStatement;
  value: WireDistributedValue;
};
/** The v1 active statement and its value (no schema fields — the legacy shape). */
let activeV1: {
  variableId: string;
  statement: WireDistributedVariableStatement;
  value: WireDistributedValue;
};
let servers: MockServer[] = [];

const DESCRIPTION_REQUIRED = "Primary endpoint of the shop";

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  dek1 = crypto.getRandomValues(new Uint8Array(32));
  built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
  ]);
  const common = { projectId: built.projectId, environmentId: ENV_ID };
  wrap1 = await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner });
  envStatement = await environmentStatementFor({
    ...common,
    name: ENV_ID,
    author: owner,
    head: { seq: 1, hashHex: built.projectId },
  });
  const head = { seq: 1, hashHex: built.projectId };
  declaredRequired = await statementFor({
    ...common,
    variableId: "v-declared",
    name: "SHOP_URL",
    author: owner,
    head,
    status: "declared",
    schema: { varType: "url", required: true, description: DESCRIPTION_REQUIRED },
  });
  declaredOptional = await statementFor({
    ...common,
    variableId: "v-optional",
    name: "OPTIONAL_HINT",
    author: owner,
    head,
    status: "declared",
    schema: { varType: "", required: false, description: "" },
  });
  activeV2 = {
    variableId: "v-port",
    statement: await statementFor({
      ...common,
      variableId: "v-port",
      name: "PORT",
      author: owner,
      head,
      schema: { varType: "number", required: true, description: "listen port" },
    }),
    value: await encryptValueFor({
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
    statement: await statementFor({
      ...common,
      variableId: "v-legacy",
      name: "LEGACY_KEY",
      author: owner,
      head,
    }),
    value: await encryptValueFor({
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
  return onRequest("GET", `/projects/${built.projectId}/chain`, () => ({
    status: 200,
    json: {
      projectId: built.projectId,
      entries: built.entries,
      headSeq: built.entries.length,
      headHashHex: built.hashes[built.hashes.length - 1],
    },
  }));
}

function deksHandler(): MockHandler {
  return onRequest("GET", `/projects/${built.projectId}/environments/${ENV_ID}/deks`, () => ({
    status: 200,
    json: { deks: [wrap1] },
  }));
}

/** The distribution set (active entries and declared / deleted statements) → digest input. */
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

/** A pull response with values (declaredVariables bundled — §12-7). */
function pullHandler(overrides?: {
  readonly variables?: readonly {
    variableId: string;
    statement: WireDistributedVariableStatement;
    value: WireDistributedValue;
  }[];
  readonly declaredVariables?: readonly WireDistributedVariableStatement[];
  /** Overrides the digest input (for negatives that deliberately misalign the distribution and the digest). */
  readonly digestStatements?: readonly WireDistributedVariableStatement[];
}): MockHandler {
  return onRequest("GET", `/projects/${built.projectId}/environments/${ENV_ID}/pull`, async () => {
    const variables = overrides?.variables ?? [activeV2, activeV1];
    const declaredVariables = overrides?.declaredVariables ?? [declaredRequired, declaredOptional];
    const manifest = await manifestFor({
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
      },
    };
  });
}

interface MetadataOverrides {
  readonly variables?: readonly WireDistributedVariableStatement[];
  readonly schemaPolicy?: "disabled" | "enabled" | "locked";
  /**
   * Echo of accepted meta operations (material for §12-10 (3)'s effect
   * check): after acceptance it serves base + the accepted statement +
   * the accepted manifest (with issuer attribution).
   */
  readonly echo?: {
    body: { statement: WireDistributedVariableStatement; manifest: WireDistributedManifest } | null;
    readonly base: readonly WireDistributedVariableStatement[];
  };
}

function metadataPolicyField(overrides?: MetadataOverrides): Record<string, unknown> {
  return overrides?.schemaPolicy === undefined ? {} : { schemaPolicy: overrides.schemaPolicy };
}

/** Distribution of an accepted meta operation (base + the accepted statement + the accepted manifest). */
function echoMetadataJson(
  echo: NonNullable<MetadataOverrides["echo"]> & {
    body: NonNullable<NonNullable<MetadataOverrides["echo"]>["body"]>;
  },
  overrides?: MetadataOverrides,
): unknown {
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
    ...metadataPolicyField(overrides),
  };
}

async function defaultMetadataJson(overrides?: MetadataOverrides): Promise<unknown> {
  const variables = overrides?.variables ?? [
    activeV2.statement,
    activeV1.statement,
    declaredRequired,
    declaredOptional,
  ];
  const manifest = await manifestFor({
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
    ...metadataPolicyField(overrides),
  };
}

/** A metadata-only pull response (declared is interleaved into variables — §12-7). */
function metadataHandler(overrides?: MetadataOverrides): MockHandler {
  return onRequest(
    "GET",
    `/projects/${built.projectId}/environments/${ENV_ID}/pull/metadata`,
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
    expect(output).toContain("NAME\tTYPE\tREQUIRED\tSTATUS\tDESCRIPTION");
    // v2 declared: type, required, description, and status in a row
    expect(output).toContain(`SHOP_URL\turl\ttrue\tdeclared\t${DESCRIPTION_REQUIRED}`);
    expect(output).toContain("OPTIONAL_HINT\t-\tfalse\tdeclared\t-");
    // v2 active: STATUS = set
    expect(output).toContain("PORT\tnumber\ttrue\tset\tlisten port");
    // v1: TYPE / REQUIRED / DESCRIPTION are `-`
    expect(output).toContain("LEGACY_KEY\t-\t-\tset\t-");
    // Types are displayed as declarations (the §14.3 display rule —
    // never the word 'verified')
    expect(output.toLowerCase()).not.toContain("verified");
    // Values never appear
    expect(output).not.toContain("8080");
    expect(output).not.toContain("legacy-value");
    // On a TTY (the default) no header note is attached
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
    // Even in an environment matching both layers of the 2-layer gate
    // that refuses value display (pull --show) — known-agent detection
    // + a non-interactive terminal — schema works
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
    // Server acceptance (§12-8) refuses control characters, but a
    // malicious server's or malicious signer's distribution isn't
    // bound — the display side's neutralization is an independent duty
    const malicious = await statementFor({
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
    // Raw ESC / raw newline injections never appear (converted to
    // escaped notation)
    expect(output).not.toContain("\u001b");
    expect(output).toContain("\\u{001b}");
    expect(output).toContain("\\u{000a}");
  });
});

describe("verifying a distribution containing declared (§6.3 / §12-7)", () => {
  it("a valued pull containing declared succeeds on a matching digest and shows the declaration row", async () => {
    // S2's known gap: unless declared is counted into the digest
    // recomputation, every pull fails on variables-digest-mismatch —
    // success itself is pinned
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    const output = env.logs.join("\n");
    expect(output).toContain("SHOP_URL\t(declared — no value set)");
    expect(output).toContain("PORT");
  });

  it("an active verified statement appearing in the declared list is refused as a missing value (§6.3)", async () => {
    // The shape where a server wanting to hide a value moves the active
    // statement into declaredVariables: the digest still matches (the
    // statement is intact), so only §6.3's value-distribution mandate
    // detects it
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [activeV1],
        declaredVariables: [declaredRequired, activeV2.statement],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("carries no value for it");
    expect(errors).toContain("value omission");
  });

  it("a distribution that pairs a declared statement with a value is refused (only declared is the legitimate valueless state)", async () => {
    const bogusValue = await encryptValueFor({
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

  it("layoutVersion v3 trips the typed error 'unsupported layout (client update)' (session-46 §8 iteration 5)", async () => {
    // Distribution decode isn't a Literal (an integer with no pinned
    // ceiling), so v3 passes decode and the support-range check before
    // signature verification refuses it in the honest failure mode —
    // it doesn't masquerade as a Schema error or a bad signature
    // (suspected tampering)
    const v3 = { ...activeV2.statement, layoutVersion: 3 };
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [{ ...activeV2, statement: v3 }, activeV1],
        declaredVariables: [],
        // The digest is computed from the v2 canonical form (the
        // client refuses at the statement stage, so it never reaches
        // the manifest stage)
        digestStatements: [activeV2.statement, activeV1.statement],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("layout version 3");
    expect(errors).toContain("update the maruhi CLI");
    expect(errors).toContain("not a tampering indication");
    expect(errors).not.toContain("forged");
    expect(errors).not.toContain("signature");
  });

  it("a partial distribution of v2 fields (an all-or-nothing violation) is refused (§12-2)", async () => {
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
    expect(env.errors.join("\n")).toContain("only part of the layout-v2 field set");
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
    // The error text must not contain the description (an injection
    // surface via logs — session-46 §8 iteration 3)
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
    const badPort = await encryptValueFor({
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
        variables: [{ ...activeV2, value: badPort }, activeV1],
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

/** A box that captures create / rename acceptance bodies and feeds them into the echo (the effect-check distribution). */
interface MutationEcho {
  body: { statement: WireDistributedVariableStatement; manifest: WireDistributedManifest } | null;
  readonly base: readonly WireDistributedVariableStatement[];
}

function captureCreate(echo: MutationEcho, calls: MockRequest[]): MockHandler {
  return onRequest(
    "POST",
    `/projects/${built.projectId}/environments/${ENV_ID}/variables`,
    (request) => {
      calls.push(request);
      echo.body = request.body as MutationEcho["body"];
      const body = request.body as {
        statement: WireDistributedVariableStatement;
        value?: unknown;
      };
      return {
        status: 200,
        json: {
          variableId: body.statement.variableId,
          version: body.value === undefined ? 0 : 1,
          epoch: 1,
        },
      };
    },
  );
}

function captureRename(echo: MutationEcho, calls: MockRequest[], variableId: string): MockHandler {
  return onRequest(
    "PATCH",
    `/projects/${built.projectId}/environments/${ENV_ID}/variables/${variableId}`,
    (request) => {
      calls.push(request);
      echo.body = request.body as MutationEcho["body"];
      return { status: 204, bodyText: "" };
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
    // No value is bundled (declared creation — §12-5)
    expect(body.value).toBeUndefined();
    expect(body.statement["status"]).toBe("declared");
    expect(body.statement["metaVersion"]).toBe(1);
    expect(body.statement["layoutVersion"]).toBe(2);
    expect(body.statement["varType"]).toBe("url");
    // Creation defaults: required = true (§1-2 — a declaration is the
    // environment's contract), description = ""
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
    // A run with only --description must not silently drop type and
    // required (full replacement is forbidden — §1-2)
    expect(body.statement["varType"]).toBe("url");
    expect(body.statement["required"]).toBe(true);
    expect(body.statement["description"]).toBe("New words");
    // Status and name are unchanged (a schema re-issue — stays
    // declared)
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

  it("the first v2 re-issue onto a v1 variable requires an explicit required (a local refusal before signing/sending)", async () => {
    // A v1 statement has nothing to inherit required from (§1-2's
    // partial update is a 'previous value' rule). Silently applying the
    // creation default true would put a presence contract the user
    // never typed onto the signature — explicit is required
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

  it("a v1 variable's v2 re-issue passes with an explicit required, and varType / description take their unspecified defaults ('')", async () => {
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
    expect(body.statement["layoutVersion"]).toBe(2);
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
    // Nothing was signed or sent (not a single POST)
    expect(lastServer().requests.filter((request) => request.method === "POST")).toHaveLength(0);
  });

  it("a disabled advisory emits advance guidance (SHOULD — it still sends: the source of truth for acceptance is the server)", async () => {
    const echo: MutationEcho = { body: null, base: [] };
    const createCalls: MockRequest[] = [];
    const env = await startEnv([
      chainHandler(),
      metadataHandler({ variables: [], schemaPolicy: "disabled", echo }),
      captureCreate(echo, createCalls),
    ]);
    expect(await runCli(["schema", "set", "NEW_VAR"], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain("schema policy as disabled");
    expect(createCalls).toHaveLength(1);
  });

  it("--required combined with --optional is a usage error", async () => {
    const env = await startEnv([chainHandler()]);
    expect(await runCli(["schema", "set", "X", "--required", "--optional"], env.layer)).toBe(2);
    expect(lastServer().requests).toHaveLength(0);
  });
});

describe("the entropy warning (ruling CW — fail-closed)", () => {
  // A dummy that merely looks like a real value (not an actual secret)
  const FAKE_SECRET = "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LXNlY3JldA0K11";

  it("detector: detects a secret-looking run and lets ordinary English sentences and identifiers through", () => {
    expect(findHighEntropySubstring(FAKE_SECRET)).not.toBeNull();
    // An API-key-like mixed token (a dummy) is detected even inside a
    // sentence
    expect(
      findHighEntropySubstring("token is x7Gh2kQ9pLmA3vB8nC4dE5fJ6hK7iL8m here"),
    ).not.toBeNull();
    // A repeating pattern isn't high-entropy (not detected — the
    // real-value likeness grounds on disorder)
    expect(findHighEntropySubstring(`token is ${"a1B2".repeat(10)}`)).toBeNull();
    // A 64-hex (a dummy's random look) is detected too
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
    // The input itself isn't put into the error (it could be a
    // secret)
    expect(errors).not.toContain(FAKE_SECRET);
    // Nothing reached the network (fail-closed at input time — before
    // the accident)
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
      onRequest(
        "POST",
        `/projects/${built.projectId}/environments/${ENV_ID}/variables/v-declared/activate`,
        (request) => {
          activateCalls.push(request);
          echo.body = request.body as MutationEcho["body"];
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
    // The value is version 1 (a declared's latest is always 0)
    expect(body.value.aad["version"]).toBe(1);
    // The activation statement: status active, metaVersion + 1, and
    // the schema fields and name carry the declared values
    // byte-exact
    expect(body.statement["status"]).toBe("active");
    expect(body.statement["metaVersion"]).toBe(2);
    expect(body.statement["name"]).toBe("SHOP_URL");
    expect(body.statement["layoutVersion"]).toBe(2);
    expect(body.statement["varType"]).toBe("url");
    expect(body.statement["required"]).toBe(true);
    expect(body.statement["description"]).toBe(DESCRIPTION_REQUIRED);
    expect(body.manifest["manifestVersion"]).toBe(2);
    expect(env.logs.join("\n")).toContain("Pushed SHOP_URL (version=1, epoch=1)");
  });

  it("a create that lost to a concurrent declare switches from 409 duplicate-name to activation", async () => {
    // The first resolution = nonexistent → create; the server answers
    // 409 (a concurrent declare landed first); the re-resolution =
    // declared → the activation compound (§12-5's retry = re-fetch →
    // re-sign)
    const echo: MutationEcho = { body: null, base: [declaredRequired] };
    let metadataCalls = 0;
    const activateCalls: MockRequest[] = [];
    const emptyManifest = await manifestFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      issuer: owner,
      head: headOf(built, 2),
      envStatement,
      statements: [],
    });
    // The re-resolved set (after the declared landed) is
    // manifestVersion 2, and prev is really chained to the first
    // manifest (adjacent-version prev verification — M1-A1)
    const declaredManifest = await manifestFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      issuer: owner,
      head: headOf(built, 2),
      envStatement,
      statements: [declaredRequired],
      manifestVersion: 2,
      prevManifestSigHashHex: await manifestHashOf(built.projectId, emptyManifest),
    });
    const env = await startEnv([
      chainHandler(),
      deksHandler(),
      onRequest(
        "GET",
        `/projects/${built.projectId}/environments/${ENV_ID}/pull/metadata`,
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
            },
          };
        },
      ),
      onRequest("POST", `/projects/${built.projectId}/environments/${ENV_ID}/variables`, () => ({
        status: 409,
        json: { _tag: "VariableConflict", variableId: "v-declared", reason: "duplicate-name" },
      })),
      onRequest(
        "POST",
        `/projects/${built.projectId}/environments/${ENV_ID}/variables/v-declared/activate`,
        (request) => {
          activateCalls.push(request);
          echo.body = request.body as MutationEcho["body"];
          return { status: 200, json: { variableId: "v-declared", version: 1, epoch: 1 } };
        },
      ),
    ]);
    env.setStdin(new TextEncoder().encode("https://shop.example"));
    expect(await runCli(["push", "SHOP_URL"], env.layer)).toBe(0);
    expect(activateCalls).toHaveLength(1);
  });
});
