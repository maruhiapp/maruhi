// Tests for `maruhi sync`'s http driver: the declarative-preset assembly
// (values may only be placed in body entries — sync-http.ts) and `sync
// apply` end-to-end against the fake vendor APIs (test/support/
// vendor-api.ts — stateful).
//
// Properties pinned down: values and tokens never appear on the URL,
// headers (other than Authorization), stdout, stderr, or error text; the
// request-body shapes (Workers = merge-patch secrets / Vercel = array +
// upsert); how deletions are expressed (Workers = null / Vercel = list →
// DELETE); 429 / 5xx retries; scrubbing of failure responses (value /
// token echoes); the missing-Worker (10007) guidance; partial success
// (Vercel's failed) split by name and left on the receipt; the
// integration token never travels to the sync target; plan never
// touches the vendor API.
// Netlify: lists to check presence and then POSTs (new) / PATCHes (one
// context of an existing key) per variable; the secret default and
// scopes; deletion by value id (the last value deletes the whole key); a
// failed POST to an existing key turns into a PATCH on the next apply;
// partial success; 429 / 5xx.

import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { decryptVariable } from "@maruhi/crypto";
import { Redacted } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { parseSyncConfig, type SyncTarget } from "../src/sync-config.ts";
import {
  buildBatches,
  checkIntegrationToken,
  HTTP_PRESETS,
  type HttpPreset,
  type PathToken,
} from "../src/sync-http.ts";
import { receiptVariableName } from "../src/sync-receipt.ts";
import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  encryptValueFor,
  environmentStatementFor,
  genesisOp,
  headOf,
  hexBytes,
  makeTestUser,
  statementFor,
  type TestUser,
  type WireDistributedEnvironmentStatement,
  type WireEncryptedPayload,
  type WireRecipientDek,
  wrapDekFor,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockRequest, MockServer } from "./support/server.ts";
import { makeValueEnvironmentServer, type StoredVariable } from "./support/value-env.ts";
import {
  makeFakeCloudflare,
  makeFakeNetlify,
  makeFakeVercel,
  type VendorOverride,
} from "./support/vendor-api.ts";

const SOURCE_ENV = "prod";
const TOKENS_ENV = "tokens";
const RECEIPTS_ENV = "sync-receipts";
const ALPHA_VALUE = "alpha-value-3";
const BETA_VALUE = "beta line 1\nbeta line 2\n";
const CF_TOKEN = "cf-token-0123456789abcdef";
const VERCEL_TOKEN = "vercel-token-fedcba9876543210";
const NETLIFY_TOKEN = "nfp_netlify-token-0011223344556677";
const SECRETS = [ALPHA_VALUE, "beta line 1", "beta line 2", CF_TOKEN, VERCEL_TOKEN, NETLIFY_TOKEN];

let owner: TestUser;
let built: BuiltChain;
const deks = new Map<string, Uint8Array>();
const wraps = new Map<string, WireRecipientDek>();
const statements = new Map<string, WireDistributedEnvironmentStatement>();
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  for (const environment of [SOURCE_ENV, TOKENS_ENV, RECEIPTS_ENV]) {
    deks.set(environment, crypto.getRandomValues(new Uint8Array(32)));
  }
  built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    {
      actor: owner,
      operation: createEnvironmentOp(SOURCE_ENV, deks.get(SOURCE_ENV) as Uint8Array),
    },
    {
      actor: owner,
      operation: createEnvironmentOp(TOKENS_ENV, deks.get(TOKENS_ENV) as Uint8Array),
    },
    {
      actor: owner,
      operation: createEnvironmentOp(RECEIPTS_ENV, deks.get(RECEIPTS_ENV) as Uint8Array),
    },
  ]);
  for (const environment of [SOURCE_ENV, TOKENS_ENV, RECEIPTS_ENV]) {
    wraps.set(
      environment,
      await wrapDekFor({
        projectId: built.projectId,
        recipient: owner,
        signer: owner,
        epoch: 1,
        environmentId: environment,
        dek: deks.get(environment) as Uint8Array,
      }),
    );
    statements.set(
      environment,
      await environmentStatementFor({
        projectId: built.projectId,
        environmentId: environment,
        name: environment,
        author: owner,
        head: { seq: 1, hashHex: built.projectId },
      }),
    );
  }
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

async function variable(input: {
  readonly environment: string;
  readonly variableId: string;
  readonly name: string;
  readonly version: number;
  readonly plaintext: string | Uint8Array;
}): Promise<StoredVariable> {
  const statement = await statementFor({
    projectId: built.projectId,
    environmentId: input.environment,
    variableId: input.variableId,
    name: input.name,
    author: owner,
    head: { seq: 1, hashHex: built.projectId },
  });
  const value = await encryptValueFor({
    dek: deks.get(input.environment) as Uint8Array,
    projectId: built.projectId,
    environmentId: input.environment,
    epoch: 1,
    variableId: input.variableId,
    version: input.version,
    plaintext: input.plaintext,
    writer: owner,
    // The head after every environment was created (straddling the
    // per-environment creation positions 2 / 3 / 4)
    head: headOf(built, built.entries.length),
  });
  return { variableId: input.variableId, statement, value };
}

async function receiptVariable(input: {
  readonly target: string;
  readonly preset: "vercel" | "cloudflare-workers" | "netlify";
  readonly variables: Readonly<Record<string, number>>;
}): Promise<StoredVariable> {
  return variable({
    environment: RECEIPTS_ENV,
    variableId: `receipt-${input.target}`,
    name: receiptVariableName(input.target),
    version: 1,
    plaintext: JSON.stringify({
      version: 1,
      target: input.target,
      preset: input.preset,
      syncedAt: "2026-09-05T00:00:00.000Z",
      variables: input.variables,
    }),
  });
}

interface Fixture {
  readonly env: TestEnv;
  readonly configPath: string;
  readonly maruhi: MockServer;
  readonly receipts: ReturnType<typeof makeValueEnvironmentServer>["state"];
}

const CF_ACCOUNT = "acc0123456789";

function cloudflareTarget(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    preset: "cloudflare-workers",
    driver: "http",
    environment: SOURCE_ENV,
    variables: "all",
    token: { environment: TOKENS_ENV, name: "CF_API_TOKEN" },
    options: { accountId: CF_ACCOUNT, name: "my-worker", environment: "staging" },
    ...overrides,
  };
}

function vercelTarget(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    preset: "vercel",
    driver: "http",
    environment: SOURCE_ENV,
    variables: ["ALPHA", "BETA"],
    token: { environment: TOKENS_ENV, name: "VERCEL_TOKEN" },
    options: { environment: "preview", projectId: "prj_123", teamId: "team_9" },
    ...overrides,
  };
}

const NETLIFY_ACCOUNT = "my-team";
const NETLIFY_SITE = "0f1e2d3c-site-id";

/** A Netlify target (`driver` omitted = http is the only driver). */
function netlifyTarget(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    preset: "netlify",
    environment: SOURCE_ENV,
    variables: ["ALPHA", "BETA"],
    token: { environment: TOKENS_ENV, name: "NETLIFY_TOKEN" },
    options: { accountId: NETLIFY_ACCOUNT, siteId: NETLIFY_SITE, context: "deploy-preview" },
    ...overrides,
  };
}

function netlifyFake(input: Partial<Parameters<typeof makeFakeNetlify>[0]> = {}) {
  return makeFakeNetlify({
    token: NETLIFY_TOKEN,
    accountId: NETLIFY_ACCOUNT,
    siteId: NETLIFY_SITE,
    ...input,
  });
}

async function startFixture(input: {
  readonly targets: Record<string, unknown>;
  readonly sourceVariables?: readonly StoredVariable[];
  readonly tokenVariables?: readonly StoredVariable[];
  readonly receipts?: readonly StoredVariable[];
  readonly vendorHandlers: readonly Parameters<typeof MockServer.start>[0][number][];
  readonly vendorHosts: readonly string[];
}): Promise<Fixture> {
  const source = makeValueEnvironmentServer({
    chain: built,
    owner,
    environmentId: SOURCE_ENV,
    envStatement: statements.get(SOURCE_ENV) as WireDistributedEnvironmentStatement,
    wrap: wraps.get(SOURCE_ENV) as WireRecipientDek,
    initialVariables:
      input.sourceVariables ??
      (await Promise.all([
        variable({
          environment: SOURCE_ENV,
          variableId: "va",
          name: "ALPHA",
          version: 3,
          plaintext: ALPHA_VALUE,
        }),
        variable({
          environment: SOURCE_ENV,
          variableId: "vb",
          name: "BETA",
          version: 1,
          plaintext: BETA_VALUE,
        }),
      ])),
  });
  const tokens = makeValueEnvironmentServer({
    chain: built,
    owner,
    environmentId: TOKENS_ENV,
    envStatement: statements.get(TOKENS_ENV) as WireDistributedEnvironmentStatement,
    wrap: wraps.get(TOKENS_ENV) as WireRecipientDek,
    initialVariables:
      input.tokenVariables ??
      (await Promise.all([
        variable({
          environment: TOKENS_ENV,
          variableId: "tc",
          name: "CF_API_TOKEN",
          version: 1,
          plaintext: CF_TOKEN,
        }),
        variable({
          environment: TOKENS_ENV,
          variableId: "tv",
          name: "VERCEL_TOKEN",
          version: 2,
          plaintext: VERCEL_TOKEN,
        }),
        variable({
          environment: TOKENS_ENV,
          variableId: "tn",
          name: "NETLIFY_TOKEN",
          version: 1,
          plaintext: NETLIFY_TOKEN,
        }),
      ])),
  });
  const receipts = makeValueEnvironmentServer({
    chain: built,
    owner,
    environmentId: RECEIPTS_ENV,
    envStatement: statements.get(RECEIPTS_ENV) as WireDistributedEnvironmentStatement,
    wrap: wraps.get(RECEIPTS_ENV) as WireRecipientDek,
    initialVariables: input.receipts ?? [],
  });
  const maruhi = await MockServer.start([
    ...source.handlers,
    ...tokens.handlers,
    ...receipts.handlers,
  ]);
  const vendor = await MockServer.start(input.vendorHandlers);
  servers.push(maruhi, vendor);
  const env = await makeTestEnv();
  for (const host of input.vendorHosts) {
    env.setVendorOrigin(host, vendor.origin);
  }
  seedSession(env, maruhi.origin, owner);
  await seedConfig(env, { server: maruhi.origin, defaultProject: built.projectId });
  const configDir = await mkdtemp(join(tmpdir(), "maruhi-sync-http-test-"));
  const configPath = join(configDir, "maruhi.sync.json");
  await writeFile(
    configPath,
    JSON.stringify({ version: 1, receipts: { environment: RECEIPTS_ENV }, targets: input.targets }),
  );
  return { env, configPath, maruhi, receipts: receipts.state };
}

function sync(fixture: Fixture, ...args: string[]): Promise<number> {
  return runCli(["sync", ...args, "--config", fixture.configPath], fixture.env.layer);
}

function allOutput(env: TestEnv): string {
  return [...env.logs, ...env.errors].join("\n");
}

/** Values and tokens never appear on stdout / stderr / the URL / headers (other than Authorization). */
function expectNoSecretLeak(env: TestEnv, requests: readonly MockRequest[]): void {
  const shown = [
    allOutput(env),
    ...requests.flatMap((request) => [
      request.path,
      JSON.stringify(request.query),
      ...Object.entries(request.headers)
        .filter(([name]) => name !== "authorization")
        .map(([, value]) => String(value)),
    ]),
  ].join("\n");
  for (const secret of SECRETS) {
    expect(shown).not.toContain(secret);
  }
}

const decoder = new TextDecoder();

async function decryptReceipt(fixture: Fixture, target: string): Promise<Record<string, unknown>> {
  const stored = fixture.receipts.variables.find(
    (entry) => entry.statement.name === receiptVariableName(target),
  );
  expect(stored).toBeDefined();
  const value = stored?.value as WireEncryptedPayload;
  const result = await decryptVariable({
    dek: deks.get(RECEIPTS_ENV) as Uint8Array,
    context: value.aad,
    nonce: hexBytes(value.nonceHex),
    ciphertext: hexBytes(value.ciphertextHex),
  });
  if (!result.ok) {
    throw new Error("receipt decrypt failed in test");
  }
  return JSON.parse(decoder.decode(result.value)) as Record<string, unknown>;
}

/** The write material for one variable (for checking batch splitting). */
function write(name: string) {
  return {
    name,
    value: Redacted.make(new TextEncoder().encode(`v-${name}`), { label: "variable-value" }),
  };
}

/** Runs one target's config through the strict parser (result or reason). */
function base(target: Record<string, unknown>) {
  return parseSyncConfig(
    JSON.stringify({ version: 1, receipts: { environment: "r" }, targets: { t: target } }),
    "/repo",
  );
}

/** Extracts target t from the parser's result (a reason string would violate the test's premise). */
function targetOf(parsed: ReturnType<typeof base>): SyncTarget {
  if (typeof parsed === "string") {
    throw new Error(parsed);
  }
  return parsed.targets.get("t") as SyncTarget;
}

/** A stub that returns a 429 (Retry-After: 0) only on the first call. */
const rateLimitedOnce: VendorOverride = (call) =>
  call === 1 ? { status: 429, headers: { "retry-after": "0" } } : undefined;

/** The preset's write-request declarations (upsert = one, create-or-update = two). */
function writeSpecsOf(preset: HttpPreset) {
  return preset.write.kind === "upsert"
    ? [preset.write.request]
    : [preset.write.create, preset.write.update];
}

/** Every path / query token appearing in the preset's declarations (write, list, delete). */
function pathTokensOf(preset: HttpPreset): PathToken[] {
  const lists = [
    ...(preset.write.kind === "create-or-update" ? [preset.write.list] : []),
    ...(preset.delete.kind === "lookup" ? [preset.delete.list] : []),
  ];
  const removes =
    preset.delete.kind === "lookup"
      ? [
          preset.delete.remove,
          ...(preset.delete.removeItem === undefined ? [] : [preset.delete.removeItem]),
        ]
      : [];
  return [...writeSpecsOf(preset), ...lists, ...removes].flatMap((spec) => [
    ...spec.path,
    ...Object.values(spec.query),
  ]);
}

describe("the http presets' declarations", () => {
  it("path / query tokens carry no values (banned by type — verified by scanning the declarations). Names appear only on single-variable request paths", () => {
    for (const preset of Object.values(HTTP_PRESETS) as HttpPreset[]) {
      for (const token of pathTokensOf(preset)) {
        if (typeof token === "string") {
          expect(token).not.toMatch(/value=|secret=|text=/i);
        } else {
          expect(["option", "id", "name"]).toContain(token.kind);
        }
      }
      // The name token appears only on requests carrying a single
      // variable (`single` writes, per-item deletes)
      for (const spec of writeSpecsOf(preset)) {
        if (spec.entries !== "single") {
          expect(
            spec.path.some((token) => typeof token !== "string" && token.kind === "name"),
          ).toBe(false);
        }
      }
      // The host is fixed (not replaceable via config)
      expect(preset.host).toMatch(/^api\.(cloudflare|vercel|netlify)\.com$/);
    }
  });

  it("checkIntegrationToken: refuses newlines, control characters, and anything outside ISO-8859-1 with a typed error, and the wording carries no value", () => {
    const encoder = new TextEncoder();
    expect(checkIntegrationToken("T", encoder.encode("abc-123"))).toBe("abc-123");
    for (const bad of ["secret-abc\n", "secret-ab\u0001c", "secret-\u00e9\u3042", ""]) {
      const result = checkIntegrationToken("T", encoder.encode(bad));
      expect(typeof result).not.toBe("string");
      expect(String((result as { message: string }).message)).not.toContain("secret-");
    }
  });

  it("buildBatches: Workers interleaves deletions into writes every 100, Vercel every 25 plus per-item deletes, Netlify all writes in one batch plus per-item deletes", () => {
    const writes = Array.from({ length: 120 }, (_, index) => write(`V${index}`));
    const workers = buildBatches({
      preset: HTTP_PRESETS["cloudflare-workers"],
      writes,
      deletes: ["GONE"],
    });
    expect(workers.map((batch) => [batch.kind, batch.names.length])).toEqual([
      ["write", 100],
      ["write", 21],
    ]);
    expect(workers[1]?.deletes).toEqual(["GONE"]);
    const vercel = buildBatches({ preset: HTTP_PRESETS.vercel, writes, deletes: ["GONE", "OLD"] });
    expect(vercel.map((batch) => [batch.kind, batch.names.length])).toEqual([
      ["write", 25],
      ["write", 25],
      ["write", 25],
      ["write", 25],
      ["write", 20],
      ["delete", 1],
      ["delete", 1],
    ]);
    const netlify = buildBatches({ preset: HTTP_PRESETS.netlify, writes, deletes: ["GONE"] });
    expect(netlify.map((batch) => [batch.kind, batch.names.length])).toEqual([
      ["write", 120],
      ["delete", 1],
    ]);
    expect(
      buildBatches({ preset: HTTP_PRESETS.netlify, writes: [], deletes: ["GONE"] }),
    ).toHaveLength(1);
  });

  it("config (Netlify): driver omitted = http, exec is refused with a reason, context / siteId / accountId are required, branch and secret consistency, the production default", () => {
    const plain = base(netlifyTarget());
    expect(typeof plain).not.toBe("string");
    expect(targetOf(plain).driver.kind).toBe("http");
    expect(targetOf(plain).production).toBe(false);
    expect(base(netlifyTarget({ driver: "exec", token: undefined }))).toContain(
      'targets.t.driver: the netlify preset has no exec driver: the Netlify CLI takes the value as a command-line argument (visible in ps), so maruhi only talks to the Netlify API; use "http"',
    );
    expect(base(netlifyTarget({ options: { accountId: "a", siteId: "s" } }))).toContain(
      "targets.t.options.context is required for the netlify preset with the http driver (one of production, deploy-preview, branch-deploy, branch, dev, dev-server, all)",
    );
    expect(base(netlifyTarget({ options: { siteId: "s", context: "production" } }))).toContain(
      "targets.t.options.accountId is required",
    );
    expect(base(netlifyTarget({ options: { accountId: "a", context: "production" } }))).toContain(
      "targets.t.options.siteId is required",
    );
    expect(
      base(netlifyTarget({ options: { accountId: "a", siteId: "s", context: "branch" } })),
    ).toContain("targets.t.options.branch is required when context is branch");
    expect(
      base(
        netlifyTarget({
          options: { accountId: "a", siteId: "s", context: "production", branch: "staging" },
        }),
      ),
    ).toContain("targets.t.options.branch applies only when context is branch");
    expect(
      base(
        netlifyTarget({ options: { accountId: "a", siteId: "s", context: "all", secret: true } }),
      ),
    ).toContain("targets.t.options.secret cannot be true when context is all");
    expect(
      base(
        netlifyTarget({ options: { accountId: "a", siteId: "s", context: "dev", secret: true } }),
      ),
    ).toContain("secret cannot be true when context is dev");
    // The production default: production / all count as production,
    // the rest don't
    for (const [context, production] of [
      ["production", true],
      ["all", true],
      ["deploy-preview", false],
      ["branch-deploy", false],
      ["dev", false],
    ] as const) {
      expect(
        targetOf(base(netlifyTarget({ options: { accountId: "a", siteId: "s", context } })))
          .production,
      ).toBe(production);
    }
    expect(
      targetOf(
        base(
          netlifyTarget({
            options: { accountId: "a", siteId: "s", context: "branch", branch: "b" },
          }),
        ),
      ).production,
    ).toBe(false);
  });

  it("config: http requires token and forbids cwd / command; exec forbids token. The token variable is never carried", () => {
    expect(base(cloudflareTarget({ token: undefined }))).toContain(
      "targets.t.token is required for the http driver",
    );
    expect(base(cloudflareTarget({ cwd: "x" }))).toContain(
      "targets.t.cwd applies only to the exec driver",
    );
    expect(base(cloudflareTarget({ driver: "exec", options: {} }))).toContain(
      "targets.t.token applies only to the http driver",
    );
    expect(base(cloudflareTarget({ driver: "ftp" }))).toContain('targets.t.driver must be "exec"');
    expect(base(cloudflareTarget({ options: { name: "w" } }))).toContain(
      "targets.t.options.accountId is required for the cloudflare-workers preset with the http driver",
    );
    expect(base(vercelTarget({ options: { environment: "preview", project: "x" } }))).toContain(
      "targets.t.options has unknown keys (project)",
    );
    // A same-environment token is silently dropped from "all"; on an
    // explicit list it's a config error
    const sameEnvAll = base(
      cloudflareTarget({ token: { environment: SOURCE_ENV, name: "CF_API_TOKEN" } }),
    );
    expect(typeof sameEnvAll).not.toBe("string");
    expect(targetOf(sameEnvAll).exclude).toEqual(["CF_API_TOKEN"]);
    expect(
      base(
        vercelTarget({
          variables: ["ALPHA", "VERCEL_TOKEN"],
          token: { environment: SOURCE_ENV, name: "VERCEL_TOKEN" },
        }),
      ),
    ).toContain("targets.t.variables lists the token variable");
    // A driver-less config reads as exec as-is (backward compat)
    const legacy = base({
      preset: "vercel",
      environment: "p",
      variables: ["A"],
      options: { environment: "production" },
    });
    expect(typeof legacy).not.toBe("string");
    expect(targetOf(legacy).driver.kind).toBe("exec");
  });
});

describe("maruhi sync apply (http, Cloudflare Workers)", () => {
  it("places values in merge-patch secrets, composes named environments into the script name, puts the token only on Authorization, and creates the receipt", async () => {
    const cf = makeFakeCloudflare({
      token: CF_TOKEN,
      scripts: [`${CF_ACCOUNT}/my-worker-staging`],
    });
    const fixture = await startFixture({
      targets: { worker: cloudflareTarget() },
      vendorHandlers: cf.handlers,
      vendorHosts: ["api.cloudflare.com"],
    });
    expect(await sync(fixture, "apply", "worker"), fixture.env.errors.join("\n")).toBe(0);
    expect(cf.requests).toHaveLength(1);
    const request = cf.requests[0] as MockRequest;
    expect(request.path).toBe(
      `/client/v4/accounts/${CF_ACCOUNT}/workers/scripts/my-worker-staging/secrets-bulk`,
    );
    expect(request.headers["content-type"]).toBe("application/merge-patch+json");
    expect(request.headers["user-agent"]).toMatch(/^maruhi-cli\//);
    expect(request.body).toEqual({
      secrets: {
        ALPHA: { name: "ALPHA", text: ALPHA_VALUE, type: "secret_text" },
        BETA: { name: "BETA", text: BETA_VALUE, type: "secret_text" },
      },
    });
    expect(cf.secrets.get(`${CF_ACCOUNT}/my-worker-staging`)?.get("BETA")).toBe(BETA_VALUE);
    expect(fixture.env.logs.join("\n")).toContain(
      "Sending to api.cloudflare.com with the token from variable CF_API_TOKEN in environment tokens",
    );
    // The header line names the sync destination via the preset's
    // describeOptions (name / environment)
    expect(fixture.env.logs.join("\n")).toContain(
      "Sync plan for target worker (environment prod -> cloudflare-workers my-worker staging via http)",
    );
    expect(fixture.env.logs.join("\n")).toContain(
      "Applied to target worker: 2 variables written, 0 deleted",
    );
    expect(fixture.env.execCalls).toEqual([]);
    expectNoSecretLeak(fixture.env, cf.requests);
    const receipt = await decryptReceipt(fixture, "worker");
    expect(receipt).toMatchObject({
      preset: "cloudflare-workers",
      variables: { ALPHA: 3, BETA: 1 },
    });
  });

  it("deletions ride the same request as nulls, and plan never touches the vendor API", async () => {
    const cf = makeFakeCloudflare({
      token: CF_TOKEN,
      scripts: [`${CF_ACCOUNT}/my-worker-staging`],
    });
    cf.secrets.get(`${CF_ACCOUNT}/my-worker-staging`)?.set("OLD", "old");
    const fixture = await startFixture({
      targets: { worker: cloudflareTarget() },
      receipts: [
        await receiptVariable({
          target: "worker",
          preset: "cloudflare-workers",
          variables: { ALPHA: 3, OLD: 1 },
        }),
      ],
      vendorHandlers: cf.handlers,
      vendorHosts: ["api.cloudflare.com"],
    });
    expect(await sync(fixture, "plan", "worker")).toBe(0);
    expect(cf.requests).toEqual([]);
    expect(fixture.env.logs.join("\n")).toContain(
      "- OLD\t(no longer synced; last delivered version 1)",
    );
    expect(await sync(fixture, "apply", "worker")).toBe(0);
    expect((cf.requests[0] as MockRequest).body).toEqual({
      secrets: { BETA: { name: "BETA", text: BETA_VALUE, type: "secret_text" }, OLD: null },
    });
    expect(cf.secrets.get(`${CF_ACCOUNT}/my-worker-staging`)?.has("OLD")).toBe(false);
    expect(await decryptReceipt(fixture, "worker")).toMatchObject({
      variables: { ALPHA: 3, BETA: 1 },
    });
  });

  it("with no Worker (10007), doesn't create a draft, guides toward a deploy, exits 1 — and the values are scrubbed", async () => {
    const cf = makeFakeCloudflare({ token: CF_TOKEN, scripts: [] });
    const fixture = await startFixture({
      targets: { worker: cloudflareTarget() },
      vendorHandlers: cf.handlers,
      vendorHosts: ["api.cloudflare.com"],
    });
    expect(await sync(fixture, "apply", "worker")).toBe(1);
    const errors = fixture.env.errors.join("\n");
    expect(errors).toContain(
      "No Worker named my-worker-staging exists in this account. maruhi does not create one",
    );
    expect(errors).toContain("the Cloudflare API refused the request while writing ALPHA, BETA");
    expect(fixture.receipts.writes).toEqual([]);
    expectNoSecretLeak(fixture.env, cf.requests);
  });

  it("waits out a 429 via Retry-After and retries; a persistent 5xx exhausts the attempts to exit 1 (response echoes are scrubbed)", async () => {
    const cf = makeFakeCloudflare({
      token: CF_TOKEN,
      scripts: [`${CF_ACCOUNT}/my-worker-staging`],
      override: rateLimitedOnce,
    });
    const fixture = await startFixture({
      targets: { worker: cloudflareTarget() },
      vendorHandlers: cf.handlers,
      vendorHosts: ["api.cloudflare.com"],
    });
    expect(await sync(fixture, "apply", "worker")).toBe(0);
    expect(cf.requests).toHaveLength(2);
    const echoing: VendorOverride = () => ({
      status: 503,
      json: {
        success: false,
        errors: [
          { code: 7000, message: `overloaded while storing ${ALPHA_VALUE} with ${CF_TOKEN}` },
        ],
        messages: [],
      },
      headers: { "retry-after": "0" },
    });
    const down = makeFakeCloudflare({
      token: CF_TOKEN,
      scripts: [`${CF_ACCOUNT}/my-worker-staging`],
      override: echoing,
    });
    const fixture2 = await startFixture({
      targets: { worker: cloudflareTarget() },
      vendorHandlers: down.handlers,
      vendorHosts: ["api.cloudflare.com"],
    });
    expect(await sync(fixture2, "apply", "worker")).toBe(1);
    expect(down.requests).toHaveLength(3);
    const errors2 = fixture2.env.errors.join("\n");
    expect(errors2).toContain("the Cloudflare API answered 503 (3 attempts)");
    // Exhausted attempts aren't a 'refusal' — worded as a send
    // failure
    expect(errors2).toContain("the request to the Cloudflare API failed while writing");
    expectNoSecretLeak(fixture2.env, down.requests);
  });

  it("a missing token variable or one containing a newline stops without sending (the wording names only the variable)", async () => {
    const cf = makeFakeCloudflare({
      token: CF_TOKEN,
      scripts: [`${CF_ACCOUNT}/my-worker-staging`],
    });
    const missing = await startFixture({
      targets: { worker: cloudflareTarget({ token: { environment: TOKENS_ENV, name: "NOPE" } }) },
      vendorHandlers: cf.handlers,
      vendorHosts: ["api.cloudflare.com"],
    });
    expect(await sync(missing, "apply", "worker")).toBe(1);
    expect(missing.env.errors.join("\n")).toContain(
      "The token variable NOPE does not exist in environment tokens",
    );
    const newline = await startFixture({
      targets: { worker: cloudflareTarget() },
      tokenVariables: [
        await variable({
          environment: TOKENS_ENV,
          variableId: "tc",
          name: "CF_API_TOKEN",
          version: 1,
          plaintext: `${CF_TOKEN}\n`,
        }),
      ],
      vendorHandlers: cf.handlers,
      vendorHosts: ["api.cloudflare.com"],
    });
    expect(await sync(newline, "apply", "worker")).toBe(1);
    expect(newline.env.errors.join("\n")).toContain(
      "The token variable CF_API_TOKEN contains a newline, a control character, or a character outside ISO-8859-1",
    );
    expect(cf.requests).toEqual([]);
    expectNoSecretLeak(newline.env, cf.requests);
  });

  it("when the token lives on the receipts environment, it's read by the same floor handle and the receipt can be written too", async () => {
    const cf = makeFakeCloudflare({
      token: CF_TOKEN,
      scripts: [`${CF_ACCOUNT}/my-worker-staging`],
    });
    const fixture = await startFixture({
      targets: {
        worker: cloudflareTarget({ token: { environment: RECEIPTS_ENV, name: "CF_API_TOKEN" } }),
      },
      receipts: [
        await variable({
          environment: RECEIPTS_ENV,
          variableId: "tc",
          name: "CF_API_TOKEN",
          version: 1,
          plaintext: CF_TOKEN,
        }),
      ],
      vendorHandlers: cf.handlers,
      vendorHosts: ["api.cloudflare.com"],
    });
    expect(await sync(fixture, "apply", "worker"), fixture.env.errors.join("\n")).toBe(0);
    expect(cf.requests).toHaveLength(1);
    expect(fixture.receipts.writes.map((entry) => entry.kind)).toEqual(["create"]);
    expect(await decryptReceipt(fixture, "worker")).toMatchObject({
      variables: { ALPHA: 3, BETA: 1 },
    });
    // Second run: reads the receipt (the new version) from the same
    // floor, and the token reads too
    expect(await sync(fixture, "plan", "worker"), fixture.env.errors.join("\n")).toBe(0);
    expect(fixture.env.logs.join("\n")).toContain("2 unchanged");
    expectNoSecretLeak(fixture.env, cf.requests);
  });

  it("a token living on the sync source's environment still isn't carried to the target", async () => {
    const cf = makeFakeCloudflare({
      token: CF_TOKEN,
      scripts: [`${CF_ACCOUNT}/my-worker-staging`],
    });
    const fixture = await startFixture({
      targets: {
        worker: cloudflareTarget({ token: { environment: SOURCE_ENV, name: "CF_API_TOKEN" } }),
      },
      sourceVariables: [
        await variable({
          environment: SOURCE_ENV,
          variableId: "va",
          name: "ALPHA",
          version: 3,
          plaintext: ALPHA_VALUE,
        }),
        await variable({
          environment: SOURCE_ENV,
          variableId: "tc",
          name: "CF_API_TOKEN",
          version: 1,
          plaintext: CF_TOKEN,
        }),
      ],
      vendorHandlers: cf.handlers,
      vendorHosts: ["api.cloudflare.com"],
    });
    expect(await sync(fixture, "apply", "worker")).toBe(0);
    expect(Object.keys((cf.requests[0] as MockRequest).body as Record<string, unknown>)).toEqual([
      "secrets",
    ]);
    expect((cf.requests[0] as MockRequest).body).toEqual({
      secrets: { ALPHA: { name: "ALPHA", text: ALPHA_VALUE, type: "secret_text" } },
    });
  });
});

describe("maruhi sync apply (http, Vercel)", () => {
  it("batches as an array with upsert=true, type is sensitive for preview, teamId is a query param, and deletion is list → DELETE", async () => {
    const vercel = makeFakeVercel({
      token: VERCEL_TOKEN,
      projectId: "prj_123",
      teamId: "team_9",
      initial: [
        { id: "env_old", key: "OLD", value: "old", type: "encrypted", target: ["preview"] },
        { id: "env_prod", key: "OLD", value: "keep", type: "encrypted", target: ["production"] },
      ],
    });
    const fixture = await startFixture({
      targets: { web: vercelTarget() },
      receipts: [
        await receiptVariable({ target: "web", preset: "vercel", variables: { ALPHA: 2, OLD: 1 } }),
      ],
      vendorHandlers: vercel.handlers,
      vendorHosts: ["api.vercel.com"],
    });
    expect(await sync(fixture, "apply", "web")).toBe(0);
    const [upsert, list, remove] = vercel.requests as [MockRequest, MockRequest, MockRequest];
    expect(upsert.method).toBe("POST");
    expect(upsert.path).toBe("/v10/projects/prj_123/env");
    expect(upsert.query).toEqual({ upsert: "true", teamId: "team_9" });
    expect(upsert.body).toEqual([
      { key: "ALPHA", value: ALPHA_VALUE, type: "sensitive", target: ["preview"] },
      { key: "BETA", value: BETA_VALUE, type: "sensitive", target: ["preview"] },
    ]);
    expect(list.method).toBe("GET");
    expect(list.query).toEqual({ target: "preview", teamId: "team_9" });
    expect(remove.method).toBe("DELETE");
    // Deletes only preview's OLD (the production namesake survives)
    expect(remove.path).toBe("/v10/projects/prj_123/env/env_old");
    expect(vercel.envs.map((env) => env.key).toSorted()).toEqual(["ALPHA", "BETA", "OLD"]);
    expect(await decryptReceipt(fixture, "web")).toMatchObject({
      variables: { ALPHA: 3, BETA: 1 },
    });
    expectNoSecretLeak(fixture.env, vercel.requests);
  });

  it("development and sensitive: false are sent as encrypted", async () => {
    const vercel = makeFakeVercel({ token: VERCEL_TOKEN, projectId: "prj_123" });
    const fixture = await startFixture({
      targets: {
        dev: vercelTarget({ options: { environment: "development", projectId: "prj_123" } }),
        plain: vercelTarget({
          options: { environment: "production", projectId: "prj_123", sensitive: false },
        }),
      },
      vendorHandlers: vercel.handlers,
      vendorHosts: ["api.vercel.com"],
    });
    expect(await sync(fixture, "apply", "dev")).toBe(0);
    expect(await sync(fixture, "apply", "plain", "--yes")).toBe(0);
    const types = vercel.requests.map((request) =>
      (request.body as { type: string }[]).map((item) => item.type),
    );
    expect(types).toEqual([
      ["encrypted", "encrypted"],
      ["encrypted", "encrypted"],
    ]);
  });

  it("partial success (failed) leaves only the delivered names on the receipt, scrubs the failure response's value echo, and exits 1", async () => {
    const vercel = makeFakeVercel({
      token: VERCEL_TOKEN,
      projectId: "prj_123",
      rejectKeys: ["BETA"],
    });
    const fixture = await startFixture({
      targets: { web: vercelTarget({ options: { environment: "preview", projectId: "prj_123" } }) },
      vendorHandlers: vercel.handlers,
      vendorHosts: ["api.vercel.com"],
    });
    expect(await sync(fixture, "apply", "web")).toBe(1);
    const errors = fixture.env.errors.join("\n");
    expect(errors).toContain(
      "the Vercel API refused the request while writing BETA (delivered before that: 1 variable written, 0 deleted)",
    );
    expect(errors).toContain("error INVALID_VALUE (BETA): value rejected for BETA: [redacted]");
    expect(await decryptReceipt(fixture, "web")).toMatchObject({ variables: { ALPHA: 3 } });
    expectNoSecretLeak(fixture.env, vercel.requests);
  });

  it("deleting a name already gone at the target counts as deleted when absent from the list (the receipt doesn't jam)", async () => {
    const vercel = makeFakeVercel({ token: VERCEL_TOKEN, projectId: "prj_123" });
    const fixture = await startFixture({
      targets: {
        web: vercelTarget({
          variables: ["ALPHA"],
          options: { environment: "preview", projectId: "prj_123" },
        }),
      },
      receipts: [
        await receiptVariable({
          target: "web",
          preset: "vercel",
          variables: { ALPHA: 3, GONE: 1 },
        }),
      ],
      vendorHandlers: vercel.handlers,
      vendorHosts: ["api.vercel.com"],
    });
    expect(await sync(fixture, "apply", "web")).toBe(0);
    expect(vercel.requests.map((request) => request.method)).toEqual(["GET"]);
    expect(fixture.env.logs.join("\n")).toContain(
      "Applied to target web: 0 variables written, 1 deleted",
    );
    expect(await decryptReceipt(fixture, "web")).toMatchObject({ variables: { ALPHA: 3 } });
  });

  it("when the list continues (pagination.next) but the name is absent, it isn't judged gone — kept on the receipt with exit 1", async () => {
    const vercel = makeFakeVercel({ token: VERCEL_TOKEN, projectId: "prj_123", paginated: true });
    const fixture = await startFixture({
      targets: {
        web: vercelTarget({
          variables: ["ALPHA"],
          options: { environment: "preview", projectId: "prj_123" },
        }),
      },
      receipts: [
        await receiptVariable({
          target: "web",
          preset: "vercel",
          variables: { ALPHA: 3, GONE: 1 },
        }),
      ],
      vendorHandlers: vercel.handlers,
      vendorHosts: ["api.vercel.com"],
    });
    expect(await sync(fixture, "apply", "web")).toBe(1);
    expect(vercel.requests.map((request) => request.method)).toEqual(["GET"]);
    expect(fixture.env.errors.join("\n")).toContain(
      "the Vercel API returned a paginated list of variables, so maruhi could not confirm that GONE is gone from the target. It stays in the receipt",
    );
    // No receipt is written (GONE remains = the next apply retries)
    expect(fixture.receipts.writes).toEqual([]);
  });

  it("a 2xx write without created isn't read as delivered, and no receipt is written", async () => {
    const vercel = makeFakeVercel({
      token: VERCEL_TOKEN,
      projectId: "prj_123",
      override: () => ({ status: 201, json: {} }),
    });
    const fixture = await startFixture({
      targets: { web: vercelTarget({ options: { environment: "preview", projectId: "prj_123" } }) },
      vendorHandlers: vercel.handlers,
      vendorHosts: ["api.vercel.com"],
    });
    expect(await sync(fixture, "apply", "web")).toBe(1);
    expect(fixture.env.errors.join("\n")).toContain(
      "HTTP 201 without a created field (unexpected response shape)",
    );
    expect(fixture.receipts.writes).toEqual([]);
  });

  it("a refused token (403) delivers nothing and writes no receipt", async () => {
    const vercel = makeFakeVercel({ token: "another-token", projectId: "prj_123" });
    const fixture = await startFixture({
      targets: { web: vercelTarget({ options: { environment: "preview", projectId: "prj_123" } }) },
      vendorHandlers: vercel.handlers,
      vendorHosts: ["api.vercel.com"],
    });
    expect(await sync(fixture, "apply", "web")).toBe(1);
    expect(fixture.env.errors.join("\n")).toContain("HTTP 403");
    expect(fixture.env.errors.join("\n")).toContain("error forbidden: Not authorized");
    expect(fixture.receipts.writes).toEqual([]);
    expectNoSecretLeak(fixture.env, vercel.requests);
  });
});

describe("maruhi sync apply (http, Netlify)", () => {
  it("lists presence, POSTs absent names (one-element array, secret, 3 scopes), PATCHes present ones (one context). The token is on Authorization only, and the receipt is created", async () => {
    const netlify = netlifyFake({
      initial: [
        {
          key: "BETA",
          scopes: ["builds", "functions", "runtime"],
          values: [{ id: "val_prod", value: "keep", context: "production" }],
          is_secret: true,
        },
      ],
    });
    const fixture = await startFixture({
      targets: { site: netlifyTarget() },
      vendorHandlers: netlify.handlers,
      vendorHosts: ["api.netlify.com"],
    });
    expect(await sync(fixture, "apply", "site"), fixture.env.errors.join("\n")).toBe(0);
    const [list, create, update] = netlify.requests as [MockRequest, MockRequest, MockRequest];
    expect(list.method).toBe("GET");
    expect(list.path).toBe(`/api/v1/accounts/${NETLIFY_ACCOUNT}/env`);
    expect(list.query).toEqual({ site_id: NETLIFY_SITE });
    expect(create.method).toBe("POST");
    expect(create.path).toBe(`/api/v1/accounts/${NETLIFY_ACCOUNT}/env`);
    expect(create.query).toEqual({ site_id: NETLIFY_SITE });
    expect(create.headers["content-type"]).toBe("application/json");
    expect(create.headers["user-agent"]).toMatch(/^maruhi-cli\//);
    expect(create.body).toEqual([
      {
        key: "ALPHA",
        is_secret: true,
        scopes: ["builds", "functions", "runtime"],
        values: [{ context: "deploy-preview", value: ALPHA_VALUE }],
      },
    ]);
    expect(update.method).toBe("PATCH");
    expect(update.path).toBe(`/api/v1/accounts/${NETLIFY_ACCOUNT}/env/BETA`);
    expect(update.query).toEqual({ site_id: NETLIFY_SITE });
    expect(update.body).toEqual({ context: "deploy-preview", value: BETA_VALUE });
    // The target's state: ALPHA is new (secret), BETA kept its
    // production value and got a deploy-preview added
    expect(netlify.vars.get("ALPHA")?.is_secret).toBe(true);
    expect(netlify.vars.get("BETA")?.values.map((value) => [value.context, value.value])).toEqual([
      ["production", "keep"],
      ["deploy-preview", BETA_VALUE],
    ]);
    expect(fixture.env.logs.join("\n")).toContain(
      "Sending to api.netlify.com with the token from variable NETLIFY_TOKEN in environment tokens",
    );
    // The header line names the sync destination via the preset's
    // describeOptions (context / branch)
    expect(fixture.env.logs.join("\n")).toContain(
      "Sync plan for target site (environment prod -> netlify deploy-preview via http)",
    );
    expect(fixture.env.logs.join("\n")).toContain(
      "Applied to target site: 2 variables written, 0 deleted",
    );
    expect(fixture.env.execCalls).toEqual([]);
    expectNoSecretLeak(fixture.env, netlify.requests);
    expect(await decryptReceipt(fixture, "site")).toMatchObject({
      preset: "netlify",
      variables: { ALPHA: 3, BETA: 1 },
    });
    // Second run: both are in the list, so PATCH only (no POST). plan
    // never touches the API
    netlify.requests.length = 0;
    expect(await sync(fixture, "plan", "site")).toBe(0);
    expect(netlify.requests).toEqual([]);
    const receipts = await startFixture({
      targets: { site: netlifyTarget() },
      receipts: [
        await receiptVariable({ target: "site", preset: "netlify", variables: { ALPHA: 1 } }),
      ],
      vendorHandlers: netlify.handlers,
      vendorHosts: ["api.netlify.com"],
    });
    expect(await sync(receipts, "apply", "site"), receipts.env.errors.join("\n")).toBe(0);
    expect(
      netlify.requests.map((request) => [request.method, request.path.split("/").at(-1)]),
    ).toEqual([
      ["GET", "env"],
      ["PATCH", "ALPHA"],
      ["PATCH", "BETA"],
    ]);
  });

  it("context all / secret false sends is_secret: false without scopes; production and all need --yes. branch rides the context_parameter", async () => {
    const netlify = netlifyFake();
    const fixture = await startFixture({
      targets: {
        everywhere: netlifyTarget({
          options: { accountId: NETLIFY_ACCOUNT, siteId: NETLIFY_SITE, context: "all" },
        }),
        plain: netlifyTarget({
          options: {
            accountId: NETLIFY_ACCOUNT,
            siteId: NETLIFY_SITE,
            context: "production",
            secret: false,
          },
        }),
        staging: netlifyTarget({
          variables: ["ALPHA"],
          options: {
            accountId: NETLIFY_ACCOUNT,
            siteId: NETLIFY_SITE,
            context: "branch",
            branch: "staging",
            secret: false,
          },
        }),
      },
      vendorHandlers: netlify.handlers,
      vendorHosts: ["api.netlify.com"],
    });
    expect(await sync(fixture, "apply", "everywhere")).toBe(1);
    expect(fixture.env.errors.join("\n")).toContain("--yes");
    expect(netlify.requests).toEqual([]);
    expect(await sync(fixture, "apply", "everywhere", "--yes")).toBe(0);
    expect(await sync(fixture, "apply", "plain", "--yes")).toBe(0);
    expect(await sync(fixture, "apply", "staging")).toBe(0);
    const bodies = netlify.requests
      .filter((request) => request.method !== "GET")
      .map((request) => request.body);
    expect(bodies[0]).toEqual([
      { key: "ALPHA", is_secret: false, values: [{ context: "all", value: ALPHA_VALUE }] },
    ]);
    // plain: ALPHA / BETA are in the list (made by everywhere) = PATCH
    // gets the production value
    expect(bodies[2]).toEqual({ context: "production", value: ALPHA_VALUE });
    expect(bodies[4]).toEqual({
      context: "branch",
      context_parameter: "staging",
      value: ALPHA_VALUE,
    });
    expect(netlify.vars.get("ALPHA")?.values.map((value) => value.context)).toEqual([
      "all",
      "production",
      "branch",
    ]);
    expectNoSecretLeak(fixture.env, netlify.requests);
  });

  it("deletion removes by id only this target's context value, keeping other contexts' values; the last value deletes the whole key. Absent from the list counts as deleted", async () => {
    const netlify = netlifyFake({
      initial: [
        {
          key: "OLD",
          scopes: ["builds", "functions", "runtime"],
          values: [
            { id: "val_old_prod", value: "keep", context: "production" },
            { id: "val_old_dp", value: "old", context: "deploy-preview" },
          ],
          is_secret: true,
        },
        {
          key: "ONLY",
          scopes: ["builds", "functions", "runtime"],
          values: [{ id: "val_only", value: "mine", context: "deploy-preview" }],
          is_secret: true,
        },
      ],
    });
    const fixture = await startFixture({
      targets: { site: netlifyTarget({ variables: ["ALPHA"] }) },
      receipts: [
        await receiptVariable({
          target: "site",
          preset: "netlify",
          variables: { ALPHA: 3, OLD: 1, ONLY: 1, GONE: 1 },
        }),
      ],
      vendorHandlers: netlify.handlers,
      vendorHosts: ["api.netlify.com"],
    });
    expect(await sync(fixture, "apply", "site"), fixture.env.errors.join("\n")).toBe(0);
    const calls = netlify.requests.map((request) => [request.method, request.path]);
    // GONE (absent from the list = counts as deleted, no DELETE sent)
    // → OLD (one value) → ONLY (the whole key)
    expect(calls).toEqual([
      ["GET", `/api/v1/accounts/${NETLIFY_ACCOUNT}/env`],
      ["GET", `/api/v1/accounts/${NETLIFY_ACCOUNT}/env`],
      ["DELETE", `/api/v1/accounts/${NETLIFY_ACCOUNT}/env/OLD/value/val_old_dp`],
      ["GET", `/api/v1/accounts/${NETLIFY_ACCOUNT}/env`],
      ["DELETE", `/api/v1/accounts/${NETLIFY_ACCOUNT}/env/ONLY`],
    ]);
    expect(netlify.vars.get("OLD")?.values.map((value) => value.context)).toEqual(["production"]);
    expect(netlify.vars.has("ONLY")).toBe(false);
    expect(fixture.env.logs.join("\n")).toContain(
      "Applied to target site: 0 variables written, 3 deleted",
    );
    expect(await decryptReceipt(fixture, "site")).toMatchObject({ variables: { ALPHA: 3 } });
    expectNoSecretLeak(fixture.env, netlify.requests);
  });

  it("a refused creation (422) leaves only the delivered names on the receipt, scrubs the response's value echo, and exits 1. If the same name was created first, re-list and switch to PATCH", async () => {
    const netlify = netlifyFake({ rejectKeys: ["BETA"] });
    const fixture = await startFixture({
      targets: { site: netlifyTarget() },
      vendorHandlers: netlify.handlers,
      vendorHosts: ["api.netlify.com"],
    });
    expect(await sync(fixture, "apply", "site")).toBe(1);
    const errors = fixture.env.errors.join("\n");
    expect(errors).toContain(
      "the Netlify API refused the request while writing BETA (delivered before that: 1 variable written, 0 deleted)",
    );
    expect(errors).toContain("error 422: Value for BETA is invalid: [redacted]");
    expect(await decryptReceipt(fixture, "site")).toMatchObject({ variables: { ALPHA: 3 } });
    expectNoSecretLeak(fixture.env, netlify.requests);
    // The shape where the same name was created between the list and
    // the send (a POST to an existing key surfaces as the target's
    // failure)
    const raced = netlifyFake({
      override: (call, request) =>
        call === 1 && request.method === "GET" ? { status: 200, json: [] } : undefined,
      initial: [
        {
          key: "ALPHA",
          scopes: ["builds", "functions", "runtime"],
          values: [{ id: "v1", value: "x", context: "deploy-preview" }],
          is_secret: true,
        },
      ],
    });
    const fixture2 = await startFixture({
      targets: { site: netlifyTarget({ variables: ["ALPHA"] }) },
      vendorHandlers: raced.handlers,
      vendorHosts: ["api.netlify.com"],
    });
    // The POST is refused for an existing key (422) → re-list → ALPHA
    // is there → PATCH. It lands in the same apply
    expect(await sync(fixture2, "apply", "site"), fixture2.env.errors.join("\n")).toBe(0);
    expect(raced.requests.map((request) => request.method)).toEqual([
      "GET",
      "POST",
      "GET",
      "PATCH",
    ]);
    expect(raced.vars.get("ALPHA")?.values[0]?.value).toBe(ALPHA_VALUE);
    expect(await decryptReceipt(fixture2, "site")).toMatchObject({ variables: { ALPHA: 3 } });
    expectNoSecretLeak(fixture2.env, raced.requests);
  });

  it("even if the re-list after a failed create keeps failing, it's reported as a create failure and the already-delivered names stay on the receipt", async () => {
    const flaky = netlifyFake({
      rejectKeys: ["BETA"],
      override: (call, request) =>
        request.method === "GET" && call > 1
          ? { status: 503, headers: { "retry-after": "0" } }
          : undefined,
    });
    const fixture = await startFixture({
      targets: { site: netlifyTarget() },
      vendorHandlers: flaky.handlers,
      vendorHosts: ["api.netlify.com"],
    });
    expect(await sync(fixture, "apply", "site")).toBe(1);
    // GET → POST ALPHA → POST BETA(422)→ GET × 3(503)
    expect(flaky.requests.map((request) => request.method)).toEqual([
      "GET",
      "POST",
      "POST",
      "GET",
      "GET",
      "GET",
    ]);
    const errors = fixture.env.errors.join("\n");
    expect(errors).toContain("error 422: Value for BETA is invalid: [redacted]");
    expect(errors).toContain(
      "Could not re-check the target after the failed create: the Netlify API answered 503 (3 attempts)",
    );
    expect(errors).toContain("delivered before that: 1 variable written, 0 deleted");
    expect(await decryptReceipt(fixture, "site")).toMatchObject({ variables: { ALPHA: 3 } });
    expectNoSecretLeak(fixture.env, flaky.requests);
  });

  it("even if one variable's send exhausts its attempts, it's reported as that variable's failure and the already-delivered names stay on the receipt", async () => {
    // ALPHA's POST passes; BETA's POST gets 503 × 3
    let posts = 0;
    const down = netlifyFake({
      override: (_call, request) => {
        if (request.method !== "POST") {
          return undefined;
        }
        posts += 1;
        return posts === 1 ? undefined : { status: 503, headers: { "retry-after": "0" } };
      },
    });
    const fixture = await startFixture({
      targets: { site: netlifyTarget() },
      vendorHandlers: down.handlers,
      vendorHosts: ["api.netlify.com"],
    });
    expect(await sync(fixture, "apply", "site")).toBe(1);
    expect(down.requests.map((request) => request.method)).toEqual([
      "GET",
      "POST",
      "POST",
      "POST",
      "POST",
    ]);
    const errors = fixture.env.errors.join("\n");
    expect(errors).toContain("the Netlify API answered 503 (3 attempts)");
    // Exhausted attempts aren't a 'refusal' — worded as a send
    // failure
    expect(errors).toContain(
      "the request to the Netlify API failed while writing BETA (delivered before that: 1 variable written, 0 deleted)",
    );
    expect(errors).not.toContain("refused the request");
    expect(await decryptReceipt(fixture, "site")).toMatchObject({ variables: { ALPHA: 3 } });
    expectNoSecretLeak(fixture.env, down.requests);
  });

  it("even if the delete batch's list exhausts its attempts, it's reported as that deletion's failure and the names the earlier write batch delivered stay on the receipt", async () => {
    let gets = 0;
    const flaky = netlifyFake({
      override: (_call, request) => {
        if (request.method !== "GET") {
          return undefined;
        }
        gets += 1;
        return gets === 1 ? undefined : { status: 503, headers: { "retry-after": "0" } };
      },
    });
    const fixture = await startFixture({
      targets: { site: netlifyTarget({ variables: ["ALPHA"] }) },
      receipts: [
        await receiptVariable({
          target: "site",
          preset: "netlify",
          variables: { ALPHA: 1, GONE: 1 },
        }),
      ],
      vendorHandlers: flaky.handlers,
      vendorHosts: ["api.netlify.com"],
    });
    expect(await sync(fixture, "apply", "site")).toBe(1);
    // The write batch (GET → POST ALPHA) delivered; the delete batch's
    // GET got 503 × 3
    expect(flaky.requests.map((request) => request.method)).toEqual([
      "GET",
      "POST",
      "GET",
      "GET",
      "GET",
    ]);
    const errors = fixture.env.errors.join("\n");
    expect(errors).toContain("the Netlify API answered 503 (3 attempts)");
    expect(errors).toContain(
      "the request to the Netlify API failed while deleting GONE (delivered before that: 1 variable written, 0 deleted)",
    );
    expect(await decryptReceipt(fixture, "site")).toMatchObject({
      variables: { ALPHA: 3, GONE: 1 },
    });
    expectNoSecretLeak(fixture.env, flaky.requests);
  });

  it("when a create response is lost and resent, it's refused for the existing key — re-list, switch to PATCH, and record it as delivered", async () => {
    const lossy = netlifyFake({ loseFirstCreateResponse: true });
    const fixture = await startFixture({
      targets: { site: netlifyTarget() },
      vendorHandlers: lossy.handlers,
      vendorHosts: ["api.netlify.com"],
    });
    expect(await sync(fixture, "apply", "site"), fixture.env.errors.join("\n")).toBe(0);
    // GET → POST ALPHA (stored but 503) → POST ALPHA (retry = 422) →
    // GET → PATCH ALPHA → POST BETA
    expect(lossy.requests.map((request) => request.method)).toEqual([
      "GET",
      "POST",
      "POST",
      "GET",
      "PATCH",
      "POST",
    ]);
    expect(lossy.vars.get("ALPHA")?.values).toHaveLength(1);
    expect(lossy.vars.get("ALPHA")?.values[0]?.value).toBe(ALPHA_VALUE);
    expect(await decryptReceipt(fixture, "site")).toMatchObject({
      variables: { ALPHA: 3, BETA: 1 },
    });
    expectNoSecretLeak(fixture.env, lossy.requests);
  });

  it("stops without sending a would-be secret value to a variable that already exists as non-secret (delivered ones go on the receipt). secret: false writes it", async () => {
    const initial = [
      {
        key: "BETA",
        scopes: ["builds", "functions", "runtime", "post_processing"],
        values: [{ id: "val_dp", value: "readable", context: "deploy-preview" }],
        is_secret: false,
      },
    ];
    const netlify = netlifyFake({ initial });
    const fixture = await startFixture({
      targets: { site: netlifyTarget() },
      vendorHandlers: netlify.handlers,
      vendorHosts: ["api.netlify.com"],
    });
    expect(await sync(fixture, "apply", "site")).toBe(1);
    const errors = fixture.env.errors.join("\n");
    expect(errors).toContain(
      "BETA already exists at the target with is_secret off, and the config asks for it on. Netlify cannot turn an existing variable into a secret",
    );
    // Don't call something that was never sent 'refused'
    expect(errors).toContain(
      "maruhi did not send the request while writing BETA (delivered before that: 1 variable written, 0 deleted)",
    );
    // Nothing was sent to BETA (its value stays readable = no maruhi
    // value was placed)
    expect(netlify.requests.map((request) => request.method)).toEqual(["GET", "POST"]);
    expect(netlify.vars.get("BETA")?.values[0]?.value).toBe("readable");
    expect(await decryptReceipt(fixture, "site")).toMatchObject({ variables: { ALPHA: 3 } });
    expectNoSecretLeak(fixture.env, netlify.requests);
    // With secret: false it writes to the non-secret variable (the
    // default secret explicitly lowered)
    const plain = netlifyFake({ initial });
    const fixture2 = await startFixture({
      targets: {
        site: netlifyTarget({
          options: {
            accountId: NETLIFY_ACCOUNT,
            siteId: NETLIFY_SITE,
            context: "deploy-preview",
            secret: false,
          },
        }),
      },
      vendorHandlers: plain.handlers,
      vendorHosts: ["api.netlify.com"],
    });
    expect(await sync(fixture2, "apply", "site"), fixture2.env.errors.join("\n")).toBe(0);
    expect(plain.vars.get("BETA")?.values[0]?.value).toBe(BETA_VALUE);
  });

  it("waits out a 429 via Retry-After and retries; a persistent 5xx exhausts the attempts to exit 1 (response echoes are scrubbed). A 401 delivers nothing", async () => {
    const limited = netlifyFake({ override: rateLimitedOnce });
    const fixture = await startFixture({
      targets: { site: netlifyTarget() },
      vendorHandlers: limited.handlers,
      vendorHosts: ["api.netlify.com"],
    });
    expect(await sync(fixture, "apply", "site"), fixture.env.errors.join("\n")).toBe(0);
    // The list gets 429 → retry → POST × 2
    expect(limited.requests.map((request) => request.method)).toEqual([
      "GET",
      "GET",
      "POST",
      "POST",
    ]);
    const echoing: VendorOverride = () => ({
      status: 503,
      json: { code: 503, message: `overloaded while storing ${ALPHA_VALUE} with ${NETLIFY_TOKEN}` },
      headers: { "retry-after": "0" },
    });
    const down = netlifyFake({ override: echoing });
    const fixture2 = await startFixture({
      targets: { site: netlifyTarget() },
      vendorHandlers: down.handlers,
      vendorHosts: ["api.netlify.com"],
    });
    expect(await sync(fixture2, "apply", "site")).toBe(1);
    expect(down.requests).toHaveLength(3);
    expect(fixture2.env.errors.join("\n")).toContain("the Netlify API answered 503 (3 attempts)");
    expectNoSecretLeak(fixture2.env, down.requests);
    const wrongToken = makeFakeNetlify({
      token: "another-token",
      accountId: NETLIFY_ACCOUNT,
      siteId: NETLIFY_SITE,
    });
    const fixture3 = await startFixture({
      targets: { site: netlifyTarget() },
      vendorHandlers: wrongToken.handlers,
      vendorHosts: ["api.netlify.com"],
    });
    expect(await sync(fixture3, "apply", "site")).toBe(1);
    const listingErrors = fixture3.env.errors.join("\n");
    expect(listingErrors).toContain("HTTP 401 while listing variables at the target");
    // The list did get a response: word it as a listing failure, not
    // 'nothing sent'
    expect(listingErrors).toContain("the Netlify API did not list the existing variables");
    expect(fixture3.receipts.writes).toEqual([]);
    expectNoSecretLeak(fixture3.env, wrongToken.requests);
  });

  it("a 2xx write without the variable's key isn't read as delivered, and no receipt is written. A token living on the sync source's environment isn't carried", async () => {
    const odd = netlifyFake({
      override: (_call, request) =>
        request.method === "POST" ? { status: 201, json: { ok: true } } : undefined,
    });
    const fixture = await startFixture({
      targets: { site: netlifyTarget() },
      vendorHandlers: odd.handlers,
      vendorHosts: ["api.netlify.com"],
    });
    expect(await sync(fixture, "apply", "site")).toBe(1);
    expect(fixture.env.errors.join("\n")).toContain(
      "HTTP 201 without the variable in the response (unexpected response shape)",
    );
    expect(fixture.receipts.writes).toEqual([]);
    const netlify = netlifyFake();
    const sameEnv = await startFixture({
      targets: {
        site: netlifyTarget({
          variables: "all",
          token: { environment: SOURCE_ENV, name: "NETLIFY_TOKEN" },
        }),
      },
      sourceVariables: [
        await variable({
          environment: SOURCE_ENV,
          variableId: "va",
          name: "ALPHA",
          version: 3,
          plaintext: ALPHA_VALUE,
        }),
        await variable({
          environment: SOURCE_ENV,
          variableId: "tn",
          name: "NETLIFY_TOKEN",
          version: 1,
          plaintext: NETLIFY_TOKEN,
        }),
      ],
      vendorHandlers: netlify.handlers,
      vendorHosts: ["api.netlify.com"],
    });
    expect(await sync(sameEnv, "apply", "site"), sameEnv.env.errors.join("\n")).toBe(0);
    expect([...netlify.vars.keys()]).toEqual(["ALPHA"]);
    expectNoSecretLeak(sameEnv.env, netlify.requests);
  });
});
