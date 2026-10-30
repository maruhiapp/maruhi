// Protocol-level tests for the MCP server through Effect 4.1's
// `McpTest.makeClient`: the same `registrationsLayer` the stdio
// transport serves (mcp.ts) is driven in memory over the real JSON-RPC
// encoding — no stdio framing, no mock maruhi server. This complements
// test/mcp.test.ts (which drives the full CLI over stdio against a mock
// server): here the registration layer itself is pinned — exactly one
// tool, the resource pair, and a `get_schema` round trip against a stub
// read.

import { Effect } from "effect";
import { McpTest } from "effect/ai";
import { describe, expect, it } from "vitest";

import { cliError } from "../src/errors.ts";
import { PROTOCOLS, registrationsLayer } from "../src/mcp.ts";

const STUB_RESULT = {
  notice: "stub notice",
  projectId: "project-1",
  environment: "dev",
  environments: ["dev", "prod"],
  variables: [],
  warnings: [],
} as const;

const stubRead = (environment: string | undefined) =>
  Effect.succeed({ ...STUB_RESULT, environment: environment ?? STUB_RESULT.environment });

const failingRead = () => Effect.fail(cliError("not logged in (stub)"));

const withClient = <A, E>(
  read: typeof stubRead | typeof failingRead,
  program: (client: McpTest.Client) => Effect.Effect<A, E>,
): Promise<A> =>
  Effect.runPromise(
    Effect.gen(function* () {
      const client = yield* McpTest.makeClient(registrationsLayer({}, read), {
        protocols: PROTOCOLS,
      });
      return yield* program(client);
    }).pipe(Effect.scoped),
  );

describe("McpTest — registrations layer round trips", () => {
  it("lists exactly the get_schema tool", async () => {
    const result = await withClient(stubRead, (client) => client.listTools());
    expect(result.tools.map((tool) => tool.name)).toEqual(["get_schema"]);
  });

  it("calls get_schema and round-trips the stub result", async () => {
    const result = await withClient(stubRead, (client) =>
      client.callTool({ name: "get_schema", arguments: { environment: "prod" } }),
    );
    expect(result.isError).not.toBe(true);
    const text = result.content
      .flatMap((item) => (item.type === "text" ? [item.text] : []))
      .join("");
    const parsed = JSON.parse(text) as { environment?: string; projectId?: string };
    expect(parsed.environment).toBe("prod");
    expect(parsed.projectId).toBe("project-1");
  });

  it("lists the default resource and the per-environment template", async () => {
    const resources = await withClient(stubRead, (client) => client.listResources());
    expect(resources.resources.map((resource) => resource.uri)).toEqual(["maruhi://schema"]);
    const templates = await withClient(stubRead, (client) => client.listResourceTemplates());
    expect(templates.resourceTemplates.map((template) => template.uriTemplate)).toEqual([
      "maruhi://schema/{environment}",
    ]);
  });

  it("reads the default resource as JSON", async () => {
    const result = await withClient(stubRead, (client) =>
      client.readResource({ uri: "maruhi://schema" }),
    );
    expect(result.contents).toHaveLength(1);
    const content = result.contents[0];
    expect(content?.mimeType).toBe("application/json");
    const parsed = JSON.parse(content !== undefined && "text" in content ? content.text : "{}") as {
      environment?: string;
    };
    expect(parsed.environment).toBe("dev");
  });

  it("surfaces a read failure as a tool error, not a transport failure", async () => {
    const result = await withClient(failingRead, (client) =>
      client.callTool({ name: "get_schema", arguments: {} }),
    );
    expect(result.isError).toBe(true);
    const text = result.content
      .flatMap((item) => (item.type === "text" ? [item.text] : []))
      .join("");
    expect(text).toContain("not logged in (stub)");
  });
});
