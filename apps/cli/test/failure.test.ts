import {
  DataLimitExceededError,
  DekWrapNotFoundError,
  ProjectLimitError,
  UnauthorizedError,
} from "@maruhi/api-schema";
import { Cause, Effect, Exit, Schema } from "effect";
import { HttpClientError, HttpClientRequest } from "effect/http";
import { describe, expect, it } from "vite-plus/test";

import { toCliError } from "../src/failure.ts";

describe("toCliError (terminal neutralization of server-sourced strings)", () => {
  it("guides a 401 to both possibilities — expired and revoked — and to re-login (AUTH_SPEC §6)", () => {
    const rendered = toCliError(new UnauthorizedError());
    expect(rendered.message).toContain("expired or revoked");
    expect(rendered.message).toContain("maruhi login");
  });

  it("typed tenant-quota errors do not fall into opaque unknown; they guide the next step (AUTH_SPEC §11-3 / §12-8)", () => {
    const projectLimit = toCliError(new ProjectLimitError({ limit: 100 }));
    expect(projectLimit.message).not.toContain("Unexpected error");
    expect(projectLimit.message).toContain("maximum number of projects (100");
    expect(projectLimit.message).toContain("existing projects are unaffected");
    const storage = toCliError(
      new DataLimitExceededError({ resource: "project-storage-bytes", limit: 9_000_000_000 }),
    );
    expect(storage.message).toContain("storage guard");
    expect(storage.message).toContain("9000000000 bytes");
    expect(storage.message).toContain("reading values");
    expect(storage.message).toContain("deleting");
    expect(storage.message).toContain("move the values to a new project");
    const environment = toCliError(
      new DataLimitExceededError({ resource: "environment-ciphertext-bytes", limit: 8_388_608 }),
    );
    expect(environment.message).toContain("per-environment limit (8388608 bytes");
    expect(environment.message).toContain("Delete values this environment no longer needs");
    expect(environment.message).toContain("another environment");
    const generic = toCliError(new DataLimitExceededError({ resource: "variables", limit: 1000 }));
    expect(generic.message).toBe("Exceeds a server acceptance limit (variables limit 1000)");
  });

  it("neutralizes the error Schema's free-form string IDs", () => {
    const notFound = toCliError(
      new DekWrapNotFoundError({ epoch: 3, recipientUserId: "x\u001b[31mred\u001b[0m\nfake" }),
    );
    expect(notFound.message).not.toContain("\u001b");
    expect(notFound.message).not.toContain("\n");
    expect(notFound.message).toContain("x\uFFFD[31mred\uFFFD[0m\uFFFDfake");
  });

  it("an unknown error past all declared cases prints no message — only the type name is attached", () => {
    const unknown = toCliError(new Error("boom sk-live-SUPER-SECRET \u001b]0;pwned\u0007"));
    expect(unknown.message).toBe("Unexpected error (Error)");
    expect(unknown.message).not.toContain("sk-live-SUPER-SECRET");
    expect(unknown.message).not.toContain("\u001b");
  });

  it("connection failure is handled by its own mapping (never falls into unknown)", () => {
    const transport = new HttpClientError.HttpClientError({
      reason: new HttpClientError.TransportError({
        request: HttpClientRequest.get("https://maruhi.example/chain"),
        cause: new Error("connect ECONNREFUSED 127.0.0.1:9"),
      }),
    });
    const rendered = toCliError(transport);
    expect(rendered.message).toContain("Failed to connect to the server");
    expect(rendered.message).not.toContain("Unexpected error");
    expect(rendered.message).not.toContain("ECONNREFUSED");
  });

  it("a response schema mismatch shows only 'location and expectation' (never values)", async () => {
    const Payload = Schema.Struct({ version: Schema.Number });
    const exit = await Effect.runPromiseExit(
      Schema.decodeUnknownEffect(Payload)({ version: "sk-live-SUPER-SECRET" }),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    if (!Exit.isFailure(exit)) return;
    const rendered = toCliError(Cause.squash(exit.cause));
    expect(rendered.message).toContain("does not match the schema");
    expect(rendered.message).toContain("Expected number");
    expect(rendered.message).toContain('["version"]');
    expect(rendered.message).not.toContain("sk-live-SUPER-SECRET");
    expect(rendered.message).toContain("values you provided");
    expect(rendered.message).not.toContain("\uFFFD");
  });
});
