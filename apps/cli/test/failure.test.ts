// Unit tests for failure.ts's toCliError: the terminal neutralization of
// server-sourced strings.

import {
  DataLimitExceededError,
  DekWrapNotFoundError,
  ProjectLimitError,
  UnauthorizedError,
} from "@maruhi/api-schema";
import { Cause, Effect, Exit, Schema } from "effect";
import { HttpClientError, HttpClientRequest } from "effect/http";
import { describe, expect, it } from "vitest";

import { toCliError } from "../src/failure.ts";

describe("toCliError (terminal neutralization of server-sourced strings)", () => {
  it("guides a 401 to both possibilities — expired and revoked — and to re-login (AUTH_SPEC §6)", () => {
    // Expiry folds into the same 401 as revocation (the distinction never reaches
    // the wire), so the guidance names both possibilities and the next step (re-login)
    const rendered = toCliError(new UnauthorizedError());
    expect(rendered.message).toContain("expired or revoked");
    expect(rendered.message).toContain("maruhi login");
  });

  it("typed tenant-quota errors do not fall into opaque unknown; they guide the next step (AUTH_SPEC §11-3 / §12-8)", () => {
    // 429 ProjectLimit (org project-count cap — only on new init)
    const projectLimit = toCliError(new ProjectLimitError({ limit: 100 }));
    expect(projectLimit.message).not.toContain("Unexpected error");
    expect(projectLimit.message).toContain("maximum number of projects (100");
    expect(projectLimit.message).toContain("existing projects are unaffected");
    // 422 DataLimitExceeded project-storage-bytes (DO total-storage guard):
    // the guidance says delete / read still work under the refusal (exit path / freeing means)
    const storage = toCliError(
      new DataLimitExceededError({ resource: "project-storage-bytes", limit: 9_000_000_000 }),
    );
    expect(storage.message).toContain("storage guard");
    expect(storage.message).toContain("9000000000 bytes");
    expect(storage.message).toContain("reading values");
    expect(storage.message).toContain("deleting");
    expect(storage.message).toContain("move the values to a new project");
    // 422 DataLimitExceeded environment-ciphertext-bytes (Sc-3): freed within the environment
    const environment = toCliError(
      new DataLimitExceededError({ resource: "environment-ciphertext-bytes", limit: 8_388_608 }),
    );
    expect(environment.message).toContain("per-environment limit (8388608 bytes");
    expect(environment.message).toContain("Delete values this environment no longer needs");
    expect(environment.message).toContain("another environment");
    // Other §12-8 quantity caps keep the conventional general form
    const generic = toCliError(new DataLimitExceededError({ resource: "variables", limit: 1000 }));
    expect(generic.message).toBe("Exceeds a server acceptance limit (variables limit 1000)");
  });

  it("neutralizes the error Schema's free-form string IDs", () => {
    // Schema.String fields unconstrained on the wire (a malicious server could embed ANSI / newlines)
    const notFound = toCliError(
      new DekWrapNotFoundError({ epoch: 3, recipientUserId: "x\u001b[31mred\u001b[0m\nfake" }),
    );
    expect(notFound.message).not.toContain("\u001b");
    expect(notFound.message).not.toContain("\n");
    expect(notFound.message).toContain("x\uFFFD[31mred\uFFFD[0m\uFFFDfake");
  });

  it("an unknown error past all declared cases prints no message — only the type name is attached", () => {
    // All three typed-client failure kinds (declared errors / HttpClientError /
    // SchemaError) are already mapped, so only a true unknown reaches here.
    // message may contain fragments of the response body, so it is **not printed** rather than neutralized
    const unknown = toCliError(new Error("boom sk-live-SUPER-SECRET \u001b]0;pwned\u0007"));
    expect(unknown.message).toBe("Unexpected error (Error)");
    expect(unknown.message).not.toContain("sk-live-SUPER-SECRET");
    expect(unknown.message).not.toContain("\u001b");
  });

  it("connection failure is handled by its own mapping (never falls into unknown)", () => {
    // Why narrowing the unknown fallback does not erase the connection-failure
    // trail: transport-level failures are explained by name in the HttpClientError mapping
    const transport = new HttpClientError.HttpClientError({
      reason: new HttpClientError.TransportError({
        request: HttpClientRequest.get("https://maruhi.example/chain"),
        cause: new Error("connect ECONNREFUSED 127.0.0.1:9"),
      }),
    });
    const rendered = toCliError(transport);
    expect(rendered.message).toContain("Failed to connect to the server");
    expect(rendered.message).not.toContain("Unexpected error");
    // The lower cause's text (host, port, etc.) is not passed through
    expect(rendered.message).not.toContain("ECONNREFUSED");
  });

  it("a response schema mismatch shows only 'location and expectation' (never values)", async () => {
    // Upstream (effect rc.109) formatting shows only the expected type and
    // location. The response body can carry variable names and ciphertext, so **if the formatting ever includes values this test fails**
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
    // Request-encode failures flow through the same channel (the direction is not
    // visible from the type), so the guidance lists both directions. If it regresses to one-sided "server's fault" guidance this fails
    expect(rendered.message).toContain("values you provided");
    // Newlines are folded into one line before neutralizing (so replacement chars do not make it unreadable)
    expect(rendered.message).not.toContain("\uFFFD");
  });
});
