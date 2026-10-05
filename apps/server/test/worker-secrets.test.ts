// The worker's secret configuration values travel as Redacted (worker-env.ts
// readWorkerSecrets): GITHUB_CLIENT_SECRET and SERVER_ENC_KEY_IKM are wrapped
// at the env read, so no rendering a log line, an error message, or a Cause
// can take — String, JSON, Effect's formatter, the Node inspect hook, a
// logged value, Cause.pretty — shows the value. The values read here are the
// dummy bindings from vitest.config.ts.

import { env } from "cloudflare:test";
import { Cause, Effect, Exit, Formatter, Inspectable, Redacted } from "effect";
import { afterEach, describe, expect, it, vi } from "vitest";

import { readWorkerSecrets, WorkerSecrets } from "../src/worker-env.ts";

const RAW_GITHUB_CLIENT_SECRET = env.GITHUB_CLIENT_SECRET;
const RAW_IKM = env.SERVER_ENC_KEY_IKM ?? "";

/** Every rendering of `value` a log line, an error message, or a crash report could take. */
function renderings(value: unknown): readonly string[] {
  const inspectable = value as { readonly [Inspectable.NodeInspectSymbol]?: () => unknown };
  return [
    String(value),
    JSON.stringify(value),
    Formatter.format(value),
    Formatter.format(value, { ignoreToString: true }),
    JSON.stringify(inspectable[Inspectable.NodeInspectSymbol]?.() ?? null),
    Cause.pretty(Cause.fail(value)),
    Cause.pretty(Cause.die(value)),
  ];
}

describe("readWorkerSecrets (the env-reading boundary for secrets)", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("wraps each secret in a labeled Redacted that unwraps to the env value", () => {
    // Guards the test itself: the dummy bindings must be configured
    expect(RAW_GITHUB_CLIENT_SECRET).not.toBe("");
    expect(RAW_IKM).not.toBe("");
    const secrets = readWorkerSecrets(env);
    expect(secrets.githubClientSecret?.label).toBe("GITHUB_CLIENT_SECRET");
    expect(secrets.serverEncKeyIkm?.label).toBe("SERVER_ENC_KEY_IKM");
    expect(secrets.githubClientSecret && Redacted.value(secrets.githubClientSecret)).toBe(
      RAW_GITHUB_CLIENT_SECRET,
    );
    expect(secrets.serverEncKeyIkm && Redacted.value(secrets.serverEncKeyIkm)).toBe(RAW_IKM);
  });

  it("never renders a secret value, alone or inside the record", () => {
    const secrets = readWorkerSecrets(env);
    const values = [secrets, secrets.githubClientSecret, secrets.serverEncKeyIkm];
    for (const rendered of values.flatMap(renderings)) {
      expect(rendered).not.toContain(RAW_GITHUB_CLIENT_SECRET);
      expect(rendered).not.toContain(RAW_IKM);
    }
    expect(String(secrets.githubClientSecret)).toBe("<redacted:GITHUB_CLIENT_SECRET>");
    expect(JSON.stringify(secrets)).toBe(
      '{"githubClientSecret":"<redacted:GITHUB_CLIENT_SECRET>","serverEncKeyIkm":"<redacted:SERVER_ENC_KEY_IKM>"}',
    );
  });

  it("keeps the values out of logs and failures raised through the service", async () => {
    // The worker and the test share one isolate, so a console spy here
    // sees what Effect's logger writes for the worker
    const lines: string[] = [];
    for (const method of ["log", "info", "warn", "error", "debug"] as const) {
      vi.spyOn(console, method).mockImplementation((...args: unknown[]) => {
        lines.push(args.map((arg) => Formatter.format(arg)).join(" "));
      });
    }
    const exit = await Effect.runPromiseExit(
      Effect.gen(function* () {
        const secrets = yield* WorkerSecrets;
        yield* Effect.logError("secrets", secrets);
        return yield* Effect.die(secrets);
      }).pipe(Effect.provideService(WorkerSecrets, readWorkerSecrets(env))),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    if (Exit.isFailure(exit)) {
      lines.push(Cause.pretty(exit.cause));
    }
    expect(lines.join("\n")).toContain("<redacted:GITHUB_CLIENT_SECRET>");
    expect(lines.join("\n")).not.toContain(RAW_GITHUB_CLIENT_SECRET);
    expect(lines.join("\n")).not.toContain(RAW_IKM);
  });

  it("maps an unset or empty secret to undefined (the unconfigured state both consumers check)", () => {
    expect(readWorkerSecrets({})).toEqual({
      githubClientSecret: undefined,
      serverEncKeyIkm: undefined,
    });
    expect(readWorkerSecrets({ GITHUB_CLIENT_SECRET: "", SERVER_ENC_KEY_IKM: "" })).toEqual({
      githubClientSecret: undefined,
      serverEncKeyIkm: undefined,
    });
  });
});
