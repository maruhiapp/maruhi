import { env } from "cloudflare:test";
import { Cause, Effect, Exit, Formatter, Inspectable, Redacted } from "effect";
import { afterEach, describe, expect, it, vi } from "vite-plus/test";

import { readWorkerSecrets, WorkerSecrets } from "../src/worker-env.ts";

const RAW_GITHUB_CLIENT_ID = env.GITHUB_CLIENT_ID;
const RAW_GITHUB_CLIENT_SECRET = env.GITHUB_CLIENT_SECRET;
const RAW_IKM = env.SERVER_ENC_KEY_IKM ?? "";
const RAW_OPS_ALERT_WEBHOOK_URL = env.OPS_ALERT_WEBHOOK_URL ?? "";

function storeOf(value: string): SecretsStoreSecret {
  return { get: () => Promise.resolve(value) };
}

const FAILING_STORE: SecretsStoreSecret = {
  get: () => Promise.reject(new Error("store read failed")),
};

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

  it("wraps each secret in a labeled Redacted that unwraps to the env value", async () => {
    expect(RAW_GITHUB_CLIENT_SECRET).not.toBe("");
    expect(RAW_IKM).not.toBe("");
    expect(RAW_OPS_ALERT_WEBHOOK_URL).not.toBe("");
    const secrets = await Effect.runPromise(readWorkerSecrets(env));
    expect(secrets.githubClientId).toBe(RAW_GITHUB_CLIENT_ID);
    expect(secrets.githubClientSecret?.label).toBe("GITHUB_CLIENT_SECRET");
    expect(secrets.serverEncKeyIkm?.label).toBe("SERVER_ENC_KEY_IKM");
    expect(secrets.opsAlertWebhookUrl?.label).toBe("OPS_ALERT_WEBHOOK_URL");
    expect(secrets.githubClientSecret && Redacted.value(secrets.githubClientSecret)).toBe(
      RAW_GITHUB_CLIENT_SECRET,
    );
    expect(secrets.serverEncKeyIkm && Redacted.value(secrets.serverEncKeyIkm)).toBe(RAW_IKM);
    expect(secrets.opsAlertWebhookUrl && Redacted.value(secrets.opsAlertWebhookUrl)).toBe(
      RAW_OPS_ALERT_WEBHOOK_URL,
    );
  });

  it("never renders a secret value, alone or inside the record", async () => {
    const secrets = await Effect.runPromise(readWorkerSecrets(env));
    const values = [
      secrets,
      secrets.githubClientSecret,
      secrets.serverEncKeyIkm,
      secrets.opsAlertWebhookUrl,
    ];
    for (const rendered of values.flatMap(renderings)) {
      expect(rendered).not.toContain(RAW_GITHUB_CLIENT_SECRET);
      expect(rendered).not.toContain(RAW_IKM);
      expect(rendered).not.toContain(RAW_OPS_ALERT_WEBHOOK_URL);
    }
    expect(String(secrets.githubClientSecret)).toBe("<redacted:GITHUB_CLIENT_SECRET>");
    expect(String(secrets.opsAlertWebhookUrl)).toBe("<redacted:OPS_ALERT_WEBHOOK_URL>");
    expect(JSON.stringify(secrets)).toBe(
      `{"githubClientId":${JSON.stringify(RAW_GITHUB_CLIENT_ID)},"githubClientSecret":"<redacted:GITHUB_CLIENT_SECRET>","serverEncKeyIkm":"<redacted:SERVER_ENC_KEY_IKM>","opsAlertWebhookUrl":"<redacted:OPS_ALERT_WEBHOOK_URL>"}`,
    );
  });

  it("keeps the values out of logs and failures raised through the service", async () => {
    const lines: string[] = [];
    for (const method of ["log", "info", "warn", "error", "debug"] as const) {
      vi.spyOn(console, method).mockImplementation((...args: unknown[]) => {
        lines.push(args.map((arg) => Formatter.format(arg)).join(" "));
      });
    }
    const resolved = await Effect.runPromise(readWorkerSecrets(env));
    const exit = await Effect.runPromiseExit(
      Effect.gen(function* () {
        const secrets = yield* WorkerSecrets;
        yield* Effect.logError("secrets", secrets);
        return yield* Effect.die(secrets);
      }).pipe(Effect.provideService(WorkerSecrets, resolved)),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    if (Exit.isFailure(exit)) {
      lines.push(Cause.pretty(exit.cause));
    }
    expect(lines.join("\n")).toContain("<redacted:GITHUB_CLIENT_SECRET>");
    expect(lines.join("\n")).not.toContain(RAW_GITHUB_CLIENT_SECRET);
    expect(lines.join("\n")).not.toContain(RAW_IKM);
    expect(lines.join("\n")).not.toContain(RAW_OPS_ALERT_WEBHOOK_URL);
  });

  it("maps an unset or empty secret to undefined (the unconfigured state all consumers check)", async () => {
    expect(await Effect.runPromise(readWorkerSecrets({}))).toEqual({
      githubClientId: undefined,
      githubClientSecret: undefined,
      serverEncKeyIkm: undefined,
      opsAlertWebhookUrl: undefined,
    });
    expect(
      await Effect.runPromise(
        readWorkerSecrets({
          GITHUB_CLIENT_ID: "",
          GITHUB_CLIENT_SECRET: "",
          SERVER_ENC_KEY_IKM: "",
          OPS_ALERT_WEBHOOK_URL: "",
        }),
      ),
    ).toEqual({
      githubClientId: undefined,
      githubClientSecret: undefined,
      serverEncKeyIkm: undefined,
      opsAlertWebhookUrl: undefined,
    });
  });

  it("resolves Secrets Store bindings to the same values as the string shape", async () => {
    const secrets = await Effect.runPromise(
      readWorkerSecrets({
        GITHUB_CLIENT_ID: storeOf(RAW_GITHUB_CLIENT_ID),
        GITHUB_CLIENT_SECRET: storeOf(RAW_GITHUB_CLIENT_SECRET),
        SERVER_ENC_KEY_IKM: storeOf(RAW_IKM),
        OPS_ALERT_WEBHOOK_URL: storeOf(RAW_OPS_ALERT_WEBHOOK_URL),
      }),
    );
    expect(secrets.githubClientId).toBe(RAW_GITHUB_CLIENT_ID);
    expect(secrets.githubClientSecret?.label).toBe("GITHUB_CLIENT_SECRET");
    expect(secrets.serverEncKeyIkm?.label).toBe("SERVER_ENC_KEY_IKM");
    expect(secrets.opsAlertWebhookUrl?.label).toBe("OPS_ALERT_WEBHOOK_URL");
    expect(secrets.githubClientSecret && Redacted.value(secrets.githubClientSecret)).toBe(
      RAW_GITHUB_CLIENT_SECRET,
    );
    expect(secrets.serverEncKeyIkm && Redacted.value(secrets.serverEncKeyIkm)).toBe(RAW_IKM);
    expect(secrets.opsAlertWebhookUrl && Redacted.value(secrets.opsAlertWebhookUrl)).toBe(
      RAW_OPS_ALERT_WEBHOOK_URL,
    );
  });

  it("maps a failed store read to undefined, preserving each consumer's absence semantics", async () => {
    expect(
      await Effect.runPromise(
        readWorkerSecrets({
          GITHUB_CLIENT_ID: FAILING_STORE,
          GITHUB_CLIENT_SECRET: FAILING_STORE,
          SERVER_ENC_KEY_IKM: FAILING_STORE,
          OPS_ALERT_WEBHOOK_URL: FAILING_STORE,
        }),
      ),
    ).toEqual({
      githubClientId: undefined,
      githubClientSecret: undefined,
      serverEncKeyIkm: undefined,
      opsAlertWebhookUrl: undefined,
    });
  });

  it("maps a store value of empty string to undefined, like the string shape", async () => {
    const secrets = await Effect.runPromise(
      readWorkerSecrets({
        GITHUB_CLIENT_ID: storeOf(""),
        GITHUB_CLIENT_SECRET: storeOf(""),
        SERVER_ENC_KEY_IKM: storeOf(""),
        OPS_ALERT_WEBHOOK_URL: storeOf(""),
      }),
    );
    expect(secrets).toEqual({
      githubClientId: undefined,
      githubClientSecret: undefined,
      serverEncKeyIkm: undefined,
      opsAlertWebhookUrl: undefined,
    });
  });
});
