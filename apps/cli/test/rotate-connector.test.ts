// Tests for the rotation connector frame (rotate-connector.ts — PF6
// rulings R2–R4): each connector creates the new credential the way its
// issuer allows a grace period, finalize invalidates exactly the previous
// one, failures name the connector and the issuer's answer but never a
// credential, and the generated password is alphanumeric.
//
//  - aws-iam-access-key: the IAM Query API is called signed; an inactive
//    second key is reclaimed, two active keys refuse; finalize deactivates
//  - cloudflare-api-token: verify → read → create with the same policies;
//    finalize deletes the previous token (already invalid = "already"); a
//    body that is not the JSON envelope is a connector error
//  - postgres / mysql: the statements run on the admin connection with
//    quoted identifiers; alternation picks the other role; in-place MySQL
//    retains the current password and finalize discards it

import { Effect, Layer } from "effect";
import { FetchHttpClient } from "effect/http";
import { TestClock } from "effect/testing";
import { describe, expect, it } from "vitest";

import type { RotateRule } from "../src/rotate-config.ts";
import {
  ConnectorCrypto,
  ConnectorError,
  type ConnectorServices,
  type CredentialValues,
  describeFinalize,
  describeValueShapes,
  finalizeCredential,
  generatePassword,
  IssuerEndpoints,
  planRotation,
  rotateCredential,
  SqlRunner,
  type SqlRunnerShape,
} from "../src/rotate-connector.ts";
import {
  type CaptureInput,
  type CaptureOutcome,
  ProcessRunner,
  ScriptLeftoverError,
  ScriptStoppedError,
} from "../src/run.ts";
import { signV4 } from "../src/sigv4.ts";
import { testEnvironmentId } from "./support/crypto.ts";

const enc = new TextEncoder();
const dec = new TextDecoder();

interface SeenCall {
  readonly url: string;
  readonly method: string;
  readonly headers: Record<string, string>;
  readonly body: string;
}

/** A fake issuer: records the call and answers as told. */
function fakeIssuer(answer: (call: SeenCall, index: number) => Response) {
  const calls: SeenCall[] = [];
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const headers: Record<string, string> = {};
    for (const [name, value] of Object.entries((init?.headers ?? {}) as Record<string, string>)) {
      headers[name.toLowerCase()] = value;
    }
    const call = {
      url: String(input),
      method: init?.method ?? "GET",
      headers,
      body: typeof init?.body === "string" ? init.body : "",
    };
    calls.push(call);
    return answer(call, calls.length - 1);
  }) as typeof fetch;
  return { calls, fetch: fetchImpl };
}

function recordingSql(
  options: { readonly failProbe?: boolean; readonly failExecute?: string } = {},
) {
  const executed: { url: string; statements: readonly string[] }[] = [];
  const probed: string[] = [];
  const sql: SqlRunnerShape = {
    execute: (url, statements) => {
      if (options.failExecute !== undefined) {
        return Promise.reject(new Error(options.failExecute));
      }
      executed.push({ url, statements });
      return Promise.resolve();
    },
    probe: (url) => {
      probed.push(url);
      return options.failProbe === true
        ? Promise.reject(new Error("connection refused"))
        : Promise.resolve();
    },
  };
  return { executed, probed, sql };
}

const FIXED_NOW = Date.parse("2026-10-02T00:00:00Z");

/**
 * The services a test's connector call sees: the fake issuer's fetch as the
 * `HttpClient`, the recorder's `SqlRunner`, the fake script runner as the
 * `ProcessRunner`'s `captureScript`, deterministic bytes as the
 * `ConnectorCrypto` source, the test issuer origins, and a `TestClock`
 * ({@link run} sets it — the SigV4 signature carries its instant).
 */
function deps(
  input: {
    fetch?: typeof fetch;
    sql?: SqlRunnerShape;
    exec?: (input: CaptureInput) => Promise<CaptureOutcome>;
  } = {},
): Layer.Layer<ConnectorServices> {
  let counter = 0;
  return Layer.mergeAll(
    Layer.provide(
      FetchHttpClient.layer,
      Layer.succeed(
        FetchHttpClient.Fetch,
        input.fetch ??
          ((() => Promise.reject(new Error("no fetch in this test"))) as unknown as typeof fetch),
      ),
    ),
    Layer.succeed(SqlRunner, input.sql ?? recordingSql().sql),
    Layer.succeed(ProcessRunner, {
      run: () => Effect.succeed(0),
      exec: () => Effect.succeed({ exitCode: 0, output: "" }),
      captureScript:
        input.exec ?? (() => Promise.reject(new Error("no script runner in this test"))),
      runSession: () => Effect.succeed(0),
    }),
    // Deterministic bytes: every password is "AAAA…" shifted by a counter
    Layer.succeed(ConnectorCrypto, {
      nextBytes: (length) => new Uint8Array(length).fill(((counter += 1) % 26) as number),
    }),
    Layer.succeed(IssuerEndpoints, {
      awsIamBase: "https://iam.test",
      awsStsBase: "https://sts.test",
      cloudflareBase: "https://cf.test",
    }),
    TestClock.layer(),
  );
}

/** Runs a connector program under the test layer at a fixed instant. */
function run<A>(
  depsLayer: Layer.Layer<ConnectorServices>,
  effect: Effect.Effect<A, ConnectorError, ConnectorServices>,
): Promise<A> {
  return Effect.runPromise(
    Effect.gen(function* () {
      yield* TestClock.setTime(FIXED_NOW);
      return yield* effect;
    }).pipe(Effect.provide(depsLayer)),
  );
}

function credential(primary: string, companions: Record<string, string> = {}): CredentialValues {
  return {
    primary: enc.encode(primary),
    companions: Object.fromEntries(Object.entries(companions).map(([k, v]) => [k, enc.encode(v)])),
  };
}

function xml(body: string): Response {
  return new Response(body, { status: 200, headers: { "content-type": "text/xml" } });
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("generatePassword", () => {
  it("is 32 alphanumerics drawn from the random bytes", () => {
    const password = generatePassword((length) => crypto.getRandomValues(new Uint8Array(length)));
    expect(password).toMatch(/^[A-Za-z0-9]{32}$/);
    // Bytes at or above the rejection limit (248+) are skipped, never biased in
    let calls = 0;
    const skipping = generatePassword((length) => {
      calls += 1;
      return new Uint8Array(length).fill(calls === 1 ? 255 : 0);
    });
    expect(skipping).toBe("A".repeat(32));
    expect(calls).toBe(2);
  });
});

describe("postgres connector", () => {
  const alternate: RotateRule = {
    connector: "postgres",
    roles: ["app_a", "app_b"],
    inputs: { adminUrl: { environment: null, name: "ADMIN_URL" } },
  };
  const inPlace: RotateRule = { connector: "postgres", roles: null, inputs: {} };
  const current = credential("postgres://app_a:old@db.example:5432/shop?sslmode=require");

  it("alternates to the other role on the admin connection and tests the new URL", async () => {
    const sql = recordingSql();
    const outcome = await run(
      deps({ sql: sql.sql }),
      rotateCredential(alternate, current, {
        adminUrl: enc.encode("postgres://admin:secret@db.example:5432/shop"),
      }),
    );
    expect(sql.executed).toHaveLength(1);
    expect(sql.executed[0]?.url).toBe("postgres://admin:secret@db.example:5432/shop");
    expect(sql.executed[0]?.statements[0]).toMatch(
      /^ALTER ROLE "app_b" WITH PASSWORD '[A-Za-z0-9]{32}'$/,
    );
    const value = dec.decode(outcome.values.primary);
    const url = new URL(value);
    expect(url.username).toBe("app_b");
    expect(url.password).toMatch(/^[A-Za-z0-9]{32}$/);
    expect(url.host).toBe("db.example:5432");
    expect(url.search).toBe("?sslmode=require");
    expect(sql.probed).toEqual([value]);
    expect((await Effect.runPromise(planRotation(alternate, current))).immediate).toBe(false);
    expect(outcome.previous).toContain("role app_a keeps its previous password");
    expect(outcome.warnings).toEqual([]);
  });

  it("in place: no grace, the plan says so, the URL's role rotates itself, and a failed probe is a warning", async () => {
    const sql = recordingSql({ failProbe: true });
    expect((await Effect.runPromise(planRotation(inPlace, current))).immediate).toBe(true);
    const outcome = await run(deps({ sql: sql.sql }), rotateCredential(inPlace, current, {}));
    expect(sql.executed[0]?.url).toBe("postgres://app_a:old@db.example:5432/shop?sslmode=require");
    expect(sql.executed[0]?.statements[0]).toMatch(/^ALTER ROLE "app_a" WITH PASSWORD '/);
    expect(outcome.warnings[0]).toContain("connection test with it failed");
    expect(outcome.warnings[0]).not.toContain("old");
    expect(outcome.previous).toContain("nothing to finalize");
  });

  it("refuses a URL whose role is neither alternated role, and a non-URL value", async () => {
    await expect(
      run(deps(), rotateCredential(alternate, credential("postgres://other:x@db/shop"), {})),
    ).rejects.toThrow("neither of the alternated roles");
    await expect(
      run(deps(), rotateCredential(alternate, credential("not a url"), {})),
    ).rejects.toThrow("expects the variable to hold a connection URL");
    await expect(
      run(deps(), rotateCredential(alternate, credential("mysql://app_a:x@db/shop"), {})),
    ).rejects.toThrow("expects a postgres / postgresql URL");
  });

  it("finalize scrambles the previous role; in place there is nothing to do", async () => {
    const sql = recordingSql();
    const previous = credential("postgres://app_a:old@db.example:5432/shop");
    const now = credential("postgres://app_b:new@db.example:5432/shop");
    const outcome = await run(
      deps({ sql: sql.sql }),
      finalizeCredential(alternate, previous, now, {}),
    );
    expect(outcome.kind).toBe("finalized");
    expect(sql.executed[0]?.statements[0]).toMatch(
      /^ALTER ROLE "app_a" WITH PASSWORD '[A-Za-z0-9]{32}'$/,
    );
    // The self-rotation admin connection is the current credential
    expect(sql.executed[0]?.url).toBe("postgres://app_b:new@db.example:5432/shop");
    expect(
      (await run(deps({ sql: sql.sql }), finalizeCredential(inPlace, previous, now, {}))).kind,
    ).toBe("nothing");
    expect(
      (await run(deps({ sql: sql.sql }), finalizeCredential(alternate, now, now, {}))).kind,
    ).toBe("nothing");
  });

  it("a failed statement names the stage and never the URL", async () => {
    const sql = recordingSql({
      failExecute: "permission denied for postgres://admin:secret@db/shop",
    });
    const error = await run(deps({ sql: sql.sql }), rotateCredential(alternate, current, {})).catch(
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(ConnectorError);
    expect((error as Error).message).toContain(
      "setting the password of role app_b failed: permission denied for <url>",
    );
    expect((error as Error).message).not.toContain("secret");
  });
});

describe("mysql connector", () => {
  const inPlace: RotateRule = { connector: "mysql", roles: null, host: "%", inputs: {} };
  const current = credential("mysql://app:old@db.example:3306/shop");

  it("sets the new password retaining the current one, and finalize discards the old password", async () => {
    const sql = recordingSql();
    const outcome = await run(deps({ sql: sql.sql }), rotateCredential(inPlace, current, {}));
    expect(sql.executed[0]?.statements[0]).toMatch(
      /^ALTER USER 'app'@'%' IDENTIFIED BY '[A-Za-z0-9]{32}' RETAIN CURRENT PASSWORD$/,
    );
    expect((await Effect.runPromise(planRotation(inPlace, current))).immediate).toBe(false);
    expect(new URL(dec.decode(outcome.values.primary)).username).toBe("app");
    const finalized = await run(
      deps({ sql: sql.sql }),
      finalizeCredential(inPlace, current, outcome.values, {}),
    );
    expect(finalized.kind).toBe("finalized");
    expect(sql.executed[1]?.statements[0]).toBe("ALTER USER 'app'@'%' DISCARD OLD PASSWORD");
    // The current (new) credential authenticates the finalize when no admin is named
    expect(sql.executed[1]?.url).toBe(dec.decode(outcome.values.primary));
  });

  it("alternates roles without retaining, under the configured host", async () => {
    const sql = recordingSql();
    const rule: RotateRule = {
      connector: "mysql",
      roles: ["app_a", "app_b"],
      host: "10.0.0.%",
      inputs: {},
    };
    await run(
      deps({ sql: sql.sql }),
      rotateCredential(rule, credential("mysql://app_b:x@db/shop"), {}),
    );
    expect(sql.executed[0]?.statements[0]).toMatch(
      /^ALTER USER 'app_a'@'10\.0\.0\.%' IDENTIFIED BY '[A-Za-z0-9]{32}'$/,
    );
  });
});

describe("aws-iam-access-key connector", () => {
  const rule: RotateRule = {
    connector: "aws-iam-access-key",
    accessKeyIdVariable: "AWS_ACCESS_KEY_ID",
    user: null,
    inputs: {},
  };
  const current = credential("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", {
    accessKeyId: "AKIAOLD0000000000001",
  });

  function keysXml(keys: readonly { id: string; status: string }[]): string {
    return `<ListAccessKeysResponse><ListAccessKeysResult><AccessKeyMetadata>${keys
      .map(
        (key) =>
          `<member><UserName>app</UserName><AccessKeyId>${key.id}</AccessKeyId><Status>${key.status}</Status><CreateDate>2026-01-01T00:00:00Z</CreateDate></member>`,
      )
      .join(
        "",
      )}</AccessKeyMetadata><IsTruncated>false</IsTruncated></ListAccessKeysResult></ListAccessKeysResponse>`;
  }

  function actionOf(call: SeenCall): string {
    return new URLSearchParams(call.body).get("Action") ?? "";
  }

  it("creates a second key signed with the current key, deriving the user from it", async () => {
    const issuer = fakeIssuer((call) => {
      switch (actionOf(call)) {
        case "GetAccessKeyLastUsed":
          return xml(
            "<GetAccessKeyLastUsedResponse><GetAccessKeyLastUsedResult><UserName>app</UserName></GetAccessKeyLastUsedResult></GetAccessKeyLastUsedResponse>",
          );
        case "ListAccessKeys":
          return xml(keysXml([{ id: "AKIAOLD0000000000001", status: "Active" }]));
        case "CreateAccessKey":
          return xml(
            "<CreateAccessKeyResponse><CreateAccessKeyResult><AccessKey><UserName>app</UserName><AccessKeyId>AKIANEW0000000000002</AccessKeyId><Status>Active</Status><SecretAccessKey>new/secret+value</SecretAccessKey></AccessKey></CreateAccessKeyResult></CreateAccessKeyResponse>",
          );
        default:
          return new Response("", { status: 500 });
      }
    });
    const outcome = await run(deps({ fetch: issuer.fetch }), rotateCredential(rule, current, {}));
    expect(issuer.calls.map(actionOf)).toEqual([
      "GetAccessKeyLastUsed",
      "ListAccessKeys",
      "CreateAccessKey",
    ]);
    const create = issuer.calls[2];
    expect(create?.url).toBe("https://iam.test/");
    expect(create?.method).toBe("POST");
    expect(create?.headers["authorization"]).toMatch(
      /^AWS4-HMAC-SHA256 Credential=AKIAOLD0000000000001\/20261002\/us-east-1\/iam\/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=[0-9a-f]{64}$/,
    );
    expect(create?.headers["host"]).toBe("iam.test");
    expect(new URLSearchParams(create?.body).get("UserName")).toBe("app");
    expect(dec.decode(outcome.values.primary)).toBe("new/secret+value");
    expect(dec.decode(outcome.values.companions["accessKeyId"] ?? new Uint8Array())).toBe(
      "AKIANEW0000000000002",
    );
    expect(outcome.facts.join(" ")).toContain("new access key AKIANEW0000000000002 created");
    expect(outcome.previous).toContain("AKIAOLD0000000000001 stays active");
  });

  it("every header SignedHeaders names reaches the wire with the value that was signed", async () => {
    // IAM recomputes the signature from the headers it receives: one signed
    // header missing or changed on the wire (a content-type dropped when the
    // body is set) is SignatureDoesNotMatch. Re-signing what arrived must
    // reproduce the Authorization header that was sent
    const issuer = fakeIssuer((call) => {
      switch (actionOf(call)) {
        case "GetAccessKeyLastUsed":
          return xml(
            "<GetAccessKeyLastUsedResponse><GetAccessKeyLastUsedResult><UserName>app</UserName></GetAccessKeyLastUsedResult></GetAccessKeyLastUsedResponse>",
          );
        case "ListAccessKeys":
          return xml(keysXml([{ id: "AKIAOLD0000000000001", status: "Active" }]));
        case "CreateAccessKey":
          return xml(
            "<CreateAccessKeyResponse><CreateAccessKeyResult><AccessKey><AccessKeyId>AKIANEW0000000000002</AccessKeyId><SecretAccessKey>s</SecretAccessKey></AccessKey></CreateAccessKeyResult></CreateAccessKeyResponse>",
          );
        default:
          return new Response("", { status: 500 });
      }
    });
    await run(deps({ fetch: issuer.fetch }), rotateCredential(rule, current, {}));
    expect(issuer.calls).toHaveLength(3);
    for (const call of issuer.calls) {
      const authorization = call.headers["authorization"] ?? "";
      const signedNames = /SignedHeaders=([^,]+),/.exec(authorization)?.[1]?.split(";") ?? [];
      expect(signedNames).toEqual(["content-type", "host", "x-amz-date"]);
      const signedOnWire: Record<string, string> = {};
      for (const name of signedNames) {
        expect(call.headers[name], `${actionOf(call)}: signed header ${name}`).toBeDefined();
        signedOnWire[name] = call.headers[name] ?? "";
      }
      const resigned = await signV4({
        method: "POST",
        url: call.url,
        region: "us-east-1",
        service: "iam",
        headers: signedOnWire,
        body: call.body,
        credentials: {
          accessKeyId: "AKIAOLD0000000000001",
          secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        },
        nowMs: FIXED_NOW,
      });
      expect(resigned.headers["authorization"]).toBe(authorization);
      for (const name of signedNames) {
        expect(resigned.headers[name]).toBe(signedOnWire[name]);
      }
    }
  });

  it("reclaims an inactive second key, refuses two active ones, and signs with the admin pair when named", async () => {
    const admin = {
      accessKeyId: enc.encode("AKIAADMIN00000000003"),
      secretAccessKey: enc.encode("admin-secret"),
    };
    const withUser: RotateRule = { ...rule, user: "app" };
    const issuer = fakeIssuer((call) => {
      switch (actionOf(call)) {
        case "ListAccessKeys":
          return xml(
            keysXml([
              { id: "AKIAOLD0000000000001", status: "Active" },
              { id: "AKIASTALE00000000009", status: "Inactive" },
            ]),
          );
        case "DeleteAccessKey":
          return xml("<DeleteAccessKeyResponse/>");
        case "CreateAccessKey":
          return xml(
            "<CreateAccessKeyResponse><CreateAccessKeyResult><AccessKey><AccessKeyId>AKIANEW0000000000002</AccessKeyId><SecretAccessKey>s</SecretAccessKey></AccessKey></CreateAccessKeyResult></CreateAccessKeyResponse>",
          );
        default:
          return new Response("", { status: 500 });
      }
    });
    const outcome = await run(
      deps({ fetch: issuer.fetch }),
      rotateCredential(withUser, current, admin),
    );
    expect(issuer.calls.map(actionOf)).toEqual([
      "ListAccessKeys",
      "DeleteAccessKey",
      "CreateAccessKey",
    ]);
    expect(new URLSearchParams(issuer.calls[1]?.body).get("AccessKeyId")).toBe(
      "AKIASTALE00000000009",
    );
    expect(issuer.calls[0]?.headers["authorization"]).toContain("Credential=AKIAADMIN00000000003/");
    expect(outcome.facts[0]).toContain("deleted the inactive access key AKIASTALE00000000009");

    const full = fakeIssuer(() =>
      xml(
        keysXml([
          { id: "AKIAOLD0000000000001", status: "Active" },
          { id: "AKIAOTHER00000000008", status: "Active" },
        ]),
      ),
    );
    await expect(
      run(deps({ fetch: full.fetch }), rotateCredential(withUser, current, admin)),
    ).rejects.toThrow("already has two active access keys");
    expect(full.calls).toHaveLength(1);
  });

  it("reports IAM's error code and message, never the secret", async () => {
    const issuer = fakeIssuer(
      () =>
        new Response(
          "<ErrorResponse><Error><Code>AccessDenied</Code><Message>User is not authorized</Message></Error></ErrorResponse>",
          { status: 403 },
        ),
    );
    const withUser: RotateRule = { ...rule, user: "app" };
    const error = await run(
      deps({ fetch: issuer.fetch }),
      rotateCredential(withUser, current, {}),
    ).catch((e: unknown) => e);
    expect((error as Error).message).toBe(
      "aws-iam-access-key: IAM answered 403 to ListAccessKeys (AccessDenied: User is not authorized)",
    );
  });

  const identityXml =
    "<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/app</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>";
  const authFailureXml =
    "<ErrorResponse><Error><Code>InvalidClientTokenId</Code><Message>The security token included in the request is invalid.</Message></Error></ErrorResponse>";

  it("finalize deactivates the other key only when an earlier version held its id and it authenticates with the previous secret; idempotent", async () => {
    const withUser: RotateRule = { ...rule, user: "app" };
    const previous = current;
    const now = credential("new", { accessKeyId: "AKIANEW0000000000002" });
    const ancestors = { accessKeyId: [enc.encode("AKIAOLD0000000000001")] };
    let status = "Active";
    const issuer = fakeIssuer((call) => {
      switch (actionOf(call)) {
        case "ListAccessKeys":
          return xml(
            keysXml([
              { id: "AKIAOLD0000000000001", status },
              { id: "AKIANEW0000000000002", status: "Active" },
            ]),
          );
        case "GetCallerIdentity":
          // The probe is signed by the candidate pair (the old key id + the previous secret)
          return call.headers["authorization"]?.includes("Credential=AKIAOLD0000000000001/") ===
            true
            ? xml(identityXml)
            : new Response(authFailureXml, { status: 403 });
        case "UpdateAccessKey":
          status = "Inactive";
          return xml("<UpdateAccessKeyResponse/>");
        default:
          return new Response("", { status: 500 });
      }
    });
    const first = await run(
      deps({ fetch: issuer.fetch }),
      finalizeCredential(withUser, previous, now, {}, ancestors),
    );
    expect(first.kind).toBe("finalized");
    const probe = issuer.calls.find((call) => actionOf(call) === "GetCallerIdentity");
    expect(probe?.url).toBe("https://sts.test/");
    const update = issuer.calls.find((call) => actionOf(call) === "UpdateAccessKey");
    expect(new URLSearchParams(update?.body).get("AccessKeyId")).toBe("AKIAOLD0000000000001");
    expect(new URLSearchParams(update?.body).get("Status")).toBe("Inactive");
    // The finalize is signed by the current credential (the new key)
    expect(update?.headers["authorization"]).toContain("Credential=AKIANEW0000000000002/");
    const second = await run(
      deps({ fetch: issuer.fetch }),
      finalizeCredential(withUser, previous, now, {}, ancestors),
    );
    expect(second.kind).toBe("already");
  });

  it("finalize never touches a key no version held, nor one that does not authenticate with the previous secret", async () => {
    const withUser: RotateRule = { ...rule, user: "app" };
    const now = credential("new", { accessKeyId: "AKIANEW0000000000002" });
    const calls: string[] = [];
    const issuer = fakeIssuer((call) => {
      calls.push(actionOf(call));
      switch (actionOf(call)) {
        case "ListAccessKeys":
          return xml(
            keysXml([
              { id: "AKIAHAND000000000003", status: "Active" },
              { id: "AKIANEW0000000000002", status: "Active" },
            ]),
          );
        case "GetCallerIdentity":
          return new Response(authFailureXml, { status: 403 });
        default:
          return new Response("", { status: 500 });
      }
    });
    // A key created by hand (no version of the key id variable held it): untouched, no probe
    const stranger = await run(
      deps({ fetch: issuer.fetch }),
      finalizeCredential(
        withUser,
        current,
        now,
        {},
        {
          accessKeyId: [enc.encode("AKIAOLD0000000000001")],
        },
      ),
    );
    expect(stranger.kind).toBe("nothing");
    expect(stranger.facts[0]).toContain(
      "access key AKIAHAND000000000003 of user app was never a version of AWS_ACCESS_KEY_ID (not created through maruhi) — left untouched",
    );
    expect(calls).toEqual(["ListAccessKeys"]);
    // A stored key id that does not pair with the previous secret (someone pushed by hand): untouched
    calls.length = 0;
    const mismatch = await run(
      deps({ fetch: issuer.fetch }),
      finalizeCredential(
        withUser,
        current,
        now,
        {},
        {
          accessKeyId: [enc.encode("AKIAHAND000000000003")],
        },
      ),
    );
    expect(mismatch.kind).toBe("nothing");
    expect(mismatch.facts[0]).toContain(
      "access key AKIAHAND000000000003 is active but does not authenticate with the previous version's secret (not that version's key) — left untouched",
    );
    expect(calls).toEqual(["ListAccessKeys", "GetCallerIdentity"]);
    // Only the current key exists: nothing to deactivate (no probe)
    calls.length = 0;
    const alone = await run(
      deps({
        fetch: fakeIssuer(() => xml(keysXml([{ id: "AKIANEW0000000000002", status: "Active" }])))
          .fetch,
      }),
      finalizeCredential(withUser, now, now, {}),
    );
    expect(alone.kind).toBe("nothing");
    expect(alone.facts[0]).toBe(
      "access key AKIANEW0000000000002 is the only key of user app (nothing to deactivate)",
    );
  });
});

describe("cloudflare-api-token connector", () => {
  const rule: RotateRule = { connector: "cloudflare-api-token", accountId: null, inputs: {} };
  const current = credential("cf-old-token-value");
  const policies = [
    {
      effect: "allow",
      resources: { "com.cloudflare.api.account.x": "*" },
      permission_groups: [{ id: "p1" }],
    },
  ];

  it("verifies the current token, copies its definition into a new token, and keeps the old one", async () => {
    const issuer = fakeIssuer((call) => {
      if (call.url.endsWith("/user/tokens/verify")) {
        return json(200, { success: true, result: { id: "tok-old", status: "active" } });
      }
      if (call.method === "GET" && call.url.endsWith("/user/tokens/tok-old")) {
        return json(200, {
          success: true,
          result: {
            id: "tok-old",
            name: "deploy",
            policies,
            condition: { request_ip: { in: ["203.0.113.0/24"] } },
            status: "active",
          },
        });
      }
      if (call.method === "POST" && call.url.endsWith("/user/tokens")) {
        return json(200, { success: true, result: { id: "tok-new", value: "cf-new-token-value" } });
      }
      return json(500, { success: false, errors: [{ code: 1, message: "unexpected" }] });
    });
    const outcome = await run(deps({ fetch: issuer.fetch }), rotateCredential(rule, current, {}));
    expect(issuer.calls.map((call) => `${call.method} ${new URL(call.url).pathname}`)).toEqual([
      "GET /client/v4/user/tokens/verify",
      "GET /client/v4/user/tokens/tok-old",
      "POST /client/v4/user/tokens",
    ]);
    expect(issuer.calls[0]?.headers["authorization"]).toBe("Bearer cf-old-token-value");
    expect(JSON.parse(issuer.calls[2]?.body ?? "{}")).toEqual({
      name: "deploy",
      policies,
      condition: { request_ip: { in: ["203.0.113.0/24"] } },
    });
    expect(dec.decode(outcome.values.primary)).toBe("cf-new-token-value");
    expect(outcome.facts[0]).toBe(
      "token deploy: replacement tok-new created with the same policies",
    );
    expect(outcome.previous).toBe("token tok-old stays valid until you finalize");
  });

  it("uses the account-owned token paths and the admin token when named", async () => {
    const accountRule: RotateRule = {
      connector: "cloudflare-api-token",
      accountId: "0".repeat(32),
      inputs: { token: { environment: null, name: "CF_ADMIN" } },
    };
    const issuer = fakeIssuer((call) => {
      if (call.url.includes("/verify")) {
        return json(200, { success: true, result: { id: "tok-old" } });
      }
      if (call.method === "GET") {
        return json(200, { success: true, result: { name: "n", policies } });
      }
      return json(200, { success: true, result: { id: "tok-new", value: "v" } });
    });
    await run(
      deps({ fetch: issuer.fetch }),
      rotateCredential(accountRule, current, { token: enc.encode("admin-token") }),
    );
    expect(new URL(issuer.calls[0]?.url ?? "").pathname).toBe(
      `/client/v4/accounts/${"0".repeat(32)}/tokens/verify`,
    );
    expect(issuer.calls[1]?.headers["authorization"]).toBe("Bearer admin-token");
    expect(issuer.calls[2]?.headers["authorization"]).toBe("Bearer admin-token");
  });

  it("an invalid current token stops before anything is created; API errors carry the code and message", async () => {
    const invalid = fakeIssuer(() =>
      json(401, { success: false, errors: [{ code: 1000, message: "Invalid API Token" }] }),
    );
    await expect(
      run(deps({ fetch: invalid.fetch }), rotateCredential(rule, current, {})),
    ).rejects.toThrow("the current value is not a valid token");
    expect(invalid.calls).toHaveLength(1);
    const denied = fakeIssuer((call) =>
      call.url.endsWith("/verify")
        ? json(200, { success: true, result: { id: "tok-old" } })
        : json(403, {
            success: false,
            errors: [{ code: 9109, message: "Unauthorized to access requested resource" }],
          }),
    );
    await expect(
      run(deps({ fetch: denied.fetch }), rotateCredential(rule, current, {})),
    ).rejects.toThrow(
      "Cloudflare answered 403 to reading token tok-old (9109: Unauthorized to access requested resource)",
    );
  });

  it("a body that is not the JSON envelope is a connector error, not an empty answer", async () => {
    const issuer = fakeIssuer(() => new Response("<html>not json</html>", { status: 200 }));
    const error = await run(
      deps({ fetch: issuer.fetch }),
      rotateCredential(rule, current, {}),
    ).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ConnectorError);
    expect((error as Error).message).toBe(
      "cloudflare-api-token: GET /client/v4/user/tokens/verify — Cloudflare's answer was not the JSON envelope it returns",
    );
  });

  it("a null or misshapen result is the step's connector error, never a crash", async () => {
    // verify answering `result: null` reads as a token Cloudflare did not verify
    const unverified = fakeIssuer(() => json(200, { success: true, result: null }));
    const notVerified = await run(
      deps({ fetch: unverified.fetch }),
      rotateCredential(rule, current, {}),
    ).catch((e: unknown) => e);
    expect(notVerified).toBeInstanceOf(ConnectorError);
    expect((notVerified as Error).message).toBe(
      "cloudflare-api-token: the current value is not a valid token (Cloudflare refused to verify it), so its policies cannot be copied. Create the replacement at the issuer and push it",
    );
    // the definition answering `result: null`
    const noDefinition = fakeIssuer((call) =>
      call.url.endsWith("/verify")
        ? json(200, { success: true, result: { id: "tok-old" } })
        : json(200, { success: true, result: null }),
    );
    const definitionError = await run(
      deps({ fetch: noDefinition.fetch }),
      rotateCredential(rule, current, {}),
    ).catch((e: unknown) => e);
    expect(definitionError).toBeInstanceOf(ConnectorError);
    expect((definitionError as Error).message).toBe(
      "cloudflare-api-token: token tok-old came back without a name and policies",
    );
    expect(noDefinition.calls).toHaveLength(2);
    // the creation answering `result: null`, then a value of another type
    for (const created of [null, { id: "tok-new", value: 42 }]) {
      const noValue = fakeIssuer((call) => {
        if (call.url.endsWith("/verify")) {
          return json(200, { success: true, result: { id: "tok-old" } });
        }
        if (call.method === "GET") {
          return json(200, { success: true, result: { name: "deploy", policies } });
        }
        return json(200, { success: true, result: created });
      });
      const creationError = await run(
        deps({ fetch: noValue.fetch }),
        rotateCredential(rule, current, {}),
      ).catch((e: unknown) => e);
      expect(creationError).toBeInstanceOf(ConnectorError);
      expect((creationError as Error).message).toBe(
        "cloudflare-api-token: Cloudflare did not return the new token's value",
      );
    }
    // finalize: a previous token whose verify carries `result: null` is already done
    const previousGone = fakeIssuer(() => json(200, { success: true, result: null }));
    expect(
      (
        await run(
          deps({ fetch: previousGone.fetch }),
          finalizeCredential(rule, current, credential("cf-new-token-value"), {}),
        )
      ).kind,
    ).toBe("already");
    expect(previousGone.calls).toHaveLength(1);
  });

  it("an error status without the envelope still names the status, and a refused connection names its reason", async () => {
    const edge = fakeIssuer(() => new Response("<html>bad gateway</html>", { status: 502 }));
    await expect(
      run(deps({ fetch: edge.fetch }), rotateCredential(rule, current, {})),
    ).rejects.toThrow("Cloudflare answered 502 to the token verification");
    const refused = (() => Promise.reject(new Error("ECONNREFUSED"))) as unknown as typeof fetch;
    await expect(
      run(deps({ fetch: refused }), rotateCredential(rule, current, {})),
    ).rejects.toThrow(
      "cloudflare-api-token: GET /client/v4/user/tokens/verify could not reach Cloudflare (ECONNREFUSED)",
    );
  });

  it("finalize deletes the previous token with the current one, and an invalid previous token is already done", async () => {
    const previous = current;
    const now = credential("cf-new-token-value");
    const issuer = fakeIssuer((call) => {
      if (call.url.endsWith("/verify")) {
        return call.headers["authorization"] === "Bearer cf-old-token-value"
          ? json(200, { success: true, result: { id: "tok-old" } })
          : json(200, { success: true, result: { id: "tok-new" } });
      }
      if (call.method === "DELETE") {
        return json(200, { success: true, result: { id: "tok-old" } });
      }
      return json(500, {});
    });
    const outcome = await run(
      deps({ fetch: issuer.fetch }),
      finalizeCredential(rule, previous, now, {}),
    );
    expect(outcome.kind).toBe("finalized");
    const deletion = issuer.calls.find((call) => call.method === "DELETE");
    expect(new URL(deletion?.url ?? "").pathname).toBe("/client/v4/user/tokens/tok-old");
    expect(deletion?.headers["authorization"]).toBe("Bearer cf-new-token-value");
    const gone = fakeIssuer((call) =>
      call.headers["authorization"] === "Bearer cf-old-token-value"
        ? json(401, { success: false, errors: [{ code: 1000, message: "Invalid API Token" }] })
        : json(200, { success: true, result: { id: "tok-new" } }),
    );
    expect(
      (await run(deps({ fetch: gone.fetch }), finalizeCredential(rule, previous, now, {}))).kind,
    ).toBe("already");
  });
});

describe("exec connector (a script of the repository — PF8)", () => {
  const SITE = { variable: "STRIPE_SECRET_KEY", environmentId: testEnvironmentId("prod") };
  const withFinalize: RotateRule = {
    connector: "exec",
    rotate: ["./rotate.sh", "--live"],
    finalize: ["./finalize.sh"],
    cwd: "/repo/ops",
    output: "value",
    companions: {},
    inputs: {
      STRIPE_ADMIN_KEY: { environment: testEnvironmentId("ops"), name: "STRIPE_ADMIN_KEY" },
    },
  };
  const noFinalize: RotateRule = { ...withFinalize, finalize: null, inputs: {} };
  const jsonRule: RotateRule = {
    ...withFinalize,
    output: "json",
    companions: { STRIPE_KEY_ID: "STRIPE_KEY_ID" },
  };
  const current = credential("sk_live_old");

  /** A fake script runner: records what the child would have seen and answers as told. */
  function fakeScript(answer: (call: CaptureInput, index: number) => CaptureOutcome) {
    const calls: CaptureInput[] = [];
    const exec = (call: CaptureInput) => {
      calls.push(call);
      return Promise.resolve(answer(call, calls.length - 1));
    };
    return { calls, exec };
  }

  const ok = (stdout: string, stderr = ""): CaptureOutcome => ({
    exitCode: 0,
    stdout: enc.encode(stdout),
    stderr,
  });

  it("runs the rotate script with the credential, the inputs, and the control variables in its environment, and reads the new value from stdout", async () => {
    const script = fakeScript(() => ok("sk_live_new\n", "creating key at stripe\n"));
    const outcome = await run(
      deps({ exec: script.exec }),
      rotateCredential(withFinalize, current, { STRIPE_ADMIN_KEY: enc.encode("rk_admin") }, SITE),
    );
    expect(script.calls).toHaveLength(1);
    expect(script.calls[0]?.command).toEqual(["./rotate.sh", "--live"]);
    expect(script.calls[0]?.cwd).toBe("/repo/ops");
    expect(script.calls[0]?.extraEnv).toEqual({
      MH_ROTATE_VARIABLE: "STRIPE_SECRET_KEY",
      MH_ROTATE_ENVIRONMENT: "prod",
      MH_ROTATE_PHASE: "rotate",
      MH_ROTATE_CURRENT: "sk_live_old",
      STRIPE_SECRET_KEY: "sk_live_old",
      STRIPE_ADMIN_KEY: "rk_admin",
    });
    // One trailing newline is dropped, nothing else is touched
    expect(dec.decode(outcome.values.primary)).toBe("sk_live_new");
    expect(outcome.values.companions).toEqual({});
    expect(outcome.facts).toEqual(["./rotate.sh: new credential produced"]);
    // The value's shape is for the local report and the acceptance (D-8 —
    // a script that printed chatter instead of a value is seen before the
    // value is pushed), never a fact the server stores
    expect(describeValueShapes(outcome)).toBe("11 bytes, 1 line");
    // … beside the current value's, for the report's line-count comparison
    // (D-16), carried as numbers (D-19)
    expect(outcome.shape).toEqual({ bytes: 11, lines: 1 });
    expect(outcome.currentShape).toEqual({ bytes: 11, lines: 1 });
    expect(outcome.previous).toContain(
      "stays valid until you finalize (./finalize.sh runs with it)",
    );
    expect((await Effect.runPromise(planRotation(withFinalize, current))).immediate).toBe(false);
    expect((await Effect.runPromise(planRotation(withFinalize, current))).description).toContain(
      "run ./rotate.sh to create the new credential",
    );
  });

  it("without a finalize script the rotation is immediate (no grace) and finalize has nothing to do", async () => {
    const script = fakeScript(() => ok("sk_live_new"));
    expect((await Effect.runPromise(planRotation(noFinalize, current))).immediate).toBe(true);
    expect((await Effect.runPromise(planRotation(noFinalize, current))).description).toContain(
      "no finalize script",
    );
    const outcome = await run(
      deps({ exec: script.exec }),
      rotateCredential(noFinalize, current, {}, SITE),
    );
    expect(outcome.previous).toContain("nothing to finalize");
    expect(describeFinalize(noFinalize)).toContain("nothing to invalidate");
    const finalized = await run(
      deps(),
      finalizeCredential(noFinalize, current, outcome.values, {}, {}, SITE),
    );
    expect(finalized.kind).toBe("nothing");
  });

  it("finalize runs the finalize script with the previous credential as MH_ROTATE_PREVIOUS and the current one under the variable's name", async () => {
    const script = fakeScript(() => ok("deleted key sk_live_old at stripe\n"));
    const previous = credential("sk_live_old");
    const now = credential("sk_live_new");
    const outcome = await run(
      deps({ exec: script.exec }),
      finalizeCredential(
        withFinalize,
        previous,
        now,
        { STRIPE_ADMIN_KEY: enc.encode("rk_admin") },
        {},
        SITE,
      ),
    );
    expect(outcome.kind).toBe("finalized");
    expect(script.calls[0]?.command).toEqual(["./finalize.sh"]);
    expect(script.calls[0]?.extraEnv).toEqual({
      MH_ROTATE_VARIABLE: "STRIPE_SECRET_KEY",
      MH_ROTATE_ENVIRONMENT: "prod",
      MH_ROTATE_PHASE: "finalize",
      MH_ROTATE_CURRENT: "sk_live_new",
      MH_ROTATE_PREVIOUS: "sk_live_old",
      STRIPE_SECRET_KEY: "sk_live_new",
      STRIPE_ADMIN_KEY: "rk_admin",
    });
    // The script's words are kept as facts, scrubbed of every credential it could echo
    expect(outcome.facts).toEqual([
      "./finalize.sh: previous credential retired (deleted key [redacted] at stripe)",
    ]);
    expect(describeFinalize(withFinalize)).toBe(
      "run ./finalize.sh with the previous credential in its environment (MH_ROTATE_PREVIOUS)",
    );
  });

  it("finalize passes the previous credential's companions as MH_ROTATE_PREVIOUS_<name>, scrubbed from the facts like every other value", async () => {
    const script = fakeScript(() => ok("deleted key key_old (secret sk_live_old)\n"));
    const outcome = await run(
      deps({ exec: script.exec }),
      finalizeCredential(
        jsonRule,
        {
          primary: enc.encode("sk_live_old"),
          companions: { STRIPE_KEY_ID: enc.encode("key_old") },
        },
        {
          primary: enc.encode("sk_live_new"),
          companions: { STRIPE_KEY_ID: enc.encode("key_new") },
        },
        {},
        {},
        SITE,
      ),
    );
    expect(outcome.kind).toBe("finalized");
    expect(script.calls[0]?.extraEnv).toEqual({
      MH_ROTATE_VARIABLE: "STRIPE_SECRET_KEY",
      MH_ROTATE_ENVIRONMENT: "prod",
      MH_ROTATE_PHASE: "finalize",
      MH_ROTATE_CURRENT: "sk_live_new",
      MH_ROTATE_PREVIOUS: "sk_live_old",
      MH_ROTATE_PREVIOUS_STRIPE_KEY_ID: "key_old",
      STRIPE_SECRET_KEY: "sk_live_new",
      STRIPE_KEY_ID: "key_new",
    });
    expect(outcome.facts).toEqual([
      "./finalize.sh: previous credential retired (deleted key [redacted] (secret [redacted]))",
    ]);
  });

  it("a JSON answer carries companions and facts; every declared companion is required and nothing undeclared is taken", async () => {
    const script = fakeScript(() =>
      ok(
        JSON.stringify({
          value: "sk_live_new",
          companions: { STRIPE_KEY_ID: "key_123" },
          facts: ["created key key_123 (value sk_live_new)"],
        }),
      ),
    );
    const outcome = await run(
      deps({ exec: script.exec }),
      rotateCredential(jsonRule, current, {}, SITE),
    );
    expect(dec.decode(outcome.values.primary)).toBe("sk_live_new");
    expect(dec.decode(outcome.values.companions["STRIPE_KEY_ID"] ?? new Uint8Array())).toBe(
      "key_123",
    );
    // The new value is scrubbed out of the script's facts
    expect(outcome.facts).toEqual([
      "./rotate.sh: new credential produced (created key [redacted] (value [redacted]))",
    ]);
    // Every value to push is shaped in the local report (the primary first,
    // then the companions by name — the acceptance's parity)
    expect(describeValueShapes(outcome)).toBe("11 bytes, 1 line; STRIPE_KEY_ID 7 bytes, 1 line");
    const missing = fakeScript(() => ok(JSON.stringify({ value: "x" })));
    await expect(
      run(deps({ exec: missing.exec }), rotateCredential(jsonRule, current, {}, SITE)),
    ).rejects.toThrow("lacks the companion STRIPE_KEY_ID the rule declares");
    const extra = fakeScript(() =>
      ok(JSON.stringify({ value: "x", companions: { STRIPE_KEY_ID: "k", OTHER: "o" } })),
    );
    await expect(
      run(deps({ exec: extra.exec }), rotateCredential(jsonRule, current, {}, SITE)),
    ).rejects.toThrow(
      "answered a companion the rule does not declare (the rule declares STRIPE_KEY_ID)",
    );
    const notJson = fakeScript(() => ok("sk_live_new"));
    await expect(
      run(deps({ exec: notJson.exec }), rotateCredential(jsonRule, current, {}, SITE)),
    ).rejects.toThrow("did not print a JSON object on stdout");
    const unknownKey = fakeScript(() =>
      ok(JSON.stringify({ value: "x", companions: { STRIPE_KEY_ID: "k" }, note: 1 })),
    );
    await expect(
      run(deps({ exec: unknownKey.exec }), rotateCredential(jsonRule, current, {}, SITE)),
    ).rejects.toThrow("has 1 unknown key; it takes value, companions, facts");
    // The script's words (an unknown key, an undeclared companion name) never reach the message
    const leaky = fakeScript(() =>
      ok(JSON.stringify({ value: "x", companions: { STRIPE_KEY_ID: "k", sk_live_leak: "o" } })),
    );
    const leakyError = await run(
      deps({ exec: leaky.exec }),
      rotateCredential(jsonRule, current, {}, SITE),
    ).catch((e: unknown) => e);
    expect((leakyError as Error).message).not.toContain("sk_live_leak");
    // A produced value must be text a process environment can carry
    const nul = fakeScript(() =>
      ok(JSON.stringify({ value: "a\u0000b", companions: { STRIPE_KEY_ID: "k" } })),
    );
    await expect(
      run(deps({ exec: nul.exec }), rotateCredential(jsonRule, current, {}, SITE)),
    ).rejects.toThrow("the value in the rotate script's JSON answer is not UTF-8 text without NUL");
    const nulCompanion = fakeScript(() =>
      ok(JSON.stringify({ value: "v", companions: { STRIPE_KEY_ID: "k\u0000" } })),
    );
    await expect(
      run(deps({ exec: nulCompanion.exec }), rotateCredential(jsonRule, current, {}, SITE)),
    ).rejects.toThrow(
      "the companion STRIPE_KEY_ID in the rotate script's answer is not UTF-8 text without NUL",
    );
  });

  it("a plain answer drops one CRLF or LF, refuses bytes that are not text, and a failing finalize script is reported like a failing rotate script", async () => {
    const crlf = fakeScript(() => ok("sk_live_new\r\n"));
    const outcome = await run(
      deps({ exec: crlf.exec }),
      rotateCredential(withFinalize, current, {}, SITE),
    );
    expect(dec.decode(outcome.values.primary)).toBe("sk_live_new");
    const twoNewlines = fakeScript(() => ok("sk_live_new\n\n"));
    const kept = await run(
      deps({ exec: twoNewlines.exec }),
      rotateCredential(withFinalize, current, {}, SITE),
    );
    expect(dec.decode(kept.values.primary)).toBe("sk_live_new\n");
    const binary = fakeScript((): CaptureOutcome => ({
      exitCode: 0,
      stdout: new Uint8Array([0xff, 0xfe, 0x0a]),
      stderr: "",
    }));
    await expect(
      run(deps({ exec: binary.exec }), rotateCredential(withFinalize, current, {}, SITE)),
    ).rejects.toThrow(
      "the value the rotate script printed on stdout is not UTF-8 text without NUL",
    );
    // finalize: the exit code and the scrubbed stderr, the previous credential never shown
    const failing = fakeScript(() => ({
      exitCode: 5,
      stdout: new Uint8Array(0),
      stderr: "cannot delete sk_live_old\n",
    }));
    const error = await run(
      deps({ exec: failing.exec }),
      finalizeCredential(
        withFinalize,
        credential("sk_live_old"),
        credential("sk_live_new"),
        {},
        {},
        SITE,
      ),
    ).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ConnectorError);
    expect((error as Error).message).toBe(
      "exec: the finalize script ./finalize.sh exited with code 5 (its stderr, filtered: cannot delete [redacted])",
    );
  });

  it("a failing script names the script and its exit code with the stderr scrubbed of every secret; an empty answer and a script that cannot start are refused", async () => {
    const failing = fakeScript(() => ({
      exitCode: 7,
      stdout: new Uint8Array(0),
      stderr: "stripe said no for sk_live_old with rk_admin\n",
    }));
    const error = await run(
      deps({ exec: failing.exec }),
      rotateCredential(withFinalize, current, { STRIPE_ADMIN_KEY: enc.encode("rk_admin") }, SITE),
    ).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ConnectorError);
    expect((error as Error).message).toBe(
      "exec: the rotate script ./rotate.sh exited with code 7 (its stderr, filtered: stripe said no for [redacted] with [redacted])",
    );
    const empty = fakeScript(() => ok("\n"));
    await expect(
      run(deps({ exec: empty.exec }), rotateCredential(withFinalize, current, {}, SITE)),
    ).rejects.toThrow("printed no value on stdout");
    const absent = deps({
      exec: () => Promise.reject(new Error("cannot start ./rotate.sh (ENOENT)")),
    });
    await expect(run(absent, rotateCredential(withFinalize, current, {}, SITE))).rejects.toThrow(
      "the rotate script ./rotate.sh did not start: cannot start ./rotate.sh (ENOENT)",
    );
    // A script maruhi stopped after it started (a flooded stdout) is not a
    // launch failure (D-11)
    const stopped = deps({
      exec: () => Promise.reject(new ScriptStoppedError("sh wrote more than 1 MiB to stdout")),
    });
    await expect(run(stopped, rotateCredential(withFinalize, current, {}, SITE))).rejects.toThrow(
      "the rotate script ./rotate.sh was stopped: sh wrote more than 1 MiB to stdout. The new credential may exist at the issuer",
    );
    // A leftover process's output: refused with the recovery when the
    // script itself exited 0 (D-14)
    const leftover = deps({
      exec: () =>
        Promise.reject(
          new ScriptLeftoverError(0, "sh exited (code 0) while a process it started kept writing"),
        ),
    });
    await expect(run(leftover, rotateCredential(withFinalize, current, {}, SITE))).rejects.toThrow(
      "exec: sh exited (code 0) while a process it started kept writing. The script exited 0, so the new credential may exist at the issuer",
    );
    // A credential that is not text cannot ride in an environment variable
    await expect(
      run(
        deps(),
        rotateCredential(
          withFinalize,
          { primary: new Uint8Array([0xff, 0xfe]), companions: {} },
          {},
          SITE,
        ),
      ),
    ).rejects.toThrow("the value of STRIPE_SECRET_KEY is not a UTF-8 text without NUL");
    // The site is required for this connector (an internal inconsistency, not a user error)
    await expect(run(deps(), rotateCredential(withFinalize, current, {}))).rejects.toThrow(
      "the rotation site (variable and environment) was not supplied",
    );
  });
});
