// Tests for the rotation connector frame (rotate-connector.ts — PF6
// rulings R2–R4): each connector creates the new credential the way its
// issuer allows a grace period, finalize invalidates exactly the previous
// one, failures name the connector and the issuer's answer but never a
// credential, and the generated password is alphanumeric.
//
//  - aws-iam-access-key: the IAM Query API is called signed; an inactive
//    second key is reclaimed, two active keys refuse; finalize deactivates
//  - cloudflare-api-token: verify → read → create with the same policies;
//    finalize deletes the previous token (already invalid = "already")
//  - postgres / mysql: the statements run on the admin connection with
//    quoted identifiers; alternation picks the other role; in-place MySQL
//    retains the current password and finalize discards it

import { describe, expect, it } from "vitest";

import type { RotateRule } from "../src/rotate-config.ts";
import {
  ConnectorError,
  type CredentialValues,
  finalizeCredential,
  generatePassword,
  planRotation,
  type RotateDeps,
  rotateCredential,
  type SqlRunnerShape,
} from "../src/rotate-connector.ts";

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

function deps(input: { fetch?: typeof fetch; sql?: SqlRunnerShape } = {}): RotateDeps {
  let counter = 0;
  return {
    fetch:
      input.fetch ??
      ((() => Promise.reject(new Error("no fetch in this test"))) as unknown as typeof fetch),
    now: () => Date.parse("2026-10-02T00:00:00Z"),
    // Deterministic bytes: every password is "AAAA…" shifted by a counter
    randomBytes: (length) => new Uint8Array(length).fill(((counter += 1) % 26) as number),
    sql: input.sql ?? recordingSql().sql,
    awsIamBase: "https://iam.test",
    awsStsBase: "https://sts.test",
    cloudflareBase: "https://cf.test",
  };
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
    const outcome = await rotateCredential(
      alternate,
      current,
      { adminUrl: enc.encode("postgres://admin:secret@db.example:5432/shop") },
      deps({ sql: sql.sql }),
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
    expect(planRotation(alternate, current).immediate).toBe(false);
    expect(outcome.previous).toContain("role app_a keeps its previous password");
    expect(outcome.warnings).toEqual([]);
  });

  it("in place: no grace, the plan says so, the URL's role rotates itself, and a failed probe is a warning", async () => {
    const sql = recordingSql({ failProbe: true });
    expect(planRotation(inPlace, current).immediate).toBe(true);
    const outcome = await rotateCredential(inPlace, current, {}, deps({ sql: sql.sql }));
    expect(sql.executed[0]?.url).toBe("postgres://app_a:old@db.example:5432/shop?sslmode=require");
    expect(sql.executed[0]?.statements[0]).toMatch(/^ALTER ROLE "app_a" WITH PASSWORD '/);
    expect(outcome.warnings[0]).toContain("connection test with it failed");
    expect(outcome.warnings[0]).not.toContain("old");
    expect(outcome.previous).toContain("nothing to finalize");
  });

  it("refuses a URL whose role is neither alternated role, and a non-URL value", async () => {
    await expect(
      rotateCredential(alternate, credential("postgres://other:x@db/shop"), {}, deps()),
    ).rejects.toThrow("neither of the alternated roles");
    await expect(rotateCredential(alternate, credential("not a url"), {}, deps())).rejects.toThrow(
      "expects the variable to hold a connection URL",
    );
    await expect(
      rotateCredential(alternate, credential("mysql://app_a:x@db/shop"), {}, deps()),
    ).rejects.toThrow("expects a postgres / postgresql URL");
  });

  it("finalize scrambles the previous role; in place there is nothing to do", async () => {
    const sql = recordingSql();
    const previous = credential("postgres://app_a:old@db.example:5432/shop");
    const now = credential("postgres://app_b:new@db.example:5432/shop");
    const outcome = await finalizeCredential(alternate, previous, now, {}, deps({ sql: sql.sql }));
    expect(outcome.kind).toBe("finalized");
    expect(sql.executed[0]?.statements[0]).toMatch(
      /^ALTER ROLE "app_a" WITH PASSWORD '[A-Za-z0-9]{32}'$/,
    );
    // The self-rotation admin connection is the current credential
    expect(sql.executed[0]?.url).toBe("postgres://app_b:new@db.example:5432/shop");
    expect(
      (await finalizeCredential(inPlace, previous, now, {}, deps({ sql: sql.sql }))).kind,
    ).toBe("nothing");
    expect((await finalizeCredential(alternate, now, now, {}, deps({ sql: sql.sql }))).kind).toBe(
      "nothing",
    );
  });

  it("a failed statement names the stage and never the URL", async () => {
    const sql = recordingSql({
      failExecute: "permission denied for postgres://admin:secret@db/shop",
    });
    const error = await rotateCredential(alternate, current, {}, deps({ sql: sql.sql })).catch(
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
    const outcome = await rotateCredential(inPlace, current, {}, deps({ sql: sql.sql }));
    expect(sql.executed[0]?.statements[0]).toMatch(
      /^ALTER USER 'app'@'%' IDENTIFIED BY '[A-Za-z0-9]{32}' RETAIN CURRENT PASSWORD$/,
    );
    expect(planRotation(inPlace, current).immediate).toBe(false);
    expect(new URL(dec.decode(outcome.values.primary)).username).toBe("app");
    const finalized = await finalizeCredential(
      inPlace,
      current,
      outcome.values,
      {},
      deps({ sql: sql.sql }),
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
    await rotateCredential(rule, credential("mysql://app_b:x@db/shop"), {}, deps({ sql: sql.sql }));
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
    const outcome = await rotateCredential(rule, current, {}, deps({ fetch: issuer.fetch }));
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
    const outcome = await rotateCredential(withUser, current, admin, deps({ fetch: issuer.fetch }));
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
      rotateCredential(withUser, current, admin, deps({ fetch: full.fetch })),
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
    const error = await rotateCredential(
      withUser,
      current,
      {},
      deps({ fetch: issuer.fetch }),
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
    const first = await finalizeCredential(
      withUser,
      previous,
      now,
      {},
      deps({ fetch: issuer.fetch }),
      ancestors,
    );
    expect(first.kind).toBe("finalized");
    const probe = issuer.calls.find((call) => actionOf(call) === "GetCallerIdentity");
    expect(probe?.url).toBe("https://sts.test/");
    const update = issuer.calls.find((call) => actionOf(call) === "UpdateAccessKey");
    expect(new URLSearchParams(update?.body).get("AccessKeyId")).toBe("AKIAOLD0000000000001");
    expect(new URLSearchParams(update?.body).get("Status")).toBe("Inactive");
    // The finalize is signed by the current credential (the new key)
    expect(update?.headers["authorization"]).toContain("Credential=AKIANEW0000000000002/");
    const second = await finalizeCredential(
      withUser,
      previous,
      now,
      {},
      deps({ fetch: issuer.fetch }),
      ancestors,
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
    const stranger = await finalizeCredential(
      withUser,
      current,
      now,
      {},
      deps({ fetch: issuer.fetch }),
      { accessKeyId: [enc.encode("AKIAOLD0000000000001")] },
    );
    expect(stranger.kind).toBe("nothing");
    expect(stranger.facts[0]).toContain(
      "access key AKIAHAND000000000003 of user app was never a version of AWS_ACCESS_KEY_ID (not created through maruhi) — left untouched",
    );
    expect(calls).toEqual(["ListAccessKeys"]);
    // A stored key id that does not pair with the previous secret (someone pushed by hand): untouched
    calls.length = 0;
    const mismatch = await finalizeCredential(
      withUser,
      current,
      now,
      {},
      deps({ fetch: issuer.fetch }),
      { accessKeyId: [enc.encode("AKIAHAND000000000003")] },
    );
    expect(mismatch.kind).toBe("nothing");
    expect(mismatch.facts[0]).toContain(
      "access key AKIAHAND000000000003 is active but does not authenticate with the previous version's secret (not that version's key) — left untouched",
    );
    expect(calls).toEqual(["ListAccessKeys", "GetCallerIdentity"]);
    // Only the current key exists: nothing to deactivate (no probe)
    calls.length = 0;
    const alone = await finalizeCredential(
      withUser,
      now,
      now,
      {},
      deps({
        fetch: fakeIssuer(() => xml(keysXml([{ id: "AKIANEW0000000000002", status: "Active" }])))
          .fetch,
      }),
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
    const outcome = await rotateCredential(rule, current, {}, deps({ fetch: issuer.fetch }));
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
    await rotateCredential(
      accountRule,
      current,
      { token: enc.encode("admin-token") },
      deps({ fetch: issuer.fetch }),
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
      rotateCredential(rule, current, {}, deps({ fetch: invalid.fetch })),
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
      rotateCredential(rule, current, {}, deps({ fetch: denied.fetch })),
    ).rejects.toThrow(
      "Cloudflare answered 403 to reading token tok-old (9109: Unauthorized to access requested resource)",
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
    const outcome = await finalizeCredential(
      rule,
      previous,
      now,
      {},
      deps({ fetch: issuer.fetch }),
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
      (await finalizeCredential(rule, previous, now, {}, deps({ fetch: gone.fetch }))).kind,
    ).toBe("already");
  });
});
