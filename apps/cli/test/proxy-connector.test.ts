// Tests for the connector frame and the github-app connector
// (proxy-connector.ts — PF4 ruling P8): the JWT GitHub receives verifies
// under the App's public key with the claims GitHub requires, the token is
// cached and re-minted before expiry, PKCS#1 and PKCS#8 keys both import,
// and failures name the connector and variable but never an input.

import { createVerify, generateKeyPairSync } from "node:crypto";

import { describe, expect, it } from "vitest";

import { parseHostPattern } from "../src/proxy-config.ts";
import { makeConnectorCredential } from "../src/proxy-connector.ts";

const enc = new TextEncoder();
const dec = new TextDecoder();

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const PKCS1 = privateKey.export({ type: "pkcs1", format: "pem" }) as string;
const PKCS8 = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
const PUBLIC = publicKey;

function hosts() {
  const parsed = parseHostPattern("api.github.com");
  if (typeof parsed === "string") {
    throw new Error(parsed);
  }
  return [parsed];
}

interface SeenCall {
  readonly url: string;
  readonly method: string;
  readonly headers: Record<string, string>;
}

/** A fake GitHub: records the call, verifies nothing itself, answers as told. */
function fakeGithub(answer: (call: SeenCall, index: number) => Response) {
  const calls: SeenCall[] = [];
  const fetchImpl = ((input: string | URL | Request, init?: RequestInit) => {
    const headers: Record<string, string> = {};
    for (const [name, value] of Object.entries((init?.headers ?? {}) as Record<string, string>)) {
      headers[name.toLowerCase()] = value;
    }
    const call = { url: String(input), method: init?.method ?? "GET", headers };
    calls.push(call);
    return Promise.resolve(answer(call, calls.length - 1));
  }) as typeof fetch;
  return { calls, fetch: fetchImpl };
}

function tokenResponse(token: string, expiresInMs: number, now: number): Response {
  return new Response(
    JSON.stringify({ token, expires_at: new Date(now + expiresInMs).toISOString() }),
    { status: 201, headers: { "content-type": "application/json" } },
  );
}

function decodeJwt(jwt: string) {
  const [header = "", payload = "", signature = ""] = jwt.split(".");
  const fromUrl = (text: string) =>
    Buffer.from(text.replaceAll("-", "+").replaceAll("_", "/"), "base64");
  return {
    header: JSON.parse(fromUrl(header).toString()) as Record<string, unknown>,
    payload: JSON.parse(fromUrl(payload).toString()) as Record<string, number | string>,
    signingInput: `${header}.${payload}`,
    signature: fromUrl(signature),
  };
}

describe("github-app connector", () => {
  it("signs an RS256 App JWT GitHub can verify, asks for an installation token, and caches it", async () => {
    let now = Date.UTC(2026, 9, 1, 12, 0, 0);
    const github = fakeGithub((call, index) =>
      tokenResponse(`ghs_minted_${index}`, 60 * 60 * 1000, now),
    );
    const credential = makeConnectorCredential({
      name: "GH_TOKEN",
      kind: "github-app",
      inputs: {
        appId: enc.encode("123456\n"),
        privateKey: enc.encode(PKCS1),
        installationId: enc.encode("987654"),
      },
      placeholder: "mhp_GH_TOKEN_x",
      hosts: hosts(),
      surfaces: ["header"],
      deps: { fetch: github.fetch, now: () => now, apiBase: "https://github.test" },
    });
    expect(dec.decode(await credential.resolve())).toBe("ghs_minted_0");
    // The call GitHub saw
    const call = github.calls[0];
    expect(call?.url).toBe("https://github.test/app/installations/987654/access_tokens");
    expect(call?.method).toBe("POST");
    expect(call?.headers["accept"]).toBe("application/vnd.github+json");
    expect(call?.headers["x-github-api-version"]).toBe("2022-11-28");
    expect(call?.headers["user-agent"]).toMatch(/^maruhi\//);
    const jwt = (call?.headers["authorization"] ?? "").replace(/^Bearer /, "");
    const decoded = decodeJwt(jwt);
    expect(decoded.header).toEqual({ alg: "RS256", typ: "JWT" });
    expect(decoded.payload["iss"]).toBe("123456");
    expect(decoded.payload["iat"]).toBe(Math.floor(now / 1000) - 60);
    expect(decoded.payload["exp"]).toBe(Math.floor(now / 1000) + 9 * 60);
    const verifier = createVerify("RSA-SHA256");
    verifier.update(decoded.signingInput);
    expect(verifier.verify(PUBLIC, decoded.signature)).toBe(true);

    // Cached: a second resolve within the hour does not call GitHub
    now += 30 * 60 * 1000;
    expect(dec.decode(await credential.resolve())).toBe("ghs_minted_0");
    expect(github.calls).toHaveLength(1);
    // Re-minted inside the five-minute margin before expiry
    now += 26 * 60 * 1000;
    expect(dec.decode(await credential.resolve())).toBe("ghs_minted_1");
    expect(github.calls).toHaveLength(2);
  });

  it("imports a PKCS#8 key too, and concurrent first uses share one mint", async () => {
    const now = Date.now();
    const github = fakeGithub((_call, index) => tokenResponse(`ghs_${index}`, 3_600_000, now));
    const credential = makeConnectorCredential({
      name: "GH_TOKEN",
      kind: "github-app",
      inputs: {
        appId: enc.encode("Iv1.abcdef0123456789"),
        privateKey: enc.encode(PKCS8),
        installationId: enc.encode("1"),
      },
      placeholder: "mhp_GH_TOKEN_y",
      hosts: hosts(),
      surfaces: ["header"],
      deps: { fetch: github.fetch, now: () => now },
    });
    const [a, b] = await Promise.all([credential.resolve(), credential.resolve()]);
    expect(dec.decode(a)).toBe("ghs_0");
    expect(dec.decode(b)).toBe("ghs_0");
    expect(github.calls).toHaveLength(1);
    expect(github.calls[0]?.url.startsWith("https://api.github.com/")).toBe(true);
  });

  it("reports GitHub's refusal and bad inputs with the connector and variable named, never an input", async () => {
    const github = fakeGithub(
      () =>
        new Response(JSON.stringify({ message: "Integration not found" }), {
          status: 404,
          headers: { "content-type": "application/json" },
        }),
    );
    const refused = makeConnectorCredential({
      name: "GH_TOKEN",
      kind: "github-app",
      inputs: {
        appId: enc.encode("123"),
        privateKey: enc.encode(PKCS1),
        installationId: enc.encode("42"),
      },
      placeholder: "mhp_GH_TOKEN_z",
      hosts: hosts(),
      surfaces: ["header"],
      deps: { fetch: github.fetch, now: Date.now },
    });
    await expect(refused.resolve()).rejects.toThrow(
      "connector github-app for GH_TOKEN: GitHub answered 404 (Integration not found)",
    );
    // A failure is not cached: the next resolve tries again
    await expect(refused.resolve()).rejects.toThrow(/404/);
    expect(github.calls).toHaveLength(2);

    const badKey = makeConnectorCredential({
      name: "GH_TOKEN",
      kind: "github-app",
      inputs: {
        appId: enc.encode("123"),
        privateKey: enc.encode("not a key SECRET-LOOKING-INPUT"),
        installationId: enc.encode("42"),
      },
      placeholder: "mhp_GH_TOKEN_w",
      hosts: hosts(),
      surfaces: ["header"],
      deps: { fetch: github.fetch, now: Date.now },
    });
    const error = await badKey.resolve().then(
      () => null,
      (reason: Error) => reason.message,
    );
    expect(error).toContain("the private key is not a PEM RSA key");
    expect(error).not.toContain("SECRET-LOOKING-INPUT");

    const badInstallation = makeConnectorCredential({
      name: "GH_TOKEN",
      kind: "github-app",
      inputs: {
        appId: enc.encode("123"),
        privateKey: enc.encode(PKCS1),
        installationId: enc.encode("not-numeric"),
      },
      placeholder: "mhp_GH_TOKEN_v",
      hosts: hosts(),
      surfaces: ["header"],
      deps: { fetch: github.fetch, now: Date.now },
    });
    await expect(badInstallation.resolve()).rejects.toThrow(
      "input installationId must be the numeric installation ID",
    );
    // GitHub was not called for the two malformed inputs
    expect(github.calls).toHaveLength(2);
  });
});
