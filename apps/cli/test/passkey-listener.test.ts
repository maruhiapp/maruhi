// Checks for the passkey PRF listener (passkey-listener.ts) and the page
// assets (passkey-page.ts).
//
// Properties pinned down (integration-options.md supplement 20 rulings A /
// C — human-review points):
//  1. Token mismatch, Host mismatch, Origin mismatch, malformed body, and
//     wrong content-type are all the same reason-free 404
//  2. A correct POST is accepted exactly once (204); afterwards it's 404.
//     After close the connection is refused
//  3. The page has no inline script / inline style / event attributes /
//     third-party URLs, and the HTML response carries a CSP (script-src
//     'self' baseline)

import { afterEach, describe, expect, it } from "vitest";

import {
  parsePrfPost,
  PRF_PAGE_CSP,
  type PrfListener,
  startPrfListener,
} from "../src/passkey-listener.ts";
import { PRF_PAGE_CSS, PRF_PAGE_HTML, PRF_PAGE_JS } from "../src/passkey-page.ts";

const PRF_HEX = "10".repeat(32);
const CREDENTIAL_HEX = "a1b2c3d4e5f60718";
const CODE = "123456";

const listeners: PrfListener[] = [];

afterEach(async () => {
  await Promise.all(listeners.splice(0).map((listener) => listener.close()));
});

async function start(): Promise<PrfListener> {
  const listener = await startPrfListener(
    {
      mode: "recover",
      rpId: "localhost",
      credentials: [{ credentialIdHex: CREDENTIAL_HEX, prfSaltHex: "22".repeat(32) }],
    },
    CODE,
  );
  listeners.push(listener);
  return listener;
}

function originOf(listener: PrfListener): string {
  return `http://localhost:${listener.port}`;
}

function post(
  listener: PrfListener,
  body: string,
  headers: Readonly<Record<string, string>> = { origin: originOf(listener) },
): Promise<Response> {
  return fetch(`${listener.url}prf`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body,
  });
}

describe("PRF listener authentication (ruling A)", () => {
  it("the URL is http://localhost:<port>/<token>/ and page assets are served only under the token", async () => {
    const listener = await start();
    expect(listener.url).toMatch(/^http:\/\/localhost:\d+\/[A-Za-z0-9_-]{43}\/$/);
    const page = await fetch(listener.url);
    expect(page.status).toBe(200);
    expect(page.headers.get("content-type")).toContain("text/html");
    expect(page.headers.get("content-security-policy")).toBe(PRF_PAGE_CSP);
    expect(page.headers.get("cache-control")).toBe("no-store");
    expect(page.headers.get("referrer-policy")).toBe("no-referrer");
    expect(await page.text()).toBe(PRF_PAGE_HTML);

    const script = await fetch(`${listener.url}app.js`);
    expect(script.status).toBe(200);
    expect(script.headers.get("content-type")).toContain("text/javascript");
    expect(await script.text()).toBe(PRF_PAGE_JS);
    expect((await fetch(`${listener.url}style.css`)).status).toBe(200);
    const config = await fetch(`${listener.url}config.json`);
    expect(await config.json()).toEqual({
      mode: "recover",
      rpId: "localhost",
      credentials: [{ credentialIdHex: CREDENTIAL_HEX, prfSaltHex: "22".repeat(32) }],
    });
  });

  it("a trailing-slashless /<token> is redirected to /<token>/ (so relatively-referenced assets resolve)", async () => {
    const listener = await start();
    const bare = await fetch(listener.url.slice(0, -1), { redirect: "manual" });
    expect(bare.status).toBe(302);
    expect(bare.headers.get("location")).toBe(new URL(listener.url).pathname);
    const followed = await fetch(listener.url.slice(0, -1));
    expect(followed.status).toBe(200);
    expect(await followed.text()).toBe(PRF_PAGE_HTML);
    // The redirect only happens for the right token (a different token
    // stays 404)
    expect(
      (await fetch(`${originOf(listener)}/${"x".repeat(43)}`, { redirect: "manual" })).status,
    ).toBe(404);
  });

  it("token mismatch, Host mismatch (127.0.0.1), and unknown assets all get the same 404", async () => {
    const listener = await start();
    const wrongToken = await fetch(`${originOf(listener)}/${"x".repeat(43)}/`);
    expect(wrongToken.status).toBe(404);
    expect(await wrongToken.text()).toBe("not found");
    const byIp = await fetch(listener.url.replace("localhost", "127.0.0.1"));
    expect(byIp.status).toBe(404);
    expect((await fetch(`${originOf(listener)}/`)).status).toBe(404);
    expect((await fetch(`${listener.url}other.js`)).status).toBe(404);
  });

  it("a POST is accepted only with an exact-Origin match + application/json + the right body", async () => {
    const listener = await start();
    const good = JSON.stringify({ code: CODE, credentialIdHex: CREDENTIAL_HEX, prfHex: PRF_HEX });
    expect((await post(listener, good, {})).status).toBe(404);
    expect((await post(listener, good, { origin: "http://evil.example" })).status).toBe(404);
    expect(
      (await post(listener, good, { origin: `http://localhost:${listener.port + 1}` })).status,
    ).toBe(404);
    expect(
      (await post(listener, good, { origin: originOf(listener), "content-type": "text/plain" }))
        .status,
    ).toBe(404);
    expect((await post(listener, "{not json")).status).toBe(404);
    expect((await post(listener, JSON.stringify({ code: CODE, prfHex: PRF_HEX }))).status).toBe(
      404,
    );
    expect(
      (
        await post(
          listener,
          JSON.stringify({ code: CODE, credentialIdHex: CREDENTIAL_HEX, prfHex: "zz" }),
        )
      ).status,
    ).toBe(404);
    expect((await post(listener, JSON.stringify({ code: CODE, error: "made-up" }))).status).toBe(
      404,
    );
    // Missing / mismatched confirmation code is a 404 (not consumed —
    // the correct POST below still passes)
    expect(
      (await post(listener, JSON.stringify({ credentialIdHex: CREDENTIAL_HEX, prfHex: PRF_HEX })))
        .status,
    ).toBe(404);
    expect(
      (
        await post(
          listener,
          JSON.stringify({ code: "000000", credentialIdHex: CREDENTIAL_HEX, prfHex: PRF_HEX }),
        )
      ).status,
    ).toBe(404);
    // A too-large body is cut unread (no response, or 404)
    await post(
      listener,
      JSON.stringify({
        code: CODE,
        credentialIdHex: "ab".repeat(1024),
        prfHex: PRF_HEX,
        pad: "x".repeat(5000),
      }),
    ).then(
      (response) => expect(response.status).toBe(404),
      () => undefined,
    );
    // A malformed POST doesn't close the listener: a correct POST still
    // passes
    const accepted = await post(listener, good);
    expect(accepted.status).toBe(204);
    expect(await listener.outcome).toEqual({ credentialIdHex: CREDENTIAL_HEX, prfHex: PRF_HEX });
  });

  it("acceptance is one-shot: a second correct POST is a 404, and after close connections fail", async () => {
    const listener = await start();
    const good = JSON.stringify({ code: CODE, credentialIdHex: CREDENTIAL_HEX, prfHex: PRF_HEX });
    expect((await post(listener, good)).status).toBe(204);
    expect((await post(listener, good)).status).toBe(404);
    expect(
      (await post(listener, JSON.stringify({ code: CODE, error: "not-allowed" }))).status,
    ).toBe(404);
    await listener.close();
    await expect(fetch(listener.url)).rejects.toThrow();
  });

  it("a reason-code POST also settles in one shot (as long as the code is attached)", async () => {
    const listener = await start();
    expect(
      (await post(listener, JSON.stringify({ code: CODE, error: "prf-unsupported" }))).status,
    ).toBe(204);
    expect(await listener.outcome).toEqual({ error: "prf-unsupported" });
  });

  it("once code mismatches hit the cap, the whole ceremony is aborted (fail-closed against brute force)", async () => {
    const listener = await start();
    const forged = (code: string) =>
      JSON.stringify({ code, credentialIdHex: CREDENTIAL_HEX, prfHex: PRF_HEX });
    for (const guess of ["000001", "000002", "000003", "000004", "000005"]) {
      expect((await post(listener, forged(guess))).status).toBe(404);
    }
    expect(await listener.outcome).toEqual({ error: "too-many-code-attempts" });
    // After the abort, even the correct code doesn't pass
    expect((await post(listener, forged(CODE))).status).toBe(404);
  });
});

describe("parsePrfPost", () => {
  it("accepts only a confirmation code + success shape / a reason code; extra keys and wrong shapes are null", () => {
    const withCode = (body: Record<string, unknown>) => JSON.stringify({ code: CODE, ...body });
    expect(parsePrfPost(withCode({ credentialIdHex: "ab", prfHex: PRF_HEX }))).toEqual({
      code: CODE,
      post: { credentialIdHex: "ab", prfHex: PRF_HEX },
    });
    expect(parsePrfPost(withCode({ error: "not-allowed" }))).toEqual({
      code: CODE,
      post: { error: "not-allowed" },
    });
    expect(parsePrfPost(withCode({ error: "not-allowed", extra: 1 }))).toBeNull();
    expect(parsePrfPost(withCode({ credentialIdHex: "ab", prfHex: PRF_HEX, x: 1 }))).toBeNull();
    expect(parsePrfPost(withCode({ credentialIdHex: "AB", prfHex: PRF_HEX }))).toBeNull();
    expect(parsePrfPost(withCode({ credentialIdHex: "", prfHex: PRF_HEX }))).toBeNull();
    expect(parsePrfPost(withCode({ credentialIdHex: "ab", prfHex: PRF_HEX.slice(1) }))).toBeNull();
    // The code is a 6-digit numeric string only (absent, short, or a
    // numeric type are all null)
    expect(parsePrfPost(JSON.stringify({ credentialIdHex: "ab", prfHex: PRF_HEX }))).toBeNull();
    expect(
      parsePrfPost(JSON.stringify({ code: "12345", credentialIdHex: "ab", prfHex: PRF_HEX })),
    ).toBeNull();
    expect(
      parsePrfPost(JSON.stringify({ code: 123456, credentialIdHex: "ab", prfHex: PRF_HEX })),
    ).toBeNull();
    expect(parsePrfPost(JSON.stringify(["ab"]))).toBeNull();
    expect(parsePrfPost("null")).toBeNull();
    expect(parsePrfPost("")).toBeNull();
  });
});

describe("page-asset invariants (ruling C — CSP script-src 'self' baseline)", () => {
  it("the HTML loads only the separate app.js and has no inline script / style, event attributes, or javascript:", () => {
    const scripts = PRF_PAGE_HTML.match(/<script\b[^>]*>/g) ?? [];
    expect(scripts).toEqual(['<script src="./app.js">']);
    expect(PRF_PAGE_HTML).not.toMatch(/<style\b/i);
    expect(PRF_PAGE_HTML).not.toMatch(/\son[a-z]+\s*=/i);
    expect(PRF_PAGE_HTML).not.toMatch(/javascript:/i);
    expect(PRF_PAGE_HTML).not.toMatch(/\sstyle\s*=/i);
    expect(PRF_PAGE_HTML).toContain('<link rel="stylesheet" href="./style.css">');
    // The confirmation-code input field lives on the page (the value only
    // rides the POST — no key material enters the DOM)
    expect(PRF_PAGE_HTML).toContain('<input id="code"');
    expect(PRF_PAGE_JS).toContain("code: code");
  });

  it("HTML / JS / CSS carry no third-party URLs, and the JS uses no eval / Function / innerHTML", () => {
    for (const asset of [PRF_PAGE_HTML, PRF_PAGE_JS, PRF_PAGE_CSS]) {
      expect(asset).not.toMatch(/https?:\/\//);
      expect(asset).not.toMatch(/\/\/[a-z0-9-]+\.[a-z]{2,}/i);
    }
    expect(PRF_PAGE_JS).not.toMatch(/\beval\s*\(/);
    expect(PRF_PAGE_JS).not.toMatch(/new\s+Function\b/);
    expect(PRF_PAGE_JS).not.toMatch(/innerHTML|outerHTML|insertAdjacentHTML|document\.write/);
    // WebAuthn requires UV (on authenticators without UV, PRF silently
    // goes missing — spike-prf.md §2)
    expect(PRF_PAGE_JS.match(/userVerification: "required"/g)).toHaveLength(3);
    expect(PRF_PAGE_JS).not.toMatch(/userVerification: "(preferred|discouraged)"/);
    // The relative-path fetches are exactly the two same-origin ones
    // (config.json and prf)
    expect(PRF_PAGE_JS.match(/fetch\(/g)).toHaveLength(2);
  });

  it("the CSP permits neither inline nor third-party", () => {
    expect(PRF_PAGE_CSP).toContain("default-src 'none'");
    expect(PRF_PAGE_CSP).toContain("script-src 'self'");
    expect(PRF_PAGE_CSP).not.toContain("unsafe-inline");
    expect(PRF_PAGE_CSP).not.toContain("unsafe-eval");
    expect(PRF_PAGE_CSP).toContain("frame-ancestors 'none'");
  });
});
