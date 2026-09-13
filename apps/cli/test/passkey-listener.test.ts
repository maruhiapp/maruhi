// パスキー PRF リスナー(passkey-listener.ts)とページ資産(passkey-page.ts)の検査。
//
// 固定する性質(integration-options.md 補足 20 裁定 A / C — 人間レビュー箇所):
//  1. トークン不一致・Host 不一致・Origin 不一致・本文不正・content-type 違いは
//     すべて理由を出さない一様 404
//  2. 正しい POST は 1 回だけ受理(204)し、以後は 404。close で接続は拒否される
//  3. ページは inline script / inline style / イベント属性 / 第三者 URL を持たず、
//     HTML 応答に CSP(script-src 'self' 基調)が付く

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

const listeners: PrfListener[] = [];

afterEach(async () => {
  await Promise.all(listeners.splice(0).map((listener) => listener.close()));
});

async function start(): Promise<PrfListener> {
  const listener = await startPrfListener({
    mode: "recover",
    rpId: "localhost",
    credentials: [{ credentialIdHex: CREDENTIAL_HEX, prfSaltHex: "22".repeat(32) }],
  });
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

describe("PRF リスナーの認証(裁定 A)", () => {
  it("URL は http://localhost:<port>/<token>/ で、ページ資産はトークン配下だけに出る", async () => {
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

  it("トークン不一致・Host 不一致(127.0.0.1)・未知の資産は一様 404", async () => {
    const listener = await start();
    const wrongToken = await fetch(`${originOf(listener)}/${"x".repeat(43)}/`);
    expect(wrongToken.status).toBe(404);
    expect(await wrongToken.text()).toBe("not found");
    const byIp = await fetch(listener.url.replace("localhost", "127.0.0.1"));
    expect(byIp.status).toBe(404);
    expect((await fetch(`${originOf(listener)}/`)).status).toBe(404);
    expect((await fetch(`${listener.url}other.js`)).status).toBe(404);
  });

  it("POST は Origin 完全一致 + application/json + 正しい本文のときだけ受理する", async () => {
    const listener = await start();
    const good = JSON.stringify({ credentialIdHex: CREDENTIAL_HEX, prfHex: PRF_HEX });
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
    expect((await post(listener, JSON.stringify({ prfHex: PRF_HEX }))).status).toBe(404);
    expect(
      (await post(listener, JSON.stringify({ credentialIdHex: CREDENTIAL_HEX, prfHex: "zz" })))
        .status,
    ).toBe(404);
    expect((await post(listener, JSON.stringify({ error: "made-up" }))).status).toBe(404);
    // 大きすぎる本文は読まずに切る(応答が無いか 404)
    await post(
      listener,
      JSON.stringify({
        credentialIdHex: "ab".repeat(1024),
        prfHex: PRF_HEX,
        pad: "x".repeat(5000),
      }),
    ).then(
      (response) => expect(response.status).toBe(404),
      () => undefined,
    );
    // 不正な POST はリスナーを閉じない: 正しい POST がまだ通る
    const accepted = await post(listener, good);
    expect(accepted.status).toBe(204);
    expect(await listener.outcome).toEqual({ credentialIdHex: CREDENTIAL_HEX, prfHex: PRF_HEX });
  });

  it("受理は 1 回限り: 2 回目の正しい POST は 404、close 後は接続できない", async () => {
    const listener = await start();
    const good = JSON.stringify({ credentialIdHex: CREDENTIAL_HEX, prfHex: PRF_HEX });
    expect((await post(listener, good)).status).toBe(204);
    expect((await post(listener, good)).status).toBe(404);
    expect((await post(listener, JSON.stringify({ error: "not-allowed" }))).status).toBe(404);
    await listener.close();
    await expect(fetch(listener.url)).rejects.toThrow();
  });

  it("理由コードの POST も 1 回で確定する", async () => {
    const listener = await start();
    expect((await post(listener, JSON.stringify({ error: "prf-unsupported" }))).status).toBe(204);
    expect(await listener.outcome).toEqual({ error: "prf-unsupported" });
  });
});

describe("parsePrfPost", () => {
  it("成功形と理由コードだけを受け、余分なキー・形式違いは null", () => {
    expect(parsePrfPost(JSON.stringify({ credentialIdHex: "ab", prfHex: PRF_HEX }))).toEqual({
      credentialIdHex: "ab",
      prfHex: PRF_HEX,
    });
    expect(parsePrfPost(JSON.stringify({ error: "not-allowed" }))).toEqual({
      error: "not-allowed",
    });
    expect(parsePrfPost(JSON.stringify({ error: "not-allowed", extra: 1 }))).toBeNull();
    expect(
      parsePrfPost(JSON.stringify({ credentialIdHex: "ab", prfHex: PRF_HEX, x: 1 })),
    ).toBeNull();
    expect(parsePrfPost(JSON.stringify({ credentialIdHex: "AB", prfHex: PRF_HEX }))).toBeNull();
    expect(parsePrfPost(JSON.stringify({ credentialIdHex: "", prfHex: PRF_HEX }))).toBeNull();
    expect(
      parsePrfPost(JSON.stringify({ credentialIdHex: "ab", prfHex: PRF_HEX.slice(1) })),
    ).toBeNull();
    expect(parsePrfPost(JSON.stringify(["ab"]))).toBeNull();
    expect(parsePrfPost("null")).toBeNull();
    expect(parsePrfPost("")).toBeNull();
  });
});

describe("ページ資産の不変条件(裁定 C — CSP script-src 'self' 基調)", () => {
  it("HTML は別ファイルの app.js だけを読み、inline script / style・イベント属性・javascript: を持たない", () => {
    const scripts = PRF_PAGE_HTML.match(/<script\b[^>]*>/g) ?? [];
    expect(scripts).toEqual(['<script src="./app.js">']);
    expect(PRF_PAGE_HTML).not.toMatch(/<style\b/i);
    expect(PRF_PAGE_HTML).not.toMatch(/\son[a-z]+\s*=/i);
    expect(PRF_PAGE_HTML).not.toMatch(/javascript:/i);
    expect(PRF_PAGE_HTML).not.toMatch(/\sstyle\s*=/i);
    expect(PRF_PAGE_HTML).toContain('<link rel="stylesheet" href="./style.css">');
  });

  it("HTML / JS / CSS は第三者の URL を持たず、JS は eval / Function / innerHTML を使わない", () => {
    for (const asset of [PRF_PAGE_HTML, PRF_PAGE_JS, PRF_PAGE_CSS]) {
      expect(asset).not.toMatch(/https?:\/\//);
      expect(asset).not.toMatch(/\/\/[a-z0-9-]+\.[a-z]{2,}/i);
    }
    expect(PRF_PAGE_JS).not.toMatch(/\beval\s*\(/);
    expect(PRF_PAGE_JS).not.toMatch(/new\s+Function\b/);
    expect(PRF_PAGE_JS).not.toMatch(/innerHTML|outerHTML|insertAdjacentHTML|document\.write/);
    // WebAuthn は UV 必須(UV 無しの認証器では PRF が黙って欠ける — spike-prf.md §2)
    expect(PRF_PAGE_JS.match(/userVerification: "required"/g)).toHaveLength(3);
    expect(PRF_PAGE_JS).not.toMatch(/userVerification: "(preferred|discouraged)"/);
    // 相対パスの fetch は同一オリジンの 2 つだけ(config.json と prf)
    expect(PRF_PAGE_JS.match(/fetch\(/g)).toHaveLength(2);
  });

  it("CSP は inline も第三者も許さない", () => {
    expect(PRF_PAGE_CSP).toContain("default-src 'none'");
    expect(PRF_PAGE_CSP).toContain("script-src 'self'");
    expect(PRF_PAGE_CSP).not.toContain("unsafe-inline");
    expect(PRF_PAGE_CSP).not.toContain("unsafe-eval");
    expect(PRF_PAGE_CSP).toContain("frame-ancestors 'none'");
  });
});
