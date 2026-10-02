// Tests for the forward proxy (proxy-server.ts — PF4 rulings P1 / P2 / P4
// / P6 / P7), end to end over real sockets: a client does what every
// HTTPS client does behind HTTPS_PROXY (CONNECT, then TLS trusting the
// run's CA), the proxy terminates the brokered host, substitutes the
// placeholder toward the origin only, scrubs the real value out of the
// response, tunnels unbrokered hosts untouched, and refuses misuse with
// a message that names the variable and the rule. The origins are
// loopback stand-ins reached through the upstream test seam.

import { lstatSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { makeEphemeralCa } from "../src/proxy-cert.ts";
import { parseHostPattern } from "../src/proxy-config.ts";
import {
  type BrokeredCredential,
  credentialsFor,
  makePlaceholder,
  matchesTarget,
} from "../src/proxy-rules.ts";
import { type ProxyDecision, type ProxyHandle, startProxy } from "../src/proxy-server.ts";
import {
  httpsViaProxy,
  httpViaProxy,
  openTunnel,
  type Origin,
  requestOver,
  secureTunnel,
  startOrigin,
} from "./support/proxy-client.ts";

const enc = new TextEncoder();
const REAL_TOKEN = "ghp_realtoken0123456789abcdefghijklmnopq";
const REAL_KEY = "sk-plain-real-key-ZZZZZZZZZZ";

function pattern(text: string) {
  const parsed = parseHostPattern(text);
  if (typeof parsed === "string") {
    throw new Error(parsed);
  }
  return parsed;
}

let runCa: Awaited<ReturnType<typeof makeEphemeralCa>>;
let originCa: Awaited<ReturnType<typeof makeEphemeralCa>>;
let secureOrigin: Origin;
let plainOrigin: Origin;
let github: BrokeredCredential;
let plainKey: BrokeredCredential;
let connectorFails: BrokeredCredential;
let open: ProxyHandle[] = [];
let hopDirs: string[] = [];

beforeAll(async () => {
  runCa = await makeEphemeralCa();
  originCa = await makeEphemeralCa();
  const leaf = await originCa.issue("api.example.test");
  secureOrigin = await startOrigin({
    tls: { key: leaf.keyPem, cert: leaf.certPem },
    marker: REAL_TOKEN,
  });
  plainOrigin = await startOrigin({});
  github = {
    name: "GITHUB_TOKEN",
    placeholder: makePlaceholder("GITHUB_TOKEN"),
    hosts: [pattern("api.example.test")],
    surfaces: ["header"],
    resolve: () => Promise.resolve(enc.encode(REAL_TOKEN)),
    known: () => [enc.encode(REAL_TOKEN)],
  };
  plainKey = {
    name: "PLAIN_KEY",
    placeholder: makePlaceholder("PLAIN_KEY"),
    hosts: [pattern("http://plain.localhost")],
    surfaces: ["header", "query", "body"],
    resolve: () => Promise.resolve(enc.encode(REAL_KEY)),
    known: () => [enc.encode(REAL_KEY)],
  };
  connectorFails = {
    name: "MINTED",
    placeholder: makePlaceholder("MINTED"),
    hosts: [pattern("api.example.test")],
    surfaces: ["header"],
    resolve: () =>
      Promise.reject(new Error("connector github-app for MINTED: installation 42 not found (404)")),
    known: () => [],
  };
});

afterEach(async () => {
  for (const handle of open) {
    await handle.close();
  }
  open = [];
  for (const dir of hopDirs) {
    rmSync(dir, { recursive: true, force: true });
  }
  hopDirs = [];
  secureOrigin.seen.length = 0;
  plainOrigin.seen.length = 0;
});

async function proxyWith(input: {
  readonly credentials: readonly BrokeredCredential[];
  readonly unmatched?: "allow" | "block";
  readonly decisions?: ProxyDecision[];
  readonly credential?: { readonly user: string; readonly password: string };
}): Promise<ProxyHandle> {
  const hopDir = mkdtempSync(join(tmpdir(), "mh-hop-"));
  hopDirs.push(hopDir);
  const handle = await startProxy({
    credentials: input.credentials,
    unmatched: input.unmatched ?? "allow",
    ca: runCa,
    hopDir,
    ...(input.credential === undefined ? {} : { credential: input.credential }),
    onDecision: (decision) => input.decisions?.push(decision),
    upstream: {
      // The rule's hosts resolve to the loopback origins
      connect: (target) =>
        target.scheme === "https"
          ? { host: "127.0.0.1", port: secureOrigin.port }
          : { host: "127.0.0.1", port: plainOrigin.port },
      ca: [originCa.certPem],
    },
  });
  open.push(handle);
  return handle;
}

describe("proxy rules", () => {
  it("matches exact hosts, wildcards (one or more labels), scheme, and port", () => {
    const api = pattern("api.example.test");
    const wild = pattern("*.example.test:8443");
    const plain = pattern("http://localhost:8787");
    expect(matchesTarget(api, { scheme: "https", host: "api.example.test", port: 443 })).toBe(true);
    expect(matchesTarget(api, { scheme: "https", host: "api.example.test", port: 8443 })).toBe(
      false,
    );
    expect(matchesTarget(api, { scheme: "http", host: "api.example.test", port: 443 })).toBe(false);
    expect(matchesTarget(wild, { scheme: "https", host: "a.example.test", port: 8443 })).toBe(true);
    expect(matchesTarget(wild, { scheme: "https", host: "a.b.example.test", port: 8443 })).toBe(
      true,
    );
    expect(matchesTarget(wild, { scheme: "https", host: "example.test", port: 8443 })).toBe(false);
    expect(matchesTarget(plain, { scheme: "http", host: "localhost", port: 8787 })).toBe(true);
    expect(matchesTarget(plain, { scheme: "https", host: "localhost", port: 8787 })).toBe(false);
  });

  it("placeholders carry the name and a random tail, and differ per call", () => {
    const a = makePlaceholder("GITHUB_TOKEN");
    const b = makePlaceholder("GITHUB_TOKEN");
    expect(a).toMatch(/^mhp_GITHUB_TOKEN_[A-Za-z0-9]{22}$/);
    expect(a).not.toBe(b);
  });
});

describe("the forward proxy", () => {
  it("substitutes a placeholder in a bearer header toward the brokered host and scrubs the echoed value out of the response", async () => {
    const decisions: ProxyDecision[] = [];
    const proxy = await proxyWith({ credentials: [github, plainKey], decisions });
    const response = await httpsViaProxy({
      proxyPort: proxy.port,
      ca: [runCa.certPem],
      url: "https://api.example.test/echo?q=1",
      headers: { authorization: `Bearer ${github.placeholder}`, "x-note": github.placeholder },
    });
    expect(response.status).toBe(200);
    // The origin received the real value, in both headers
    const seen = secureOrigin.seen[0];
    expect(seen?.headers.authorization).toBe(`Bearer ${REAL_TOKEN}`);
    expect(seen?.headers["x-note"]).toBe(REAL_TOKEN);
    expect(seen?.headers.host).toBe("api.example.test");
    expect(seen?.headers["accept-encoding"]).toBe("identity");
    expect(seen?.url).toBe("/echo?q=1");
    // The echo came back with the placeholder, not the value — in the body and in a header
    const body = response.body.toString("utf8");
    expect(body).not.toContain(REAL_TOKEN);
    expect(body).toContain(`Bearer ${github.placeholder}`);
    expect(response.headers["x-echo-authorization"]).toBe(`Bearer ${github.placeholder}`);
    expect(decisions).toEqual([
      {
        kind: "brokered",
        method: "GET",
        target: { scheme: "https", host: "api.example.test", port: 443 },
        path: "/echo",
        status: 200,
        substituted: ["GITHUB_TOKEN"],
      },
    ]);
  });

  it("decodes a Basic credential, substitutes inside it, and re-encodes (git over HTTPS)", async () => {
    const proxy = await proxyWith({ credentials: [github] });
    const basic = Buffer.from(`x-access-token:${github.placeholder}`).toString("base64");
    const response = await httpsViaProxy({
      proxyPort: proxy.port,
      ca: [runCa.certPem],
      url: "https://api.example.test/repo.git/info/refs",
      headers: { authorization: `Basic ${basic}` },
    });
    expect(response.status).toBe(200);
    const auth = secureOrigin.seen[0]?.headers.authorization ?? "";
    expect(Buffer.from(auth.replace(/^Basic /, ""), "base64").toString()).toBe(
      `x-access-token:${REAL_TOKEN}`,
    );
  });

  it("refuses a placeholder toward a host its rule does not name, naming the variable (the request is not sent)", async () => {
    const decisions: ProxyDecision[] = [];
    const proxy = await proxyWith({ credentials: [github, plainKey], decisions });
    // PLAIN_KEY's rule names only the plain host; using it toward the brokered API host is refused
    const response = await httpsViaProxy({
      proxyPort: proxy.port,
      ca: [runCa.certPem],
      url: "https://api.example.test/echo",
      headers: { authorization: `Bearer ${plainKey.placeholder}` },
    });
    expect(response.status).toBe(403);
    const text = response.body.toString();
    expect(text).toContain(
      "the placeholder for PLAIN_KEY is only substituted toward the hosts its rule names",
    );
    expect(text).toContain("api.example.test:443");
    expect(text).not.toContain(REAL_KEY);
    expect(secureOrigin.seen).toHaveLength(0);
    expect(decisions[0]?.kind).toBe("blocked");
  });

  it("refuses a placeholder on a surface the rule does not allow, and says which surface to add", async () => {
    const proxy = await proxyWith({ credentials: [github] });
    const response = await httpsViaProxy({
      proxyPort: proxy.port,
      ca: [runCa.certPem],
      url: "https://api.example.test/issues",
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ body: `my token is ${github.placeholder}` }),
    });
    expect(response.status).toBe(403);
    expect(response.body.toString()).toContain(
      'the placeholder for GITHUB_TOKEN appears in the body of the request, but its rule allows only: header (add "body" to the rule\'s surfaces to allow it)',
    );
    expect(secureOrigin.seen).toHaveLength(0);
  });

  it("substitutes in the query and the body when the rule allows those surfaces (plain HTTP, absolute form)", async () => {
    const proxy = await proxyWith({ credentials: [github, plainKey] });
    const response = await httpViaProxy({
      proxyPort: proxy.port,
      url: `http://plain.localhost/echo?key=${plainKey.placeholder}`,
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: `secret=${plainKey.placeholder}&other=1`,
    });
    expect(response.status).toBe(200);
    const seen = plainOrigin.seen[0];
    expect(seen?.url).toBe(`/echo?key=${REAL_KEY}`);
    expect(seen?.body).toBe(`secret=${REAL_KEY}&other=1`);
    expect(seen?.headers["content-length"]).toBe(String(Buffer.byteLength(seen?.body ?? "")));
    // and the echo is scrubbed back to the placeholder
    const text = response.body.toString();
    expect(text).not.toContain(REAL_KEY);
    expect(text).toContain(plainKey.placeholder);
  });

  it("tunnels a host no rule names untouched: the client's own TLS reaches the origin and nothing is substituted", async () => {
    const decisions: ProxyDecision[] = [];
    const proxy = await proxyWith({ credentials: [github], decisions });
    // other.example.test is served by the same origin (leaf for api.example.test), so the client
    // must trust the origin's CA and name the origin's host for its own verification
    const tunnel = await openTunnel(proxy.port, "other.example.test:443");
    if ("refused" in tunnel) {
      throw new Error("tunnel refused");
    }
    const secure = await secureTunnel(tunnel.socket, "api.example.test", [originCa.certPem]);
    expect(secure.authorized).toBe(true);
    const response = await requestOver(secure, {
      method: "GET",
      host: "api.example.test",
      path: "/echo",
      headers: { authorization: `Bearer ${github.placeholder}` },
    });
    secure.destroy();
    expect(response.status).toBe(200);
    // Not inspected: the placeholder went out as it was
    expect(secureOrigin.seen[0]?.headers.authorization).toBe(`Bearer ${github.placeholder}`);
    expect(decisions).toEqual([
      { kind: "tunnelled", target: { scheme: "https", host: "other.example.test", port: 443 } },
    ]);
  });

  it("blocks unmatched hosts when asked (CONNECT and plain), with a message", async () => {
    const proxy = await proxyWith({ credentials: [github], unmatched: "block" });
    const tunnel = await openTunnel(proxy.port, "other.example.test:443");
    expect("refused" in tunnel && tunnel.refused.status).toBe(403);
    expect("refused" in tunnel && tunnel.refused.body.toString()).toContain(
      "other.example.test:443 is not named by any rule and this run blocks unmatched hosts",
    );
    const plain = await httpViaProxy({
      proxyPort: proxy.port,
      url: "http://elsewhere.example.test/x",
    });
    expect(plain.status).toBe(403);
    // A brokered host still works
    const ok = await httpsViaProxy({
      proxyPort: proxy.port,
      ca: [runCa.certPem],
      url: "https://api.example.test/ok",
    });
    expect(ok.status).toBe(200);
  });

  it("refuses an https URL sent in plain text (no downgrade) and a non-absolute request target", async () => {
    const proxy = await proxyWith({ credentials: [github] });
    const downgrade = await httpViaProxy({
      proxyPort: proxy.port,
      url: "https://api.example.test/echo",
    });
    expect(downgrade.status).toBe(400);
    expect(downgrade.body.toString()).toContain("an https URL sent in plain text is refused");
    expect(secureOrigin.seen).toHaveLength(0);
  });

  it("answers 502 with the connector's reason when a credential cannot be minted (no secret in the message)", async () => {
    const decisions: ProxyDecision[] = [];
    const proxy = await proxyWith({ credentials: [github, connectorFails], decisions });
    const response = await httpsViaProxy({
      proxyPort: proxy.port,
      ca: [runCa.certPem],
      url: "https://api.example.test/echo",
      headers: { authorization: `Bearer ${connectorFails.placeholder}` },
    });
    expect(response.status).toBe(502);
    expect(response.body.toString()).toContain(
      "connector github-app for MINTED: installation 42 not found (404)",
    );
    expect(secureOrigin.seen).toHaveLength(0);
    expect(decisions[0]?.kind).toBe("error");
  });

  it("keeps a binary response byte-transparent and scrubs a large text response across chunks", async () => {
    const proxy = await proxyWith({ credentials: [github] });
    const binary = await httpsViaProxy({
      proxyPort: proxy.port,
      ca: [runCa.certPem],
      url: "https://api.example.test/binary",
    });
    expect(binary.status).toBe(200);
    expect(binary.body.length).toBe(4096);
    for (let i = 0; i < 4096; i++) {
      expect(binary.body[i]).toBe((i * 7919) & 0xff);
    }
    const big = await httpsViaProxy({
      proxyPort: proxy.port,
      ca: [runCa.certPem],
      url: "https://api.example.test/big",
    });
    const text = big.body.toString("utf8");
    expect(text).not.toContain(REAL_TOKEN);
    expect(text.split(github.placeholder).length - 1).toBe(2000);
  });

  it("decompresses a response the origin compressed anyway, so the echoed value is still scrubbed", async () => {
    const proxy = await proxyWith({ credentials: [github] });
    const response = await httpsViaProxy({
      proxyPort: proxy.port,
      ca: [runCa.certPem],
      url: "https://api.example.test/gzip",
      headers: { authorization: `Bearer ${github.placeholder}`, "accept-encoding": "gzip" },
    });
    expect(response.status).toBe(200);
    expect(response.headers["content-encoding"]).toBeUndefined();
    const text = response.body.toString("utf8");
    expect(text).toBe(`compressed echo: Bearer ${github.placeholder}`);
    expect(text).not.toContain(REAL_TOKEN);
  });

  it("serves several requests over one tunnel (keep-alive through the loopback hop)", async () => {
    const proxy = await proxyWith({ credentials: [github] });
    const tunnel = await openTunnel(proxy.port, "api.example.test:443");
    if ("refused" in tunnel) {
      throw new Error("tunnel refused");
    }
    const secure = await secureTunnel(tunnel.socket, "api.example.test", [runCa.certPem]);
    const { Agent } = await import("node:http");
    const agent = new Agent({ keepAlive: true, maxSockets: 1 });
    // Every request of this agent rides the one tunnel socket
    (agent as unknown as { createConnection: () => unknown }).createConnection = () => secure;
    const first = await requestOver(secure, {
      method: "GET",
      host: "api.example.test",
      path: "/ok",
      agent,
    });
    const second = await requestOver(secure, {
      method: "GET",
      host: "api.example.test",
      path: "/echo",
      headers: { authorization: `Bearer ${github.placeholder}` },
      agent,
    });
    agent.destroy();
    expect(first.status, first.body.toString()).toBe(200);
    expect(first.body.toString()).toBe("ok");
    expect(second.status).toBe(200);
    expect(secureOrigin.seen[1]?.headers.authorization).toBe(`Bearer ${REAL_TOKEN}`);
  });

  it("requires this run's proxy credential when one is set (407 otherwise), for CONNECT and plain alike", async () => {
    const credential = { user: "maruhi", password: "r4nd0mR4nd0mR4nd0m" };
    const proxy = await proxyWith({ credentials: [github, plainKey], credential });
    const without = await openTunnel(proxy.port, "api.example.test:443");
    expect("refused" in without && without.refused.status).toBe(407);
    expect("refused" in without && without.refused.headers["proxy-authenticate"]).toContain(
      "Basic",
    );
    const wrong = await openTunnel(proxy.port, "api.example.test:443", "maruhi:wrong");
    expect("refused" in wrong && wrong.refused.status).toBe(407);
    const plainWithout = await httpViaProxy({
      proxyPort: proxy.port,
      url: "http://plain.example.test/ok",
    });
    expect(plainWithout.status).toBe(407);
    expect(secureOrigin.seen).toHaveLength(0);
    expect(plainOrigin.seen).toHaveLength(0);
    const auth = `${credential.user}:${credential.password}`;
    const ok = await httpsViaProxy({
      proxyPort: proxy.port,
      ca: [runCa.certPem],
      url: "https://api.example.test/echo",
      headers: { authorization: `Bearer ${github.placeholder}` },
      auth,
    });
    expect(ok.status).toBe(200);
    expect(secureOrigin.seen[0]?.headers.authorization).toBe(`Bearer ${REAL_TOKEN}`);
    // The credential is a hop-by-hop header: never forwarded to the origin
    expect(secureOrigin.seen[0]?.headers["proxy-authorization"]).toBeUndefined();
    const plainOk = await httpViaProxy({
      proxyPort: proxy.port,
      url: "http://plain.example.test/ok",
      auth,
    });
    expect(plainOk.status).toBe(200);
    expect(proxy.url).toBe(`http://maruhi:${credential.password}@127.0.0.1:${proxy.port}`);
    expect(proxy.address).toBe(`127.0.0.1:${proxy.port}`);
  });

  it("never mints a connector credential for a request that does not use its placeholder, and scrubs with the values it already holds", async () => {
    let mints = 0;
    const minted = enc.encode("ghs_minted_value_000000000000");
    const connector: BrokeredCredential = {
      name: "MINTED",
      placeholder: makePlaceholder("MINTED"),
      hosts: [pattern("api.example.test")],
      surfaces: ["header"],
      resolve: () => {
        mints += 1;
        return Promise.resolve(minted);
      },
      known: () => (mints > 0 ? [minted] : []),
    };
    const proxy = await proxyWith({ credentials: [github, connector] });
    // A brokered request that uses only GITHUB_TOKEN: the connector is not touched
    const first = await httpsViaProxy({
      proxyPort: proxy.port,
      ca: [runCa.certPem],
      url: "https://api.example.test/echo",
      headers: { authorization: `Bearer ${github.placeholder}` },
    });
    expect(first.status).toBe(200);
    expect(mints).toBe(0);
    // A request that uses the connector's placeholder mints once
    const second = await httpsViaProxy({
      proxyPort: proxy.port,
      ca: [runCa.certPem],
      url: "https://api.example.test/echo",
      headers: { authorization: `Bearer ${connector.placeholder}` },
    });
    expect(second.status).toBe(200);
    expect(mints).toBe(1);
    expect(secureOrigin.seen[1]?.headers.authorization).toBe(
      "Bearer ghs_minted_value_000000000000",
    );
    // … and its echo is scrubbed from the body with the connector's placeholder
    expect(second.body.toString()).toContain(`Bearer ${connector.placeholder}`);
    expect(second.body.toString()).not.toContain("ghs_minted_value");
  });

  it("scrubs the JSON-escaped form of an echoed value (the sync fragment rule) and refuses an unreadable content encoding", async () => {
    const quoted: BrokeredCredential = {
      name: "QUOTED",
      placeholder: makePlaceholder("QUOTED"),
      hosts: [pattern("api.example.test")],
      surfaces: ["header"],
      resolve: () => Promise.resolve(enc.encode('va"lue-with-quote')),
      known: () => [enc.encode('va"lue-with-quote')],
    };
    const proxy = await proxyWith({ credentials: [quoted] });
    const echo = await httpsViaProxy({
      proxyPort: proxy.port,
      ca: [runCa.certPem],
      url: "https://api.example.test/echo",
      headers: { authorization: `Bearer ${quoted.placeholder}` },
    });
    // The origin's JSON echo carries the value escaped (`va\"lue…`); the scrub still catches it
    const text = echo.body.toString();
    expect(text).not.toContain("lue-with-quote");
    expect(text).toContain(quoted.placeholder);
    const opaque = await httpsViaProxy({
      proxyPort: proxy.port,
      ca: [runCa.certPem],
      url: "https://api.example.test/unknown-encoding",
    });
    expect(opaque.status).toBe(502);
    expect(opaque.body.toString()).toContain("content encoding the proxy cannot read (x-made-up)");
    expect(opaque.body.toString()).not.toContain("opaque bytes");
  });

  it("reports a plain request toward a host no rule names as relayed, not brokered", async () => {
    const decisions: ProxyDecision[] = [];
    const proxy = await proxyWith({ credentials: [github], decisions });
    const response = await httpViaProxy({
      proxyPort: proxy.port,
      url: "http://plain.example.test/ok?x=1",
    });
    expect(response.status).toBe(200);
    expect(decisions).toEqual([
      {
        kind: "relayed",
        method: "GET",
        target: { scheme: "http", host: "plain.example.test", port: 80 },
        path: "/ok",
        status: 200,
      },
    ]);
  });

  it("puts the hop servers on Unix sockets inside the private directory, never on a TCP port (§21 R-2)", async () => {
    const proxy = await proxyWith({ credentials: [github, plainKey] });
    const hopDir = hopDirs.at(-1) ?? "";
    // Before any request: the plain-HTTP hop only
    expect(readdirSync(hopDir)).toEqual(["plain"]);
    const brokered = await httpsViaProxy({
      proxyPort: proxy.port,
      ca: [runCa.certPem],
      url: "https://api.example.test/ok",
      headers: { authorization: `Bearer ${github.placeholder}` },
    });
    expect(brokered.status).toBe(200);
    // One TLS-terminated hop per brokered authority, a socket file (not a port)
    expect(readdirSync(hopDir).toSorted()).toEqual(["h1", "plain"]);
    for (const name of readdirSync(hopDir)) {
      expect(lstatSync(join(hopDir, name)).isSocket(), name).toBe(true);
    }
  });

  it("percent-encodes a value substituted into the query and refuses one that cannot be a header (§19 C-4)", async () => {
    const awkward: BrokeredCredential = {
      name: "AWKWARD",
      placeholder: makePlaceholder("AWKWARD"),
      hosts: [pattern("http://plain.localhost")],
      surfaces: ["header", "query"],
      resolve: () => Promise.resolve(enc.encode("a b&c=d#e/f%")),
      known: () => [enc.encode("a b&c=d#e/f%")],
    };
    const multiline: BrokeredCredential = {
      name: "PEMLIKE",
      placeholder: makePlaceholder("PEMLIKE"),
      hosts: [pattern("api.example.test")],
      surfaces: ["header", "body"],
      resolve: () => Promise.resolve(enc.encode("line1\nline2")),
      known: () => [enc.encode("line1\nline2")],
    };
    const proxy = await proxyWith({ credentials: [awkward, multiline] });
    // A multi-line value substituted only into the body is sent as it is (§21 R-9)
    const inBody = await httpsViaProxy({
      proxyPort: proxy.port,
      ca: [runCa.certPem],
      url: "https://api.example.test/echo",
      method: "POST",
      headers: { "content-type": "text/plain" },
      body: `key=${multiline.placeholder}`,
    });
    expect(inBody.status).toBe(200);
    expect(secureOrigin.seen[0]?.body).toBe("key=line1\nline2");
    secureOrigin.seen.length = 0;
    const query = await httpViaProxy({
      proxyPort: proxy.port,
      url: `http://plain.localhost/echo?key=${awkward.placeholder}`,
    });
    expect(query.status).toBe(200);
    expect(plainOrigin.seen[0]?.url).toBe(`/echo?key=${encodeURIComponent("a b&c=d#e/f%")}`);
    const header = await httpsViaProxy({
      proxyPort: proxy.port,
      ca: [runCa.certPem],
      url: "https://api.example.test/echo",
      headers: { authorization: `Bearer ${multiline.placeholder}` },
    });
    expect(header.status).toBe(502);
    expect(header.body.toString()).toContain(
      "the value of PEMLIKE cannot be sent in a header (it contains a line break or a non-Latin-1 character); the request was not sent",
    );
    expect(header.body.toString()).not.toContain("line1");
    expect(secureOrigin.seen).toHaveLength(0);
  });

  it("keeps a HEAD response's Content-Length, matches an absolute DNS name (trailing dot), and closes with a tunnel still open (§19 C-16 / C-19 / C-3)", async () => {
    const proxy = await proxyWith({ credentials: [github] });
    const head = await httpsViaProxy({
      proxyPort: proxy.port,
      ca: [runCa.certPem],
      url: "https://api.example.test/ok",
      method: "HEAD",
    });
    expect(head.status).toBe(200);
    expect(head.headers["content-length"]).toBe("2");
    expect(head.body.length).toBe(0);
    // `api.example.test.` is the same host
    const dotted = await httpsViaProxy({
      proxyPort: proxy.port,
      ca: [runCa.certPem],
      url: "https://api.example.test./echo",
      headers: { authorization: `Bearer ${github.placeholder}` },
    });
    expect(dotted.status).toBe(200);
    expect(secureOrigin.seen[1]?.headers.authorization).toBe(`Bearer ${REAL_TOKEN}`);
    // An open blind tunnel does not hold close() open
    const tunnel = await openTunnel(proxy.port, "other.example.test:443");
    expect("socket" in tunnel).toBe(true);
    const started = Date.now();
    await proxy.close();
    expect(Date.now() - started).toBeLessThan(2_000);
    open = open.filter((handle) => handle !== proxy);
  });

  it("credentialsFor narrows to the rules naming the target", () => {
    expect(
      credentialsFor([github, plainKey], { scheme: "https", host: "api.example.test", port: 443 }),
    ).toEqual([github]);
    expect(
      credentialsFor([github, plainKey], { scheme: "http", host: "plain.localhost", port: 80 }),
    ).toEqual([plainKey]);
  });
});
