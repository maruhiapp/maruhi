// Probe that runs the forward proxy (proxy-server.ts) **under Bun** — the
// production runtime — and drives it with real clients: curl (the
// OpenSSL-based client most tools resemble), Bun's own fetch behind
// `proxy` + `tls.ca`, and a shell child spawned through the production
// ProcessRunner with the control environment `proxy run` builds. vitest
// runs on Node, so live-proxy.test.ts launches this script with `bun` and
// reads one JSON line from stdout.
//
// Under test: the TLS-wrap + loopback shape works under Bun's node:tls /
// node:http (the probe that chose it — pf4-design.md P2), substitution
// toward the brokered host, the blind tunnel toward another host, and
// that a child honouring HTTPS_PROXY / SSL_CERT_FILE reaches the origin
// with the real value while holding only the placeholder.

import { mkdtemp, rm, writeFile } from "node:fs/promises";
import http from "node:http";
import https from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import tls from "node:tls";

import { Effect } from "effect";

import { liveLayer } from "../../src/live.ts";
import { makeEphemeralCa } from "../../src/proxy-cert.ts";
import { parseHostPattern } from "../../src/proxy-config.ts";
import { makePlaceholder } from "../../src/proxy-rules.ts";
import { proxyControlEnv } from "../../src/proxy-run.ts";
import { startProxy } from "../../src/proxy-server.ts";
import { ProcessRunner } from "../../src/run.ts";

const REAL = "ghp_probe_real_value_0123456789";
const enc = new TextEncoder();

function pattern(text: string) {
  const parsed = parseHostPattern(text);
  if (typeof parsed === "string") {
    throw new Error(parsed);
  }
  return parsed;
}

const runCa = await makeEphemeralCa();
const originCa = await makeEphemeralCa();
const leaf = await originCa.issue("api.example.test");

// The origin: echoes the authorization header and the path
const seen: string[] = [];
const origin = https.createServer({ key: leaf.keyPem, cert: leaf.certPem }, (req, res) => {
  seen.push(`${req.method} ${req.url} auth=${req.headers.authorization ?? "none"}`);
  res.setHeader("content-type", "text/plain");
  res.end(`origin saw auth=${req.headers.authorization ?? "none"}`);
});
await new Promise<void>((resolve) => origin.listen(0, "127.0.0.1", () => resolve()));
const originPort = (origin.address() as AddressInfo).port;

const dir = await mkdtemp(join(tmpdir(), "maruhi-proxy-probe-"));
const placeholder = makePlaceholder("GITHUB_TOKEN");
const proxy = await startProxy({
  hopDir: dir,
  credentials: [
    {
      name: "GITHUB_TOKEN",
      placeholder,
      hosts: [pattern("api.example.test")],
      surfaces: ["header"],
      resolve: () => Promise.resolve(enc.encode(REAL)),
      known: () => [enc.encode(REAL)],
    },
  ],
  // The production shape: a per-run credential carried in the proxy URL (curl and Bun fetch read it from there)
  credential: { user: "maruhi", password: "probe-credential-0123456789" },
  unmatched: "allow",
  ca: runCa,
  upstream: {
    connect: () => ({ host: "127.0.0.1", port: originPort }),
    ca: [originCa.certPem],
  },
});

const caPath = join(dir, "ca.pem");
const bundlePath = join(dir, "bundle.pem");
await writeFile(caPath, runCa.certPem);
await writeFile(bundlePath, `${tls.rootCertificates.join("\n")}\n${runCa.certPem}`);

// 1. Bun fetch behind the proxy, trusting the run's CA
const bunFetch = await fetch("https://api.example.test/bun", {
  headers: { authorization: `Bearer ${placeholder}` },
  proxy: proxy.url,
  tls: { ca: runCa.certPem },
} as RequestInit).then((r) => r.text());

// 2. A blind tunnel: another host, verified by the client against the origin's CA
const tunnelled = await fetch("https://other.example.test/tunnel", {
  headers: { authorization: `Bearer ${placeholder}`, host: "api.example.test" },
  proxy: proxy.url,
  tls: { ca: originCa.certPem, rejectUnauthorized: false },
} as RequestInit)
  .then((r) => r.text())
  .catch((error: Error) => `ERR ${error.message}`);

// 3. curl, as a child of the production ProcessRunner with the control environment
const control = proxyControlEnv({ proxyUrl: proxy.url, bundlePath, caPath });
const curlOutput = join(dir, "curl.out");
const program = Effect.gen(function* () {
  const runner = yield* ProcessRunner;
  return yield* runner.run({
    command: [
      "sh",
      "-c",
      `curl -sS -H "Authorization: Bearer $GITHUB_TOKEN" https://api.example.test/curl > "${curlOutput}" 2>&1; echo "exit=$?" >> "${curlOutput}"`,
    ],
    extraEnv: { ...control, GITHUB_TOKEN: placeholder },
    holdSignals: true,
  });
});
const curlExit = await Effect.runPromise(program.pipe(Effect.provide(liveLayer())));
const curlText = await Bun.file(curlOutput).text();

// 4. A plain-HTTP absolute-form request through the proxy (Node http client under Bun)
const plain = await new Promise<string>((resolve) => {
  const request = http.request(
    {
      host: "127.0.0.1",
      port: proxy.port,
      method: "GET",
      path: "http://plain.example.test/x",
      headers: { host: "plain.example.test" },
    },
    (response) => {
      let text = "";
      response.on("data", (chunk: Buffer) => {
        text += chunk.toString();
      });
      response.on("end", () => resolve(`${response.statusCode} ${text}`));
    },
  );
  request.on("error", (error) => resolve(`ERR ${error.message}`));
  request.end();
});

await proxy.close();
origin.close();
await rm(dir, { recursive: true, force: true });

console.log(JSON.stringify({ bunFetch, tunnelled, curlExit, curlText, plain, seen, placeholder }));
