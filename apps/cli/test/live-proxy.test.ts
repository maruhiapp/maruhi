// Pins the forward proxy under the production runtime (Bun) with real
// clients — curl through the production ProcessRunner with the control
// environment of `proxy run`, Bun's fetch, and a blind tunnel. vitest runs
// on Node, so the proxy is exercised via a probe launched under `bun`
// (support/proxy-probe.ts), the same trick as live-exec.test.ts.

import { spawnSync } from "node:child_process";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

const PROBE = join(import.meta.dirname, "support", "proxy-probe.ts");

interface ProbeResult {
  readonly bunFetch: string;
  readonly tunnelled: string;
  readonly curlExit: number;
  readonly curlText: string;
  readonly plain: string;
  readonly seen: readonly string[];
  readonly placeholder: string;
}

describe("the forward proxy (live — Bun runtime, real clients)", () => {
  it("brokers for Bun fetch and curl with the proxy credential from the URL, tunnels another host untouched, and refuses an unauthenticated plain request", () => {
    const result = spawnSync("bun", [PROBE], {
      encoding: "utf8",
      timeout: 60_000,
      // Nothing of this process's proxy settings may reach the probe
      env: {
        ...process.env,
        HTTP_PROXY: "",
        HTTPS_PROXY: "",
        http_proxy: "",
        https_proxy: "",
        NO_PROXY: "",
        no_proxy: "",
      },
    });
    expect(result.status, result.stderr).toBe(0);
    const lines = result.stdout.trim().split("\n");
    const probe = JSON.parse(lines[lines.length - 1] ?? "") as ProbeResult;
    // Bun fetch: placeholder out, real value at the origin, placeholder back in the echo
    expect(probe.bunFetch).toBe(`origin saw auth=Bearer ${probe.placeholder}`);
    expect(probe.seen).toContain(`GET /bun auth=Bearer ghp_probe_real_value_0123456789`);
    // The blind tunnel: not inspected, the placeholder reached the origin as it was
    expect(probe.tunnelled).toBe(`origin saw auth=Bearer ${probe.placeholder}`);
    expect(probe.seen).toContain(`GET /tunnel auth=Bearer ${probe.placeholder}`);
    // curl (OpenSSL) as a child with the control environment only
    expect(probe.curlExit).toBe(0);
    expect(probe.curlText).toContain(`origin saw auth=Bearer ${probe.placeholder}`);
    expect(probe.curlText).toContain("exit=0");
    expect(probe.seen).toContain(`GET /curl auth=Bearer ghp_probe_real_value_0123456789`);
    // A plain request without the run's proxy credential is refused before anything else
    expect(probe.plain).toMatch(
      /^407 maruhi proxy: this run's proxy credential is missing or wrong/,
    );
  }, 60_000);
});
