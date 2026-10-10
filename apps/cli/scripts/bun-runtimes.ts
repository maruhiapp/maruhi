// The Bun runtimes embedded in the release binaries. build-binaries.ts hands
// each one to `bun build --compile --compile-executable-path`; without it,
// `--compile` copies the running bun for the host target and downloads the
// other targets' runtimes from npm, with no digest pinned in this repository.
//
// Bumping Bun changes BUN_RUNTIME_VERSION and every sha256 here together with
// `.bun-version` and scripts/install-bun.sh (whose linux-x64 pin is the same
// zip; apps/cli/test/workflows-supply-chain.test.ts fails until all of them
// agree). Each sha256 is the line for `zip` in the release's clearsigned
// SHASUMS256.txt.asc, checked by the gpgv procedure in that script's header,
// then picked with:
//   grep -E ' bun-(linux-x64|linux-aarch64|darwin-x64|darwin-aarch64|windows-x64)\.zip$' shasums.txt

import { createHash } from "node:crypto";

import type { TARGETS } from "./shared.ts";

type BunTarget = (typeof TARGETS)[number]["bunTarget"];

interface BunRuntime {
  /** The release asset, as named in SHASUMS256.txt. */
  readonly zip: string;
  /** The executable's path inside the zip. */
  readonly member: string;
  readonly sha256: string;
}

export const BUN_RUNTIME_VERSION = "1.4.2";

export const BUN_RUNTIMES: Readonly<Record<BunTarget, BunRuntime>> = {
  "bun-linux-x64": {
    zip: "bun-linux-x64.zip",
    member: "bun-linux-x64/bun",
    sha256: "36368faef7527875d5ffa52e53cd48021741f2a83eb6208a8dd64068d422a913",
  },
  "bun-linux-arm64": {
    zip: "bun-linux-aarch64.zip",
    member: "bun-linux-aarch64/bun",
    sha256: "54328bbc2d9c8e0c9f892c544d66c57a83b84139e34909e5ee81758f1ac8fda7",
  },
  "bun-darwin-x64": {
    zip: "bun-darwin-x64.zip",
    member: "bun-darwin-x64/bun",
    sha256: "80520d7e17526308c9185d261679ac6d27798d3803a0e9f7ff9121ab8affb012",
  },
  "bun-darwin-arm64": {
    zip: "bun-darwin-aarch64.zip",
    member: "bun-darwin-aarch64/bun",
    sha256: "90987a3a16d7db556d886ac3d551e7b6d3edf0a1cf43acaed622e8676be1d12f",
  },
  "bun-windows-x64": {
    zip: "bun-windows-x64.zip",
    member: "bun-windows-x64/bun.exe",
    sha256: "ce4c17497b2f29712a99d3d53f028de28cd42e3bacb8589599e7f000e49b6405",
  },
};

export const runtimeUrl = (runtime: BunRuntime): string =>
  `https://github.com/oven-sh/bun/releases/download/bun-v${BUN_RUNTIME_VERSION}/${runtime.zip}`;

/** Downloads `url` and returns its bytes only when they match `sha256`; nothing is written. */
export async function downloadVerified(
  url: string,
  sha256: string,
  fetchFn: typeof fetch = fetch,
): Promise<Uint8Array> {
  const response = await fetchFn(url);
  if (!response.ok) {
    throw new Error(`${url}: HTTP ${response.status}`);
  }
  const bytes = new Uint8Array(await response.arrayBuffer());
  const actual = createHash("sha256").update(bytes).digest("hex");
  if (actual !== sha256) {
    throw new Error(`${url}: SHA-256 ${actual} does not match the pinned ${sha256}`);
  }
  return bytes;
}
