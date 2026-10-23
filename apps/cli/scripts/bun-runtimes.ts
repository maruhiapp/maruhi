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

export const BUN_RUNTIME_VERSION = "1.4.4";

export const BUN_RUNTIMES: Readonly<Record<BunTarget, BunRuntime>> = {
  "bun-linux-x64": {
    zip: "bun-linux-x64.zip",
    member: "bun-linux-x64/bun",
    sha256: "bf8ccbfb2b0b80159e0f9a6d15c55317add8077534dbc6130a3edb52fccb395c",
  },
  "bun-linux-arm64": {
    zip: "bun-linux-aarch64.zip",
    member: "bun-linux-aarch64/bun",
    sha256: "baa6bb36f51d6e58561e02bbea825038a9df454f673d6d776e8bbf86f8c7850e",
  },
  "bun-darwin-x64": {
    zip: "bun-darwin-x64.zip",
    member: "bun-darwin-x64/bun",
    sha256: "50a3491f73abc2fe81673171a85762d3bc2cc1680ccecadd983de99adf77977e",
  },
  "bun-darwin-arm64": {
    zip: "bun-darwin-aarch64.zip",
    member: "bun-darwin-aarch64/bun",
    sha256: "c240d7f0ccb90c263a849fcdb09b7ee62630d921348ed6aafda86b9d577bc510",
  },
  "bun-windows-x64": {
    zip: "bun-windows-x64.zip",
    member: "bun-windows-x64/bun.exe",
    sha256: "cd2c0fccc78f3ede1f50ca827a15f063eda13d4d150a3d0674f4f6e323d864a5",
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
