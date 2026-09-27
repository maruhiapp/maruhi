// Environment-independent check infrastructure. The same checks are invoked
// from both vitest (node / workerd / browser) and direct Bun execution
// (test/run-in-bun.ts).

import { decodeHex, encodeHex } from "../../src/index.ts";

export interface CheckResult {
  readonly name: string;
  readonly ok: boolean;
  readonly detail?: string;
}

export function toHex(bytes: Uint8Array): string {
  return encodeHex(bytes);
}

/** Decodes test-vector hex (trusted fixed input). Throws on malformed input. */
export function fromHex(s: string): Uint8Array {
  const bytes = decodeHex(s);
  if (bytes === null) {
    throw new Error(`test vector contains malformed hex: ${s.slice(0, 16)}…`);
  }
  return bytes;
}

/** Small collector for accumulating check results */
export class Checks {
  readonly results: CheckResult[] = [];

  push(name: string, ok: boolean, detail?: string): void {
    this.results.push({ name, ok, ...(detail === undefined ? {} : { detail }) });
  }
}

/**
 * Checks that the rejection reason matches the expectation, and records a
 * matching reason into the exercised set (viewpoint 7 — exhaustive pinning of
 * the reason space; shared by the negative sieves of meta / value / manifest).
 * `rejectedReason` is passed pre-narrowed by the caller to "the reason when
 * rejected with the expected kind, otherwise undefined" (the discriminated
 * union of kinds differs per layer).
 */
export function expectRejectedReason<R extends string>(
  c: Checks,
  name: string,
  rejectedReason: R | undefined,
  expectedReason: string | undefined,
  exercised: Set<R>,
  detail?: string,
): void {
  const rejected = rejectedReason !== undefined && rejectedReason === expectedReason;
  if (rejectedReason !== undefined && rejected) {
    exercised.add(rejectedReason);
  }
  c.push(name, rejected, detail);
}

/**
 * Checks that every member of the reason union is actually exercised by at
 * least one negative (viewpoint 7). The Record type of coverage forces sync
 * with the union at compile time, catching "implemented a new rejection rule
 * but there is no negative case" via type + test.
 */
export function reasonCoverageChecks<R extends string>(
  c: Checks,
  label: string,
  coverage: Record<R, true>,
  exercised: ReadonlySet<R>,
): void {
  // Object.keys returns string[], but the keys of Record<R, true> are only R
  // (a direct conversion is TS2352, so it goes through unknown)
  for (const reason of Object.keys(coverage) as unknown as readonly R[]) {
    c.push(`${label} reason coverage: ${reason} is exercised by a negative`, exercised.has(reason));
  }
}
