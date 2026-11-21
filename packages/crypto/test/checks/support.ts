import { decodeHex, encodeHex } from "../../src/index.ts";

export interface CheckResult {
  readonly name: string;
  readonly ok: boolean;
  readonly detail?: string;
}

export function toHex(bytes: Uint8Array): string {
  return encodeHex(bytes);
}

export function fromHex(s: string): Uint8Array {
  const bytes = decodeHex(s);
  if (bytes === null) {
    throw new Error(`test vector contains malformed hex: ${s.slice(0, 16)}…`);
  }
  return bytes;
}

export class Checks {
  readonly results: CheckResult[] = [];

  push(name: string, ok: boolean, detail?: string): void {
    this.results.push({ name, ok, ...(detail === undefined ? {} : { detail }) });
  }
}

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

export function reasonCoverageChecks<R extends string>(
  c: Checks,
  label: string,
  coverage: Record<R, true>,
  exercised: ReadonlySet<R>,
): void {
  for (const reason of Object.keys(coverage) as unknown as readonly R[]) {
    c.push(`${label} reason coverage: ${reason} is exercised by a negative`, exercised.has(reason));
  }
}
