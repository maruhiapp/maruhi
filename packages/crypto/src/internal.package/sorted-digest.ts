import { encodeHex, utf8Encode } from "./bytes.ts";
import { encodeLengthPrefixed, type LengthPrefixedField } from "./encoding.ts";
import type { CryptoResult } from "./errors.ts";
import { sha256 } from "./hash.ts";
import { invalidInput } from "./validate.ts";

function compareUtf8Bytes(a: string, b: string): number {
  const bytesA = utf8Encode(a);
  const bytesB = utf8Encode(b);
  const length = Math.min(bytesA.length, bytesB.length);
  for (let i = 0; i < length; i += 1) {
    const delta = (bytesA[i] ?? 0) - (bytesB[i] ?? 0);
    if (delta !== 0) {
      return delta;
    }
  }
  return bytesA.length - bytesB.length;
}

export async function computeVariableKeyedDigest<Entry>(spec: {
  readonly suite: string;
  readonly domain: string;
  readonly entries: readonly Entry[];
  readonly variableIdOf: (entry: Entry) => string;
  readonly entryInvalidField: (entry: Entry) => string | null;
  readonly entryFields: (entry: Entry) => readonly LengthPrefixedField[];
}): Promise<CryptoResult<string>> {
  if (spec.suite.length === 0) {
    return invalidInput("suite");
  }
  const seen = new Set<string>();
  for (const entry of spec.entries) {
    const field = spec.entryInvalidField(entry);
    if (field !== null) {
      return invalidInput(field);
    }
    const variableId = spec.variableIdOf(entry);
    if (seen.has(variableId)) {
      return invalidInput("entry variableId (duplicate)");
    }
    seen.add(variableId);
  }
  const ordered = spec.entries.toSorted((a, b) =>
    compareUtf8Bytes(spec.variableIdOf(a), spec.variableIdOf(b)),
  );
  const fields: LengthPrefixedField[] = [`${spec.suite}/${spec.domain}`];
  for (const entry of ordered) {
    fields.push(encodeLengthPrefixed(spec.entryFields(entry)));
  }
  return { ok: true, value: encodeHex(await sha256(encodeLengthPrefixed(fields))) };
}
