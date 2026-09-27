// Check pinning the CRYPTO_SPEC §2.1 encoder against test-vectors/encoding.json.

import { decodeHex, encodeLengthPrefixed } from "../../src/index.ts";
import encodingVectors from "../../test-vectors/encoding.json" with { type: "json" };
import { type CheckResult, Checks, fromHex, toHex } from "./support.ts";

interface EncodingCase {
  readonly name: string;
  readonly fields: readonly string[];
  readonly expected_hex: string;
}

export async function encodingChecks(): Promise<CheckResult[]> {
  const c = new Checks();
  const cases = encodingVectors.cases as readonly EncodingCase[];

  for (const v of cases) {
    c.push(`encoding: ${v.name}`, toHex(encodeLengthPrefixed(v.fields)) === v.expected_hex);
  }

  // Numbers produce the same byte string as their decimal stringification (§2.1)
  c.push(
    "encoding: number equals decimal string form",
    toHex(encodeLengthPrefixed(["epoch", 42])) === toHex(encodeLengthPrefixed(["epoch", "42"])),
  );

  // Numeric bounds (§2.1): only non-negative safe integers are subject to
  // decimal stringification. Non-integers (1.5), MAX_SAFE_INTEGER + 1 (the
  // float64 precision-loss region — decimal stringification is not unique
  // there), and negatives are rejected with TypeError (the split that keeps
  // this out of the JSON vectors is the ruling in docs/notes/session-34.md)
  for (const bad of [1.5, Number.MAX_SAFE_INTEGER + 1, -1]) {
    let rejected = false;
    try {
      encodeLengthPrefixed(["epoch", bad]);
    } catch (error) {
      rejected = error instanceof TypeError;
    }
    c.push(`encoding: rejects non-canonical number field (${bad})`, rejected);
  }
  // The inside of the upper bound (MAX_SAFE_INTEGER itself) has a unique
  // decimal stringification and is accepted
  c.push(
    "encoding: MAX_SAFE_INTEGER equals its decimal string form",
    toHex(encodeLengthPrefixed([Number.MAX_SAFE_INTEGER])) ===
      toHex(encodeLengthPrefixed([String(Number.MAX_SAFE_INTEGER)])),
  );

  // Uint8Array fields ride as-is (used for payload_bytes embedding in chain canonicalization)
  c.push(
    "encoding: Uint8Array field embeds raw bytes",
    toHex(encodeLengthPrefixed([new Uint8Array([0xab, 0xcd])])) === "00000002abcd",
  );

  // hex conversion (public API): lowercase round-trip; malformed input and uppercase return null
  c.push("hex: roundtrip", toHex(fromHex("00ff10ab")) === "00ff10ab");
  c.push(
    "hex: malformed rejected",
    decodeHex("0") === null && decodeHex("zz") === null && decodeHex("AB") === null,
  );

  return c.results;
}
