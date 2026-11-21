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

  c.push(
    "encoding: number equals decimal string form",
    toHex(encodeLengthPrefixed(["epoch", 42])) === toHex(encodeLengthPrefixed(["epoch", "42"])),
  );

  for (const bad of [1.5, Number.MAX_SAFE_INTEGER + 1, -1]) {
    let rejected = false;
    try {
      encodeLengthPrefixed(["epoch", bad]);
    } catch (error) {
      rejected = error instanceof TypeError;
    }
    c.push(`encoding: rejects non-canonical number field (${bad})`, rejected);
  }
  c.push(
    "encoding: MAX_SAFE_INTEGER equals its decimal string form",
    toHex(encodeLengthPrefixed([Number.MAX_SAFE_INTEGER])) ===
      toHex(encodeLengthPrefixed([String(Number.MAX_SAFE_INTEGER)])),
  );

  c.push(
    "encoding: Uint8Array field embeds raw bytes",
    toHex(encodeLengthPrefixed([new Uint8Array([0xab, 0xcd])])) === "00000002abcd",
  );

  c.push("hex: roundtrip", toHex(fromHex("00ff10ab")) === "00ff10ab");
  c.push(
    "hex: malformed rejected",
    decodeHex("0") === null && decodeHex("zz") === null && decodeHex("AB") === null,
  );

  return c.results;
}
