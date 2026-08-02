// CRYPTO_SPEC §2.1 のエンコーダを test-vectors/encoding.json で固定するチェック。

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

  // 数値は 10 進文字列化と同一バイト列(§2.1)
  c.push(
    "encoding: number equals decimal string form",
    toHex(encodeLengthPrefixed(["epoch", 42])) === toHex(encodeLengthPrefixed(["epoch", "42"])),
  );

  // Uint8Array フィールドはそのまま載る(チェーン正規化の payload_bytes 埋め込みで使う)
  c.push(
    "encoding: Uint8Array field embeds raw bytes",
    toHex(encodeLengthPrefixed([new Uint8Array([0xab, 0xcd])])) === "00000002abcd",
  );

  // hex 変換(公開 API): 小文字ラウンドトリップ、不正入力・大文字は null
  c.push("hex: roundtrip", toHex(fromHex("00ff10ab")) === "00ff10ab");
  c.push(
    "hex: malformed rejected",
    decodeHex("0") === null && decodeHex("zz") === null && decodeHex("AB") === null,
  );

  return c.results;
}
