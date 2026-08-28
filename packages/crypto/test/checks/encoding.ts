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

  // 数値境界(§2.1 / session-31 M1-T2): 10 進文字列化の対象は非負の安全整数のみ。
  // 非整数(1.5)・MAX_SAFE_INTEGER + 1(float64 の精度喪失域 — 10 進文字列化が
  // 一意でない)・負数は TypeError で拒否する(JSON ベクターで表現しない分担は
  // docs/notes/session-34.md の裁定)
  for (const bad of [1.5, Number.MAX_SAFE_INTEGER + 1, -1]) {
    let rejected = false;
    try {
      encodeLengthPrefixed(["epoch", bad]);
    } catch (error) {
      rejected = error instanceof TypeError;
    }
    c.push(`encoding: rejects non-canonical number field (${bad})`, rejected);
  }
  // 上界の内側(MAX_SAFE_INTEGER 自身)は一意な 10 進文字列化を持ち受理される
  c.push(
    "encoding: MAX_SAFE_INTEGER equals its decimal string form",
    toHex(encodeLengthPrefixed([Number.MAX_SAFE_INTEGER])) ===
      toHex(encodeLengthPrefixed([String(Number.MAX_SAFE_INTEGER)])),
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
