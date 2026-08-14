// CRYPTO_SPEC §3(FP のワード表示 = BIP39 英語 12 語)のチェック。
//
// 辞書の完全性(3 層):
//   (1) 既知ハッシュの固定 — 2048 語を「word\n」連結で再構成した canonical
//       english.txt の SHA-256 が upstream(bitcoin/bips)の既知値と一致する
//   (2) BIP39 公式テストベクター(Trezor 由来)の 128-bit エントロピー 4 件 —
//       符号化ロジック自体の独立検証(チェックサムのビット位置まで固定される)
//   (3) 構造不変条件 — 2048 語・重複なし・昇順・^[a-z]+$・先頭 4 文字の一意性
// 加えて、chain-entries.json / dek-wrap.json のサーバー鍵 FP の期待語列を
// 第三の独立実装(python-mnemonic)で計算した値と一致させる(仕様の照合対象 —
// §9 の grant 儀式 — と同じ入力での固定)。

import {
  BIP39_ENGLISH_WORDS,
  FINGERPRINT_WORD_COUNT,
  fingerprintToWords,
} from "../../src/index.ts";
import chainVectors from "../../test-vectors/chain-entries.json" with { type: "json" };
import dekWrapVectors from "../../test-vectors/dek-wrap.json" with { type: "json" };
import { type CheckResult, Checks, fromHex, toHex } from "./support.ts";

// upstream english.txt(2048 行・各行 "word\n")の SHA-256(bitcoin/bips)
const UPSTREAM_WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";

// BIP39 公式テストベクター(128-bit エントロピー = FP と同じ 16 バイト形)
const OFFICIAL_VECTORS: readonly { readonly entropyHex: string; readonly words: string }[] = [
  {
    entropyHex: "00000000000000000000000000000000",
    words:
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  },
  {
    entropyHex: "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
    words: "legal winner thank year wave sausage worth useful legal winner thank yellow",
  },
  {
    entropyHex: "80808080808080808080808080808080",
    words: "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
  },
  {
    entropyHex: "ffffffffffffffffffffffffffffffff",
    words: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
  },
];

// サーバー鍵 FP の期待語列(python-mnemonic で独立計算した固定値)
const SERVER_FP_VECTORS: readonly {
  readonly name: string;
  readonly fpHex: string;
  readonly words: string;
}[] = [
  {
    name: "chain-entries server_key",
    fpHex: chainVectors.server_key.key_fingerprint_hex,
    words: "excite will story level neglect vocal amount tennis jewel aspect observe crystal",
  },
  {
    name: "dek-wrap server_keypair",
    fpHex: dekWrapVectors.server_keypair.server_key_fingerprint_hex,
    words: "virtual priority truck defense smart armed palm balcony raven casual shop present",
  },
];

async function wordlistIntegrityChecks(c: Checks): Promise<void> {
  const canonical = `${BIP39_ENGLISH_WORDS.join("\n")}\n`;
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical)),
  );
  c.push("fp-words: wordlist sha256 matches upstream", toHex(digest) === UPSTREAM_WORDLIST_SHA256);
  c.push("fp-words: wordlist has 2048 entries", BIP39_ENGLISH_WORDS.length === 2048);
  c.push(
    "fp-words: wordlist entries are unique",
    new Set(BIP39_ENGLISH_WORDS).size === BIP39_ENGLISH_WORDS.length,
  );
  c.push(
    "fp-words: wordlist is codepoint-ascending",
    BIP39_ENGLISH_WORDS.every(
      (word, index) => index === 0 || (BIP39_ENGLISH_WORDS[index - 1] ?? "") < word,
    ),
  );
  c.push(
    "fp-words: wordlist entries are lowercase ascii",
    BIP39_ENGLISH_WORDS.every((word) => /^[a-z]+$/.test(word)),
  );
  // BIP39 の性質: 先頭 4 文字だけで語が一意に定まる(口頭照合の誤り耐性の根拠)
  c.push(
    "fp-words: first four letters are unique",
    new Set(BIP39_ENGLISH_WORDS.map((word) => word.slice(0, 4))).size ===
      BIP39_ENGLISH_WORDS.length,
  );
}

async function officialVectorChecks(c: Checks): Promise<void> {
  for (const vector of OFFICIAL_VECTORS) {
    const words = await fingerprintToWords(fromHex(vector.entropyHex));
    c.push(
      `fp-words: official vector ${vector.entropyHex.slice(0, 8)}…`,
      words.ok &&
        words.value.length === FINGERPRINT_WORD_COUNT &&
        words.value.join(" ") === vector.words,
    );
  }
}

async function serverFingerprintChecks(c: Checks): Promise<void> {
  for (const vector of SERVER_FP_VECTORS) {
    const words = await fingerprintToWords(fromHex(vector.fpHex));
    c.push(`fp-words: ${vector.name}`, words.ok && words.value.join(" ") === vector.words);
  }
}

async function invalidInputChecks(c: Checks): Promise<void> {
  // 16 バイト以外は InvalidInput(throw しない)
  for (const length of [0, 15, 17, 32]) {
    const result = await fingerprintToWords(new Uint8Array(length));
    c.push(
      `fp-words: length ${length} rejected`,
      !result.ok && result.error.kind === "InvalidInput",
    );
  }
}

export async function fingerprintWordsChecks(): Promise<CheckResult[]> {
  const c = new Checks();
  await wordlistIntegrityChecks(c);
  await officialVectorChecks(c);
  await serverFingerprintChecks(c);
  await invalidInputChecks(c);
  return c.results;
}
