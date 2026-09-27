// Checks for CRYPTO_SPEC §3 (the FP word display = 12 BIP39 English words).
//
// Wordlist integrity (3 layers):
//   (1) Known-hash pin — the SHA-256 of the canonical english.txt reconstructed
//       by joining the 2048 words as "word\n" matches the known upstream
//       (bitcoin/bips) value
//   (2) 4 entries of the official BIP39 test vectors (sourced from Trezor) at
//       128-bit entropy — an independent verification of the encoding logic
//       itself (pinned down to the checksum bit positions)
//   (3) Structural invariants — 2048 words, no duplicates, ascending order,
//       ^[a-z]+$, uniqueness of the first 4 letters
// In addition, the expected word sequences of the server key FPs in
// chain-entries.json / dek-wrap.json are matched against values computed by a
// third independent implementation (python-mnemonic) — a pin on the same input
// as the spec's comparison target (the §9 grant ceremony).

import {
  BIP39_ENGLISH_WORDS,
  FINGERPRINT_WORD_COUNT,
  fingerprintToWords,
} from "../../src/index.ts";
import chainVectors from "../../test-vectors/chain-entries.json" with { type: "json" };
import dekWrapVectors from "../../test-vectors/dek-wrap.json" with { type: "json" };
import { type CheckResult, Checks, fromHex, toHex } from "./support.ts";

// SHA-256 of the upstream english.txt (2048 lines, each "word\n") (bitcoin/bips)
const UPSTREAM_WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";

// Official BIP39 test vectors (128-bit entropy = the same 16-byte shape as an FP)
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

// Expected word sequences of the server key FPs (fixed values computed independently with python-mnemonic)
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
  // BIP39 property: the first 4 letters uniquely determine a word (the basis of error tolerance in verbal comparison)
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
  // Anything other than 16 bytes is InvalidInput (does not throw)
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
