import { Redacted } from "effect";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

const SECRET_BYTES = 32;
const SYMBOL_COUNT = Math.ceil((SECRET_BYTES * 8) / 5);
const GROUP_SIZE = 4;

export function formatRecoveryCode(
  redactedSecret: Redacted.Redacted<Uint8Array>,
): Redacted.Redacted<string> {
  const secret = Redacted.value(redactedSecret);
  if (secret.length !== SECRET_BYTES) {
    throw new Error("recovery secret must be 32 bytes");
  }
  let bits = 0;
  let acc = 0;
  let symbols = "";
  for (const byte of secret) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      symbols += ALPHABET[(acc >> bits) & 0b11111];
      acc &= (1 << bits) - 1;
    }
  }
  if (bits > 0) {
    symbols += ALPHABET[(acc << (5 - bits)) & 0b11111];
  }
  const groups: string[] = [];
  for (let i = 0; i < symbols.length; i += GROUP_SIZE) {
    groups.push(symbols.slice(i, i + GROUP_SIZE));
  }
  return Redacted.make(groups.join("-"), { label: "recovery-code" });
}

export function parseRecoveryCode(text: string): Redacted.Redacted<Uint8Array> | null {
  const symbols = text.replace(/[\s-]/g, "").toUpperCase();
  if (symbols.length !== SYMBOL_COUNT) {
    return null;
  }
  const out = new Uint8Array(SECRET_BYTES);
  let bits = 0;
  let acc = 0;
  let offset = 0;
  for (const symbol of symbols) {
    const value = ALPHABET.indexOf(symbol);
    if (value < 0) {
      return null;
    }
    acc = (acc << 5) | value;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out[offset] = (acc >> bits) & 0xff;
      offset += 1;
      acc &= (1 << bits) - 1;
    }
  }
  if (acc !== 0) {
    return null;
  }
  return Redacted.make(out, { label: "recovery-secret" });
}
