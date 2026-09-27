// Schema helpers for fixed-length lowercase hex strings, plus the single
// point where domain-named aliases are defined (shared by the chain, the
// data plane, and auth).
//
// Naming convention: things that agree in both meaning and width merge
// into one name (SHA-256 hash = Sha256Hex, key fingerprint =
// KeyFingerprintHex); things that share a width but differ in meaning
// (a public key vs a hash, signatures over different signed domains)
// keep their domain names. Hex alias definitions are centralized in this
// file so multiple names for the same entity do not proliferate across
// files (single-use lengths — nonces, wrap ciphertexts, etc. — stay
// local to their call sites).

import { Schema } from "effect";

/** Pattern for an exact-length lowercase-hex string (`bytes` decoded bytes). */
export function hexPattern(bytes: number): RegExp {
  return new RegExp(`^[0-9a-f]{${bytes * 2}}$`);
}

/** Schema for an exact-length lowercase-hex string (`bytes` decoded bytes). */
export function hexString(bytes: number): Schema.String {
  return Schema.String.check(
    Schema.isPattern(hexPattern(bytes), {
      description: `lowercase hex (${bytes} bytes)`,
    }),
  );
}

/** SHA-256 hash (chain head, prev, entry hash, signed-bytes hash). */
export const Sha256Hex = hexString(32);

/** 32-byte public key (key registration in chain payloads — Ed25519 / X25519). */
export const PublicKeyHex = hexString(32);

/** X25519 encryption public key (recipient key for DEK wraps — CRYPTO_SPEC §5). */
export const EncPubHex = hexString(32);

/** HPKE enc (the encapsulated sender ephemeral public key — CRYPTO_SPEC §5). */
export const HpkeEncHex = hexString(32);

/** Key fingerprint (16 bytes — CRYPTO_SPEC §3). */
export const KeyFingerprintHex = hexString(16);

/** Chain entry signature (Ed25519 — CRYPTO_SPEC §6.1). */
export const SignatureHex = hexString(64);

/** DEK-wrap registration signature (Ed25519 — CRYPTO_SPEC §5.1). */
export const WrapSignatureHex = hexString(64);

/** Value write signature (Ed25519 — CRYPTO_SPEC §4.1). */
export const ValueSignatureHex = hexString(64);

/** Meta-statement signature (Ed25519 — CRYPTO_SPEC §4.2). */
export const MetaSignatureHex = hexString(64);

/** Environment-manifest signature (Ed25519 — CRYPTO_SPEC §4.3). */
export const ManifestSignatureHex = hexString(64);

/** Invite acceptance signature (Ed25519 — CRYPTO_SPEC §6.5). */
export const InviteAcceptSignatureHex = hexString(64);

/** Invite link signature (Ed25519 — CRYPTO_SPEC §6.5; the link key's co-signature). */
export const InviteLinkSignatureHex = hexString(64);

/** Invite issuance signature (Ed25519 — CRYPTO_SPEC §6.5; the inviter's chain sig key). */
export const InviteIssueSignatureHex = hexString(64);

/** Head-attestation signature (Ed25519 — CRYPTO_SPEC §6.6). */
export const HeadAttestationSignatureHex = hexString(64);

/**
 * Integer starting at 1 (epoch / version / chain seq — CRYPTO_SPEC §3 /
 * §4 / §6). Not hex, but kept here as the shared definition for the
 * chain-head field family (the hash + seq pair).
 */
export const PositiveInt = Schema.Number.check(Schema.isInt(), Schema.isGreaterThanOrEqualTo(1));
