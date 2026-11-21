import { Schema } from "effect";

export function hexPattern(bytes: number): RegExp {
  return new RegExp(`^[0-9a-f]{${bytes * 2}}$`);
}

export function hexString(bytes: number): Schema.String {
  return Schema.String.check(
    Schema.isPattern(hexPattern(bytes), {
      description: `lowercase hex (${bytes} bytes)`,
    }),
  );
}

export const Sha256Hex = hexString(32);

export const PublicKeyHex = hexString(32);

export const EncPubHex = hexString(32);

export const HpkeEncHex = hexString(32);

export const KeyFingerprintHex = hexString(16);

export const SignatureHex = hexString(64);

export const WrapSignatureHex = hexString(64);

export const ValueSignatureHex = hexString(64);

export const MetaSignatureHex = hexString(64);

export const ManifestSignatureHex = hexString(64);

export const InviteAcceptSignatureHex = hexString(64);

export const InviteLinkSignatureHex = hexString(64);

export const InviteIssueSignatureHex = hexString(64);

export const HeadAttestationSignatureHex = hexString(64);

export const PositiveInt = Schema.Number.check(Schema.isInt(), Schema.isGreaterThanOrEqualTo(1));
